"""
Watcher IDS Dashboard — Webhook Engine
Stores webhook configurations in SQLite and delivers alert notifications
via HTTP POST to Slack, Discord, or any generic JSON endpoint.

Delivery is async (background thread + queue) so it never blocks the
tail thread or SSE broadcasts.
"""

import json
import logging
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from queue import Queue, Empty

log = logging.getLogger("watcher.webhooks")

# Severities in order — used for filtering UI
ALL_SEVERITIES = ["critical", "high", "medium", "low", "info"]

# ── SSRF protection ──────────────────────────────────────────────────────────
# Webhook URLs are validated before delivery and before saving.
# By default, private/loopback ranges are blocked to prevent SSRF.
# Set allow_local_ips=True (via Settings → Webhooks → Allow Local IPs)
# if your webhook target is on the same network — e.g. n8n running locally.

import ipaddress
import urllib.parse

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]

_ALLOWED_SCHEMES = {"http", "https"}

# ── Webhook list in-memory cache (P-01 fix) ───────────────────────────────────
# dispatch() is called on every alert; caching avoids a DB round-trip each time.
_wh_cache: list = []
_wh_cache_ts: float = 0.0
_wh_cache_lock = threading.Lock()
_WH_CACHE_TTL = 30   # seconds — webhooks rarely change


def validate_webhook_url(url: str, allow_local: bool = False) -> str | None:
    """
    Validate a webhook URL for safety.
    Returns None if OK, or an error string if blocked.

    allow_local=True permits RFC1918 / loopback destinations (e.g. n8n on LAN).
    allow_local=False (default) blocks all private/loopback IPs — SSRF protection.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return "Invalid URL"

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return f"URL scheme '{parsed.scheme}' not allowed (use http or https)"

    hostname = parsed.hostname
    if not hostname:
        return "URL has no hostname"

    # Block metadata endpoints by hostname
    if hostname.lower() in ("169.254.169.254", "metadata.google.internal"):
        return "URL targets a cloud metadata endpoint"

    if allow_local:
        return None   # n8n / local targets explicitly permitted

    # Resolve and check every address the hostname maps to
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}"

    for info in infos:
        addr_str = info[4][0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return (
                    f"URL resolves to private/loopback address {addr_str}. "
                    "Enable 'Allow Local IPs' in Webhook settings if your "
                    "webhook target (e.g. n8n) is on the local network."
                )
    return None


# How many delivery attempts before giving up on one alert
MAX_RETRIES    = 3
RETRY_DELAY    = 5      # seconds between retries
QUEUE_MAX      = 1000   # max pending deliveries
DELIVERY_TIMEOUT = 10   # seconds per HTTP request

# Rate limiting — suppress repeated fires of the same sig on the same webhook.
# A webhook will not re-fire for the same signature_id within this window.
COOLDOWN_SECS  = 60     # seconds (set to 0 to disable)

# Internal rate-limit state: maps (webhook_id, sig_id) → last-fired epoch
_cooldown: dict[tuple, float] = {}
_cooldown_lock = threading.Lock()


class WebhookDB:
    """
    Stores webhook configurations in the same SQLite database as alerts.
    Each webhook has:
      - id, name, type (slack|discord|generic), url
      - enabled flag
      - severities: JSON list of which severities trigger this webhook
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL,
                type            TEXT    NOT NULL DEFAULT 'generic',
                url             TEXT    NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1,
                severities      TEXT    NOT NULL DEFAULT '["critical","high","medium","low","info"]',
                allow_local_ips INTEGER NOT NULL DEFAULT 0,
                created_at      REAL    NOT NULL,
                last_fired      REAL,
                fire_count      INTEGER NOT NULL DEFAULT 0,
                last_error      TEXT
            )
        """)
        # Migration: add allow_local_ips column for existing installs
        cols = {r[1] for r in c.execute("PRAGMA table_info(webhooks)").fetchall()}
        if "allow_local_ips" not in cols:
            c.execute("ALTER TABLE webhooks ADD COLUMN allow_local_ips INTEGER NOT NULL DEFAULT 0")
        c.commit()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        rows = self._conn().execute("""
            SELECT id, name, type, url, enabled, severities, allow_local_ips,
                   created_at, last_fired, fire_count, last_error
            FROM webhooks ORDER BY id
        """).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_cached(self) -> list[dict]:
        """
        Return the webhook list from memory when possible (P-01).
        Refreshes from DB if the cache is older than _WH_CACHE_TTL seconds.
        All mutations call _invalidate_cache() so the next dispatch() sees
        the updated list immediately.
        """
        global _wh_cache, _wh_cache_ts
        with _wh_cache_lock:
            if time.time() - _wh_cache_ts > _WH_CACHE_TTL:
                _wh_cache    = self.get_all()
                _wh_cache_ts = time.time()
            return list(_wh_cache)   # shallow copy — callers must not mutate

    def _invalidate_cache(self):
        """Force the next get_cached() call to re-query the database."""
        global _wh_cache_ts
        with _wh_cache_lock:
            _wh_cache_ts = 0.0

    def get(self, wid: int) -> dict | None:
        row = self._conn().execute(
            "SELECT id, name, type, url, enabled, severities, allow_local_ips, "
            "created_at, last_fired, fire_count, last_error "
            "FROM webhooks WHERE id = ?", (wid,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def create(self, name: str, wtype: str, url: str,
               severities: list, enabled: bool = True,
               allow_local_ips: bool = False) -> dict:
        now = time.time()
        c   = self._conn()
        cur = c.execute("""
            INSERT INTO webhooks (name, type, url, enabled, severities, allow_local_ips, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, wtype, url, 1 if enabled else 0,
              json.dumps(severities), 1 if allow_local_ips else 0, now))
        c.commit()
        self._invalidate_cache()
        return self.get(cur.lastrowid)

    def update(self, wid: int, **fields) -> dict | None:
        allowed = {"name", "type", "url", "enabled", "severities", "allow_local_ips"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get(wid)
        if "severities" in updates and isinstance(updates["severities"], list):
            updates["severities"] = json.dumps(updates["severities"])
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        if "allow_local_ips" in updates:
            updates["allow_local_ips"] = 1 if updates["allow_local_ips"] else 0
            # BUG FIX: when the user enables "Allow Local / Private IPs", clear
            # any stale SSRF-blocked last_error so the UI no longer shows the old
            # "Blocked: URL resolves to private/loopback address" banner.
            if updates["allow_local_ips"]:
                updates["last_error"] = None
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [wid]
        c = self._conn()
        c.execute(f"UPDATE webhooks SET {cols} WHERE id = ?", vals)
        c.commit()
        self._invalidate_cache()
        return self.get(wid)

    def delete(self, wid: int):
        c = self._conn()
        c.execute("DELETE FROM webhooks WHERE id = ?", (wid,))
        c.commit()
        self._invalidate_cache()

    def _mark_fired(self, wid: int, error: str | None = None):
        c = self._conn()
        if error:
            c.execute("""
                UPDATE webhooks
                SET last_fired = ?, fire_count = fire_count + 1, last_error = ?
                WHERE id = ?
            """, (time.time(), error[:500], wid))
        else:
            c.execute("""
                UPDATE webhooks
                SET last_fired = ?, fire_count = fire_count + 1, last_error = NULL
                WHERE id = ?
            """, (time.time(), wid))
        c.commit()

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(row)
        try:
            d["severities"] = json.loads(d.get("severities", "[]"))
        except Exception:
            d["severities"] = ALL_SEVERITIES
        d["enabled"]         = bool(d.get("enabled", 1))
        d["allow_local_ips"] = bool(d.get("allow_local_ips", 0))
        return d


# ── Payload formatters ────────────────────────────────────────────────────────

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

SEV_COLOR = {
    "critical": 15158332,   # red
    "high":     16744272,   # orange
    "medium":   16766720,   # yellow
    "low":      5025616,    # green
    "info":     5267393,    # blue
}


def format_slack(alert: dict) -> dict:
    """Slack Block Kit payload."""
    sev   = alert.get("severity", "info")
    emoji = SEV_EMOJI.get(sev, "⚪")
    ts    = alert.get("ts", "")[:19].replace("T", " ")
    return {
        "text": f"{emoji} *Watcher Alert* — {alert.get('sig_msg', '')}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Watcher IDS Alert",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert.get('sig_msg', 'Unknown signature')}*",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev.upper()}"},
                    {"type": "mrkdwn", "text": f"*Category*\n{alert.get('category', '—')}"},
                    {"type": "mrkdwn", "text": f"*Source*\n`{alert.get('src_ip', '?')}:{alert.get('src_port', '?')}`"},
                    {"type": "mrkdwn", "text": f"*Destination*\n`{alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}`"},
                    {"type": "mrkdwn", "text": f"*Protocol*\n{alert.get('proto', '?')}"},
                    {"type": "mrkdwn", "text": f"*SID*\n{alert.get('sig_id', '?')}"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"🕐 {ts}  |  Interface: {alert.get('iface', 'eth0')}"}
                ]
            }
        ]
    }


def format_discord(alert: dict) -> dict:
    """Discord webhook payload using embeds."""
    sev   = alert.get("severity", "info")
    emoji = SEV_EMOJI.get(sev, "⚪")
    ts    = alert.get("ts", "")[:19].replace("T", " ")
    return {
        "username": "Watcher IDS",
        "avatar_url": "",
        "embeds": [
            {
                "title": f"{emoji} {alert.get('sig_msg', 'Unknown signature')}",
                "color": SEV_COLOR.get(sev, 5267393),
                "fields": [
                    {"name": "Severity",     "value": sev.upper(),                                           "inline": True},
                    {"name": "Category",     "value": alert.get("category", "—"),                           "inline": True},
                    {"name": "Protocol",     "value": alert.get("proto", "?"),                              "inline": True},
                    {"name": "Source",       "value": f"`{alert.get('src_ip','?')}:{alert.get('src_port','?')}`", "inline": True},
                    {"name": "Destination",  "value": f"`{alert.get('dst_ip','?')}:{alert.get('dst_port','?')}`", "inline": True},
                    {"name": "SID",          "value": str(alert.get("sig_id", "?")),                        "inline": True},
                ],
                "footer": {"text": f"Watcher IDS  •  {ts}"},
            }
        ]
    }


def format_generic(alert: dict) -> dict:
    """Plain JSON payload for custom endpoints (Teams, Mattermost, etc.)."""
    return {
        "source":      "Watcher IDS",
        "timestamp":   alert.get("ts", ""),
        "severity":    alert.get("severity", "info"),
        "signature":   alert.get("sig_msg", ""),
        "category":    alert.get("category", ""),
        "sig_id":      alert.get("sig_id", 0),
        "src_ip":      alert.get("src_ip", ""),
        "src_port":    alert.get("src_port", 0),
        "dst_ip":      alert.get("dst_ip", ""),
        "dst_port":    alert.get("dst_port", 0),
        "proto":       alert.get("proto", ""),
        "iface":       alert.get("iface", ""),
        "action":      alert.get("action", "allowed"),
    }


def build_payload(wtype: str, alert: dict) -> dict:
    if wtype == "slack":
        return format_slack(alert)
    if wtype == "discord":
        return format_discord(alert)
    return format_generic(alert)


# ── HTTP delivery ─────────────────────────────────────────────────────────────

def deliver(url: str, payload: dict, allow_local: bool = False) -> str | None:
    """
    POST payload as JSON to url.
    Returns None on success, or an error string on failure.
    Validates URL for SSRF before connecting (allow_local bypasses for n8n etc.)
    """
    ssrf_err = validate_webhook_url(url, allow_local=allow_local)
    if ssrf_err:
        return f"Blocked: {ssrf_err}"
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Watcher-IDS/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=DELIVERY_TIMEOUT) as resp:
            status = resp.status
            if 200 <= status < 300:
                return None
            return f"HTTP {status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return f"URLError: {e.reason}"
    except Exception as e:
        return f"Error: {e}"


# ── Delivery queue + worker ────────────────────────────────────────────────────

_queue: Queue = Queue(maxsize=QUEUE_MAX)


def enqueue(webhook: dict, alert: dict,
            retry_after: float = 0.0, attempt: int = 1):
    """Non-blocking enqueue. Drops silently if queue is full."""
    try:
        _queue.put_nowait((webhook, alert, retry_after, attempt))
    except Exception:
        pass


def delivery_worker(wdb: WebhookDB):
    """
    Runs forever in a daemon thread.
    Drains the delivery queue without blocking on retry back-off (P-04).

    Failed deliveries are re-enqueued with a future retry_after timestamp
    so the worker can continue processing other webhooks during the wait
    window instead of sleeping and stalling all deliveries.
    """
    while True:
        try:
            webhook, alert, retry_after, attempt = _queue.get(timeout=1)
        except Empty:
            continue

        # Deferred item — not ready yet; put it back and yield briefly
        now = time.time()
        if retry_after > now:
            try:
                _queue.put_nowait((webhook, alert, retry_after, attempt))
            except Exception:
                pass   # queue full — drop this retry
            time.sleep(0.1)
            continue

        wid         = webhook["id"]
        wtype       = webhook.get("type", "generic")
        url         = webhook.get("url", "")
        payload     = build_payload(wtype, alert)
        allow_local = webhook.get("allow_local_ips", False)

        error = deliver(url, payload, allow_local=allow_local)
        if error is None:
            log.info("Webhook %d (%s) fired OK for alert %s",
                     wid, webhook.get("name", "?"), alert.get("sig_id", "?"))
            wdb._mark_fired(wid, None)
        else:
            log.warning("Webhook %d attempt %d/%d failed: %s",
                        wid, attempt, MAX_RETRIES, error)
            if attempt < MAX_RETRIES:
                # Re-enqueue for a future attempt — does not block the worker
                enqueue(webhook, alert,
                        retry_after=time.time() + RETRY_DELAY,
                        attempt=attempt + 1)
            else:
                log.error("Webhook %d giving up after %d attempts: %s",
                          wid, MAX_RETRIES, error)
                wdb._mark_fired(wid, error)


# ── Main dispatcher ────────────────────────────────────────────────────────────

def dispatch(alert: dict, wdb: WebhookDB):
    """
    Called by tail_thread for each new alert.
    Checks every enabled webhook and enqueues delivery if:
      - the alert's severity matches the webhook's configured filter, AND
      - the same (signature, src_ip) pair has not already fired this webhook
        within COOLDOWN_SECS.

    The cooldown is keyed on (webhook_id, sig_id, src_ip) so that the same
    rule firing from different source IPs is never suppressed — only repeated
    hits from the same host are throttled.
    """
    sev    = alert.get("severity", "info")
    sig_id = alert.get("sig_id", 0)
    src_ip = alert.get("src_ip", "")
    now    = time.time()

    with _cooldown_lock:
        # Prune stale entries so the dict doesn't grow unboundedly
        if len(_cooldown) > 10_000:
            cutoff = now - COOLDOWN_SECS
            stale  = [k for k, t in _cooldown.items() if t < cutoff]
            for k in stale:
                del _cooldown[k]

    for wh in wdb.get_cached():
        if not wh.get("enabled"):
            continue
        if sev not in wh.get("severities", ALL_SEVERITIES):
            continue

        if COOLDOWN_SECS > 0:
            key = (wh["id"], sig_id, src_ip)
            with _cooldown_lock:
                last_fired = _cooldown.get(key, 0.0)
                if now - last_fired < COOLDOWN_SECS:
                    log.debug(
                        "Webhook %d: suppressing sig %s from %s (cooldown %.0fs remaining)",
                        wh["id"], sig_id, src_ip, COOLDOWN_SECS - (now - last_fired),
                    )
                    continue
                _cooldown[key] = now

        enqueue(wh, alert)
