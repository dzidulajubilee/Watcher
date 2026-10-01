"""
Watcher IDS Dashboard — EVE JSON Tail
Background thread that tails eve.json and dispatches all event types:
  alert, flow, dns, http
"""

import json
import logging
import os
from collections import deque
import secrets
import threading
import time

from webhooks import dispatch as _webhook_dispatch

log = logging.getLogger("watcher.tail")

_SEVERITY_MAP = {
    1: "critical",   # classtype: trojan-activity, attempted-admin, domain-c2, etc.
    2: "high",       # classtype: bad-unknown, attempted-recon, misc-attack, etc.
    3: "medium",     # classtype: icmp-event, network-scan, protocol-command-decode, etc.
    4: "low",        # classtype: tcp-connection
    5: "info",       # custom local rules (local.rules, sid:9000001+)
}

# Category overrides — these take precedence over the numeric priority map.
# Suricata writes the classtype's short description into alert.category in eve.json.
# Only entries that need reclassification away from their default priority are listed.
_CATEGORY_OVERRIDE = {
    "not suspicious traffic": "info",   # classtype:not-suspicious  (priority 3 → info)
    "misc activity":          "low",    # classtype:misc-activity    (priority 3 → low)
}


def map_severity(level, category: str = "") -> str:
    """
    Resolve a Suricata numeric priority + category string to a Watcher
    severity label.

    Category overrides are checked first so that semantically weak classtypes
    (not-suspicious, misc-activity) are not over-reported as 'medium' purely
    because Suricata assigns them priority 3.
    """
    override = _CATEGORY_OVERRIDE.get(category.lower().strip())
    if override:
        return override
    return _SEVERITY_MAP.get(level, "info")


def parse_eve_line(raw: str):
    """
    Parse one eve.json line.
    Returns (event_type, parsed) where event_type is one of:
      'alert' | 'flow' | 'dns' | 'http' | None
    parsed is the normalised dict (for alert) or raw evt dict (for others).
    """
    raw = raw.strip()
    if not raw:
        return None, None
    try:
        evt = json.loads(raw)
    except json.JSONDecodeError:
        return None, None

    etype = evt.get("event_type")

    if etype == "alert":
        a = evt.get("alert", {})
        return "alert", {
            "id":       f"{evt.get('flow_id',0)}-{int(time.time()*1000)}-{secrets.token_hex(4)}",
            "ts":       evt.get("timestamp", ""),
            "src_ip":   evt.get("src_ip", ""),
            "src_port": evt.get("src_port", 0),
            "dst_ip":   evt.get("dest_ip", ""),
            "dst_port": evt.get("dest_port", 0),
            "proto":    evt.get("proto", "TCP").upper(),
            "iface":    evt.get("in_iface", ""),
            "flow_id":  evt.get("flow_id", 0),
            "sig_id":   a.get("signature_id", 0),
            "sig_msg":  a.get("signature", ""),
            "category": a.get("category", ""),
            "severity": map_severity(a.get("severity"), a.get("category", "")),
            "action":   a.get("action", "allowed"),
            "raw":      evt,
        }

    if etype == "flow":
        return "flow", evt

    if etype == "dns":
        return "dns", evt

    if etype == "http":
        return "http", evt

    return None, None


def _flow_summary(evt: dict) -> dict:
    """Compact flow dict for SSE broadcast (avoids sending huge raw eve blobs)."""
    f = evt.get("flow", {})
    return {
        "flow_id":        evt.get("flow_id", 0),
        "ts":             evt.get("timestamp", ""),
        "src_ip":         evt.get("src_ip", ""),
        "src_port":       evt.get("src_port", 0),
        "dst_ip":         evt.get("dest_ip", ""),
        "dst_port":       evt.get("dest_port", 0),
        "proto":          evt.get("proto", "").upper(),
        "app_proto":      evt.get("app_proto", ""),
        "state":          f.get("state", ""),
        "reason":         f.get("reason", ""),
        "pkts_toserver":  f.get("pkts_toserver", 0),
        "pkts_toclient":  f.get("pkts_toclient", 0),
        "bytes_toserver": f.get("bytes_toserver", 0),
        "bytes_toclient": f.get("bytes_toclient", 0),
        "alerted":        bool(f.get("alerted")),
    }


def _dns_summary(evt: dict) -> dict:
    d = evt.get("dns", {})
    return {
        "ts":       evt.get("timestamp", ""),
        "src_ip":   evt.get("src_ip", ""),
        "dst_ip":   evt.get("dest_ip", ""),
        "flow_id":  evt.get("flow_id", 0),
        "dns_type": d.get("type", ""),
        "rrname":   d.get("rrname", ""),
        "rrtype":   d.get("rrtype", ""),
        "rcode":    d.get("rcode", ""),
        "ttl":      d.get("ttl", 0),
    }


def _http_summary(evt: dict) -> dict:
    h = evt.get("http", {})
    return {
        "ts":         evt.get("timestamp", ""),
        "src_ip":     evt.get("src_ip", ""),
        "dst_ip":     evt.get("dest_ip", ""),
        "flow_id":    evt.get("flow_id", 0),
        "hostname":   h.get("hostname", ""),
        "url":        h.get("url", ""),
        "method":     h.get("http_method", ""),
        "status":     h.get("status", 0),
        "user_agent": h.get("http_user_agent", ""),
    }


# ── Group commit tuning ────────────────────────────────────────────────────
# Events are written in batches: one transaction per BATCH_MAX_EVENTS events
# or per BATCH_MAX_WAIT seconds, whichever comes first — and immediately
# whenever the reader has caught up with eve.json, so a quiet sensor sees no
# added latency.  Under sustained load the added latency is at most
# BATCH_MAX_WAIT.  Dashboards and webhooks are notified only after the batch
# is committed, so what they show is always stored.
BATCH_MAX_EVENTS = 500
BATCH_MAX_WAIT   = 0.10    # seconds

# ── Live view batching (v1.10) ─────────────────────────────────────────────
# Flow / DNS / HTTP events are NOT streamed to browsers one by one: at
# thousands of events per second a browser cannot keep up, its SSE queue
# overflows, and it is disconnected (missing alerts while it reconnects).
# Instead, once per LIVE_BATCH_INTERVAL the most recent LIVE_BATCH_MAX
# summaries of each type are sent as one '<type>_batch' SSE event:
#     {"items": [oldest … newest], "count": <events in the interval>,
#      "interval": <seconds>}
# Alerts are still streamed individually and immediately.  All events are
# stored regardless; this only affects the live view.
LIVE_BATCH_INTERVAL = 1.0   # seconds
LIVE_BATCH_MAX      = 200   # most recent items per type per interval


def tail_thread(path: str, db, registry, wdb=None, dns_db=None, sup_db=None,
               explain_engine=None):
    """
    Runs forever in a daemon thread.
    Tails eve.json, persists each event, and broadcasts SSE summaries.
    dns_db: DnsDB instance — if provided, DNS events go here instead of db.
    explain_engine: optional ExplainEngine — auto-generates executive summaries
      for new sig_ids in the background (one call per unique SID, cached).

    v1.9: reads complete lines only (a line Suricata has only half-written is
    left for the next read instead of being parsed and lost), tracks the file
    position in bytes (no per-line tell()), and group-commits events.
    """
    # Track which sig_ids we have already queued for auto-explain this session.
    _explained_sids: set = set()
    log.info("Tailing %s", path)

    pos = 0
    try:
        pos = os.path.getsize(path)
        log.info("Starting at offset %d (existing history skipped).", pos)
    except OSError:
        log.warning("Eve file not found yet — will wait.")

    b_alerts, b_flows, b_dns, b_http = [], [], [], []
    pending, first_at = 0, 0.0
    warned_no_dns_db = False

    live_items  = {k: deque(maxlen=LIVE_BATCH_MAX) for k in ("flow", "dns", "http")}
    live_counts = {k: 0 for k in live_items}
    live_last   = [time.monotonic()]

    def emit_live(force: bool = False):
        now = time.monotonic()
        if not force and now - live_last[0] < LIVE_BATCH_INTERVAL:
            return
        interval = round(now - live_last[0], 3)
        live_last[0] = now
        for kind, items in live_items.items():
            if live_counts[kind]:
                registry.broadcast(f"{kind}_batch", {"items": list(items),
                                                     "count": live_counts[kind],
                                                     "interval": interval})
                items.clear()
                live_counts[kind] = 0

    def flush():
        nonlocal b_alerts, b_flows, b_dns, b_http, pending, warned_no_dns_db
        if not pending:
            return
        db.insert_batch(alerts=b_alerts, flows=b_flows, http=b_http)
        if dns_db is not None:
            dns_db.insert_batch(b_dns)
        elif b_dns and not warned_no_dns_db:
            log.warning("No DNS database configured — DNS events are not stored.")
            warned_no_dns_db = True
        # Publish only after the batch is committed.
        for parsed in b_alerts:
            registry.broadcast("alert", parsed)
            if wdb is not None:
                _webhook_dispatch(parsed, wdb)
            # ── Auto-explain (background, per unique SID) ──
            if explain_engine is not None:
                _auto_explain(parsed, explain_engine,
                              _explained_sids)
        # Flow/DNS/HTTP: summarised into the once-per-second live batches.
        # Only the last LIVE_BATCH_MAX of each type can be shown, so skip
        # building summaries that would be discarded immediately.
        for kind, events, summarise in (("flow", b_flows, _flow_summary),
                                        ("dns",  b_dns,   _dns_summary),
                                        ("http", b_http,  _http_summary)):
            if events:
                live_counts[kind] += len(events)
                live_items[kind].extend(summarise(e) for e in events[-LIVE_BATCH_MAX:])
        b_alerts, b_flows, b_dns, b_http = [], [], [], []
        pending = 0
        emit_live()

    while True:
        try:
            with open(path, "rb") as f:
                f.seek(pos)
                while True:
                    line = f.readline()
                    if line.endswith(b"\n"):
                        pos += len(line)
                        etype, parsed = parse_eve_line(
                            line.decode("utf-8", errors="replace"))
                        if etype is None:
                            continue
                        if etype == "alert":
                            if sup_db is not None and sup_db.is_suppressed(parsed):
                                continue          # silenced by suppression rule
                            b_alerts.append(parsed)
                        elif etype == "flow":
                            b_flows.append(parsed)
                        elif etype == "dns":
                            b_dns.append(parsed)
                        elif etype == "http":
                            b_http.append(parsed)
                        pending += 1
                        if pending == 1:
                            first_at = time.monotonic()
                        if (pending >= BATCH_MAX_EVENTS or
                                time.monotonic() - first_at >= BATCH_MAX_WAIT):
                            flush()
                        continue

                    # No complete line available: either EOF, or Suricata is
                    # mid-write.  Leave a partial line in the file for the next
                    # read, publish what we have, then wait.
                    if line:
                        f.seek(pos)
                    flush()
                    emit_live()          # keep the live view current when idle
                    try:
                        if os.path.getsize(path) < pos:
                            log.info("Log rotation detected — rewinding.")
                            pos = 0
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
        except OSError as exc:
            flush()
            log.warning("Cannot open %s: %s — retrying in 3 s.", path, exc)
            time.sleep(3)


def purge_thread(db, auth, dns_db=None):
    from config import PURGE_EVERY
    while True:
        time.sleep(PURGE_EVERY)
        db.purge_old()
        auth.purge_expired()
        if dns_db is not None:
            dns_db.purge_old()
        # Checkpoint WAL files after purge so they don't grow unbounded
        try:
            db._conn().execute("PRAGMA wal_checkpoint(PASSIVE)")
            if dns_db is not None:
                dns_db._conn().execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            pass

def replay_eve(path: str, db, registry,
               dns_db=None, sup_db=None,
               progress_cb=None) -> dict:
    """
    Read eve.json from the beginning and insert every event into the DB.
    Alerts already stored (same flow_id + timestamp + signature) are skipped
    via AlertDB.alert_exists() — alert IDs carry a random suffix, so the
    primary key alone cannot de-duplicate.  Flows/DNS/HTTP use deterministic
    keys and are de-duplicated by INSERT OR IGNORE.
    Called by the admin Data Control panel — runs in a background thread.

    Webhooks are intentionally NOT fired during replay; only live tail_thread
    events should trigger external notifications.

    progress_cb: optional callable(inserted, skipped, total_lines) for status updates.
    Returns { inserted, skipped, errors, lines, suppressed, duplicates }.
    skipped = suppressed + duplicates (kept for UI compatibility).
    """
    inserted = skipped = errors = lines = 0
    suppressed = duplicates = 0
    log.info("Replay started: %s", path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                lines += 1
                etype, parsed = parse_eve_line(raw)
                if etype is None:
                    continue
                try:
                    if etype == "alert":
                        if sup_db and sup_db.is_suppressed(parsed):
                            skipped += 1; suppressed += 1
                        elif db.alert_exists(parsed["flow_id"], parsed["ts"],
                                             parsed["sig_id"]):
                            skipped += 1; duplicates += 1
                        else:
                            db.insert(parsed)
                            registry.broadcast("alert", parsed)
                            # wdb intentionally omitted — replay must not fire live webhooks
                            inserted += 1
                    elif etype == "flow":
                        db.insert_flow(parsed); inserted += 1
                    elif etype == "dns":
                        if dns_db:
                            dns_db.insert(parsed)
                            inserted += 1
                    elif etype == "http":
                        db.insert_http(parsed); inserted += 1
                    if progress_cb and lines % 1000 == 0:
                        progress_cb(inserted, skipped, lines)
                except Exception as exc:
                    log.warning("Replay line %d error: %s", lines, exc)
                    errors += 1
    except OSError as exc:
        log.error("Replay failed to open %s: %s", path, exc)
        return {"inserted": inserted, "skipped": skipped,
                "errors": errors + 1, "lines": lines,
                "suppressed": suppressed, "duplicates": duplicates}

    log.info("Replay complete: %d lines, %d inserted, %d skipped "
             "(%d suppressed, %d already stored), %d errors.",
             lines, inserted, skipped, suppressed, duplicates, errors)
    return {"inserted": inserted, "skipped": skipped,
            "errors": errors, "lines": lines,
            "suppressed": suppressed, "duplicates": duplicates}


def _auto_explain(alert: dict, engine, seen: set) -> None:
    """
    Fire-and-forget: spawn a daemon thread to generate an executive summary
    for a new sig_id.  Skips immediately if:
      - no API key is configured
      - this sig_id was already queued this session
      - the DB already has a cached explanation for this SID
    """
    sig_id = alert.get("sig_id")
    if not sig_id or sig_id in seen:
        return
    if not engine.has_key():
        return

    # Mark as seen before spawning to prevent race on rapid duplicates
    seen.add(sig_id)

    def _worker():
        try:
            result = engine.explain(alert, force=False)
            if result.get("cached"):
                log.debug("Auto-explain SID %d: cache hit, skipped API call.", sig_id)
            else:
                log.info("Auto-explain SID %d: summary generated (%d tokens).",
                         sig_id,
                         result.get("prompt_tokens", 0) + result.get("completion_tokens", 0))
        except Exception as exc:
            log.warning("Auto-explain SID %d failed: %s", sig_id, exc)

    t = threading.Thread(target=_worker, daemon=True,
                         name=f"explain-{sig_id}")
    t.start()
