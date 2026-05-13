"""
Watcher IDS Dashboard — EVE JSON Tail
Background thread that tails eve.json and dispatches all event types:
  alert, flow, dns, http
"""

import json
import logging
import os
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


def tail_thread(path: str, db, registry, wdb=None, dns_db=None, sup_db=None,
               explain_engine=None):
    """
    Runs forever in a daemon thread.
    Tails eve.json, persists each event, and broadcasts SSE summaries.
    dns_db: DnsDB instance — if provided, DNS events go here instead of db.
    explain_engine: optional ExplainEngine — auto-generates executive summaries
      for new sig_ids in the background (one call per unique SID, cached).
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

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                while True:
                    line = f.readline()
                    if line:
                        etype, parsed = parse_eve_line(line)

                        if etype == "alert":
                            if sup_db is not None and sup_db.is_suppressed(parsed):
                                pass  # silenced by suppression rule
                            else:
                                db.insert(parsed)
                                registry.broadcast("alert", parsed)
                                if wdb is not None:
                                    _webhook_dispatch(parsed, wdb)
                                # ── Auto-explain (background, per unique SID) ──
                                if explain_engine is not None:
                                    _auto_explain(parsed, explain_engine,
                                                  _explained_sids)

                        elif etype == "flow":
                            db.insert_flow(parsed)
                            registry.broadcast("flow", _flow_summary(parsed))

                        elif etype == "dns":
                            if dns_db is not None:
                                dns_db.insert(parsed)
                            else:
                                db.insert_dns(parsed)
                            registry.broadcast("dns", _dns_summary(parsed))

                        elif etype == "http":
                            db.insert_http(parsed)
                            registry.broadcast("http", _http_summary(parsed))

                        pos = f.tell()
                    else:
                        try:
                            if os.path.getsize(path) < pos:
                                log.info("Log rotation detected — rewinding.")
                                pos = 0
                                break
                        except OSError:
                            pass
                        time.sleep(0.1)
        except OSError as exc:
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
    Existing records are skipped (upsert-on-conflict by ts+flow_id).
    Called by the admin Data Control panel — runs in a background thread.

    Webhooks are intentionally NOT fired during replay; only live tail_thread
    events should trigger external notifications.

    progress_cb: optional callable(inserted, skipped, total_lines) for status updates.
    Returns { inserted, skipped, errors, lines }.
    """
    inserted = skipped = errors = lines = 0
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
                            skipped += 1
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
                        else:
                            db.insert_dns(parsed)
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
                "errors": errors + 1, "lines": lines}

    log.info("Replay complete: %d lines, %d inserted, %d skipped, %d errors.",
             lines, inserted, skipped, errors)
    return {"inserted": inserted, "skipped": skipped,
            "errors": errors, "lines": lines}


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
