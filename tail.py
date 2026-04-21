"""
Watcher IDS Dashboard — EVE JSON Tail
Background thread that tails eve.json and dispatches all event types:
  alert, flow, dns, http
"""

import json
import logging
import os
import time

log = logging.getLogger("watcher.tail")

_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def map_severity(level):
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
            "id":       f"{evt.get('flow_id',0)}-{int(time.time()*1000)}",
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
            "severity": map_severity(a.get("severity")),
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


def tail_thread(path: str, db, registry, wdb=None):
    """
    Runs forever in a daemon thread.
    Tails eve.json, persists each event, and broadcasts SSE summaries.
    """
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
                            db.insert(parsed)
                            registry.broadcast("alert", parsed)
                            if wdb is not None:
                                from webhooks import dispatch
                                dispatch(parsed, wdb)

                        elif etype == "flow":
                            db.insert_flow(parsed)
                            registry.broadcast("flow", _flow_summary(parsed))

                        elif etype == "dns":
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


def purge_thread(db, auth):
    from config import PURGE_EVERY
    while True:
        time.sleep(PURGE_EVERY)
        db.purge_old()
        auth.purge_expired()
