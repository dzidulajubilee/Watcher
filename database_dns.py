"""
Watcher IDS Dashboard — DNS Database
Dedicated SQLite wrapper for DNS events.

Kept separate from events.db because DNS query volume is typically an order
of magnitude higher than alerts or flows — on an active network, thousands of
DNS events per minute are normal. A dedicated dns.db prevents that write
pressure from affecting alert queries and chart generation in events.db.

Bug fix (vs previous inline implementation in database.py):
  The old unique ID used only flow_id + tx_id + type, which collided whenever
  tx_id=0 (common in Suricata). The new ID includes rrname, making it
  genuinely unique per query name per transaction.
"""

import json
import logging
import re as _re
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger("watcher.dns_db")

_RE_USEC = _re.compile(r"(\.\d{3})\d+")
_RE_TZ   = _re.compile(r"([+-]\d{2})(\d{2})$")


class DnsDB:
    def __init__(self, path: str | Path, retain_days: int = 90):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        self._conn()
        log.info("DNS DB    : %s  (retain %d days)", self.path, self.retain_days)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.execute("""
                CREATE TABLE IF NOT EXISTS dns_events (
                    id       TEXT PRIMARY KEY,
                    ts       TEXT NOT NULL,
                    ts_epoch REAL NOT NULL,
                    src_ip   TEXT,
                    src_port INTEGER,
                    dst_ip   TEXT,
                    dst_port INTEGER,
                    iface    TEXT,
                    flow_id  INTEGER,
                    tx_id    INTEGER,
                    dns_type TEXT,
                    rrname   TEXT,
                    rrtype   TEXT,
                    rcode    TEXT,
                    ttl      INTEGER,
                    answers  TEXT
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_ts     ON dns_events (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_rrname ON dns_events (rrname)")
            c.commit()
            self._local.conn = c
        return self._local.conn

    # ── Timestamp helper (identical to AlertDB) ───────────────────────────────

    def _to_epoch(self, ts: str) -> float:
        if not ts:
            return 0.0
        normalised = _RE_USEC.sub(r"\1", ts)
        normalised = _RE_TZ.sub(r"\1:\2", normalised)
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(normalised, fmt).timestamp()
            except ValueError:
                pass
        return 0.0

    # ── Insert ────────────────────────────────────────────────────────────────

    def insert(self, evt: dict):
        """
        Persist one DNS event from eve.json.

        Unique ID: flow_id + tx_id + dns_type + rrname
        Previously the ID omitted rrname, causing all events with tx_id=0
        (very common in Suricata) to collide and be silently dropped by
        INSERT OR IGNORE.
        """
        d    = evt.get("dns", {})
        ts   = evt.get("timestamp", "")
        rrname = d.get("rrname", "")

        # rrname-inclusive key — genuinely unique per query per transaction
        uid = (
            f"{evt.get('flow_id', 0)}"
            f"-{d.get('tx_id', 0)}"
            f"-{d.get('type', '')}"
            f"-{rrname}"
        )

        answers_json = json.dumps(d.get("answers", d.get("grouped", {})) or [])

        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO dns_events
                   (id, ts, ts_epoch, src_ip, src_port, dst_ip, dst_port,
                    iface, flow_id, tx_id, dns_type, rrname, rrtype,
                    rcode, ttl, answers)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ts, self._to_epoch(ts),
                 evt.get("src_ip", ""),  evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("in_iface", ""), evt.get("flow_id", 0),
                 d.get("tx_id", 0),      d.get("type", ""),
                 rrname,                 d.get("rrtype", ""),
                 d.get("rcode", ""),     d.get("ttl", 0),
                 answers_json),
            )
            c.commit()
        except sqlite3.Error as e:
            log.warning("DNS DB insert: %s", e)

    # ── Fetch ─────────────────────────────────────────────────────────────────

    def fetch(self, days: int = None, limit: int = 5000) -> list[dict]:
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows   = self._conn().execute(
            """SELECT id, ts, src_ip, src_port, dst_ip, dst_port,
                      flow_id, tx_id, dns_type, rrname, rrtype,
                      rcode, ttl, answers
               FROM   dns_events
               WHERE  ts_epoch >= ?
               ORDER  BY ts_epoch DESC
               LIMIT  ?""",
            (cutoff, limit),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["answers"] = json.loads(d.get("answers") or "[]")
            except Exception:
                d["answers"] = []
            result.append(d)
        return result

    # ── Maintenance ───────────────────────────────────────────────────────────

    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        c      = self._conn()
        cur    = c.execute(
            "DELETE FROM dns_events WHERE ts_epoch < ?", (cutoff,)
        )
        c.commit()
        if cur.rowcount:
            log.info("DNS DB: purged %d old rows.", cur.rowcount)

    def clear(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM dns_events")
        c.commit()
        log.info("DNS DB cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    def count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM dns_events"
        ).fetchone()[0]

    def stats(self) -> dict:
        c      = self._conn()
        cutoff = time.time() - self.retain_days * 86400
        total  = c.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0]
        recent = c.execute(
            "SELECT COUNT(*) FROM dns_events WHERE ts_epoch >= ?", (cutoff,)
        ).fetchone()[0]
        return {"total": total, "recent": recent}
