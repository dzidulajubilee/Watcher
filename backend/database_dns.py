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

from sqlite_util import RowCounter, delete_in_chunks, write_with_retry
from timeparse   import to_epoch as _fast_to_epoch

log = logging.getLogger("watcher.dns_db")

_RE_USEC = _re.compile(r"(\.\d{3})\d+")
_RE_TZ   = _re.compile(r"([+-]\d{2})(\d{2})$")


class DnsDB:
    def __init__(self, path: str | Path, retain_days: int = 90):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        # One writer at a time within this process (see sqlite_util.write_with_retry)
        self._write_lock = threading.Lock()
        self._conn()
        self._counter    = RowCounter(self._conn, ("dns_events",))
        log.info("DNS DB    : %s  (retain %d days)", self.path, self.retain_days)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.execute("PRAGMA cache_size   = -4096")    # 4 MB page cache
            c.execute("PRAGMA mmap_size    = 67108864") # 64 MB mmap read
            c.execute("PRAGMA temp_store   = MEMORY")
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
        # Fast exact parser; like the original, fails silently (0.0)
        return _fast_to_epoch(ts, warn=False)

    # ── Insert ────────────────────────────────────────────────────────────────

    _SQL = """INSERT OR IGNORE INTO dns_events
                   (id, ts, ts_epoch, src_ip, src_port, dst_ip, dst_port,
                    iface, flow_id, tx_id, dns_type, rrname, rrtype,
                    rcode, ttl, answers)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

    def _row(self, evt: dict) -> tuple:
        """
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
        return (uid, ts, self._to_epoch(ts),
                evt.get("src_ip", ""),  evt.get("src_port", 0),
                evt.get("dest_ip", ""), evt.get("dest_port", 0),
                evt.get("in_iface", ""), evt.get("flow_id", 0),
                d.get("tx_id", 0),      d.get("type", ""),
                rrname,                 d.get("rrtype", ""),
                d.get("rcode", ""),     d.get("ttl", 0),
                answers_json)

    def insert(self, evt: dict):
        """Persist one DNS event from eve.json."""
        try:
            n = write_with_retry(self._conn(),
                                 lambda c: c.execute(self._SQL, self._row(evt)).rowcount,
                                 "DNS insert", lock=self._write_lock)
            self._counter.add("dns_events", n)
        except sqlite3.Error as e:
            log.warning("DNS DB insert: %s", e)

    def insert_batch(self, events):
        """Insert many DNS events in one transaction (group commit)."""
        if not events:
            return
        try:
            rows = [self._row(e) for e in events]
            n = write_with_retry(self._conn(),
                                 lambda c: c.executemany(self._SQL, rows).rowcount,
                                 "DNS batch", lock=self._write_lock)
            self._counter.add("dns_events", n)
        except (sqlite3.Error, TypeError, ValueError) as e:
            log.warning("DNS batch insert failed (%s) — retrying row by row.", e)
            for ev in events:
                self.insert(ev)

    # ── Fetch ─────────────────────────────────────────────────────────────────

    def fetch(self, days: int = None, limit: int = 300,
              offset: int = 0, **kwargs) -> dict:
        """
        Paginated fetch. Returns { "rows": [...], "total": N }.
        Total is cached via _precomputed_total kwarg when available.
        """
        cutoff = time.time() - (days or self.retain_days) * 86400
        conn   = self._conn()

        total = kwargs.get("_precomputed_total")
        if total is None and (days or self.retain_days) >= self.retain_days:
            total = self._counter.get("dns_events")     # O(1), no COUNT(*)
        if total is None:
            total = conn.execute(
                "SELECT COUNT(*) FROM dns_events WHERE ts_epoch >= ?", (cutoff,)
            ).fetchone()[0]

        rows = conn.execute(
            """SELECT id, ts, src_ip, src_port, dst_ip, dst_port,
                      flow_id, tx_id, dns_type, rrname, rrtype,
                      rcode, ttl, answers
               FROM   dns_events
               WHERE  ts_epoch >= ?
               ORDER  BY ts_epoch DESC
               LIMIT  ? OFFSET ?""",
            (cutoff, limit, offset),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["answers"] = json.loads(d.get("answers") or "[]")
            except Exception:
                d["answers"] = []
            result.append(d)
        return {"rows": result, "total": total}

    # ── Maintenance ───────────────────────────────────────────────────────────

    def flush_all(self) -> int:
        """Delete all DNS records. Returns deleted count."""
        n = delete_in_chunks(self._conn(), "dns_events", lock=self._write_lock)
        self._counter.add("dns_events", -n)
        return n

    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        n = delete_in_chunks(self._conn(), "dns_events", "ts_epoch < ?", (cutoff,), lock=self._write_lock)
        self._counter.add("dns_events", -n)
        if n:
            log.info("DNS DB: purged %d old rows.", n)

    def clear(self) -> int:
        n = delete_in_chunks(self._conn(), "dns_events", lock=self._write_lock)
        self._counter.add("dns_events", -n)
        log.info("DNS DB cleared — %d rows deleted.", n)
        return n

    def count(self) -> int:
        return self._counter.get("dns_events")

    def stats(self) -> dict:
        total = self._counter.get("dns_events")
        # rows past the retention window exist only until the hourly purge
        return {"total": total, "recent": total}
