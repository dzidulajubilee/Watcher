"""
Watcher IDS Dashboard — Database (Events)
Thread-safe SQLite wrapper for alert/flow/http event tables:
  alerts, flows, http_events, ack_history.

DNS events have been moved to DnsDB (database_dns.py) due to their
substantially higher write volume. See config_db.py for config tables.
"""

import json
import logging
import re as _re
import sqlite3
import threading
import time
from datetime import datetime

from config import RETAIN_DAYS

log = logging.getLogger("watcher.db")

# Pre-compiled timestamp normalisation patterns (used in the hot path)
_RE_USEC  = _re.compile(r"(\.\d{3})\d+")         # 123456 → 123  (µs→ms)
_RE_TZ    = _re.compile(r"([+-]\d{2})(\d{2})$")   # +0000  → +00:00


class AlertDB:
    def __init__(self, path: str, retain_days: int = RETAIN_DAYS):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        self._conn()
        log.info("Events DB : %s  (retain %d days)", self.path, self.retain_days)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")

            c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, iface TEXT, flow_id INTEGER, sig_id INTEGER,
                sig_msg TEXT, category TEXT, severity TEXT, action TEXT, raw_json TEXT,
                ack_status TEXT NOT NULL DEFAULT 'new',
                ack_note TEXT, ack_by TEXT, ack_at REAL)""")

            c.execute("CREATE INDEX IF NOT EXISTS idx_a_ts     ON alerts (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_a_sev    ON alerts (severity)")
            # Composite: accelerates time-range + severity filters together
            c.execute("CREATE INDEX IF NOT EXISTS idx_a_ts_sev ON alerts (ts_epoch, severity)")

            # Migration: add ack columns to existing databases
            alert_cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
            for col, ddl in (
                ("ack_status", "ALTER TABLE alerts ADD COLUMN ack_status TEXT NOT NULL DEFAULT 'new'"),
                ("ack_note",   "ALTER TABLE alerts ADD COLUMN ack_note TEXT"),
                ("ack_by",     "ALTER TABLE alerts ADD COLUMN ack_by TEXT"),
                ("ack_at",     "ALTER TABLE alerts ADD COLUMN ack_at REAL"),
            ):
                if col not in alert_cols:
                    c.execute(ddl)

            c.execute("""CREATE TABLE IF NOT EXISTS ack_history (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id   TEXT    NOT NULL,
                status     TEXT    NOT NULL,
                note       TEXT,
                username   TEXT,
                changed_at REAL    NOT NULL)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ah_alert ON ack_history (alert_id)")

            c.execute("""CREATE TABLE IF NOT EXISTS flows (
                flow_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, app_proto TEXT, iface TEXT,
                pkts_toserver INTEGER DEFAULT 0, pkts_toclient INTEGER DEFAULT 0,
                bytes_toserver INTEGER DEFAULT 0, bytes_toclient INTEGER DEFAULT 0,
                duration_s REAL DEFAULT 0, state TEXT, reason TEXT, alerted INTEGER DEFAULT 0)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_f_ts ON flows (ts_epoch)")

            c.execute("""CREATE TABLE IF NOT EXISTS http_events (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                iface TEXT, flow_id INTEGER, hostname TEXT, url TEXT,
                method TEXT, status INTEGER, user_agent TEXT, content_type TEXT,
                req_bytes INTEGER DEFAULT 0, resp_bytes INTEGER DEFAULT 0, protocol TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_h_ts       ON http_events (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_h_hostname ON http_events (hostname)")

            c.commit()
            self._local.conn = c
        return self._local.conn

    def _to_epoch(self, ts: str) -> float:
        """
        Parse a Suricata ISO-8601 timestamp to a Unix epoch float.

        Uses module-level compiled regexes (not re-imported per call).
        Falls back to 0.0 on any parse failure.
        """
        if not ts:
            return 0.0
        normalised = _RE_USEC.sub(r"\1", ts)
        normalised = _RE_TZ.sub(r"\1:\2", normalised)
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(normalised, fmt).timestamp()
            except ValueError:
                pass
        log.warning("_to_epoch: could not parse %r (normalised: %r)", ts, normalised)
        return 0.0

    # ── Alerts ────────────────────────────────────────────────────────────────

    def insert(self, alert: dict):
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO alerts
                   (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    proto,iface,flow_id,sig_id,sig_msg,category,severity,action,raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert["id"], alert.get("ts", ""), self._to_epoch(alert.get("ts", "")),
                 alert.get("src_ip", ""), alert.get("src_port", 0),
                 alert.get("dst_ip", ""), alert.get("dst_port", 0),
                 alert.get("proto", ""), alert.get("iface", ""), alert.get("flow_id", 0),
                 alert.get("sig_id", 0), alert.get("sig_msg", ""), alert.get("category", ""),
                 alert.get("severity", "info"), alert.get("action", "allowed"),
                 json.dumps(alert.get("raw", {}))))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (alert): %s", e)

    def fetch_recent(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT id,ts,src_ip,src_port,dst_ip,dst_port,proto,iface,
                      flow_id,sig_id,sig_msg,category,severity,action,raw_json,
                      ack_status,ack_note,ack_by,ack_at
               FROM alerts WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["raw"] = json.loads(d.pop("raw_json", "{}"))
            except Exception:
                d["raw"] = {}
            result.append(d)
        return result

    # ── Flows ─────────────────────────────────────────────────────────────────

    def insert_flow(self, evt: dict):
        f   = evt.get("flow", {})
        ts  = evt.get("timestamp", "")
        dur = 0.0
        try:
            t1  = datetime.fromisoformat(f.get("start", "").replace("+0000", "+00:00"))
            t2  = datetime.fromisoformat(f.get("end",   "").replace("+0000", "+00:00"))
            dur = (t2 - t1).total_seconds()
        except Exception:
            pass
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO flows
                   (flow_id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    proto,app_proto,iface,pkts_toserver,pkts_toclient,
                    bytes_toserver,bytes_toclient,duration_s,state,reason,alerted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (evt.get("flow_id", 0), ts, self._to_epoch(ts),
                 evt.get("src_ip", ""), evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("proto", "").upper(), evt.get("app_proto", ""),
                 evt.get("in_iface", ""),
                 f.get("pkts_toserver", 0), f.get("pkts_toclient", 0),
                 f.get("bytes_toserver", 0), f.get("bytes_toclient", 0),
                 dur, f.get("state", ""), f.get("reason", ""),
                 1 if f.get("alerted") else 0))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (flow): %s", e)

    def fetch_flows(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT flow_id,ts,src_ip,src_port,dst_ip,dst_port,proto,app_proto,
                      pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,
                      duration_s,state,reason,alerted
               FROM flows WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def insert_http(self, evt: dict):
        h   = evt.get("http", {})
        ts  = evt.get("timestamp", "")
        uid = f"{evt.get('flow_id',0)}-{evt.get('tx_id',0)}-http"
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO http_events
                   (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    iface,flow_id,hostname,url,method,status,
                    user_agent,content_type,req_bytes,resp_bytes,protocol)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ts, self._to_epoch(ts),
                 evt.get("src_ip", ""), evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("in_iface", ""), evt.get("flow_id", 0),
                 h.get("hostname", ""), h.get("url", ""),
                 h.get("http_method", ""), h.get("status", 0),
                 h.get("http_user_agent", ""), h.get("http_content_type", ""),
                 h.get("request_headers_raw_len", h.get("length", 0)),
                 h.get("response_headers_raw_len", h.get("response_len", 0)),
                 h.get("protocol", "")))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (http): %s", e)

    def fetch_http(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT id,ts,src_ip,src_port,dst_ip,dst_port,flow_id,
                      hostname,url,method,status,user_agent,content_type,
                      req_bytes,resp_bytes,protocol
               FROM http_events WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── Acknowledgement ───────────────────────────────────────────────────────

    def acknowledge(self, alert_id: str, status: str, note: str = "",
                    username: str = "") -> bool:
        """
        Set the ack_status on an alert and append an ack_history entry.
        Valid statuses: new | acknowledged | false_positive | investigating
        """
        VALID = {"new", "acknowledged", "false_positive", "investigating"}
        if status not in VALID:
            return False
        now      = time.time()
        note_val = note.strip() or None
        user_val = username or None
        c        = self._conn()
        cur      = c.execute(
            """UPDATE alerts SET ack_status=?, ack_note=?, ack_by=?, ack_at=?
               WHERE id=?""",
            (status, note_val, user_val, now, alert_id),
        )
        if cur.rowcount > 0:
            c.execute(
                """INSERT INTO ack_history (alert_id, status, note, username, changed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (alert_id, status, note_val, user_val, now),
            )
        c.commit()
        return cur.rowcount > 0

    def bulk_acknowledge(self, alert_ids: list, status: str, note: str = "",
                         username: str = "") -> int:
        """
        Acknowledge multiple alerts efficiently using a single UPDATE statement
        (IN clause) and a single executemany for history inserts.
        Returns the number of alerts actually updated.
        """
        VALID = {"new", "acknowledged", "false_positive", "investigating"}
        if status not in VALID or not alert_ids:
            return 0

        now      = time.time()
        note_val = note.strip() or None
        user_val = username or None
        c        = self._conn()

        # Single UPDATE for all matching IDs — O(1) statements instead of O(N)
        placeholders = ",".join(["?"] * len(alert_ids))
        cur = c.execute(
            f"UPDATE alerts SET ack_status=?, ack_note=?, ack_by=?, ack_at=? "
            f"WHERE id IN ({placeholders})",
            [status, note_val, user_val, now, *alert_ids],
        )
        updated = cur.rowcount

        if updated > 0:
            # Re-query only the IDs that were actually touched (ack_at = now)
            # so ack_history never gets phantom rows for missing alert IDs.
            matched = c.execute(
                f"SELECT id FROM alerts WHERE id IN ({placeholders}) AND ack_at=?",
                [*alert_ids, now],
            ).fetchall()
            c.executemany(
                """INSERT INTO ack_history (alert_id, status, note, username, changed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                [(r["id"], status, note_val, user_val, now) for r in matched],
            )

        c.commit()
        return updated

    def fetch_ack_history(self, alert_id: str) -> list:
        """Return all acknowledgement history entries for an alert, newest first."""
        rows = self._conn().execute(
            """SELECT status, note, username, changed_at
               FROM ack_history WHERE alert_id=?
               ORDER BY changed_at DESC""",
            (alert_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Maintenance ───────────────────────────────────────────────────────────

    _PURGEABLE_TABLES = ("alerts", "flows", "http_events")
    _PURGE_SQL = {
        t: f"DELETE FROM {t} WHERE ts_epoch<?"
        for t in ("alerts", "flows", "http_events")
    }

    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        total  = 0
        c      = self._conn()
        for table in self._PURGEABLE_TABLES:
            cur    = c.execute(self._PURGE_SQL[table], (cutoff,))
            total += cur.rowcount
        c.commit()
        if total:
            log.info("Purged %d total rows older than %d days.", total, self.retain_days)

    def clear_all(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM alerts")
        c.commit()
        log.info("Alerts cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    def clear_flows(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM flows")
        c.commit()
        log.info("Flows cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    # ── Chart data ────────────────────────────────────────────────────────────

    def chart_top_talkers(self, limit: int = 10, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT src_ip, COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ? AND src_ip != ''
               GROUP BY src_ip ORDER BY cnt DESC LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [{"ip": r["src_ip"], "count": r["cnt"]} for r in rows]

    def chart_alert_trend(self, hours: int = 24) -> list[dict]:
        now    = time.time()
        cutoff = now - hours * 3600
        rows   = self._conn().execute(
            """SELECT CAST((ts_epoch - ?) / 3600 AS INTEGER) AS bucket,
                      COUNT(*) AS cnt
               FROM   alerts
               WHERE  ts_epoch >= ?
               GROUP  BY bucket
               ORDER  BY bucket ASC""",
            (cutoff, cutoff),
        ).fetchall()
        buckets = {r["bucket"]: r["cnt"] for r in rows}
        return [
            {"ts":    time.strftime("%H:%M", time.localtime(cutoff + h * 3600)),
             "epoch": int(cutoff + h * 3600),
             "count": buckets.get(h, 0)}
            for h in range(hours)
        ]

    def chart_alert_trend_days(self, days: int = 7) -> list[dict]:
        now    = time.time()
        cutoff = now - days * 86400
        rows   = self._conn().execute(
            """SELECT CAST((ts_epoch - ?) / 86400 AS INTEGER) AS bucket,
                      COUNT(*) AS cnt
               FROM   alerts
               WHERE  ts_epoch >= ?
               GROUP  BY bucket
               ORDER  BY bucket ASC""",
            (cutoff, cutoff),
        ).fetchall()
        buckets = {r["bucket"]: r["cnt"] for r in rows}
        return [
            {"ts":    time.strftime("%b %d", time.localtime(cutoff + d * 86400)),
             "epoch": int(cutoff + d * 86400),
             "count": buckets.get(d, 0)}
            for d in range(days)
        ]

    def chart_by_category(self, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT COALESCE(NULLIF(category,''), 'Uncategorized') as cat,
                      COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ?
               GROUP BY cat ORDER BY cnt DESC LIMIT 12""",
            (cutoff,),
        ).fetchall()
        return [{"category": r["cat"], "count": r["cnt"]} for r in rows]

    def chart_by_severity(self, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT severity, COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ?
               GROUP BY severity ORDER BY cnt DESC""",
            (cutoff,),
        ).fetchall()
        return [{"severity": r["severity"], "count": r["cnt"]} for r in rows]

    _COUNT_SQL = {
        t: f"SELECT COUNT(*) FROM {t}"
        for t in ("alerts", "flows", "http_events")
    }
    _RECENT_SQL = {
        t: f"SELECT COUNT(*) FROM {t} WHERE ts_epoch>=?"
        for t in ("alerts", "flows", "http_events")
    }

    def stats(self) -> dict:
        c      = self._conn()
        cutoff = time.time() - self.retain_days * 86400

        def _cnt(t):    return c.execute(self._COUNT_SQL[t]).fetchone()[0]
        def _recent(t): return c.execute(self._RECENT_SQL[t], (cutoff,)).fetchone()[0]

        oldest = c.execute("SELECT MIN(ts) FROM alerts").fetchone()[0]
        return {
            "alerts": {"total": _cnt("alerts"),     "recent": _recent("alerts")},
            "flows":  {"total": _cnt("flows"),       "recent": _recent("flows")},
            "http":   {"total": _cnt("http_events"), "recent": _recent("http_events")},
            "oldest": oldest,
        }
