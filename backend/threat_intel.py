"""
Watcher IDS Dashboard — Threat Intelligence Database
Custom explanations for Suricata signatures, keyed by SID or category.

Lookup priority:
  1. Exact sig_id match
  2. Category match (sig_id IS NULL entries)
  3. None

Lives in config.db alongside users/webhooks.
"""

import json
import logging
import time

log = logging.getLogger("watcher.threat_intel")


class ThreatIntelDB:
    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sig_id      INTEGER,
                sig_msg     TEXT,
                category    TEXT COLLATE NOCASE,
                explanation TEXT NOT NULL,
                tags        TEXT NOT NULL DEFAULT '[]',
                refs        TEXT NOT NULL DEFAULT '[]',
                created_by  TEXT,
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_ti_sigid ON threat_intel (sig_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ti_cat   ON threat_intel (category)")
        c.commit()

    def _hydrate(self, row) -> dict | None:
        if not row:
            return None
        d = dict(row)
        for key in ("tags", "refs"):
            try:
                d[key] = json.loads(d.get(key) or "[]")
            except Exception:
                d[key] = []
        return d

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM threat_intel ORDER BY updated_at DESC"
        ).fetchall()
        return [self._hydrate(r) for r in rows]

    def get_by_id(self, tid: int) -> dict | None:
        return self._hydrate(
            self._conn().execute(
                "SELECT * FROM threat_intel WHERE id = ?", (tid,)
            ).fetchone()
        )

    def create(self, sig_id, sig_msg, category, explanation,
               tags, refs, created_by) -> dict:
        now = time.time()
        c   = self._conn()
        cur = c.execute(
            """INSERT INTO threat_intel
               (sig_id, sig_msg, category, explanation, tags, refs,
                created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (int(sig_id) if sig_id else None,
             sig_msg or None, category or None,
             explanation,
             json.dumps(tags or []), json.dumps(refs or []),
             created_by, now, now),
        )
        c.commit()
        return self.get_by_id(cur.lastrowid)

    def update(self, tid: int, **fields) -> dict | None:
        allowed = {"sig_id", "sig_msg", "category", "explanation", "tags", "refs"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_by_id(tid)
        for key in ("tags", "refs"):
            if key in updates and isinstance(updates[key], list):
                updates[key] = json.dumps(updates[key])
        for key in ("sig_msg", "category"):
            if key in updates and not updates[key]:
                updates[key] = None
        if "sig_id" in updates:
            try:
                updates["sig_id"] = int(updates["sig_id"]) if updates["sig_id"] else None
            except (ValueError, TypeError):
                updates["sig_id"] = None
        updates["updated_at"] = time.time()
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [tid]
        c    = self._conn()
        c.execute(f"UPDATE threat_intel SET {cols} WHERE id = ?", vals)
        c.commit()
        return self.get_by_id(tid)

    def delete(self, tid: int):
        c = self._conn()
        c.execute("DELETE FROM threat_intel WHERE id = ?", (tid,))
        c.commit()

    # ── Lookup ────────────────────────────────────────────────────────────────

    def lookup(self, sig_id: int = None, category: str = None) -> dict | None:
        """Best explanation for an alert — SID first, category fallback."""
        if sig_id:
            row = self._conn().execute(
                "SELECT * FROM threat_intel WHERE sig_id = ? "
                "ORDER BY updated_at DESC LIMIT 1",
                (int(sig_id),),
            ).fetchone()
            if row:
                return self._hydrate(row)
        if category:
            row = self._conn().execute(
                "SELECT * FROM threat_intel "
                "WHERE sig_id IS NULL AND category = ? COLLATE NOCASE "
                "ORDER BY updated_at DESC LIMIT 1",
                (category,),
            ).fetchone()
            if row:
                return self._hydrate(row)
        return None

    # ── Coverage gaps ─────────────────────────────────────────────────────────

    def coverage_gaps(self, top_sids: list[dict], limit: int = 10) -> list[dict]:
        """
        Given a list of {sig_id, sig_msg, count} dicts (from AlertDB.top_sids),
        return those whose sig_id has no explanation yet, up to `limit`.
        """
        covered = {
            row[0]
            for row in self._conn().execute(
                "SELECT sig_id FROM threat_intel WHERE sig_id IS NOT NULL"
            ).fetchall()
        }
        return [r for r in top_sids if r["sig_id"] not in covered][:limit]

    def stats(self) -> dict:
        c      = self._conn()
        total  = c.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
        by_sid = c.execute(
            "SELECT COUNT(*) FROM threat_intel WHERE sig_id IS NOT NULL"
        ).fetchone()[0]
        by_cat = c.execute(
            "SELECT COUNT(*) FROM threat_intel "
            "WHERE sig_id IS NULL AND category IS NOT NULL"
        ).fetchone()[0]
        return {"total": total, "by_sid": by_sid, "by_category": by_cat}
