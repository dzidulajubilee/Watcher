"""
Watcher IDS Dashboard — Alert Suppression
Stores suppression rules in config.db and checks them in the tail hot-path
using a thread-safe in-memory cache (refreshed every 30 s).

A rule suppresses an alert when every non-null field in the rule matches:
  sig_id   — exact match on signature ID
  src_ip   — exact match on source IP
  category — case-insensitive match on alert category

Rules can have an optional expiry timestamp; expired rules are skipped.
"""

import logging
import threading
import time

log = logging.getLogger("watcher.suppression")

_CACHE_TTL = 30  # seconds between cache refreshes


class SuppressionDB:
    def __init__(self, conn_fn):
        self._conn       = conn_fn
        self._cache: list = []
        self._cache_ts   = 0.0
        self._lock       = threading.Lock()
        self._setup()

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS suppression_rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                sig_id     INTEGER,
                src_ip     TEXT,
                category   TEXT COLLATE NOCASE,
                reason     TEXT,
                expires_at REAL,
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_by TEXT,
                created_at REAL    NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_sup_sigid ON suppression_rules (sig_id)")
        c.commit()

    def _row(self, row) -> dict | None:
        if not row:
            return None
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM suppression_rules ORDER BY created_at DESC"
        ).fetchall()
        return [self._row(r) for r in rows]

    def get_by_id(self, sid: int) -> dict | None:
        return self._row(
            self._conn().execute(
                "SELECT * FROM suppression_rules WHERE id = ?", (sid,)
            ).fetchone()
        )

    def create(self, name: str, sig_id, src_ip, category,
               reason: str, expires_at, created_by: str) -> dict:
        now = time.time()
        c   = self._conn()
        cur = c.execute(
            """INSERT INTO suppression_rules
               (name, sig_id, src_ip, category, reason, expires_at,
                enabled, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (name,
             int(sig_id)  if sig_id    else None,
             src_ip       if src_ip    else None,
             category     if category  else None,
             reason or None,
             float(expires_at) if expires_at else None,
             created_by, now),
        )
        c.commit()
        self._invalidate_cache()
        return self.get_by_id(cur.lastrowid)

    def update(self, rule_id: int, **fields) -> dict | None:
        allowed = {"name", "sig_id", "src_ip", "category",
                   "reason", "expires_at", "enabled"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_by_id(rule_id)
        for key in ("src_ip", "category", "reason"):
            if key in updates and not updates[key]:
                updates[key] = None
        if "sig_id" in updates:
            try:
                updates["sig_id"] = int(updates["sig_id"]) if updates["sig_id"] else None
            except (ValueError, TypeError):
                updates["sig_id"] = None
        if "expires_at" in updates:
            try:
                updates["expires_at"] = float(updates["expires_at"]) if updates["expires_at"] else None
            except (ValueError, TypeError):
                updates["expires_at"] = None
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [rule_id]
        c    = self._conn()
        c.execute(f"UPDATE suppression_rules SET {cols} WHERE id = ?", vals)
        c.commit()
        self._invalidate_cache()
        return self.get_by_id(rule_id)

    def delete(self, rule_id: int):
        c = self._conn()
        c.execute("DELETE FROM suppression_rules WHERE id = ?", (rule_id,))
        c.commit()
        self._invalidate_cache()

    # ── Hot-path suppression check ────────────────────────────────────────────

    def is_suppressed(self, alert: dict) -> bool:
        """
        Return True if the alert matches any active suppression rule.
        Called on every alert in the tail thread — must be fast.
        Uses a cached rule list, refreshed at most every 30 s.
        """
        rules = self._get_cache()
        now   = time.time()
        for rule in rules:
            # Skip expired rules
            exp = rule.get("expires_at")
            if exp and now > exp:
                continue
            # All non-null conditions must match (AND logic)
            if rule["sig_id"]  is not None and rule["sig_id"]  != alert.get("sig_id"):
                continue
            if rule["src_ip"]  is not None and rule["src_ip"]  != alert.get("src_ip"):
                continue
            if rule["category"] is not None and \
               rule["category"].lower() != (alert.get("category") or "").lower():
                continue
            log.debug("Alert suppressed by rule %d (%s)", rule["id"], rule["name"])
            return True
        return False

    # ── Cache management ──────────────────────────────────────────────────────

    def _get_cache(self) -> list:
        if time.time() - self._cache_ts > _CACHE_TTL:
            with self._lock:
                # Double-check after acquiring lock
                if time.time() - self._cache_ts > _CACHE_TTL:
                    self._cache    = self._load_active()
                    self._cache_ts = time.time()
        return self._cache

    def _load_active(self) -> list:
        rows = self._conn().execute(
            "SELECT id, name, sig_id, src_ip, category, expires_at "
            "FROM suppression_rules WHERE enabled = 1"
        ).fetchall()
        return [dict(r) for r in rows]

    def _invalidate_cache(self):
        with self._lock:
            self._cache_ts = 0.0
