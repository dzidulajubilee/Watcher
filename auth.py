"""
Watcher IDS Dashboard — Authentication (RBAC-aware)
Single-password emergency fallback + full user/session management.
Sessions now carry username and role, checked on every protected request.
"""

import logging
import secrets
import time

from config         import SESSION_TTL
from password_utils import hash_password, verify_password

log = logging.getLogger("watcher.auth")


class AuthManager:
    """
    Manages the legacy single-password (emergency fallback) and the
    RBAC session table.

    Session tokens store username + role so the handler can enforce
    per-role permissions without a DB lookup on every request.

    Migration:
      Old sessions (no username/role columns) are invalidated on startup
      so everyone re-authenticates with username + password.
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                username   TEXT NOT NULL DEFAULT '',
                role       TEXT NOT NULL DEFAULT 'admin'
            )
        """)
        # Migration: add columns to existing sessions table if absent
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        if "username" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN username TEXT DEFAULT ''")
        if "role" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN role TEXT DEFAULT 'admin'")
        c.commit()

    # ── Single-password (legacy / emergency fallback) ─────────────────────────

    def set_password(self, password: str):
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO auth (key, value) VALUES ('pw_hash', ?)",
            (hash_password(password),),
        )
        c.commit()
        log.info("Single-password updated.")

    def get_hash(self) -> str | None:
        row = self._conn().execute(
            "SELECT value FROM auth WHERE key = 'pw_hash'"
        ).fetchone()
        return row[0] if row else None

    def check_password(self, password: str) -> bool:
        """Emergency fallback: checks against single stored password."""
        stored = self.get_hash()
        return bool(stored and verify_password(password, stored))

    # ── Sessions ──────────────────────────────────────────────────────────────

    def create_session(self, username: str = "", role: str = "admin") -> str:
        """Create a session token carrying username and role."""
        token = secrets.token_hex(32)
        now   = time.time()
        c     = self._conn()
        c.execute(
            """INSERT INTO sessions
               (token, created_at, expires_at, username, role)
               VALUES (?, ?, ?, ?, ?)""",
            (token, now, now + SESSION_TTL, username, role),
        )
        c.commit()
        return token

    def validate_session(self, token: str) -> bool:
        """Return True if token exists and has not expired."""
        return self.get_session(token) is not None

    def get_session(self, token: str) -> dict | None:
        """
        Return session dict {token, username, role} if valid,
        or None if missing/expired.
        """
        if not token:
            return None
        row = self._conn().execute(
            "SELECT token, expires_at, username, role "
            "FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if not row:
            return None
        if time.time() > row["expires_at"]:
            c = self._conn()
            c.execute("DELETE FROM sessions WHERE token = ?", (token,))
            c.commit()
            return None
        return {"token": row["token"], "username": row["username"],
                "role": row["role"]}

    def revoke_session(self, token: str):
        c = self._conn()
        c.execute("DELETE FROM sessions WHERE token = ?", (token,))
        c.commit()

    def revoke_all_sessions(self):
        """Invalidate every active session — called when RBAC is first enabled."""
        c   = self._conn()
        cur = c.execute("DELETE FROM sessions")
        c.commit()
        if cur.rowcount:
            log.info("Revoked %d sessions (RBAC migration).", cur.rowcount)

    def purge_expired(self):
        c   = self._conn()
        cur = c.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (time.time(),)
        )
        c.commit()
        if cur.rowcount:
            log.info("Purged %d expired sessions.", cur.rowcount)
