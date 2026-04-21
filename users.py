"""
Watcher IDS Dashboard — User Management (RBAC)
Manages user accounts with role-based access control.

Roles:
  admin   — full access: all views, clear data, webhooks, user management
  analyst — read access: all views, no clear/delete, no webhooks/settings
  viewer  — stream only: alerts view only, no detail panel, no controls

Password storage: same PBKDF2-SHA256 as AuthManager (260k rounds).
"""

import hashlib
import hmac
import logging
import secrets
import time

from config import PBKDF2_ITERS

log = logging.getLogger("watcher.users")

ROLES       = ("admin", "analyst", "viewer")
ROLE_ADMIN  = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER  = "viewer"


class UserManager:
    """
    Manages the `users` table in SQLite.

    Each user has:
      id, username, pw_hash, role, enabled, created_at, last_login
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                pw_hash    TEXT    NOT NULL,
                role       TEXT    NOT NULL DEFAULT 'analyst',
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at REAL    NOT NULL,
                last_login REAL
            )
        """)
        # Also add role + username columns to sessions table if not present
        # (ALTER TABLE IF NOT EXISTS column is not supported in older SQLite,
        #  so we check first)
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        if "username" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN username TEXT DEFAULT ''")
        if "role" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN role TEXT DEFAULT 'admin'")
        c.commit()

    # ── Password helpers (identical algorithm to AuthManager) ─────────────────

    def _hash(self, password: str) -> str:
        salt = secrets.token_hex(16)
        h    = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
        )
        return f"{salt}${h.hex()}"

    def _verify(self, password: str, stored: str) -> bool:
        try:
            salt, h = stored.split("$", 1)
            check   = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
            )
            return hmac.compare_digest(check.hex(), h)
        except Exception:
            return False

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create(self, username: str, password: str,
               role: str = ROLE_ANALYST) -> dict | None:
        """
        Create a new user. Returns the user dict on success, None if
        the username already exists.
        """
        if role not in ROLES:
            raise ValueError(f"Invalid role: {role}")
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")
        try:
            c = self._conn()
            c.execute(
                """INSERT INTO users (username, pw_hash, role, enabled, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (username, self._hash(password), role, time.time()),
            )
            c.commit()
            return self.get_by_username(username)
        except Exception as e:
            if "UNIQUE" in str(e).upper():
                return None
            raise

    def get_by_username(self, username: str) -> dict | None:
        row = self._conn().execute(
            "SELECT id, username, role, enabled, created_at, last_login "
            "FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        return dict(row) if row else None

    def get_by_id(self, uid: int) -> dict | None:
        row = self._conn().execute(
            "SELECT id, username, role, enabled, created_at, last_login "
            "FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        return dict(row) if row else None

    def get_all(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT id, username, role, enabled, created_at, last_login "
            "FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def update(self, uid: int, **fields) -> dict | None:
        """Update allowed fields: role, enabled, username."""
        allowed = {"role", "enabled", "username"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_by_id(uid)
        if "role" in updates and updates["role"] not in ROLES:
            raise ValueError(f"Invalid role: {updates['role']}")
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [uid]
        self._conn().execute(f"UPDATE users SET {cols} WHERE id = ?", vals)
        self._conn().commit()
        return self.get_by_id(uid)

    def set_password(self, uid: int, new_password: str):
        """Reset a user's password."""
        self._conn().execute(
            "UPDATE users SET pw_hash = ? WHERE id = ?",
            (self._hash(new_password), uid),
        )
        self._conn().commit()
        log.info("Password reset for user id=%d", uid)

    def delete(self, uid: int):
        self._conn().execute("DELETE FROM users WHERE id = ?", (uid,))
        self._conn().commit()

    def count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    def count_admins(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1"
        ).fetchone()[0]

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> dict | None:
        """
        Verify username + password.
        Returns the user dict on success (with pw_hash included for
        internal use), or None on failure.
        """
        row = self._conn().execute(
            "SELECT id, username, pw_hash, role, enabled, created_at, last_login "
            "FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if not d["enabled"]:
            return None
        if not self._verify(password, d["pw_hash"]):
            return None
        # Update last_login
        self._conn().execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (time.time(), d["id"]),
        )
        self._conn().commit()
        d.pop("pw_hash")
        return d

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def bootstrap_admin(self, existing_pw_hash: str) -> tuple[str, str] | None:
        """
        Called on first run if no users exist.
        Creates an 'admin' account with username 'admin' and the same
        password that was already set via --password / single-password auth.
        Returns (username, raw_password) so it can be logged once,
        or None if users already exist.
        """
        if self.count() > 0:
            return None
        # We can't recover the plaintext from the existing hash.
        # Generate a new strong password for the admin account.
        pw       = secrets.token_urlsafe(14)
        username = "admin"
        self.create(username, pw, role=ROLE_ADMIN)
        log.info("=" * 58)
        log.info("  RBAC enabled — first Admin account created:")
        log.info("  Username: %s", username)
        log.info("  Password: %s", pw)
        log.info("  Change:   Settings → Users → Edit")
        log.info("=" * 58)
        return username, pw
