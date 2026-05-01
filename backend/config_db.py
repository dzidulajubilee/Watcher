"""
Watcher IDS Dashboard — Config Database
Lightweight SQLite wrapper for low-write configuration tables:
  auth, sessions, users, webhooks.

Kept separate from AlertDB (events.db) so high-volume alert/flow/dns/http
writes never contend with login, session validation, or webhook lookups —
even under WAL mode, write locks on one database don't affect the other.

AuthManager, UserManager, and WebhookDB each accept a conn_fn callable;
pass ConfigDB._conn to all three.
"""

import logging
import sqlite3
import threading
from pathlib import Path

log = logging.getLogger("watcher.config_db")


class ConfigDB:
    """
    Thread-safe SQLite connection pool (one connection per thread) for the
    configuration database.  Table creation is delegated to the managers
    that own each table (AuthManager, UserManager, WebhookDB).
    """

    def __init__(self, path: str | Path):
        self.path   = str(path)
        self._local = threading.local()
        self._conn()                      # create the file and set PRAGMAs
        log.info("Config DB : %s", self.path)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            # WAL keeps readers non-blocking; NORMAL sync is safe for config data
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.commit()
            self._local.conn = c
        return self._local.conn
