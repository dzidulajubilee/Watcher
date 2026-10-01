# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Watcher IDS Dashboard — SQLite write helpers for high event rates.

write_with_retry  Run a write transaction; if the database is locked by another
                  writer, roll back and retry with back-off instead of giving up.
                  (Previously an insert that waited more than 5 s for the lock
                  was logged and DROPPED — silent data loss, Standing Rule 6.)

delete_in_chunks  Delete matching rows a few thousand at a time, committing and
                  pausing between chunks, so the write lock is never held for
                  long.  (A single hourly DELETE of millions of rows held the
                  lock for many seconds, stalling ingest.)

RowCounter        Per-table row counts maintained incrementally, so /health and
                  paginated fetches no longer run COUNT(*) over the full table
                  (linear in table size: ~0.4 s per 10 M rows).
"""

import logging
import sqlite3
import threading
import time

log = logging.getLogger("watcher.sqlite")

_LOCK_MARKERS = ("locked", "busy")


def _is_lock_error(exc: Exception) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and \
        any(m in str(exc).lower() for m in _LOCK_MARKERS)


class _NoLock:
    def __enter__(self): return self
    def __exit__(self, *a): return False


_NO_LOCK = _NoLock()


def write_with_retry(conn: sqlite3.Connection, work, what: str = "write",
                     lock=None):
    """
    Execute work(conn) and commit.  On a lock/busy error: roll back, wait
    (exponential back-off, max 1 s) and retry until it succeeds.  Each attempt
    already waits up to the connection's own busy timeout (5 s by default).
    Any other error is rolled back and re-raised to the caller.

    lock: optional in-process lock shared by all writers of this database
    file.  Threads of this process then take turns directly instead of
    polling SQLite's busy handler (which, after a while, re-checks only every
    ~100 ms and so kept missing the gaps between purge chunks — starving the
    ingest thread).  It is released while sleeping between retries.
    """
    delay, started, last_warn = 0.05, time.monotonic(), 0.0
    guard = lock if lock is not None else _NO_LOCK
    while True:
        with guard:
            try:
                result = work(conn)
                conn.commit()
                return result
            except sqlite3.Error as exc:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                if not _is_lock_error(exc):
                    raise
            waited = time.monotonic() - started
            if waited - last_warn >= 30:
                log.warning("%s waiting for database lock (%.0f s so far) — "
                            "data is held, not dropped.", what, waited)
                last_warn = waited
            time.sleep(delay)
            delay = min(delay * 2, 1.0)


def delete_in_chunks(conn: sqlite3.Connection, table: str, where: str = "1",
                     params: tuple = (), chunk: int = 5000,
                     pause: float = 0.005, lock=None) -> int:
    """
    DELETE FROM table WHERE <where>, in chunks of `chunk` rows, committing
    after each chunk and pausing briefly so other writers get the lock.
    `table` and `where` must be trusted constants (never user input).
    Returns the total number of rows deleted.
    """
    sql = (f"DELETE FROM {table} WHERE rowid IN "
           f"(SELECT rowid FROM {table} WHERE {where} LIMIT {int(chunk)})")
    total = 0
    while True:
        n = write_with_retry(conn, lambda c: c.execute(sql, params).rowcount,
                             f"delete from {table}", lock=lock)
        total += n
        if n < chunk:
            return total
        time.sleep(pause)


class RowCounter:
    """
    Incrementally maintained row counts for a fixed set of tables.

    The first get() counts each table once with COUNT(*) (at server start this
    happens before ingest begins, so the count is exact).  Afterwards every
    successful insert/delete in this process adjusts the count via add().
    Changes made outside this process (e.g. migrate.py, manual SQL) are not
    seen until the service restarts.
    """

    def __init__(self, conn_fn, tables):
        self._conn_fn = conn_fn
        self._tables  = tuple(tables)
        self._lock    = threading.Lock()
        self._counts  = None           # dict once initialised
        self._pending = None           # deltas recorded while counting

    def add(self, table: str, n: int):
        if not n:
            return
        with self._lock:
            if self._counts is not None:
                self._counts[table] = self._counts.get(table, 0) + n
            elif self._pending is not None:
                self._pending[table] = self._pending.get(table, 0) + n

    def _ensure(self):
        with self._lock:
            if self._counts is not None:
                return
            if self._pending is None:
                self._pending = {}
                initialising = True
            else:
                initialising = False        # another thread is counting
        if not initialising:
            while True:
                time.sleep(0.05)
                with self._lock:
                    if self._counts is not None:
                        return
        c = self._conn_fn()
        counted = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                   for t in self._tables}
        with self._lock:
            for t, n in self._pending.items():
                counted[t] = counted.get(t, 0) + n
            self._counts, self._pending = counted, None

    def get(self, table: str) -> int:
        self._ensure()
        with self._lock:
            return max(0, self._counts.get(table, 0))
