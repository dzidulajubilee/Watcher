#!/usr/bin/env python3
"""
Watcher IDS Dashboard — Database Migration
Migrates the old monolithic alerts.db (single file containing everything)
to the new split layout:

  events.db  ←  alerts, flows, dns_events, http_events, ack_history
  config.db  ←  auth, sessions, users, webhooks

Run once after upgrading. Safe to re-run — all inserts use INSERT OR IGNORE
so no data is duplicated.

Usage
-----
    python3 migrate.py                                       # defaults
    python3 migrate.py --source /root/alerts.db             # custom source
    python3 migrate.py --source /root/alerts.db \\
                       --events ./events.db \\
                       --config ./config.db

After a successful run you can start the server normally (no --db flag needed
unless you moved the databases out of the project directory).
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path

# ── Defaults (match config.py) ────────────────────────────────────────────────
HERE            = Path(__file__).parent
DEFAULT_SOURCE  = HERE / "alerts.db"
DEFAULT_EVENTS  = HERE / "events.db"
DEFAULT_CONFIG  = HERE / "config.db"

# ── Tables that belong in each destination ────────────────────────────────────
EVENT_TABLES  = ("alerts", "flows", "dns_events", "http_events", "ack_history")
CONFIG_TABLES = ("auth", "sessions", "users", "webhooks")


def open_db(path: Path, label: str) -> sqlite3.Connection:
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA synchronous  = NORMAL")
    c.execute("PRAGMA foreign_keys = OFF")   # avoid FK issues during bulk copy
    c.commit()
    print(f"  Opened {label}: {path}")
    return c


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def copy_table(src: sqlite3.Connection, dst: sqlite3.Connection,
               table: str) -> int:
    """
    Copy all rows from src.table → dst.table.
    The destination table must already exist (created by the manager _setup).
    Uses INSERT OR IGNORE so re-runs never produce duplicates.
    Returns the number of rows inserted.
    """
    if not table_exists(src, table):
        print(f"    {table:20s}  not in source — skipping")
        return 0

    if not table_exists(dst, table):
        print(f"    {table:20s}  not in destination — skipping (run server once first?)")
        return 0

    # Only copy columns that exist in BOTH source and destination
    src_cols = set(columns(src, table))
    dst_cols = set(columns(dst, table))
    shared   = [c for c in columns(dst, table) if c in src_cols]   # preserve dst order

    if not shared:
        print(f"    {table:20s}  no overlapping columns — skipping")
        return 0

    col_list    = ", ".join(shared)
    placeholder = ", ".join(["?"] * len(shared))

    rows = src.execute(f"SELECT {col_list} FROM {table}").fetchall()
    if not rows:
        print(f"    {table:20s}  0 rows in source")
        return 0

    dst.executemany(
        f"INSERT OR IGNORE INTO {table} ({col_list}) VALUES ({placeholder})",
        [tuple(r[c] for c in shared) for r in rows],
    )
    dst.commit()
    inserted = dst.execute(
        f"SELECT changes()"
    ).fetchone()[0]
    print(f"    {table:20s}  {len(rows):>6} source rows  →  {inserted:>6} inserted")
    return inserted


def ensure_schema(path: Path, which: str):
    """
    Boot the relevant managers against the destination database so their
    _setup() methods create all necessary tables before we copy into them.
    """
    # Import here so migrate.py works even if run from a different directory
    sys.path.insert(0, str(HERE))

    if which == "events":
        from database import AlertDB
        AlertDB(path=str(path), retain_days=9999)   # just triggers _conn / schema

    elif which == "config":
        from config_db  import ConfigDB
        from auth       import AuthManager
        from users      import UserManager
        from webhooks   import WebhookDB
        cfg = ConfigDB(path=str(path))
        AuthManager(conn_fn=cfg._conn)
        UserManager(conn_fn=cfg._conn)
        WebhookDB(conn_fn=cfg._conn)


def run_migration(source: Path, events: Path, config: Path, dry_run: bool):
    print()
    print("Watcher DB Migration")
    print("=" * 56)
    print(f"  Source  : {source}")
    print(f"  Events  : {events}")
    print(f"  Config  : {config}")
    if dry_run:
        print("  Mode    : DRY RUN (no writes)")
    print()

    if not source.exists():
        print(f"ERROR: Source database not found: {source}")
        print("       Pass the correct path with --source")
        sys.exit(1)

    # Open source
    src = open_db(source, "source")

    # Discover which tables actually exist in the source
    src_tables = {
        r[0] for r in src.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    print(f"  Tables in source: {', '.join(sorted(src_tables)) or '(none)'}")
    print()

    if dry_run:
        print("Dry run — no changes written.")
        src.close()
        return

    # ── Events DB ─────────────────────────────────────────────────────────────
    print(f"[1/2] Migrating event tables → {events}")
    ensure_schema(events, "events")
    dst_events = open_db(events, "events destination")

    total_events = 0
    for table in EVENT_TABLES:
        total_events += copy_table(src, dst_events, table)

    dst_events.close()
    print(f"      Total rows copied: {total_events}")
    print()

    # ── Config DB ─────────────────────────────────────────────────────────────
    print(f"[2/2] Migrating config tables → {config}")
    ensure_schema(config, "config")
    dst_config = open_db(config, "config destination")

    total_config = 0
    for table in CONFIG_TABLES:
        total_config += copy_table(src, dst_config, table)

    dst_config.close()
    print(f"      Total rows copied: {total_config}")
    print()

    src.close()

    print("=" * 56)
    print("Migration complete.")
    print()
    print("You can now start Watcher without any --db flag:")
    print("    python3 server.py")
    print()
    if source not in (events, config):
        print(f"The original file at '{source}' has not been modified.")
        print("Keep it as a backup until you've verified the new databases.")
    print()


def main():
    p = argparse.ArgumentParser(
        description="Migrate Watcher from monolithic alerts.db to split events/config databases.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--source",   default=str(DEFAULT_SOURCE),
                   help="Path to the old monolithic alerts.db")
    p.add_argument("--events",   default=str(DEFAULT_EVENTS),
                   help="Destination path for events.db (alerts, flows, dns, http)")
    p.add_argument("--config",   default=str(DEFAULT_CONFIG),
                   help="Destination path for config.db (auth, sessions, users, webhooks)")
    p.add_argument("--dry-run",  action="store_true",
                   help="Show what would be migrated without writing anything")
    args = p.parse_args()

    run_migration(
        source  = Path(args.source),
        events  = Path(args.events),
        config  = Path(args.config),
        dry_run = args.dry_run,
    )


if __name__ == "__main__":
    main()
