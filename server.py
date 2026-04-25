#!/usr/bin/env python3
"""
Watcher IDS Dashboard — Entry point

Usage
-----
    python3 server.py
    python3 server.py --eve /var/log/suricata/eve.json --port 8765
    python3 server.py --password mysecretpassword      # set/change password
    python3 server.py --db /var/lib/watcher/events.db --config-db /var/lib/watcher/config.db

Databases
---------
  events.db  (--db)         High-volume write: alerts, flows, dns, http events.
  config.db  (--config-db)  Low-write config:  auth, sessions, users, webhooks.

Keeping them separate prevents sustained event writes from contending with
login/session checks even under WAL mode.

First run
---------
If no password is set a random one is generated, printed to the console,
and saved (hashed) in config.db.  Change it any time:
    python3 server.py --password <new-password>
"""

import argparse
import logging
import secrets
import socketserver
import threading
from http.server import HTTPServer

import config
from auth       import AuthManager
from users      import UserManager
from config_db  import ConfigDB
from database   import AlertDB
from handlers   import Handler
from registry   import Registry
from tail       import purge_thread, tail_thread
from webhooks   import WebhookDB, delivery_worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("watcher")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Each request (including long-lived SSE connections) runs in its own thread."""
    daemon_threads = True


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Watcher IDS Dashboard",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--eve",          default=config.DEFAULT_EVE,
                   help="Path to Suricata eve.json")
    p.add_argument("--port",         default=config.DEFAULT_PORT, type=int,
                   help="TCP port to listen on")
    p.add_argument("--host",         default=config.DEFAULT_HOST,
                   help="Bind address")
    p.add_argument("--db",           default=str(config.DEFAULT_DB),
                   help="Path to events SQLite database (alerts, flows, dns, http)")
    p.add_argument("--config-db",    default=str(config.DEFAULT_CONFIG_DB),
                   dest="config_db",
                   help="Path to config SQLite database (auth, sessions, users, webhooks)")
    p.add_argument("--retain-days",  default=config.RETAIN_DAYS, type=int,
                   help="Days to keep events in the database")
    p.add_argument("--password",     default=None,
                   help="Set or change the dashboard password, then exit")
    return p


def main():
    args = build_arg_parser().parse_args()

    # ── Events DB ─────────────────────────────────────────────────────────────
    db = AlertDB(path=args.db, retain_days=args.retain_days)

    # ── Config DB (auth, sessions, users, webhooks) ───────────────────────────
    cfg_db = ConfigDB(path=args.config_db)

    # ── Auth (uses config DB) ─────────────────────────────────────────────────
    auth = AuthManager(conn_fn=cfg_db._conn)

    # Password management mode: set password and exit
    if args.password:
        auth.set_password(args.password)
        log.info("Password updated. Restart the server without --password.")
        return

    # First-run: auto-generate a password if none exists
    if not auth.get_hash():
        pw = secrets.token_urlsafe(14)
        auth.set_password(pw)
        log.info("=" * 58)
        log.info("  No password set — generated a random one:")
        log.info("  PASSWORD: %s", pw)
        log.info("  Change:   python3 server.py --password <new>")
        log.info("=" * 58)

    # ── Registry ──────────────────────────────────────────────────────────────
    registry = Registry()

    # ── Webhook DB (uses config DB) ───────────────────────────────────────────
    wdb = WebhookDB(conn_fn=cfg_db._conn)

    # ── User manager — RBAC (uses config DB) ─────────────────────────────────
    um = UserManager(conn_fn=cfg_db._conn)

    # Bootstrap: if no users yet, create the first admin account
    um.bootstrap_admin(auth.get_hash() or "")

    # Invalidate old sessions that pre-date the username/role columns
    cfg_db._conn().execute(
        "DELETE FROM sessions WHERE username = '' OR username IS NULL"
    )
    cfg_db._conn().commit()

    # ── Wire dependencies into the handler ────────────────────────────────────
    Handler.db       = db
    Handler.auth     = auth
    Handler.registry = registry
    Handler.wdb      = wdb
    Handler.um       = um

    # ── Log DB state ──────────────────────────────────────────────────────────
    s = db.stats()
    log.info(
        "DB: alerts=%d  flows=%d  dns=%d  oldest: %s",
        s["alerts"]["total"], s["flows"]["total"],
        s["dns"]["total"], s["oldest"] or "none",
    )

    # ── Background threads ────────────────────────────────────────────────────
    threading.Thread(
        target=tail_thread,
        args=(args.eve, db, registry, wdb),
        daemon=True, name="tail",
    ).start()

    threading.Thread(
        target=purge_thread,
        args=(db, auth),
        daemon=True, name="purge",
    ).start()

    threading.Thread(
        target=delivery_worker,
        args=(wdb,),
        daemon=True, name="webhooks",
    ).start()

    # ── HTTP server ───────────────────────────────────────────────────────────
    srv = ThreadedHTTPServer((args.host, args.port), Handler)
    srv.allow_reuse_address = True

    log.info("Login      →  http://localhost:%d/login",  args.port)
    log.info("Dashboard  →  http://localhost:%d/",       args.port)
    log.info("Health     →  http://localhost:%d/health", args.port)
    log.info("Ready — waiting for connections.")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        srv.server_close()


if __name__ == "__main__":
    main()
