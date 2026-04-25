# 👁 Watcher IDS Dashboard

A lightweight, self-hosted web dashboard for [Suricata](https://suricata.io/) IDS alerts. Watcher tails your `eve.json` log in real time, stores events in SQLite, and streams them to your browser over Server-Sent Events (SSE).

No Node.js, no build step, no external services — just Python 3.11+ and a browser.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [First Run](#first-run)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Role-Based Access Control](#role-based-access-control)
- [Webhooks](#webhooks)
- [Database](#database)
- [Security Notes](#security-notes)
- [Upgrading](#upgrading)

---

## Features

- **Real-time alert stream** via SSE — no polling, no page refresh
- **Multi-event support** — alerts, flows, DNS, HTTP events from eve.json
- **RBAC** — three roles: `admin`, `analyst`, `viewer`
- **Alert acknowledgement** — mark alerts as acknowledged, false positive, or under investigation, with full history
- **Webhook notifications** — Slack, Discord, or any generic JSON endpoint, with per-severity filters and per-signature cooldown
- **Charts** — top talkers, alert trend (hourly/daily), by category, by severity
- **Multiple themes** — Night, Light, Midnight Blue, Solarized Dark, Dracula, Nord
- **Dual-database design** — high-volume event writes never contend with auth/session lookups
- **Self-contained** — single directory, two SQLite files, no runtime dependencies beyond the stdlib

---

## Requirements

- Python **3.11** or later (uses `str | None` union syntax)
- Suricata writing `eve.json` (any recent version)
- A modern browser

No pip packages are required. All dependencies are Python stdlib.

---

## Installation

```bash
git clone https://github.com/yourname/watcher.git
cd watcher
```

That's it. There is nothing to install.

---

## First Run

```bash
python3 server.py
```

On first run, Watcher generates a random admin password and prints it to the console:

```
========================================================
  RBAC enabled — first Admin account created:
  Username: admin
  Password: xK9mT2vQpLwRnY
  Change:   Settings → Users → Edit
========================================================
```

Open `http://localhost:8765/login` and sign in.

To set a specific password before starting the server:

```bash
python3 server.py --password mysecretpassword
```

---

## Usage

```
python3 server.py [OPTIONS]

Options:
  --eve PATH          Path to Suricata eve.json
                      default: /var/log/suricata/eve.json
  --port INT          TCP port to listen on
                      default: 8765
  --host ADDR         Bind address
                      default: 0.0.0.0
  --db PATH           Path to events database (alerts, flows, dns, http)
                      default: ./events.db
  --config-db PATH    Path to config database (auth, sessions, users, webhooks)
                      default: ./config.db
  --retain-days INT   Days to keep events in the database
                      default: 90
  --password TEXT     Set or change the dashboard password, then exit
```

### Examples

```bash
# Default — eve.json at the standard Suricata path
python3 server.py

# Custom paths
python3 server.py \
  --eve /var/log/suricata/eve.json \
  --db /var/lib/watcher/events.db \
  --config-db /var/lib/watcher/config.db \
  --port 9000

# Change the admin password
python3 server.py --password newpassword
```

### Running as a systemd service

```ini
# /etc/systemd/system/watcher.service
[Unit]
Description=Watcher IDS Dashboard
After=network.target suricata.service

[Service]
Type=simple
User=watcher
WorkingDirectory=/opt/watcher
ExecStart=/usr/bin/python3 server.py \
    --eve /var/log/suricata/eve.json \
    --db /var/lib/watcher/events.db \
    --config-db /var/lib/watcher/config.db
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now watcher
```

---

## Configuration

Runtime constants live in `config.py`. CLI arguments override the relevant ones at startup.

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_EVE` | `/var/log/suricata/eve.json` | Suricata event log |
| `DEFAULT_PORT` | `8765` | HTTP listen port |
| `DEFAULT_HOST` | `0.0.0.0` | Bind address |
| `DEFAULT_DB` | `./events.db` | Events database path |
| `DEFAULT_CONFIG_DB` | `./config.db` | Config database path |
| `RETAIN_DAYS` | `90` | Event retention window (days) |
| `PURGE_EVERY` | `3600` | Seconds between purge cycles |
| `PING_EVERY` | `10` | SSE keep-alive interval (seconds) |
| `MAX_QUEUE` | `500` | Max queued SSE messages per client |
| `SESSION_TTL` | `604800` | Session cookie lifetime (7 days) |
| `PBKDF2_ITERS` | `260000` | PBKDF2-SHA256 iteration count |
| `FRONTEND_DIR` | `./frontend/` | Static file directory |

---

## Project Structure

```
watcher/
│
├── server.py           Entry point — wires all modules, starts HTTP server
├── config.py           Runtime constants and default paths
│
├── database.py         AlertDB — SQLite wrapper for high-volume event tables
│                         (alerts, flows, dns_events, http_events, ack_history)
├── config_db.py        ConfigDB — SQLite wrapper for config tables
│                         (auth, sessions, users, webhooks)
│
├── auth.py             AuthManager — session management, legacy single-password
├── users.py            UserManager — RBAC user accounts
├── password_utils.py   Shared PBKDF2-SHA256 hash / verify helpers
│
├── handlers.py         HTTP request handler — all routes
├── registry.py         SSE client registry — thread-safe fan-out
├── tail.py             eve.json tail thread — parses and dispatches events
├── webhooks.py         WebhookDB + async HTTP delivery engine
│
└── frontend/
    ├── index.html      Dashboard shell (loads React via CDN)
    ├── app.jsx         React application (Babel transpiled in-browser)
    ├── styles.css      Theme variables and global styles
    ├── login.html      Login page
    └── login.js        Login page logic
```

---

## Architecture

### Dual-Database Design

Watcher uses two separate SQLite files:

```
events.db   ←  alerts, flows, dns_events, http_events, ack_history
config.db   ←  auth, sessions, users, webhooks
```

The events database receives a continuous stream of writes from the tail thread. The config database is almost never written to (only on login and user changes). Keeping them separate means a heavy alert ingestion burst never delays a session lookup or login, even under WAL mode.

### Threading Model

```
main thread
  └── ThreadedHTTPServer (one thread per HTTP connection)
        ├── GET /events  → long-lived SSE thread per browser tab
        └── GET/POST/*   → short-lived request threads

daemon threads
  ├── tail_thread    — reads eve.json line by line, writes to events.db,
  │                    broadcasts SSE via Registry
  ├── purge_thread   — hourly: deletes old rows, purges expired sessions
  └── webhooks       — drains delivery queue, retries failed HTTP POSTs
```

### SSE Fan-out

Each browser tab connecting to `/events` gets a `Queue` registered in the `Registry`. When the tail thread processes a new event, `registry.broadcast()` puts a formatted SSE message into every connected client's queue. Clients whose queues are full (e.g. a stalled tab) are silently dropped and will reconnect automatically via the browser's `EventSource` retry.

### Password Hashing

All passwords (both the legacy single-password and RBAC user passwords) are hashed with PBKDF2-SHA256 at 260,000 iterations using a random 16-byte hex salt. The implementation lives in `password_utils.py` and is shared by `AuthManager` and `UserManager`.

---

## API Reference

All endpoints except `/login`, `/logout`, and `/frontend/login.js` require a valid session cookie (`suri_session`).

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Sign in. Body: `{"username": "...", "password": "..."}` |
| `GET` | `/logout` | Revoke session, redirect to `/login` |
| `GET` | `/me` | Returns `{"username": "...", "role": "..."}` |

### Events

| Method | Path | Query params | Description |
|---|---|---|---|
| `GET` | `/alerts` | `days`, `limit` | Recent alerts (JSON array) |
| `GET` | `/flows` | `days`, `limit` | Recent flow events |
| `GET` | `/dns` | `days`, `limit` | Recent DNS events |
| `GET` | `/http` | `days`, `limit` | Recent HTTP events |
| `GET` | `/events` | — | SSE stream (keep-alive) |

Query params default: `days=90`, `limit=5000`. Max: `limit=20000`.

### Alert Acknowledgement

| Method | Path | Body | Description |
|---|---|---|---|
| `POST` | `/alerts/<id>/ack` | `{"status": "...", "note": "..."}` | Acknowledge one alert |
| `POST` | `/alerts/bulk-ack` | `{"ids": [...], "status": "...", "note": "..."}` | Acknowledge multiple alerts |
| `GET` | `/alerts/<id>/ack/history` | — | Full acknowledgement history |

Valid statuses: `new`, `acknowledged`, `false_positive`, `investigating`.

### Charts

| Method | Path | Query params | Description |
|---|---|---|---|
| `GET` | `/charts` | `days`, `trend` | Top talkers, trend, by category, by severity |

`trend` is in hours (24–2160). Values above 24 are bucketed by day automatically.

### Webhooks *(admin only)*

| Method | Path | Description |
|---|---|---|
| `GET` | `/webhooks` | List all webhooks |
| `POST` | `/webhooks` | Create webhook |
| `PUT` | `/webhooks/<id>` | Update webhook |
| `DELETE` | `/webhooks/<id>` | Delete webhook |
| `POST` | `/webhooks/<id>/test` | Fire a test alert |

Webhook body fields: `name`, `type` (`slack`/`discord`/`generic`), `url`, `severities` (array), `enabled` (bool).

### Users *(admin only)*

| Method | Path | Description |
|---|---|---|
| `GET` | `/users` | List all users |
| `POST` | `/users` | Create user. Body: `{"username", "password", "role"}` |
| `PUT` | `/users/<id>` | Update user (role, enabled, username, password) |
| `DELETE` | `/users/<id>` | Delete user |

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | `{"status": "ok", "clients": N, "db": {...}, "time": epoch}` |
| `DELETE` | `/alerts` | Wipe all alerts *(admin only)* |
| `DELETE` | `/flows` | Wipe all flows *(admin only)* |
| `DELETE` | `/dns` | Wipe all DNS events *(admin only)* |

---

## Role-Based Access Control

| Capability | admin | analyst | viewer |
|---|:---:|:---:|:---:|
| View alerts, flows, DNS, HTTP | ✓ | ✓ | ✓ (alerts only) |
| Receive SSE stream | ✓ | ✓ | ✓ |
| Acknowledge / annotate alerts | ✓ | ✓ | — |
| Bulk acknowledge | ✓ | ✓ | — |
| Clear event tables | ✓ | — | — |
| Manage webhooks | ✓ | — | — |
| Manage users | ✓ | — | — |

The last admin account cannot be demoted, disabled, or deleted. An admin cannot delete their own account.

### Emergency Fallback

If RBAC users are unavailable, the original single-password mechanism still works. Sign in with username `admin` and the password set via `--password`. This creates an admin session and is intended for recovery only.

---

## Webhooks

Webhooks are delivered asynchronously by a background thread so they never block the tail thread or SSE stream.

**Supported targets:**
- **Slack** — Block Kit payload with severity colour coding
- **Discord** — Embed payload with colour-coded severity fields
- **Generic** — Plain JSON, compatible with Teams, Mattermost, and custom endpoints

**Per-severity filtering:** each webhook independently chooses which severity levels trigger it (`critical`, `high`, `medium`, `low`, `info`).

**Cooldown:** the same `(webhook_id, signature_id, src_ip)` triple will not re-fire within 60 seconds (configurable via `COOLDOWN_SECS` in `webhooks.py`). Repeated hits from the same host are throttled; different source IPs for the same rule are never suppressed.

**Retry:** failed deliveries are retried up to 3 times with a 5-second delay. The last error and fire count are stored in the database and visible in the UI.

---

## Database

### events.db

| Table | Key columns | Purpose |
|---|---|---|
| `alerts` | `id`, `ts_epoch`, `severity`, `sig_id` | Suricata alert events |
| `flows` | `flow_id`, `ts_epoch` | Network flow records |
| `dns_events` | `id`, `ts_epoch`, `rrname` | DNS query/response events |
| `http_events` | `id`, `ts_epoch`, `hostname` | HTTP transaction events |
| `ack_history` | `alert_id`, `changed_at` | Per-alert acknowledgement audit log |

**Indexes:** `ts_epoch` (all tables), `severity` (alerts), composite `(ts_epoch, severity)` (alerts), `rrname` (dns), `hostname` (http), `alert_id` (ack_history).

### config.db

| Table | Purpose |
|---|---|
| `auth` | Single key-value store for the legacy password hash |
| `sessions` | Active session tokens with username, role, and expiry |
| `users` | RBAC user accounts |
| `webhooks` | Webhook configurations and delivery stats |

Both databases use `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = NORMAL`. Each thread gets its own connection via `threading.local`.

### Retention and Purge

The purge thread runs every `PURGE_EVERY` seconds and deletes rows older than `retain_days` from all four event tables in a single transaction. Expired sessions are purged in the same cycle.

---

## Security Notes

- All passwords are hashed with PBKDF2-SHA256 (260,000 rounds, random 16-byte salt). The hash format is `salt$hex_digest`.
- Session tokens are 256-bit random hex strings (`secrets.token_hex(32)`).
- Session cookies are `HttpOnly; SameSite=Strict`.
- Failed login attempts incur a 1-second delay (no lockout, but rate-limits brute force from a single connection).
- The `Server:` header is suppressed to avoid triggering Suricata SID 2034635 against the dashboard itself.
- Static files are served with a path traversal check: the resolved target path must be inside `FRONTEND_DIR`.
- It is strongly recommended to run Watcher behind a TLS-terminating reverse proxy (nginx, Caddy) in production. The built-in server speaks plain HTTP.

---

## Upgrading

### From single-file (pre-RBAC) to current

Watcher will detect an existing `alerts.db` (the old combined database) on startup. The schema migration runs automatically — `ack_status`, `ack_note`, `ack_by`, `ack_at` columns are added to `alerts` if absent, and `username`/`role` columns are added to `sessions` if absent.

Sessions without a `username` are invalidated at startup so all users re-authenticate under RBAC.

### Database path change (events.db / config.db)

If you are upgrading from a version that used a single `alerts.db`, pass the old path to `--db` and let `--config-db` default to a new `config.db`:

```bash
python3 server.py --db /path/to/alerts.db
```

The config tables (`auth`, `sessions`, `users`, `webhooks`) will be initialised fresh in the new `config.db` and the events tables remain in the path you provided.

## License

AGPL — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built for blue team ops. No cloud. No telemetry. Your data stays on your network.</sub>
</div>
