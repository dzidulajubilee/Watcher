# 👁 Watcher IDS Dashboard

A lightweight, self-hosted **Intrusion Detection System dashboard** that tails Suricata's `eve.json` log in real time and streams alerts to a browser UI over SSE (Server-Sent Events). Built with Python's standard library — no framework dependencies.

---

## Features

- **Real-time alert streaming** via Server-Sent Events — no polling, no websockets
- **Multi-event support** — alerts, flows, DNS, and HTTP events from Suricata
- **Role-Based Access Control (RBAC)** — three roles: `admin`, `analyst`, `viewer`
- **Webhook notifications** — Slack, Discord, and generic JSON endpoints with per-severity filtering and cooldown suppression
- **Multiple UI themes** — Night, Light, Midnight Blue, Solarized Dark, Dracula, Nord
- **Automatic data retention** — configurable purge cycle for old alerts (default: 90 days)
- **Zero npm / no build step** — React loaded from CDN; run with a single Python command
- **SQLite backend** — single-file database, no external DB required

---

## Requirements

- Python 3.10+
- [Suricata](https://suricata.io/) configured to write `eve.json`
- No third-party Python packages required

---

## Quick Start

**1. Clone the repo**
```bash
git clone https://github.com/yourname/watcher.git
cd watcher
```

**2. Set a password**
```bash
python3 server.py --password mysecretpassword
```

**3. Start the server**
```bash
python3 server.py
```

**4. Open the dashboard**
```
http://localhost:8765/
```

On first run with no existing users, an `admin` account is auto-created and the credentials are printed to the console.

---

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata eve.json |
| `--port` | `8765` | TCP port to listen on |
| `--host` | `0.0.0.0` | Bind address |
| `--db` | `./alerts.db` | Path to SQLite database file |
| `--retain-days` | `90` | Days to keep alerts in the database |
| `--password` | — | Set or change the dashboard password, then exit |

---

## Project Structure

```
watcher/
├── server.py       # Entry point — wires all modules and starts the HTTP server
├── auth.py         # Session management + legacy single-password fallback
├── users.py        # RBAC user management (admin / analyst / viewer)
├── database.py     # SQLite schema + queries for alerts, flows, DNS, HTTP
├── handlers.py     # HTTP request handlers (REST API + SSE + static files)
├── registry.py     # Thread-safe SSE client registry (fan-out broadcasts)
├── tail.py         # Background thread that tails eve.json
├── webhooks.py     # Webhook engine (Slack, Discord, generic JSON)
├── config.py       # All runtime constants
└── frontend/
    ├── index.html  # Main dashboard shell (loads React from CDN)
    ├── app.jsx     # React dashboard application
    ├── login.html  # Login page
    ├── login.js    # Login page logic
    └── styles.css  # Shared stylesheet + theme variables
```

---

## Roles

| Role | Capabilities |
|------|-------------|
| `admin` | Full access — all views, clear data, webhooks, user management |
| `analyst` | Read access — all views, no delete/clear, no settings |
| `viewer` | Stream only — alerts view, no detail panel, no controls |

---

## Webhooks

Webhooks can be configured via the Settings panel in the dashboard. Supported targets:

- **Slack** (Block Kit format)
- **Discord** (Embeds format)
- **Generic** (plain JSON — compatible with Teams, Mattermost, etc.)

Each webhook supports **per-severity filtering** and a **cooldown** (default: 60 s) to suppress repeated firings of the same rule from the same source IP.

---

## Configuration

All defaults live in `config.py`:

```python
SESSION_TTL   = 86400 * 7   # Session cookie lifetime (7 days)
PBKDF2_ITERS  = 260_000     # Password hashing rounds
RETAIN_DAYS   = 90          # Alert retention in SQLite
PURGE_EVERY   = 3600        # Seconds between purge cycles
PING_EVERY    = 10          # SSE keep-alive interval (seconds)
MAX_QUEUE     = 500         # Max queued SSE messages per client
```

Override any value via CLI flags or by editing `config.py` directly.

---

## Security Notes

- Passwords are hashed with **PBKDF2-SHA256** (260,000 rounds) with a random salt
- Session tokens are 32-byte cryptographically random hex strings
- Sessions expire after 7 days and are purged automatically
- Old sessions without RBAC metadata are invalidated on upgrade

---



## License

AGPL — see [LICENSE](LICENSE) for details.

<div align="center">
<sub>Built for blue team ops. No cloud. No telemetry. Your data stays on your network.</sub>
</div>
