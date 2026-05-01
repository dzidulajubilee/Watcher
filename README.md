# 👁 Watcher IDS Dashboard

A self-hosted, real-time intrusion detection dashboard for [Suricata](https://suricata.io).  
Reads `eve.json`, streams live alerts, and presents everything in a fast single-page UI with no external dependencies at runtime.


---

## Features

| Category | Details |
|---|---|
| **Live streaming** | Server-Sent Events push alerts, flows, DNS, and HTTP events to all connected browsers the instant Suricata writes them |
| **Alert management** | Acknowledge, investigate, or mark as false positive — individually or in bulk. Full audit history per alert |
| **Threat Intel** | Custom per-SID or per-category explanations written by your team. Coverage gap view shows your top-firing unexlained signatures |
| **Suppression rules** | Silence known-noisy signatures by SID, source IP, or category — with optional expiry dates |
| **Charts** | Alert trend, top talkers, severity distribution, category breakdown — across 24h / 7d / 30d / 60d / 90d |
| **Flow events** | Full Suricata flow records with bytes, packets, duration, app-proto |
| **DNS events** | Every query and response with answers, TTL, rcode |
| **Webhooks** | Slack, Discord, or generic JSON — per-severity filtering and per-signature cooldown |
| **RBAC** | Three roles: `admin` (full), `analyst` (read + ack), `viewer` (stream only) |
| **Themes** | Night · Light · Midnight Blue · Solarized Dark · Dracula · Nord |

---

## Architecture

```
Suricata ──► eve.json ──► tail.py ──► SQLite (events.db / dns.db)
                                   └──► SSE registry ──► browsers
                                   └──► Webhook queue ──► Slack / Discord

Browser ◄──► Python HTTP server (handlers.py)
              ├── /            → frontend/index.html  (React SPA)
              ├── /alerts      → REST API (JSON)
              ├── /events      → SSE stream
              ├── /threat-intel→ Threat Intel API
              ├── /suppression → Suppression rules API
              └── /frontend/*  → Static assets (pre-built by Vite)
```

**No Node.js on the server.** The frontend is compiled once (by you, during a build) and shipped as plain JS. The Python server just serves static files.

### Databases

| File | Contents |
|---|---|
| `events.db` | alerts, flows, http\_events, ack\_history |
| `dns.db` | dns\_events (separated — high write volume) |
| `config.db` | auth, sessions, users, webhooks, threat\_intel, suppression\_rules |

---

## Repository layout

```
watcher/
├── backend/                  Python server — all source files
│   ├── server.py             Entry point, wires everything together
│   ├── handlers.py           HTTP routing and all API endpoints
│   ├── tail.py               eve.json tail thread + suppression check
│   ├── database.py           AlertDB — alerts, flows, http, ack
│   ├── database_dns.py       DnsDB — high-volume DNS events
│   ├── config_db.py          ConfigDB — SQLite wrapper for config tables
│   ├── auth.py               Session management
│   ├── users.py              RBAC user management
│   ├── webhooks.py           Webhook engine (Slack / Discord / generic)
│   ├── threat_intel.py       Threat Intel database
│   ├── suppression.py        Suppression rules — in-memory cached engine
│   ├── registry.py           SSE client fan-out
│   ├── password_utils.py     PBKDF2-SHA256 hashing
│   ├── migrate.py            One-time DB migration tool
│   └── config.py             Runtime constants (dev paths)
│
├── frontend-src/             React source — edit this, then `npm run build`
│   ├── src/
│   │   ├── main.jsx          Entry point
│   │   ├── App.jsx           Root component — all state and SSE wiring
│   │   ├── Detail.jsx        Alert detail panel (Details / History / Raw JSON)
│   │   ├── Charts.jsx        All SVG chart components
│   │   ├── FlowsDns.jsx      Flow and DNS views
│   │   ├── Settings.jsx      Users + Webhooks settings
│   │   ├── ThreatIntel.jsx   Explain dialog + Threat Intel panel
│   │   ├── Suppression.jsx   Suppression rules panel
│   │   ├── components.jsx    Shared: Clock, Sparkline, Timeline, AckBadge
│   │   ├── themes.jsx        Theme definitions and ThemePicker
│   │   ├── utils.js          fmtTime, fmtBytes, fmtDur, constants
│   │   └── styles.css        All CSS (theme vars + layout + components)
│   ├── public/
│   │   ├── login.html        Login page
│   │   └── login.js          Login page logic
│   ├── index.html            Vite entry HTML
│   ├── vite.config.js        Vite config (base, outDir, dev proxy)
│   └── package.json
│
├── packaging/                .deb packaging support files
│   ├── postinst              Runs after install (create user, systemd, groups)
│   ├── prerm                 Runs before remove (stop service)
│   ├── postrm                Runs after purge (clean up data)
│   ├── watcher.service       systemd unit with security hardening
│   └── watcher.conf          Default config file (/etc/watcher/watcher.conf)
│
├── .github/workflows/
│   └── build.yml             GitHub Actions: build .deb on tag push
│
├── build-deb.sh              Build script — produces the installable .deb
└── README.md
```

---

## Installation

### Option A — Install the pre-built .deb (recommended)

Download the latest `.deb` from the [Releases](../../releases) page:

```bash
sudo apt install ./watcher-ids_1.1.0_all.deb
```

That's it. The installer:
- Creates a locked-down `watcher` system user
- Adds `watcher` to the `suricata` group (eve.json read access)
- Starts `watcher.service` via systemd
- Auto-generates credentials on first run

Get your credentials:
```bash
journalctl -u watcher | grep -A2 PASSWORD
```

Open the dashboard: `http://your-server:8765/`

---

### Option B — Build the .deb yourself

**Prerequisites:** Node.js 18+, `dpkg-deb`

```bash
git clone https://github.com/dzidulajubilee/Watcher.git
cd watcher-ids
./build-deb.sh 1.1.0
sudo apt install ./packaging/build/watcher-ids_1.1.0_all.deb
```

The build script installs npm dependencies, compiles the frontend with Vite, assembles the package tree, and calls `dpkg-deb`.

---

### Option C — Run directly (development)

```bash
# Clone and install frontend deps once
git clone https://github.com/dzidulajubilee/Watcher.git
cd watcher-ids
cd frontend-src && npm install && npm run build && cd ..

# Run the server (from the backend directory)
cd backend
python3 server.py

# With options
python3 server.py --eve /var/log/suricata/eve.json --port 8765 --retain-days 90
```

---

## Configuration

Edit `/etc/watcher/watcher.conf` (preserved across upgrades):

```bash
# Uncomment and customise ONE WATCHER_ARGS line
WATCHER_ARGS=--eve /var/log/suricata/eve.json --port 8765 --retain-days 30

systemctl restart watcher
```

| Flag | Default | Description |
|---|---|---|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata eve.json |
| `--port` | `8765` | TCP port to listen on |
| `--host` | `0.0.0.0` | Bind address |
| `--retain-days` | `90` | Days to keep events in SQLite |
| `--db` | `/var/lib/watcher/events.db` | Events database path |
| `--dns-db` | `/var/lib/watcher/dns.db` | DNS database path |
| `--config-db` | `/var/lib/watcher/config.db` | Config database path |
| `--password` | — | Set/change admin password, then exit |

---

## RBAC — Roles

| Permission | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View alerts / flows / DNS / charts | ✓ | ✓ | ✓ |
| Alert detail panel | ✓ | ✓ | — |
| Acknowledge / bulk-ack alerts | ✓ | ✓ | — |
| Explain (Threat Intel lookup) | ✓ | ✓ | — |
| Clear alerts / flows / DNS | ✓ | — | — |
| Manage webhooks | ✓ | — | — |
| Manage suppression rules | ✓ | — | — |
| Add / edit Threat Intel | ✓ | ✓ | — |
| Delete Threat Intel entries | ✓ | — | — |
| Manage users | ✓ | — | — |

---

## Threat Intel

The **Explain** button appears in the alert toolbar whenever an alert is selected.  
Clicking it opens a dialog showing your team's saved explanation for that signature.

Explanations can be scoped to:
- **Exact SID** — applies only to one specific Suricata signature (highest priority)
- **Category** — applies to all alerts of that category (fallback)

Each entry supports free-text explanation, tags, and reference URLs.

Manage entries at **Settings → Threat Intel**. The **Coverage Gaps** tab shows your most-fired signatures that have no explanation yet, sorted by fire count.

---

## Suppression Rules

Suppression silences alerts *before* they are stored or broadcast. Rules match on any combination of:

- `sig_id` — exact Suricata signature ID
- `src_ip` — exact source IP address  
- `category` — alert category (case-insensitive)

All specified conditions must match (AND logic). Rules can have an optional expiry date — expired rules are kept for audit purposes but no longer applied.

Rules are cached in memory and refreshed from the database every 30 seconds, so changes take effect quickly without a restart.

Manage at **Settings → Suppression** (admin only).

---

## Webhooks

Watcher supports **Slack**, **Discord**, and **Generic JSON** webhooks.  
Each webhook has its own severity filter and a 60-second per-signature cooldown (configurable in `webhooks.py`) to prevent alert storms.

Test any webhook from the Settings panel without waiting for a real alert.

---

## Upgrading

```bash
sudo apt install ./watcher-ids_1.x.x_all.deb
```

dpkg stops the running service, replaces files, restarts. Databases survive untouched. `/etc/watcher/watcher.conf` is preserved as a dpkg conffile.

---

## Uninstalling

```bash
sudo apt remove watcher-ids       # removes files, keeps databases and config
sudo apt purge  watcher-ids       # removes everything including /var/lib/watcher
```

---

## Frontend development (hot reload)

```bash
# Terminal 1 — Python backend
cd backend && python3 server.py

# Terminal 2 — Vite dev server
cd frontend-src && npm run dev
```

Open `http://localhost:5173/` — Vite proxies all API calls to port 8765.  
Changes to any `.jsx` or `.css` file appear in the browser instantly.

When satisfied, build for production:
```bash
cd frontend-src && npm run build
```

---

## GitHub Actions

Pushing a tag triggers an automatic build and GitHub Release:

```bash
git tag v1.2.0
git push origin v1.2.0
```

The workflow installs Node, builds the frontend, assembles the `.deb`, and attaches it to the release. No secrets needed — only the default `GITHUB_TOKEN`.

---

## Requirements

**Server (runtime)**
- Debian / Ubuntu (any recent release)
- Python 3.10 or later (standard library only — no pip installs)
- Suricata writing `eve.json`

**Build machine (one-time, not needed on server)**
- Node.js 18+ and npm (to compile the frontend)
- `dpkg-deb` (pre-installed on Debian/Ubuntu)

---

## License

AGPL — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built for blue team ops. No cloud. No telemetry. Your data stays on your network.</sub>
</div>