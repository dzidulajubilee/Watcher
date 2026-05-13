# Watcher IDS Dashboard

A self-hosted, real-time intrusion detection dashboard for [Suricata](https://suricata.io).  
Reads `eve.json`, streams live alerts, and presents everything in a fast single-page UI with no external dependencies at runtime.

---

## Features

| Category | Details |
|---|---|
| **Live streaming** | Server-Sent Events push alerts, flows, DNS, and HTTP events to all connected browsers the instant Suricata writes them |
| **Alert management** | Acknowledge, investigate, or mark as false positive — individually or in bulk. Full audit history per alert |
| **Threat Intel** | Custom per-SID or per-category explanations written by your team. Coverage gap view shows your top-firing unexplained signatures |
| **AI Explain** | Auto-generated executive summaries for every unique signature — DeepSeek, OpenAI, Claude, or NVIDIA NIM |
| **Suppression rules** | Silence known-noisy signatures by SID, source IP, or category — with optional expiry dates |
| **Charts** | Alert trend, top talkers, severity distribution, category breakdown — across 24h / 7d / 30d / 60d / 90d |
| **Flow events** | Full Suricata flow records with bytes, packets, duration, app-proto |
| **DNS events** | Every query and response with answers, TTL, rcode |
| **HTTP events** | Hostname, URL, method, status code, user-agent per transaction |
| **Webhooks** | Slack, Discord, or generic JSON — per-severity filtering and per-signature cooldown |
| **RBAC** | Three roles: `admin` (full), `analyst` (read + ack), `viewer` (stream only) |
| **Themes** | Night · Light · Midnight Blue · Solarized Dark · Dracula · Nord |

---

## Architecture

### Data pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Suricata (IDS engine)                                                      │
│  /var/log/suricata/eve.json  ◄── continuous append                         │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │ inotify-style readline loop
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  tail.py  (tail_thread — daemon)                                          │
│                                                                           │
│  parse_eve_line()                                                         │
│    ├── alert  → suppression check → DB insert → SSE broadcast → webhook  │
│    ├── flow   → DB insert → SSE broadcast                                │
│    ├── dns    → DNS DB insert → SSE broadcast                            │
│    └── http   → DB insert → SSE broadcast                                │
│                                                                           │
│  purge_thread (daemon)  — hourly retention sweep + WAL checkpoint        │
└────────┬───────────────────────┬──────────────────────────────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌──────────────────────┐
│  events.db      │    │  config.db            │
│  ─────────────  │    │  ─────────────────    │
│  alerts         │    │  users / sessions     │
│  flows          │    │  webhooks             │
│  http_events    │    │  threat_intel         │
│  ack_history    │    │  suppression_rules    │
└─────────────────┘    └──────────────────────┘
         │
         ▼
┌─────────────────┐
│  dns.db         │    ← separated: high write-volume DNS events
│  ─────────────  │      never hold events.db WAL writer lock
│  dns_events     │
└─────────────────┘
```

### SSE fan-out

```
tail_thread ──► registry.broadcast()
                   ├──► client queue 1  ──► browser tab A
                   ├──► client queue 2  ──► browser tab B
                   └──► client queue N  ──► browser tab N
                         (max 500 items; dead clients pruned automatically)
```

### Webhook delivery pipeline

```
tail_thread ──► dispatch() ──► [severity filter] ──► [cooldown check]
                                                           │
                                                           ▼
                                               _queue  (max 1 000 items)
                                                           │
                                               delivery_worker (daemon)
                                                 ├── attempt 1 → ok? → done
                                                 ├── fail → re-enqueue(retry_after + 5 s)
                                                 └── 3 failures → give up, log error
```

### HTTP server

```
Browser ◄──► Python HTTP server  (handlers.py — ThreadedHTTPServer)
              │
              ├── GET  /                  → frontend/index.html   (React SPA)
              ├── GET  /frontend/*        → static assets (pre-built by Vite)
              ├── GET  /events            → SSE stream  (persistent connection)
              │
              ├── GET  /alerts            → alert list, search, pagination
              ├── POST /alerts/bulk-ack   → bulk acknowledge
              ├── POST /alerts/delete-selected
              ├── GET  /alerts/explain    → AI Explain (full build only)
              │
              ├── GET  /flows             → flow records
              ├── GET  /dns               → DNS events
              ├── GET  /http              → HTTP events
              ├── GET  /charts            → aggregated chart data
              │
              ├── GET  /health            → stats + uptime
              ├── GET  /me                → current user + role
              │
              ├── GET|POST|PUT|DELETE /users       → user management
              ├── GET|POST|PUT|DELETE /webhooks     → webhook CRUD
              ├── GET|POST|PUT|DELETE /suppression  → suppression rules
              │
              ├── GET|POST|PUT|DELETE /threat-intel          → TI CRUD
              ├── GET  /threat-intel/lookup                   → explain lookup
              ├── GET  /threat-intel/gaps                     → coverage gaps
              ├── GET  /threat-intel/stats                    → statistics
              ├── GET  /threat-intel/export                   → JSON export
              ├── POST /threat-intel/import                   → bulk import
              │
              ├── GET|POST /settings/explain   → AI Explain config
              ├── POST /admin/replay           → reimport eve.json into DB
              └── POST /admin/flush            → wipe all event data
```

### Thread model

| Thread | Name | Role |
|--------|------|------|
| Main | `server` | Accepts TCP connections, spawns one thread per request |
| Daemon | `tail` | Tails `eve.json`, inserts events, drives SSE + webhooks |
| Daemon | `purge` | Hourly: deletes old rows, checkpoints WAL, runs `PRAGMA optimize` |
| Daemon | `delivery_worker` | Drains webhook queue, retries with back-off (non-blocking) |
| Daemon | `explain-{sid}` | Spawned per new SID to call AI provider (full build only) |

### Dual build

```
./build-deb.sh 1.7.3
       │
       ├── Step 1: npm run build (frontend-src → frontend/)
       │
       ├── Step 2: strip-ai.py (full source → AI-free source tree)
       │              removes: explain.py, LLM routes, AI settings panel
       │              keeps:   Explain button, Threat Intel tab, all data views
       │
       ├── Step 3: watcher-ids_1.7.3_all.deb        (full — AI Explain included)
       ├── Step 4: watcher-ids_1.7.3-noai_all.deb   (AI-free — smaller footprint)
       └── Step 5: watcher-ids-src_1.7.3.zip        (source archive)
```

**No Node.js on the server.** The frontend is compiled once at build time and shipped as plain JS/CSS. The Python server serves static files only.

---

## Repository layout

```
watcher-ids/
├── backend/                  Python server — all source files
│   ├── server.py             Entry point, argument parsing, wires all components
│   ├── handlers.py           HTTP routing and all API endpoints
│   ├── tail.py               eve.json tail + replay + suppression check
│   ├── database.py           AlertDB — alerts, flows, http, ack history
│   ├── database_dns.py       DnsDB — high-volume DNS events
│   ├── config_db.py          ConfigDB — SQLite wrapper for config tables
│   ├── auth.py               Session management
│   ├── users.py              RBAC user management
│   ├── webhooks.py           Webhook engine — delivery queue, Slack/Discord/generic
│   ├── explain.py            AI Explain engine (full build only)
│   ├── threat_intel.py       Threat Intel database
│   ├── suppression.py        Suppression rules — in-memory cached engine (30 s TTL)
│   ├── registry.py           SSE client fan-out
│   ├── password_utils.py     PBKDF2-SHA256 hashing
│   ├── migrate.py            One-time DB migration tool
│   └── config.py             Runtime constants and default paths
│
├── frontend-src/             React source — edit this, then `npm run build`
│   ├── src/
│   │   ├── main.jsx          Entry point
│   │   ├── App.jsx           Root component — all state and SSE wiring
│   │   ├── Detail.jsx        Alert detail panel (Details / History / Raw JSON)
│   │   ├── Charts.jsx        All SVG chart components
│   │   ├── FlowsDns.jsx      Flow and DNS/HTTP views
│   │   ├── Settings.jsx      Users, Webhooks, AI Explain settings
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
│   ├── vite.config.js        Vite config (base: /frontend/, dev proxy → :8765)
│   └── package.json
│
├── packaging/                .deb packaging support files
│   ├── postinst              Runs after install: create user, systemd, seed admin
│   ├── prerm                 Runs before remove: stop service
│   ├── postrm                Runs after purge: clean up data directories
│   ├── watcher.service       systemd unit with security hardening
│   └── watcher.conf          Default config file (/etc/watcher/watcher.conf)
│
├── .github/workflows/
│   └── build.yml             GitHub Actions: build both .deb variants on tag push
│
├── build-deb.sh              Dual-build script — produces full .deb, noai .deb, source .zip
├── strip-ai.py               Strips LLM engine from source tree to produce AI-free variant
└── README.md
```

---

## Installation

### Option A — Install the pre-built .deb (recommended)

Download the latest `.deb` from the [Releases](../../releases) page:

```bash
sudo apt install ./watcher-ids_1.7.3_all.deb
```

That's it. The installer:
- Creates a locked-down `watcher` system user
- Adds `watcher` to the `suricata` group (eve.json read access)
- Starts `watcher.service` via systemd
- Seeds the admin account on first install (password printed to the install banner)

Retrieve your credentials:
```bash
journalctl -u watcher | grep -A5 "First-run credentials"
```

Open the dashboard: `http://your-server:8765/`

---

### Option B — Build the .deb yourself

**Prerequisites:** Node.js 18+, `dpkg-deb`

```bash
git clone https://github.com/yourname/watcher-ids.git
cd watcher-ids
./build-deb.sh 1.7.3
sudo apt install ./packaging/build/watcher-ids_1.7.3_all.deb
```

The build script compiles the frontend with Vite, strips the AI engine for the noai variant, assembles both package trees, and calls `dpkg-deb`. Three artifacts are produced per run:

| Artifact | Description |
|---|---|
| `watcher-ids_1.7.3_all.deb` | Full build — includes AI Explain (DeepSeek / OpenAI / Claude / NVIDIA) |
| `watcher-ids_1.7.3-noai_all.deb` | AI-free build — LLM engine removed, Threat Intel and Explain button kept |
| `watcher-ids-src_1.7.3.zip` | Source archive for distribution |

---

### Option C — Run directly (development)

```bash
# Clone and install frontend deps once
git clone https://github.com/yourname/watcher-ids.git
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
| View alerts / flows / DNS / HTTP / charts | ✓ | ✓ | ✓ |
| Alert detail panel | ✓ | ✓ | — |
| Acknowledge / bulk-ack alerts | ✓ | ✓ | — |
| Explain (Threat Intel lookup) | ✓ | ✓ | — |
| Add / edit Threat Intel | ✓ | ✓ | — |
| Delete Threat Intel entries | ✓ | — | — |
| Clear alerts / flows / DNS | ✓ | — | — |
| Manage webhooks | ✓ | — | — |
| Manage suppression rules | ✓ | — | — |
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

## AI Explain (full build only)

The full build includes an auto-explain engine that generates an executive summary the first time each unique signature ID fires. Summaries are cached in the database and never re-fetched.

Supported providers: **DeepSeek**, **OpenAI**, **Claude (Anthropic)**, **NVIDIA NIM**.

Configure at **Settings → AI Explain** or via `watcher.conf`. The noai build (`-noai` deb) has the LLM engine removed entirely — the Explain button and Threat Intel panel remain fully functional.

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
Each webhook has its own severity filter and a 60-second per-signature cooldown to prevent alert storms.

Deliveries are asynchronous — a background worker drains the queue with non-blocking retry (up to 3 attempts, 5-second back-off). A failed or slow endpoint never stalls other webhooks.

Test any webhook from the Settings panel without waiting for a real alert.

---

## Upgrading

```bash
sudo apt install ./watcher-ids_1.7.3_all.deb
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
**Note:** the session cookie is scoped to port 8765, so log in at `http://localhost:8765/` once before switching to the Vite URL.

Changes to any `.jsx` or `.css` file appear in the browser instantly.

When satisfied, build for production:
```bash
cd frontend-src && npm run build
```

---

## GitHub Actions

Pushing a tag triggers an automatic build and GitHub Release:

```bash
git tag v1.7.3
git push origin v1.7.3
```

The workflow installs Node, builds the frontend, assembles both `.deb` variants (full + noai), and attaches them to the release. No secrets needed — only the default `GITHUB_TOKEN`.

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

AGPL-3.0 — see [LICENSE](LICENSE).

---

## Changelog

### v1.7.3 — 2026-05-13

#### Security
- **S-03 · Alert ID collision under high traffic** — Alert IDs are now constructed as `{flow_id}-{epoch_ms}-{4-byte-hex}`. The 32-bit entropy suffix makes same-millisecond collisions on the same flow statistically impossible, preventing the silent `INSERT OR IGNORE` drops that could occur at high event rates or during replay.

#### Correctness
- **S-04 · Replay must not fire live webhooks** — `replay_eve()` no longer accepts a `wdb` parameter and never calls the webhook dispatcher. Importing 90 days of `eve.json` history no longer floods Slack / Discord / Teams endpoints with stale notifications or triggers provider rate-limit bans.

#### Performance
- **P-01 · Webhook config DB query on every alert** — `dispatch()` now calls `wdb.get_cached()` instead of `wdb.get_all()`. The webhook list is held in memory with a 30-second TTL and invalidated immediately on any `create` / `update` / `delete`. On a busy sensor (1 000 alerts/s) this eliminates ~999 redundant `SELECT` queries per second.
- **P-04 · Single delivery worker blocking on retry sleep** — The webhook delivery worker no longer calls `time.sleep(RETRY_DELAY)` inside its loop. Failed deliveries are re-enqueued with a `retry_after` timestamp; the worker picks up the next ready item and only yields for 100 ms when all pending items are in their back-off window. Two simultaneously-down webhook endpoints no longer stack their 15-second stalls.

### v1.7.2 — 2026-05-12

- Fix: `0 found in DB` badge rendered as a large 200 px box (CSS class-name collision resolved)
- All search-status badges now identical in size: `Searching…` / `N found in DB` / `0 found in DB`

### v1.7.1

- Full-database alert search by SID, IP, or signature text
- Search queries the whole DB — not just loaded rows
- Debounced search (400 ms) with `N found in DB` result count
- Load-more support for search result pagination
- ✕ clear button in search input
- `dst_ip` index for faster destination searches

### v1.7.0

- AI Explain — executive summaries on every alert (DeepSeek / OpenAI / Claude / NVIDIA NIM)
- Auto-generate summary on each new unique signature ID
- Settings → AI Explain: enable, pick provider, manage API keys via UI or `watcher.conf`
- Fix: webhook Test now respects Allow Local IPs setting
- Fix: stale SSRF-blocked error cleared when Local IPs enabled
- Fully air-gapped — zero external font/CDN dependencies
