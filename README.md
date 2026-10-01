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
│  /var/log/suricata/eve.json  ◄── continuous append                          │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │ inotify-style readline loop
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  tail.py  (tail_thread — daemon)                                          │
│                                                                           │
│  parse_eve_line()                                                         │
│    ├── alert  → suppression check → DB insert → SSE broadcast → webhook   │
│    ├── flow   → DB insert → SSE broadcast                                 │
│    ├── dns    → DNS DB insert → SSE broadcast                             │
│    └── http   → DB insert → SSE broadcast                                 │
│                                                                           │
│  purge_thread (daemon)  — hourly retention sweep + WAL checkpoint         │
└────────┬───────────────────────┬──────────────────────────────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌──────────────────────┐
│  events.db      │    │  config.db           │
│  ─────────────  │    │  ─────────────────   │
│  alerts         │    │  users / sessions    │
│  flows          │    │  webhooks            │
│  http_events    │    │  threat_intel        │
│  ack_history    │    │  suppression_rules   │
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
./build-deb.sh 1.10.0
       │
       ├── Step 1: npm run build (frontend-src → frontend/)
       │
       ├── Step 2: strip-ai.py (full source → AI-free source tree)
       │              removes: explain.py, LLM routes, AI settings panel
       │              keeps:   Explain button, Threat Intel tab, all data views
       │
       ├── Step 3: watcher-ids_1.10.0_all.deb        (full — AI Explain included)
       ├── Step 4: watcher-ids_1.10.0-noai_all.deb   (AI-free — smaller footprint)
       └── Step 5: watcher-ids-src_1.10.0.zip        (source archive)
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
│   ├── backup.py             Database backups: backup / list / restore
│   ├── sqlite_util.py        Lock-retry writes, chunked deletes, O(1) row counters
│   ├── timeparse.py          Fast exact Suricata timestamp parser
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
│   ├── postrm                Runs after purge: clean up data dirs + Watcher-created nginx/systemd files
│   ├── watcher-cli           /usr/bin/watcher admin command (--setup-https etc.)
│   ├── watcher-backup.*      systemd timer + service for daily backups
│   ├── backup.conf           Backup settings (/etc/watcher/backup.conf)
│   ├── watcher.service       systemd unit with security hardening
│   └── watcher.conf          Default config file (/etc/watcher/watcher.conf)
│
├── .github/workflows/
│   └── build.yml             GitHub Actions: build both .deb variants on tag push
│
├── tests/                    Regression tests (stdlib unittest)
├── build-deb.sh              Dual-build script — produces full .deb, noai .deb, source .zip
├── strip-ai.py               Strips LLM engine from source tree to produce AI-free variant
└── README.md
```

---

## Installation

### Option A — Install the pre-built .deb (recommended)

Download the latest `.deb` from the [Releases](../../releases) page:

```bash
sudo apt install ./watcher-ids_1.10.0_all.deb
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

To serve it over HTTPS instead (recommended on shared networks), run `sudo watcher --setup-https` — see [HTTPS](#https-nginx-front-end).

---

### Option B — Build the .deb yourself

**Prerequisites:** Node.js 18+, `dpkg-deb`

```bash
git clone https://github.com/yourname/watcher-ids.git
cd watcher-ids
./build-deb.sh 1.10.0
sudo apt install ./packaging/build/watcher-ids_1.10.0_all.deb
```

The build script compiles the frontend with Vite, strips the AI engine for the noai variant, assembles both package trees, and calls `dpkg-deb`. Three artifacts are produced per run:

| Artifact | Description |
|---|---|
| `watcher-ids_1.10.0_all.deb` | Full build — includes AI Explain (DeepSeek / OpenAI / Claude / NVIDIA) |
| `watcher-ids_1.10.0-noai_all.deb` | AI-free build — LLM engine removed, Threat Intel and Explain button kept |
| `watcher-ids-src_1.10.0.zip` | Source archive for distribution |

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
| `--host` | `0.0.0.0` | Bind address (default taken from the `WATCHER_HOST` environment variable if set — `watcher --setup-https` sets it to `127.0.0.1`) |
| `--retain-days` | `90` | Days to keep events in SQLite |
| `--db` | `/var/lib/watcher/events.db` | Events database path |
| `--dns-db` | `/var/lib/watcher/dns.db` | DNS database path |
| `--config-db` | `/var/lib/watcher/config.db` | Config database path |
| `--password` | — | Set the emergency (break-glass) fallback password for the `admin` login, then exit |
| `--clear-password` | — | Disable the emergency fallback password, then exit |

### Emergency fallback password (break-glass)

Normal logins use the accounts in **Settings → Users**. As a last resort, an operator with shell access can set a fallback password that logs in as `admin`:

```bash
sudo -u watcher python3 /opt/watcher/server.py --password '<new-password>'   # enable
sudo -u watcher python3 /opt/watcher/server.py --clear-password              # disable
sudo systemctl restart watcher
```

Since v1.8.0 no fallback password is generated automatically. Earlier versions created one on first start and printed it to the journal; on upgraded installs that old password **no longer works** (the stored hash is kept but ignored).

---

## HTTPS (nginx front end)

```bash
sudo watcher --setup-https          # enable
watcher --https-status              # inspect
sudo watcher --remove-https         # revert to plain HTTP on :8765
```

`--setup-https`:

1. Installs `nginx` (and `openssl`) with `apt-get` **only if they are missing**. On an air-gapped host, install them from local packages first; if `apt-get` fails the command prints offline instructions and changes nothing.
2. Checks for conflicts before changing anything — other nginx sites on the chosen ports (read from `nginx -T`, so includes are covered) or non-nginx programs on those ports. It never overwrites an nginx config it did not create.
3. Creates a self-signed certificate in `/etc/watcher/tls/` (ECDSA P-256, 825 days, host name and IP addresses in the SAN). An existing certificate is kept; `--regen-cert` replaces it and backs up the old pair.
4. Writes `/etc/nginx/conf.d/watcher.conf` (HTTPS on 443, HTTP→HTTPS redirect on 80, unbuffered live stream) and rolls back if `nginx -t` fails. If nginx was installed by this command, its stock welcome site is disabled so the redirect works; `--remove-https` re-enables it.
5. Binds the backend to `127.0.0.1` with a systemd drop-in (`/etc/systemd/system/watcher.service.d/https.conf`), so port 8765 is no longer reachable from the network. `watcher.conf` is not edited — but an explicit `--host` in `WATCHER_ARGS` still wins, and the command warns about it.
6. Restarts the services and verifies that the Watcher login page is served over HTTPS; prints the certificate's SHA-256 fingerprint so users can check it when their browser warns about the self-signed certificate.

Options: `--hostname NAME`, `--https-port N` (e.g. `8443` if 443 is taken), `--http-port N` (`0` disables the redirect), `--regen-cert`.

Behind the proxy, the backend trusts `X-Real-IP` / `X-Forwarded-Proto` **only from loopback**, so logs and the login rate limit see the real client address, and the session cookie is marked `Secure`.

To use a certificate from your own CA instead, replace `/etc/watcher/tls/watcher.crt` and `watcher.key` and run `sudo systemctl reload nginx`.

---

## Backups

A systemd timer backs up the databases **daily at about 02:30** to `/var/backups/watcher/` (settings: `/etc/watcher/backup.conf`).

```bash
sudo watcher --backup-now                    # back up now
watcher --list-backups                       # list (newest first)
sudo watcher --restore watcher-20261001-023112                 # everything
sudo watcher --restore watcher-20261001-023112 --only config   # users, webhooks, threat intel, rules only
```

- **Consistent while Watcher runs.** Each database is copied in one SQLite read transaction (online backup API), so ingest keeps writing and the copy is a consistent snapshot. Every copy is checked with `PRAGMA quick_check`.
- **`config.db` first.** It is small and holds what is hardest to recreate (users, webhooks, threat intel, suppression rules, settings).
- **Free-space guard.** A database whose copy would leave less than `BACKUP_MIN_FREE_PERCENT` (default 10 %) of the disk free is **skipped and reported** — the others are still backed up. `config.db` is exempt while its copy is at most a tenth of the free space, so the most valuable data is still saved on a nearly full disk. The backup never fills the disk Suricata and Watcher write to.
- **Atomic and rotated.** A backup is written to a `.partial-…` folder and renamed only when every copy has succeeded and verified. The newest `BACKUP_KEEP` (default 2) complete backups are kept; the oldest is removed only after a new one succeeds, so peak use is `(BACKUP_KEEP + 1) × database size`.
- **Restore is non-destructive.** `--restore` stops the service, verifies the backup, moves the current files to `/var/lib/watcher/pre-restore-<time>/`, restores, and starts the service again.
- **Kept on purge.** `apt purge watcher-ids` does not delete `/var/backups/watcher`.

**Sizing.** Backups need as much space as the databases. With the default 90-day retention, a sensor at 5,000 events/s can reach ~8 TB of data; if the disk cannot hold the copies, set `BACKUP_DATABASES="config"` (or add storage) — the guard will otherwise skip the large databases every night and log why.

**Same disk ≠ off-site.** Local backups protect against corruption, mistakes and bad upgrades, not against losing the disk or server. Copy the newest backup elsewhere regularly, e.g. `rsync -a /var/backups/watcher/ backup-host:/srv/watcher/`.

Check the last run: `journalctl -u watcher-backup -n 30`. Change the schedule: `sudo systemctl edit watcher-backup.timer`. Disable: `sudo systemctl disable --now watcher-backup.timer`.

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
| Force-regenerate an AI explanation | ✓ | ✓ | — |

Changing a user's role, disabling, renaming or deleting them ends their active sessions immediately. The webhook list (`GET /webhooks`) is admin-only because webhook URLs contain secret tokens.

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

Configure at **Settings → AI Explain** or via `watcher.conf` (`AI_PROVIDER` and the provider's API-key variable; the Settings UI takes priority). AI Explain is enabled by default but makes no API calls until a key is configured. Only the signature, SID, category, severity and protocol are sent to the provider — source/destination IP addresses are not. The noai build (`-noai` deb) has the LLM engine removed entirely — the Explain button and Threat Intel panel remain fully functional.

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
sudo apt install ./watcher-ids_1.10.0_all.deb
```

dpkg stops the running service, replaces files, restarts. Databases survive untouched. `/etc/watcher/watcher.conf` is preserved as a dpkg conffile. An HTTPS setup (`watcher --setup-https`) survives upgrades.

**Upgrading to 1.10.0:** daily backups are enabled automatically (see [Backups](#backups)); the first one runs at the next ~02:30. Check free space before then, or run `sudo watcher --backup-now` to see what fits. The live Flows/DNS views update once per second instead of per event.

**Upgrading to 1.9.0:** no schema changes. On the first start the event counts shown by `/health` are computed once (a full count, as every `/health` request did before); afterwards they are maintained incrementally. The hourly purge now deletes in small chunks — it takes longer in total but no longer blocks ingest.

**Upgrading to 1.8.0:** the first start adds one index to `events.db` (`idx_a_flow_ts`), which can take a little while on a large database. The old auto-generated fallback password stops working — see [Emergency fallback password](#emergency-fallback-password-break-glass).

---

## Uninstalling

```bash
sudo apt remove watcher-ids       # removes files, keeps databases and config
sudo apt purge  watcher-ids       # removes everything including /var/lib/watcher
```

`purge` also removes the nginx site and systemd drop-in created by `watcher --setup-https` (and the certificates in `/etc/watcher/tls`). nginx itself is not uninstalled.

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

## Tests

Regression tests use only the Python standard library and run against temporary databases:

```bash
python3 -m unittest discover -s tests -v
```

---

## GitHub Actions

Pushing a tag triggers an automatic build and GitHub Release:

```bash
git tag v1.10.0
git push origin v1.10.0
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

### v1.10.0 — 2026-09-30

#### New
- **Database backups** — daily systemd timer (`watcher-backup.timer`), `sudo watcher --backup-now`, `watcher --list-backups`, `sudo watcher --restore NAME [--only config,events,dns]`. Consistent online copies (one-step SQLite backup API — a stepwise backup restarted 113 times in 12 s under live ingest and would never finish), `quick_check` verification, per-database free-space guard, atomic completion, rotation after success, non-destructive restore. Settings in `/etc/watcher/backup.conf`. Backups are kept on purge.

#### Performance
- **Live view batching** — flows, DNS and HTTP events are sent to browsers once per second (the most recent 200 of each plus the true count) instead of one message per event; alerts are still sent individually and immediately. A 50,000-event burst: 38,036 → 1,446 messages per dashboard (12.0 → 1.6 MB). All events are still stored.

### v1.9.0 — 2026-09-30

#### Performance (measured on one CPU core, realistic event mix)
- **Ingest throughput ≈4.8× higher** — ~9,200 → ~42,000–47,000 events/s. Events are group-committed (up to 500 events or 100 ms per transaction, and immediately whenever the reader has caught up, so a quiet sensor sees no added latency); timestamps are parsed by a fast exact parser (6× faster, bit-identical results); the tail no longer calls `tell()` per line. Stored data is identical to v1.8.0 (verified row-by-row).
- **`/health` counts are O(1)** — previously `COUNT(*)` over whole tables on every refresh (~0.4 s per 10 M rows). DNS pagination no longer counts the whole DNS table on every page.

#### Correctness
- **Events split across writes are no longer lost** — a line Suricata had only half-written was parsed, failed, and skipped (both halves lost). Only complete lines are processed now.
- **The hourly purge no longer stalls ingest or drops events** — a single large `DELETE` held the write lock for seconds; an insert that waited more than 5 s was logged and dropped. Purge, Flush and Clear now delete in small chunks, writers in the process take turns via a shared lock, and a write that meets a locked database waits and retries instead of dropping data. Measured with 6 M expired rows: longest ingest stall 5.0 s → 0.12 s, events dropped 1 → 0.
- Dashboards and webhooks are notified only after the events are committed.
- A missing DNS database no longer crashes the tail thread (latent: `AlertDB.insert_dns` did not exist).

### v1.8.0 — 2026-09-30

#### New
- **`watcher --setup-https`** — serves the dashboard over HTTPS via nginx with a self-signed certificate; binds the backend to `127.0.0.1`. `--remove-https` reverts it; `--https-status` inspects it. See [HTTPS](#https-nginx-front-end).
- Regression test suite (`tests/`, standard library only).

#### Security
- The fallback password is no longer auto-generated and printed to the journal; it works only if set explicitly with `--password` (`--clear-password` disables it). Previously it acted as a permanent admin login that survived password changes and account disabling.
- Sessions are revoked when a user is demoted, disabled, renamed or deleted (previously they kept their old privileges for up to 7 days).
- `GET /webhooks` is admin-only (URLs contain secret tokens).
- Webhook SSRF protection now blocks `0.0.0.0`, IPv4-mapped IPv6, IPv6 link-local, CGNAT and other non-global addresses, and re-validates every redirect.
- Forcing an AI explanation to regenerate requires the admin or analyst role.

#### Correctness
- Live stream: a browser that fell behind during an alert burst (or a replay) stayed "connected" but stopped receiving alerts. The server now closes such streams so the browser reconnects.
- Replay no longer duplicates alerts that are already stored (a regression from the v1.7.3 random ID suffix). Alert IDs keep their entropy suffix; replay checks flow ID, timestamp and signature instead.
- Malformed `sig_id` / `expires_at` values return HTTP 400 instead of dropping the connection; a bad `sig_id` in a suppression-rule update no longer silently widens the rule.
- Threat-intel imports record the importing user; a rejected user update no longer changes the password.

#### Data & privacy
- AI prompts no longer include source/destination IP addresses (they were sent to the provider and cached per signature).
- Orphaned acknowledgement history is purged with the hourly maintenance.
- `AI_PROVIDER` in `watcher.conf` is now honoured.

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

### v1.6.0

- Full-database alert search — queries entire retention window, not just loaded rows
- Search across `sig_id` (index-backed), `src_ip`, `dst_ip`, `sig_msg`, `category`
- `idx_a_dst_ip` index added for destination IP search performance
- Admin Data Control panel: Replay (reimport `eve.json` without firing webhooks) and Flush (wipe all event data)
- Replay is async — returns immediately, pollable via `GET /admin/replay`

### v1.5.0

- Dual-build system: single `./build-deb.sh` run produces full `.deb`, noai `.deb`, and source `.zip`
- `strip-ai.py` — new tool that surgically removes the LLM engine from the source tree
- AI-free variant keeps the Explain button, ExplainDialog, and Threat Intel tab fully functional
- `build-deb.sh` rewritten: Step 1 builds frontend, Step 2 strips AI, Steps 3–5 package and archive

### v1.4.0

- NVIDIA NIM added as fourth AI provider (`deepseek-ai/deepseek-v4-pro` via `integrate.api.nvidia.com`)
- Uses existing OpenAI-compatible `_call_openai_compat()` path — no new network code
- `NVIDIA_API_KEY` env var support + Settings UI card
- `watcher.conf` updated with NVIDIA key comment and link to `build.nvidia.com`

### v1.3.1

- Backend: 3 new SQLite PRAGMAs on `events.db` and `dns.db` (cache, mmap, temp_store)
- Backend: 2 new indexes — `idx_a_sig_id` (GROUP BY), `idx_a_ack` (bulk-ack filter)
- Backend: `fetch_recent()` strips `raw_json` by default; lazy `fetch_raw(id)` for Detail Raw tab
- Backend: `registry.py` — `json.dumps()` moved outside lock; snapshot-then-iterate pattern
- Backend: `dispatch` import moved to module level — no per-alert attribute lookup
- Backend: `_stats_cache` — `stats()` result cached 5 s; avoids 7 DB queries per `/health` poll
- Backend: `GET /alerts/<id>/raw` endpoint for single-alert raw JSON
- Frontend: `alertIdsRef` Set replaces O(n) `prev.some()` scan — O(1) dedup per SSE event
- Frontend: `aiEnabled` fetched once on mount and passed as prop
- Frontend: Raw tab lazy-fetches JSON only on open
- Packaging: `LICENSE` file bundled inside `.deb`; `AGPL-3.0-or-later` in `DEBIAN/control`

### v1.3.0

- Multi-provider AI: OpenAI (`gpt-4o-mini`) and Anthropic Claude Haiku added alongside DeepSeek
- Global enable/disable toggle — when off, no API calls made and AI tab hidden
- Per-provider key storage, masked hint display, and key-management links in Settings
- `watcher.conf` updated with `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` comments

### v1.2.1

- Auto-explain: every new unique `sig_id` triggers a background thread that pre-fetches the summary
- Prompt rewritten to strict 3-sentence executive summary; `MAX_TOKENS` reduced 700 → 220
- `_explained_sids` set prevents duplicate API calls within a session
- License changed from MIT to **AGPL-3.0-or-later**; all backend files updated with SPDX headers

### v1.2.0

- AI-powered alert explanations via DeepSeek — on-demand, cached by `sig_id`
- `explain.py` — new `ExplainDB` (SQLite cache) + `ExplainEngine` (stdlib `urllib`)
- `POST /alerts/explain`, `GET/PUT /settings/explain` API endpoints
- ExplainDialog in UI: AI Explanation tab + Threat Intel tab; Cached/Fresh badge; Regenerate button
- Settings → AI Explain tab: key status, save/clear, How It Works card

### v1.1.0

- Self-hosted fonts: Google Fonts CDN replaced with bundled `woff2` files (ibm-plex-mono/sans, inter, jetbrains-mono)
- Install-time credential bootstrap: `postinst` seeds `config.db` with PBKDF2-SHA256 admin hash before service start; password printed in install banner
