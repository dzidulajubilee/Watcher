# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## Refactor & Optimisation

### Added

- **`password_utils.py`** — Shared `hash_password()` and `verify_password()` module (PBKDF2-SHA256, 260 k rounds). Single source of truth for password hashing; previously the identical implementation was duplicated across `auth.py` and `users.py`.
- **`config_db.py`** — `ConfigDB` class: a dedicated SQLite connection pool for low-write configuration tables (`auth`, `sessions`, `users`, `webhooks`). Follows the same `threading.local` pattern as `AlertDB`.
- **Dual-database layout** — events and config data now live in separate files:
  - `events.db` — high-volume writes: `alerts`, `flows`, `dns_events`, `http_events`, `ack_history`
  - `config.db` — low-write config: `auth`, `sessions`, `users`, `webhooks`
- **`--config-db` CLI argument** in `server.py` to specify the config database path (default: `./config.db`).
- **Composite index** `idx_a_ts_sev` on `alerts(ts_epoch, severity)` — accelerates the common query pattern of time-range filtering combined with severity grouping.
- **`_send_json_body()` helper** in `handlers.py` — centralises the encode / set-headers / write pattern that was previously duplicated across `_serve_alerts`, `_serve_table`, `_serve_charts`, and several other data routes.
- **`README.md`** — Full project documentation covering installation, CLI usage, architecture, API reference, RBAC, webhooks, database schema, security notes, and upgrade guide.

### Changed

- **`database.py`** — `import re` and `from datetime import datetime` moved to module level and regex patterns pre-compiled as `_RE_USEC` / `_RE_TZ`. These were previously re-imported inside `_to_epoch()` on every call (the hottest path in the codebase).
- **`database.py`** — All `insert*()` methods now hold a single local reference `c = self._conn()` instead of calling `self._conn()` twice per insert (execute + commit), halving `threading.local` lookups on every write.
- **`database.py` — `bulk_acknowledge()`** rewritten to use a single `UPDATE ... WHERE id IN (...)` statement followed by one `executemany()` for history inserts, replacing a per-row loop with individual commits. Bulk acknowledgement is now O(1) SQL statements regardless of batch size.
- **`auth.py`** — Removed duplicated `_hash()` / `_verify()` methods; now imports from `password_utils`.
- **`users.py`** — Same as `auth.py`; duplicate hashing removed.
- **`server.py`** — `AlertDB` (events) and `ConfigDB` (config) are now created independently. `AuthManager`, `UserManager`, and `WebhookDB` receive `cfg_db._conn` instead of `db._conn`, routing all config I/O to the dedicated config database.
- **`config.py`** — `DEFAULT_DB` now points to `events.db`; `DEFAULT_CONFIG_DB` added pointing to `config.db`.
- **`handlers.py`** — Data endpoints (`/alerts`, `/flows`, `/dns`, `/http`, `/charts`, `/users`, `/webhooks`, `/alerts/<id>/ack/history`) migrated to the new `_send_json_body()` helper.

### Fixed

- Sessions created before the RBAC `username`/`role` columns existed are invalidated at startup, preventing stale anonymous sessions from persisting across upgrades.
- `bulk_acknowledge()` previously committed inside the loop, meaning a failure partway through left some rows updated and others not. The rewrite wraps everything in a single transaction.

---

## [v1] — Initial Release

- Real-time Suricata `eve.json` tail with SSE fan-out to connected browsers
- Alert, flow, DNS, and HTTP event ingestion and storage in SQLite
- RBAC with three roles: `admin`, `analyst`, `viewer`
- Alert acknowledgement with status, notes, and audit history
- Bulk acknowledgement across multiple alerts
- Webhook notifications (Slack, Discord, generic JSON) with per-severity filtering and cooldown
- Charts: top talkers, alert trend (hourly/daily), by category, by severity
- Six UI themes: Night, Light, Midnight Blue, Solarized Dark, Dracula, Nord
- Session-based authentication with PBKDF2-SHA256 password hashing
- Legacy single-password emergency fallback
- Configurable data retention with background purge thread
- `--password` flag for headless password management
- Auto-generated admin credentials on first run
- `GET /health` endpoint for monitoring integrations
