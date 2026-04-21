"""
Watcher IDS Dashboard — Configuration
All runtime constants live here. Override via CLI args in server.py.
"""

from pathlib import Path

# ── Server defaults ───────────────────────────────────────────────────────────
DEFAULT_EVE   = "/var/log/suricata/eve.json"
DEFAULT_PORT  = 8765
DEFAULT_HOST  = "0.0.0.0"
DEFAULT_DB    = Path(__file__).parent / "alerts.db"

# ── Data retention ────────────────────────────────────────────────────────────
RETAIN_DAYS   = 90      # days to keep alerts in SQLite
PURGE_EVERY   = 3600    # seconds between purge cycles (1 hour)

# ── SSE ───────────────────────────────────────────────────────────────────────
PING_EVERY    = 10      # seconds between SSE keep-alive pings
MAX_QUEUE     = 500     # max queued SSE messages per client before dropping

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_TTL   = 86400 * 7   # session cookie lifetime (7 days)
PBKDF2_ITERS  = 260_000     # PBKDF2-SHA256 iteration count

# ── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND_DIR  = Path(__file__).parent / "frontend"
