"""Watcher IDS Dashboard — Configuration (development defaults)."""
from pathlib import Path

DEFAULT_EVE   = "/var/log/suricata/eve.json"
DEFAULT_PORT  = 8765
DEFAULT_HOST  = "0.0.0.0"

DEFAULT_DB        = Path("events.db")
DEFAULT_DNS_DB    = Path("dns.db")
DEFAULT_CONFIG_DB = Path("config.db")

RETAIN_DAYS   = 90
PURGE_EVERY   = 3600
PING_EVERY    = 10
MAX_QUEUE     = 500
SESSION_TTL   = 86400 * 7
PBKDF2_ITERS  = 260_000
FRONTEND_DIR  = Path("frontend")
