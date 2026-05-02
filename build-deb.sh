#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Watcher IDS — .deb builder
# Usage:  ./build-deb.sh [version]
#   e.g.  ./build-deb.sh 1.1.0
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="${1:-1.1.0}"
PKG="watcher-ids_${VERSION}_all"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="${ROOT}/packaging/build/${PKG}"

echo "▶  Building watcher-ids v${VERSION}"

# ── 1. Build frontend ─────────────────────────────────────────────────────────
echo "▶  Building frontend…"
cd "${ROOT}/frontend-src"
npm install --silent
npm run build
cd "${ROOT}"

# ── 2. Create package tree ────────────────────────────────────────────────────
rm -rf "${BUILD}"
mkdir -p \
  "${BUILD}/DEBIAN" \
  "${BUILD}/opt/watcher/frontend/assets" \
  "${BUILD}/opt/watcher/frontend/fonts" \
  "${BUILD}/var/lib/watcher" \
  "${BUILD}/lib/systemd/system" \
  "${BUILD}/etc/watcher"

# ── 3. DEBIAN control files ───────────────────────────────────────────────────
cat > "${BUILD}/DEBIAN/control" << EOF
Package: watcher-ids
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Watcher IDS <watcher@localhost>
Description: Watcher IDS Dashboard
 Real-time Suricata IDS dashboard. Reads eve.json, streams alerts,
 tracks flows/DNS/HTTP, charts, webhooks, threat intel, suppression rules.
EOF

cp "${ROOT}/packaging/postinst"       "${BUILD}/DEBIAN/postinst"
cp "${ROOT}/packaging/prerm"          "${BUILD}/DEBIAN/prerm"
cp "${ROOT}/packaging/postrm"         "${BUILD}/DEBIAN/postrm"
echo "/etc/watcher/watcher.conf" >   "${BUILD}/DEBIAN/conffiles"
chmod 755 "${BUILD}/DEBIAN/postinst" "${BUILD}/DEBIAN/prerm" "${BUILD}/DEBIAN/postrm"

# ── 4. Backend Python files ───────────────────────────────────────────────────
cp "${ROOT}/backend/"*.py "${BUILD}/opt/watcher/"

# Install-time config.py — overwrite with hardcoded system paths
cat > "${BUILD}/opt/watcher/config.py" << 'PYEOF'
"""Watcher IDS Dashboard — Configuration (installed system paths)."""
from pathlib import Path

DEFAULT_EVE   = "/var/log/suricata/eve.json"
DEFAULT_PORT  = 8765
DEFAULT_HOST  = "0.0.0.0"

DEFAULT_DB        = Path("/var/lib/watcher/events.db")
DEFAULT_DNS_DB    = Path("/var/lib/watcher/dns.db")
DEFAULT_CONFIG_DB = Path("/var/lib/watcher/config.db")

RETAIN_DAYS   = 90
PURGE_EVERY   = 3600
PING_EVERY    = 10
MAX_QUEUE     = 500
SESSION_TTL   = 86400 * 7
PBKDF2_ITERS  = 260_000
FRONTEND_DIR  = Path("/opt/watcher/frontend")
PYEOF

# ── 5. Built frontend ─────────────────────────────────────────────────────────
cp "${ROOT}/frontend/index.html"    "${BUILD}/opt/watcher/frontend/"
cp "${ROOT}/frontend/login.html"    "${BUILD}/opt/watcher/frontend/"
cp "${ROOT}/frontend/login.js"      "${BUILD}/opt/watcher/frontend/"
cp "${ROOT}/frontend/assets/"*      "${BUILD}/opt/watcher/frontend/assets/"
cp "${ROOT}/frontend/fonts/"*       "${BUILD}/opt/watcher/frontend/fonts/"

# ── 6. Systemd + config ───────────────────────────────────────────────────────
cp "${ROOT}/packaging/watcher.service" "${BUILD}/lib/systemd/system/watcher.service"
cp "${ROOT}/packaging/watcher.conf"    "${BUILD}/etc/watcher/watcher.conf"

# ── 7. Build .deb ─────────────────────────────────────────────────────────────
chmod 755 "${BUILD}/var/lib/watcher" "${BUILD}/etc/watcher"
dpkg-deb --build --root-owner-group \
  "${BUILD}" \
  "${ROOT}/packaging/build/watcher-ids_${VERSION}_all.deb"

echo ""
echo "✓  Built:  packaging/build/watcher-ids_${VERSION}_all.deb"
echo "   Size:   $(du -sh "${ROOT}/packaging/build/watcher-ids_${VERSION}_all.deb" | cut -f1)"
echo ""
echo "   Install: sudo apt install ./packaging/build/watcher-ids_${VERSION}_all.deb"
