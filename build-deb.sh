#!/usr/bin/env bash
# Watcher IDS — dual-build script
# Produces TWO .deb packages and one source .zip from a single source tree:
#   watcher-ids_<VERSION>_all.deb        — full build with AI Explain
#   watcher-ids_<VERSION>-noai_all.deb  — AI-free variant (strip-ai.py applied)
#
# Usage:
#   ./build-deb.sh [VERSION]
#   VERSION defaults to the value in packaging/control (or 1.7.0 if absent)
#
# Requirements: python3, dpkg-deb, npm (for frontend rebuild)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-}"

# ── Auto-detect version ───────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  CTRL="$SCRIPT_DIR/packaging/control"
  if [[ -f "$CTRL" ]]; then
    VERSION="$(grep '^Version:' "$CTRL" | awk '{print $2}')"
  fi
  VERSION="${VERSION:-1.7.2}"
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Watcher IDS dual-build  v${VERSION}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

BUILD_DIR="$SCRIPT_DIR/packaging/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ════════════════════════════════════════════════════════════════════════
# STEP 1 — Build frontend (shared by both variants)
# ════════════════════════════════════════════════════════════════════════
echo "▶  Building frontend …"
cd "$SCRIPT_DIR/frontend-src"
npm install --silent
npm run build
cd "$SCRIPT_DIR"
echo "   ✓ Frontend built"
echo ""

# ════════════════════════════════════════════════════════════════════════
# STEP 2 — Run strip-ai.py to produce the AI-free source tree
# ════════════════════════════════════════════════════════════════════════
NOAI_SRC="$BUILD_DIR/src-noai"
echo "▶  Stripping AI from source tree …"
python3 "$SCRIPT_DIR/strip-ai.py" \
  --src "$SCRIPT_DIR" \
  --out "$NOAI_SRC" \
  --version "$VERSION" \
  --quiet
echo "   ✓ AI-free source tree written to: $NOAI_SRC"
echo ""

# ════════════════════════════════════════════════════════════════════════
# Helper: build one .deb from a backend source dir + label
# ════════════════════════════════════════════════════════════════════════
build_deb() {
  local BACKEND_SRC="$1"    # directory containing *.py
  local FRONTEND_SRC="$2"   # directory containing built frontend (index.html, assets/, fonts/)
  local PKG_SUFFIX="$3"     # "" or "-noai"
  local DEB_VERSION="${VERSION}${PKG_SUFFIX}"
  local PKG_NAME="watcher-ids_${DEB_VERSION}_all"
  local PKG_ROOT="$BUILD_DIR/$PKG_NAME"

  echo "▶  Building ${PKG_NAME}.deb …"

  rm -rf "$PKG_ROOT"
  mkdir -p \
    "$PKG_ROOT/DEBIAN" \
    "$PKG_ROOT/opt/watcher/frontend/assets" \
    "$PKG_ROOT/opt/watcher/frontend/fonts" \
    "$PKG_ROOT/var/lib/watcher" \
    "$PKG_ROOT/lib/systemd/system" \
    "$PKG_ROOT/etc/watcher"

  # ── DEBIAN/control ──────────────────────────────────────────────────
  cat > "$PKG_ROOT/DEBIAN/control" << CTRL
Package: watcher-ids
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10)
Maintainer: Watcher IDS <watcher@localhost>
License: AGPL-3.0-or-later
Description: Watcher IDS Dashboard${PKG_SUFFIX:+ (AI-free build)}
 Real-time Suricata IDS dashboard. Reads eve.json, streams alerts,
 tracks flows/DNS/HTTP, charts, webhooks, threat intel, suppression rules.$([ -z "$PKG_SUFFIX" ] && echo "
 Includes AI-powered alert explanations (DeepSeek/OpenAI/Claude/NVIDIA).")
 Fully air-gapped — no external dependencies.
CTRL

  # ── Packaging scripts ────────────────────────────────────────────────
  local PKGSRC
  if [[ -z "$PKG_SUFFIX" ]]; then
    PKGSRC="$SCRIPT_DIR/packaging"
  else
    PKGSRC="$NOAI_SRC/packaging"
  fi
  cp "$PKGSRC/postinst"       "$PKG_ROOT/DEBIAN/postinst"
  cp "$PKGSRC/prerm"          "$PKG_ROOT/DEBIAN/prerm"
  cp "$PKGSRC/postrm"         "$PKG_ROOT/DEBIAN/postrm"
  echo "/etc/watcher/watcher.conf" > "$PKG_ROOT/DEBIAN/conffiles"
  chmod 755 "$PKG_ROOT/DEBIAN/postinst" \
            "$PKG_ROOT/DEBIAN/prerm" \
            "$PKG_ROOT/DEBIAN/postrm"

  # ── Python backend ───────────────────────────────────────────────────
  cp "$BACKEND_SRC/"*.py "$PKG_ROOT/opt/watcher/"

  # Override config.py with system-path version
  cat > "$PKG_ROOT/opt/watcher/config.py" << 'PYEOF'
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

  # ── Syntax check all packaged Python files ───────────────────────────
  echo "   Syntax-checking Python …"
  for f in "$PKG_ROOT/opt/watcher/"*.py; do
    python3 -m py_compile "$f" || { echo "   FAIL: $(basename $f)"; exit 1; }
  done
  echo "   ✓ All Python files pass"

  # ── Frontend (variant-specific build output) ─────────────────────────
  cp "$FRONTEND_SRC/index.html" "$PKG_ROOT/opt/watcher/frontend/"
  cp "$FRONTEND_SRC/login.html" "$PKG_ROOT/opt/watcher/frontend/"
  cp "$FRONTEND_SRC/login.js"   "$PKG_ROOT/opt/watcher/frontend/"
  cp "$FRONTEND_SRC/assets/"*   "$PKG_ROOT/opt/watcher/frontend/assets/"
  cp "$FRONTEND_SRC/fonts/"*    "$PKG_ROOT/opt/watcher/frontend/fonts/"

  # ── Systemd + config ─────────────────────────────────────────────────
  cp "$PKGSRC/watcher.service" "$PKG_ROOT/lib/systemd/system/watcher.service"
  cp "$PKGSRC/watcher.conf"    "$PKG_ROOT/etc/watcher/watcher.conf"

  chmod 755 "$PKG_ROOT/var/lib/watcher" "$PKG_ROOT/etc/watcher"

  # ── Airgap check: no external URLs in built JS/CSS ───────────────────
  if grep -ql "googleapis\|gstatic\|cdnjs\|jsdelivr\|unpkg" \
       "$FRONTEND_SRC/assets/"* 2>/dev/null; then
    echo "   FAIL: external font/CDN reference found in built frontend!"
    exit 1
  fi
  echo "   ✓ Airgap check passed"

  # ── Build the .deb ───────────────────────────────────────────────────
  dpkg-deb --build --root-owner-group \
    "$PKG_ROOT" \
    "$BUILD_DIR/${PKG_NAME}.deb"

  echo "   ✓ $(du -sh "$BUILD_DIR/${PKG_NAME}.deb" | cut -f1)  →  $BUILD_DIR/${PKG_NAME}.deb"
  echo ""
}

# ════════════════════════════════════════════════════════════════════════
# STEP 3 — Build full (AI-enabled) .deb
# ════════════════════════════════════════════════════════════════════════
build_deb "$SCRIPT_DIR/backend" "$SCRIPT_DIR/frontend" ""

# ════════════════════════════════════════════════════════════════════════
# STEP 4 — Build AI-free frontend then AI-free .deb
# ════════════════════════════════════════════════════════════════════════
NOAI_FRONTEND="$NOAI_SRC/frontend"
echo "▶  Building AI-free frontend …"
cd "$NOAI_SRC/frontend-src"
# Symlink node_modules from the full build to avoid a redundant npm install
ln -sf "$SCRIPT_DIR/frontend-src/node_modules" node_modules 2>/dev/null || true
npm run build --silent
cd "$SCRIPT_DIR"
echo "   ✓ AI-free frontend built → $NOAI_FRONTEND"
echo ""

build_deb "$NOAI_SRC/backend" "$NOAI_FRONTEND" "-noai"

# ════════════════════════════════════════════════════════════════════════
# STEP 5 — Source .zip (full AI-enabled tree, for GitHub)
# ════════════════════════════════════════════════════════════════════════
echo "▶  Building source zip …"
ZIP_STAGE="$BUILD_DIR/watcher-ids-airgapped"
mkdir -p \
  "$ZIP_STAGE/backend" \
  "$ZIP_STAGE/frontend-src" \
  "$ZIP_STAGE/frontend/assets" \
  "$ZIP_STAGE/frontend/fonts" \
  "$ZIP_STAGE/packaging"

# Backend (dev config.py, not system-path version)
cp "$SCRIPT_DIR/backend/"*.py "$ZIP_STAGE/backend/"

# Frontend source
cp -r "$SCRIPT_DIR/frontend-src/." "$ZIP_STAGE/frontend-src/"

# Built frontend (AI-enabled — the zip is the full source)
cp "$SCRIPT_DIR/frontend/index.html" "$ZIP_STAGE/frontend/"
cp "$SCRIPT_DIR/frontend/login.html" "$ZIP_STAGE/frontend/"
cp "$SCRIPT_DIR/frontend/login.js"   "$ZIP_STAGE/frontend/"
cp "$SCRIPT_DIR/frontend/assets/"*   "$ZIP_STAGE/frontend/assets/"
cp "$SCRIPT_DIR/frontend/fonts/"*    "$ZIP_STAGE/frontend/fonts/"

# Packaging
cp "$SCRIPT_DIR/packaging/postinst"       "$ZIP_STAGE/packaging/"
cp "$SCRIPT_DIR/packaging/prerm"          "$ZIP_STAGE/packaging/"
cp "$SCRIPT_DIR/packaging/postrm"         "$ZIP_STAGE/packaging/"
cp "$SCRIPT_DIR/packaging/watcher.conf"   "$ZIP_STAGE/packaging/"
cp "$SCRIPT_DIR/packaging/watcher.service" "$ZIP_STAGE/packaging/"

# Strip script + build script
cp "$SCRIPT_DIR/strip-ai.py"  "$ZIP_STAGE/"
cp "$SCRIPT_DIR/build-deb.sh" "$ZIP_STAGE/"

# Extras
for f in .gitignore README.md LICENSE; do
  [[ -f "$SCRIPT_DIR/$f" ]] && cp "$SCRIPT_DIR/$f" "$ZIP_STAGE/"
done

ZIP_OUT="$BUILD_DIR/watcher-ids-src_${VERSION}.zip"
cd "$BUILD_DIR"
zip -r "$ZIP_OUT" "watcher-ids-airgapped/" \
  -x "*/node_modules/*" -x "*/__pycache__/*" -x "*/.git/*" \
  > /dev/null
cd "$SCRIPT_DIR"
echo "   ✓ $(du -sh "$ZIP_OUT" | cut -f1)  →  $ZIP_OUT"
echo ""

# ════════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════════
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Build complete — v${VERSION}"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-60s║\n" "  Full:    watcher-ids_${VERSION}_all.deb"
printf "║  %-60s║\n" "  AI-free: watcher-ids_${VERSION}-noai_all.deb"
printf "║  %-60s║\n" "  Source:  watcher-ids-src_${VERSION}.zip"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-60s║\n" "  Output dir: $BUILD_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
