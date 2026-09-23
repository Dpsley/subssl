#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -eq 0 ]]; then
  INSTALL_MODE="system"
  PREFIX="${SUBSSL_PREFIX:-/opt/subssl}"
  BIN_DIR="${SUBSSL_BIN_DIR:-/usr/local/bin}"
else
  INSTALL_MODE="user"
  PREFIX="${SUBSSL_PREFIX:-$HOME/.local/share/subssl}"
  BIN_DIR="${SUBSSL_BIN_DIR:-$HOME/.local/bin}"
fi

VENV="$PREFIX/venv"
APP_DIR="$PREFIX/app"
BIN_PATH="$BIN_DIR/subssl"

command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }
python3 -m venv --help >/dev/null 2>&1 || {
  echo "python3-venv is required. On Debian/Ubuntu: sudo apt install -y python3-venv" >&2
  exit 1
}

# Clean only the application runtime, never user config/state/reports.
rm -rf "$VENV" "$APP_DIR"
mkdir -p "$PREFIX" "$BIN_DIR"

if [[ "$INSTALL_MODE" == "system" ]]; then
  # Cleanup the broken 2.0.0 sudo installation which used root's HOME.
  rm -f /root/.local/bin/subssl 2>/dev/null || true
  rm -rf /root/.local/share/subssl 2>/dev/null || true
fi

if [[ "${SUBSSL_SYSTEM_SITE_PACKAGES:-0}" == "1" ]]; then
  python3 -m venv --system-site-packages "$VENV"
else
  python3 -m venv "$VENV"
fi

if [[ "${SUBSSL_SKIP_DEPS:-0}" != "1" ]]; then
  "$VENV/bin/python" -m pip install -U pip
  "$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"
fi

mkdir -p "$APP_DIR"
cp -a "$ROOT/subssl" "$APP_DIR/subssl"

cat > "$BIN_PATH" <<EOF2
#!/usr/bin/env bash
cd "$APP_DIR"
exec "$VENV/bin/python" -m subssl.cli "\$@"
EOF2
chmod 0755 "$BIN_PATH"

# A system installation is intentionally root-owned/read-only.
if [[ "$INSTALL_MODE" == "system" ]]; then
  chmod -R a+rX "$PREFIX"
fi

echo
echo "subssl installed successfully"
echo "mode:    $INSTALL_MODE"
echo "runtime: $PREFIX"
echo "command: $BIN_PATH"

if command -v subssl >/dev/null 2>&1; then
  echo "Run: subssl"
elif [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
  echo "Run: subssl"
else
  echo
  echo "'$BIN_DIR' is not in your current PATH."
  echo "For this shell run:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
  echo "Do not source ~/.bashrc unless your current shell is bash."
fi
