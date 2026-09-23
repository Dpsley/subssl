#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  rm -f "${SUBSSL_BIN_DIR:-/usr/local/bin}/subssl"
  rm -rf "${SUBSSL_PREFIX:-/opt/subssl}"
  # Also clean the broken 2.0.0 sudo layout if still present.
  rm -f /root/.local/bin/subssl 2>/dev/null || true
  rm -rf /root/.local/share/subssl 2>/dev/null || true
  echo "System runtime removed. User config/reports were not touched."
else
  rm -f "${SUBSSL_BIN_DIR:-$HOME/.local/bin}/subssl"
  rm -rf "${SUBSSL_PREFIX:-$HOME/.local/share/subssl}"
  echo "User runtime removed. Config/reports kept in ~/.config/subssl and ~/.local/state/subssl"
fi
