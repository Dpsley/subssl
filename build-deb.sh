#!/usr/bin/env bash
# Build a self-contained Debian package from a source checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.2.4"
PACKAGE="subssl_${VERSION}_all.deb"
STAGE="$(mktemp -d)"
DEST="$ROOT/dist/$PACKAGE"
trap 'rm -rf "$STAGE"' EXIT

command -v dpkg-deb >/dev/null || {
  echo "dpkg-deb is required; run this on Debian, Ubuntu, or a compatible build host." >&2
  exit 1
}

mkdir -p "$STAGE/DEBIAN" "$STAGE/opt/subssl" "$STAGE/usr/bin" "$STAGE/usr/share/doc/subssl/grafana" "$STAGE/usr/share/doc/subssl/prometheus"
chmod 0755 "$STAGE"
cp "$ROOT/debian/DEBIAN/control" "$ROOT/debian/DEBIAN/copyright" "$ROOT/debian/DEBIAN/postinst" "$STAGE/DEBIAN/"
cp -a "$ROOT/subssl/." "$STAGE/opt/subssl/"
# A checkout may contain bytecode from a local test run. Never ship it: Python
# recreates matching bytecode for the target interpreter automatically.
find "$STAGE/opt/subssl" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$STAGE/opt/subssl" -type d -name '__pycache__' -empty -delete
find "$STAGE/opt/subssl" -type d -exec chmod 0755 {} +
find "$STAGE/opt/subssl" -type f -name '*.py' -exec chmod 0644 {} +
cp "$ROOT/debian/subssl" "$STAGE/usr/bin/subssl"
cp "$ROOT/debian/README.Debian" "$STAGE/usr/share/doc/subssl/README.Debian"
cp "$ROOT/grafana/subssl-certificates-dashboard.json" "$STAGE/usr/share/doc/subssl/grafana/"
cp "$ROOT/prometheus/subssl-alerts.yml" "$STAGE/usr/share/doc/subssl/prometheus/"
chmod 0755 "$STAGE/usr/bin/subssl"
chmod 0755 "$STAGE/DEBIAN/postinst"
chmod -R go-w "$STAGE"

mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$DEST"
echo "Built: $DEST"
