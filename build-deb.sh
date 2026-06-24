#!/usr/bin/env bash
#
# Build a Debian package (.deb) for AppBlocker.
#
# Produces dist/appblocker_<version>_all.deb from the sources in this repo.
# The resulting package declares its dependencies (python3-tk, polkit), so
# installing it auto-pulls everything and enables the background service:
#
#     sudo apt install ./dist/appblocker_<version>_all.deb
#
# Requires: dpkg-deb (package: dpkg). No root needed to *build*.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
META="$ROOT/packaging/debian"
STAGE="$ROOT/build/deb"
DIST="$ROOT/dist"

VERSION="$(sed -n 's/^Version: //p' "$META/control" | head -1)"
if [ -z "$VERSION" ]; then
    echo "Could not read Version from $META/control" >&2
    exit 1
fi

echo "==> Building appblocker $VERSION"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/lib/systemd/system" \
         "$STAGE/usr/share/doc/appblocker"
mkdir -p "$DIST"

# --- control + maintainer scripts ------------------------------------------
install -m 644 "$META/control"  "$STAGE/DEBIAN/control"
install -m 755 "$META/postinst" "$STAGE/DEBIAN/postinst"
install -m 755 "$META/prerm"    "$STAGE/DEBIAN/prerm"
install -m 755 "$META/postrm"   "$STAGE/DEBIAN/postrm"

# --- program + launchers ---------------------------------------------------
install -m 755 "$ROOT/appblocker.py"            "$STAGE/usr/bin/appblocker"
install -m 755 "$ROOT/packaging/appblocker-admin" "$STAGE/usr/bin/appblocker-admin"
install -m 644 "$ROOT/packaging/appblocker.desktop" \
    "$STAGE/usr/share/applications/appblocker.desktop"
install -m 644 "$ROOT/appblocker.service" \
    "$STAGE/usr/lib/systemd/system/appblocker.service"

# --- docs ------------------------------------------------------------------
install -m 644 "$ROOT/README.md" "$STAGE/usr/share/doc/appblocker/README.md"

# dpkg likes a non-world-writable tree owned by root; --root-owner-group makes
# the archive record root:root without needing fakeroot.
OUT="$DIST/appblocker_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"

echo
echo "Built: $OUT"
echo "Install with:  sudo apt install $OUT"
