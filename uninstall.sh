#!/usr/bin/env bash
#
# Remove a system-wide AppBlocker installation (see install.sh).
# By default the config in /etc/appblocker is kept; pass --purge to delete it.
#
# Usage:  sudo ./uninstall.sh [--purge]
#
set -euo pipefail

BIN=/usr/local/bin
APPS=/usr/share/applications
UNIT=/etc/systemd/system/appblocker.service
CFG=/etc/appblocker
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "This uninstaller needs root. Re-run with:  sudo ./uninstall.sh" >&2
    exit 1
fi

echo "==> Stopping and disabling the service"
systemctl disable --now appblocker.service 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing installed files"
rm -f "$BIN/appblocker" "$BIN/appblocker-admin" "$APPS/appblocker.desktop"

if [ "$PURGE" -eq 1 ]; then
    echo "==> Purging config $CFG"
    rm -rf "$CFG"
else
    echo "==> Keeping config in $CFG (use --purge to delete it)"
fi

echo "Done. AppBlocker has been removed."
