#!/usr/bin/env bash
#
# AppBlocker system-wide installer.
#
# Installs AppBlocker so that:
#   * a root daemon (systemd service) enforces a shared blocklist for ALL
#     users on the machine — starts on boot, no commands needed to run it;
#   * the admin GUI is available from the applications menu (and as the
#     `appblocker-admin` command), launching with a graphical password prompt
#     via pkexec so children cannot open it.
#
# Usage:  sudo ./install.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/usr/local/bin
APPS=/usr/share/applications
UNIT=/etc/systemd/system/appblocker.service
CFG=/etc/appblocker

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer needs root. Re-run with:  sudo ./install.sh" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required but was not found." >&2
    exit 1
fi

echo "==> Installing the appblocker program to $BIN/appblocker"
install -Dm755 "$SCRIPT_DIR/appblocker.py" "$BIN/appblocker"

echo "==> Installing the admin launcher to $BIN/appblocker-admin"
# Wrapper that opens the system-wide GUI as root with a graphical auth prompt.
cat > "$BIN/appblocker-admin" <<'EOF'
#!/bin/sh
# Launch the AppBlocker admin GUI as root via a graphical polkit prompt.
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec env DISPLAY="$DISPLAY" \
        XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        /usr/local/bin/appblocker --system "$@"
else
    # Fallback for systems without polkit: prompt in a terminal.
    exec sudo /usr/local/bin/appblocker --system "$@"
fi
EOF
chmod 755 "$BIN/appblocker-admin"

echo "==> Creating root-only config directory $CFG"
mkdir -p "$CFG"
chmod 711 "$CFG"   # children can't list/read the password hash or blocklist

echo "==> Installing application menu entry"
cat > "$APPS/appblocker.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Version=1.0
Name=AppBlocker (Admin)
GenericName=Application Blocker
Comment=Block apps and browsers for all users, with timers and schedules
Exec=appblocker-admin
Icon=security-high
Terminal=false
Categories=Utility;System;Security;
StartupNotify=true
Keywords=block;parental;control;timer;schedule;browser;
EOF
chmod 644 "$APPS/appblocker.desktop"

echo "==> Installing and starting the background service"
install -Dm644 "$SCRIPT_DIR/appblocker.service" "$UNIT"
# The shipped unit points ExecStart at /usr/bin/appblocker (the .deb path);
# this manual installer puts the program in $BIN, so rewrite it to match or the
# service would fail to exec (systemd status 203/EXEC).
sed -i "s#^ExecStart=.*#ExecStart=$BIN/appblocker --daemon#" "$UNIT"
systemctl daemon-reload
systemctl enable --now appblocker.service

echo
echo "AppBlocker is installed and the enforcement service is running."
echo
echo "  • The background blocker starts automatically on every boot — no"
echo "    command is ever needed to keep it running."
echo "  • Open \"AppBlocker (Admin)\" from your applications menu (or run"
echo "    'appblocker-admin') to set blocks, schedules, and target users."
echo "  • On first launch you'll set the parent password."
echo
echo "Service status:  systemctl status appblocker"
echo "Uninstall:       sudo ./uninstall.sh"
