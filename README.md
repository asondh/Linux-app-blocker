# AppBlocker

A simple, parent-friendly desktop app for Linux that blocks applications
(especially web browsers) for a configurable amount of time. No `sudo` required.

## Features

- **Tkinter GUI** — uses only the Python standard library + `tkinter`.
- **Password protected** — a parent password (SHA-256 hashed) gates the app and
  every unblock action. Set on first run.
- **Pre-populated browsers** — Firefox, Chromium, Google Chrome, and Brave are
  auto-detected via `which`, showing name, executable path, and status.
- **Add custom apps** — browse for or type any executable path.
- **No-sudo blocking** — a background monitor thread scans `/proc` every few
  seconds and kills any process matching a blocked app, so a launched browser is
  closed within a few seconds.
- **Timer mode** — block for N minutes with a live countdown; auto-unblocks when
  the timer expires.
- **Manual mode** — stays blocked until the parent authenticates and unblocks.
- **Red/green status** and a **Quick Block: Browsers** shortcut.
- **System tray icon** (lock/unlock status) when `pystray` + `Pillow` are
  installed; otherwise it minimizes normally.
- **Persistent state** in `~/.appblocker/` so blocking survives restarts.

## Requirements

- Python 3 with `tkinter` (Debian/Ubuntu: `sudo apt install python3-tk`).
- Optional tray: `pip install pystray Pillow`.

## Install & run

```bash
# Put the app in your home folder (the .desktop launcher expects it there):
cp appblocker.py ~/appblocker.py
python3 ~/appblocker.py
```

### Desktop launcher

```bash
cp AppBlocker.desktop ~/Desktop/
chmod +x ~/Desktop/AppBlocker.desktop
# Double-click it (you may need to "Allow Launching" the first time).
```

If you keep `appblocker.py` somewhere other than your home folder, edit the
`Exec=` line in `AppBlocker.desktop` accordingly.

## State files (`~/.appblocker/`)

- `config.json` — the SHA-256 password hash.
- `blocked.json` — the app list and current block/timer state.

## Notes

This is a deterrent for kids, not a hardened security boundary: it relies on the
monitor process running, and a knowledgeable user with the same login could stop
it. Keep AppBlocker running (minimized/tray) while blocking is active.
