# AppBlocker

A parent-friendly Linux app that blocks applications (especially browsers) for
your kids — with **timers**, **weekly schedules**, **per-user targeting**, and a
**block-until-unblocked** mode. Pure Python standard library + `tkinter`.

It runs in two ways:

| | **User mode** (default) | **System mode** (recommended for admins) |
|---|---|---|
| Who it blocks | Only the logged-in user | Any users you choose, across the whole machine |
| Enforced by | A monitor inside the GUI | A root **systemd service** (always on, starts at boot) |
| Config location | `~/.appblocker/` (user-writable) | `/etc/appblocker/` (root-only — kids can't edit it) |
| Can a child disable it? | Yes (runs under their login) | No (needs your admin password) |
| Setup | Copy one file | `sudo ./install.sh` once |

## Features

- **Pre-populated browsers** — Firefox, Chromium, Google Chrome, Brave, auto
  detected via `which`. Add any custom app by path.
- **Block modes** (per app):
  - **Manual** — blocked until you unblock it.
  - **Timer** — blocked for N minutes, then auto-unblocks (live countdown).
  - **Schedule** — blocked **during** weekly day/time windows (e.g. school
    hours `Mon–Fri 08:00–15:00`, bedtime `21:00–07:00`). Overnight windows are
    supported.
- **Per-user targeting** (system mode) — choose exactly which children a block
  applies to, or "All users".
- **No-sudo blocking mechanism** — a monitor scans `/proc` and kills any blocked
  process within a few seconds. As root (system mode) it can enforce across all
  users; as a normal user it covers your own session.
- **Password protected** — SHA-256 hash; unblocking and settings need it.
- **Red / amber / green** status (blocked now / scheduled / free), a
  **Quick Block: Browsers** shortcut, and an optional **system tray** icon
  (`pystray` + `Pillow`).

## Quick start (per-user, no install)

```bash
sudo apt install python3-tk        # tkinter (Debian/Ubuntu); Fedora: python3-tkinter
cp appblocker.py ~/appblocker.py
python3 ~/appblocker.py
```

Or copy `AppBlocker.desktop` to `~/Desktop` and double-click it.

## Recommended: system-wide install (runs as an executable, no commands)

This is the answer to *"I don't want to run special commands"* and *"manage all
my children's accounts at once"*:

```bash
sudo ./install.sh
```

That installs everything and **starts a background service that runs on every
boot by itself** — you never type a command to keep blocking active. It also
adds:

- **AppBlocker (Admin)** in your applications menu — just click it. It opens
  with a graphical password prompt (via `pkexec`), so children can't open it.
- An `appblocker` executable on your `PATH` and an `appblocker-admin` launcher.

On first launch you set the parent password. Then pick a browser → **Block** →
choose **Manual / Timer / Schedule**, the **users** it applies to, and you're
done. Changes take effect within a few seconds; you can even close the window —
the root service keeps enforcing.

Uninstall any time:

```bash
sudo ./uninstall.sh            # keeps your config
sudo ./uninstall.sh --purge    # also removes /etc/appblocker
```

> Want a single self-contained binary with no Python at all? You can optionally
> build one with [PyInstaller](https://pyinstaller.org):
> `pip install pyinstaller && pyinstaller --onefile appblocker.py` →
> `dist/appblocker`. The systemd install above already gives you a no-command
> experience without needing this.

## Files

- `appblocker.py` — the whole app (GUI **and** `--daemon`/`--system` modes).
- `appblocker.service` — systemd unit for the root enforcement daemon.
- `install.sh` / `uninstall.sh` — system-wide install/removal.
- `AppBlocker.desktop` — simple double-click launcher for the no-install case.

## Run modes

```bash
appblocker            # user-mode GUI (or system-mode GUI automatically if root)
appblocker --system   # force system-mode GUI (edits /etc/appblocker)
appblocker --daemon   # headless root enforcement loop (used by systemd)
```

## State files

- User mode: `~/.appblocker/config.json` (password) and `blocked.json` (rules).
- System mode: `/etc/appblocker/config.json` and `blocked.json` (root-only).

## Requirements

- Python 3 with `tkinter` for the GUI (`python3-tk` / `python3-tkinter`).
  The `--daemon` does **not** need tkinter.
- Optional tray: `pip install pystray Pillow`.
- System mode uses `systemd` and (for the graphical admin prompt) `pkexec`.

## Note on security

This is a strong *deterrent*, and in system mode it is enforced by a root
service that children cannot stop or reconfigure without your password. It is
not, however, a kernel-level sandbox: a determined user with their own root
access could still interfere. For household parental control it does the job.
