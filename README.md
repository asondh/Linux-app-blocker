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
- **Auto-block rules** — *"while my child is running app X, automatically block
  apps Y and Z for them."* Pick a trigger app and the apps to disable while it
  runs; the block applies only to the user actually running the trigger and
  lifts a few seconds after they close it. Manage these under
  **⛓ Auto-Block Rules** in the admin window.
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

## Recommended: install as a Debian package (.deb)

On Debian/Ubuntu/Mint/Pop!_OS this is the "install it like a normal app" route —
`apt` pulls in the prerequisites (`python3-tk`, `polkit`) for you and turns on
the background service automatically, so there is **no manual setup**:

```bash
./build-deb.sh                                    # builds dist/appblocker_<ver>_all.deb
sudo apt install ./dist/appblocker_0.2.0_all.deb  # installs + auto-resolves deps
```

Building the `.deb` only needs `dpkg-deb` (already on every Debian system) and
no root. Want a prebuilt `.deb` to just download and double-click? Ask and I'll
attach one to a GitHub release.

Remove it like any package: `sudo apt remove appblocker` (add `--purge` to also
delete `/etc/appblocker`).

## Alternative: shell installer (any systemd distro)

If you are not on a Debian-based distro, install the prerequisites yourself and
run the shell installer:

```bash
sudo apt install python3 python3-tk policykit-1   # Debian/Ubuntu
# Fedora: sudo dnf install python3 python3-tkinter polkit
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

## Blocking web apps (PWAs) and custom programs

Click **➕ Add App**. You get two ways to identify an app:

- **An installed program** — browse to its file. It's matched by its process
  name (and the built-in browsers already know their real process names, e.g.
  Brave runs as `brave`, Chrome as `chrome`).
- **A web app / PWA, or a custom command** — a PWA on the desktop is really your
  browser opened with a web address, so it has no program of its own. Paste the
  web address (e.g. `app.roblox.com`) and AppBlocker blocks any browser window
  launched for that address — without blocking the rest of the browser.

## Troubleshooting: "it didn't block anything"

The blocker kills a program by its *running* process name. If a custom app
isn't being blocked, find its real name while it's open:

```bash
ps -eo comm,args | grep -i <part-of-the-name>
```

Use the name shown in the first column when adding the app. (The four built-in
browsers are already configured correctly.) To confirm the background service
is running: `systemctl status appblocker`.

## Blocking websites

In the admin window, click **🌐 Block Websites** and enter one domain per line
(e.g. `youtube.com`). They're blocked in **every browser, for everyone on the
machine**, by adding entries to `/etc/hosts`. This is a blocklist: the sites you
list are blocked, everything else works.

Notes and limits:

- It is **machine-wide**, not per-user (the hosts file is global).
- It's a blocklist only. "Allow only these, block everything else" needs
  DNS-level control and isn't included yet.
- A browser set to use **secure DNS (DoH)** or a **VPN** can bypass it.
- Only the four built-in browsers' real process names are auto-known; website
  blocks work in all of them.
- Emergency off switch (from a terminal): `sudo appblocker --web-clear`
  removes every AppBlocker entry from `/etc/hosts`. `appblocker --web-status`
  lists what's blocked. Uninstalling the package also clears them.

## Auto-block rules (conditional blocking)

Open **⛓ Auto-Block Rules** and click **Add Rule**:

1. **Trigger app** — when this app is running (e.g. *Steam*)…
2. **Apps to block** — …these get disabled (e.g. *Firefox*, *Chrome*)…
3. **Users** (system mode) — …for the user(s) running the trigger.

The daemon checks every few seconds: as soon as a targeted child launches the
trigger, the chosen apps are killed for *that* child only (other users are
unaffected). When they quit the trigger, the targets are allowed again. Rules
can be toggled on/off or deleted (both require the parent password). This is
stored in `blocked.json` next to your other settings.

## Files

- `appblocker.py` — the whole app (GUI **and** `--daemon`/`--system` modes).
- `appblocker.service` — systemd unit for the root enforcement daemon.
- `build-deb.sh` — builds the `.deb` package into `dist/`.
- `packaging/` — Debian control file, maintainer scripts, and shared launchers.
- `install.sh` / `uninstall.sh` — shell installer for non-Debian systemd distros.
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
