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

## Website-visit monitoring & alerts

Open **📊 Activity** (admin window). Browsing history is **recorded
automatically** whenever the machine is on — the daemon reads each user's
**browser history** (Firefox / Chrome / Chromium / Brave). The window pulls the
latest data as soon as you open it, and you can filter by **user, date range,
and site**, with an approximate **time-per-site** summary — so you skim a table,
not a wall of text. (No master switch to remember; recording is always on.)

Click **🔔 Alerts & Email** to:

- **Watch specific sites** — get alerted the moment any user visits one.
- **Email alerts** — enter an SMTP account (e.g. Gmail `smtp.gmail.com`, port
  587, with an **app password**) and use **Send test email** to confirm it
  works. Alerts then arrive in your inbox within seconds of a visit.

Honest limits:

- It reads browser history, so **incognito/private windows and cleared history
  are not captured.** (v0.7.0 adds a lockdown to disable incognito and block
  history deletion — closing this gap.)
- **Time-on-site is approximate** (estimated from the gaps between visits).
- It is **not** affected by secure-DNS/VPN — the browser records its own
  history regardless.

**Searches** — the Activity window shows a **Searches** table that pulls the
query out of search URLs (Google, YouTube, Bing, Amazon, etc.), and you can
**alert on search keywords**: under 🔔 Alerts & Email, list words (e.g.
self-harm terms) and get emailed when any user's search matches.

**Filters** — filter the log by **user**, a **custom date range** (From/To;
blank = all time), and **site**. **Quiet hours** mute alert emails overnight,
and alerts can go to **multiple recipients** (comma-separate the addresses).

Useful from a terminal: `sudo appblocker --email-test` (send a test alert) and
`sudo appblocker --import-history` (import history once now).

## Remote dashboard (view activity from your phone)

You can view the activity from anywhere — no logging into the monitored machine.
The machine pushes the data to a **private** GitHub repo, and a static dashboard
page (`docs/index.html`) reads it **with your own token**, so the data is never
public.

**One-time setup:**

1. **Create a private repo** for the data, e.g. `you/appblocker-data` (empty is
   fine).
2. **Make two fine-grained GitHub tokens** (GitHub → Settings → Developer
   settings → Fine-grained tokens), each limited to that one repo:
   - a **write** token (Contents: Read and write) — for the machine, and
   - a **read** token (Contents: Read-only) — for the dashboard page.
3. In AppBlocker → **📊 Activity → ☁ Remote Dashboard**, tick *Enable*, enter
   the repo (`you/appblocker-data`) and the **write** token, then **Sync now**
   to confirm it pushes `data.json`.
4. **Host the dashboard page.** Put `docs/index.html` on **GitHub Pages**
   (repo → Settings → Pages → source = `/docs`). It contains no data, so it's
   fine for it to be public. *(GitHub Pages from a private repo needs a paid
   plan — if your data repo is private and on the free plan, just put this one
   HTML file in a small public repo and enable Pages there.)*
5. **Open the Pages URL** on your phone/PC, enter the data repo + your **read**
   token once (saved in that browser), and **bookmark it**.

It refreshes on demand (the page's Refresh button, or **Sync now** on the
machine) and **opportunistically** on a timer whenever the machine is on — same
idea as the email digests. Terminal helper: `sudo appblocker --sync-now`.

The dashboard has filterable tables (by user / date range / site) for **visits**,
**searches**, and **time-per-site**. Everything stays private to your GitHub
account and your browser; keep the tokens secret (both are revocable anytime).

## Blocked-attempt alerts, digests, tamper alerts, adult blocklist

- **Blocked-attempt log & alerts** — every time a child tries to open a blocked
  app, it's logged (see the **Blocked-app attempts** table in 📊 Activity and on
  the dashboard) and, if enabled in 🔔 Alerts & Email, you get an email:
  *"Sam tried to open Brave at 3:12pm."*
- **Daily summary email (digest)** — in 🔔 Alerts & Email, tick *"Email me a
  summary every N hours"*. It's **opportunistic**: it sends the next time the
  machine is online after the interval elapses (not tied to a fixed clock time),
  so a machine that's only on briefly still sends it.
- **Tamper / "monitoring was off" alert** — if the service was stopped or the
  machine was off for more than ~15 minutes, you get an email when it comes back
  (*"AppBlocker was not running from … to …"*), so blocking/monitoring can't be
  quietly disabled without you knowing.
- **One-toggle adult-content blocklist** — in 🌐 Block Websites, tick *"Also
  block a built-in adult-content list"* to merge a curated set of well-known
  adult domains into the website blocking. (Starter list — pair with a family
  DNS filter for comprehensive coverage.)

> Note on timing: watched-site/keyword and blocked-attempt **alerts are not tied
> to the digest** — they're sent the next time the machine is online (and
> immediately on boot), because the browser saves history to disk, so a visit
> made just before logging off or shutting down is still caught.

## Browser lockdown (disable incognito)

Click **🔒 Lockdown** (admin window) → *"Disable private/incognito browsing and
block clearing of history."* This writes each browser's official **managed
policy** (as root) so:

- **Incognito/private browsing is turned off** in Chrome, Chromium, Brave and
  Firefox, and
- **history deletion is blocked** in Chrome/Chromium/Brave.

It applies to all users, takes effect after a browser restart, and **can't be
undone by a child** without your admin password. This makes the Activity
monitoring reliable — browsing can't be hidden with incognito or a history
wipe. Emergency off switch: `sudo appblocker --lockdown-clear` (uninstalling
also clears it). Only policy files AppBlocker created are ever touched.

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

A rule can **also block websites while the trigger runs** — fill in the
"…and block these websites" field (e.g. `youtube.com, tiktok.com`). Those sites
are blocked (machine-wide, via `/etc/hosts`) only while the trigger app/PWA is
running, and unblocked again when it closes. Example: *while the homework PWA is
open, block YouTube.* (Website blocks can't be scoped to one user, since the
hosts file is global.)

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
