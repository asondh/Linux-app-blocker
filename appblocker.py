#!/usr/bin/env python3
"""
AppBlocker — a parent-friendly Linux desktop app to block applications
(especially web browsers) for a configurable amount of time.

Design goals:
  * Pure Python standard library + tkinter (no required third-party deps).
  * Two modes of operation:
      - User mode (default): a per-user GUI that blocks apps for the logged-in
        user only. State in ~/.appblocker/. No sudo required, but a tech-savvy
        child can stop it because it runs under their own login.
      - System mode (admin): a single root-owned daemon enforces a shared
        blocklist in /etc/appblocker/ for EVERY user on the machine, and the
        GUI (run as root via the installer/pkexec) edits that shared blocklist.
        Children cannot read or edit the root-only config, and cannot stop the
        systemd-managed daemon without the admin password.
  * Password protected (SHA-256 hash stored alongside the blocklist).
  * Optional system tray icon if pystray + Pillow are installed.

Run modes:
    appblocker.py            # user-mode GUI (or system-mode GUI if run as root)
    appblocker.py --system   # force system-mode GUI (edits /etc/appblocker)
    appblocker.py --daemon   # headless root daemon (used by the systemd unit)

State directories:
    user mode   -> ~/.appblocker/
    system mode -> /etc/appblocker/

Author: AppBlocker
License: MIT
"""

import os
import sys
import json
import time
import signal
import hashlib
import glob
import ssl
import shutil
import sqlite3
import smtplib
import argparse
import tempfile
import threading
import subprocess
from email.message import EmailMessage
from urllib.parse import urlparse, parse_qs

# tkinter is only needed for the GUI. The root daemon (--daemon) runs headless,
# possibly on a machine without python3-tk, so import it lazily/guarded.
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
    HAS_TK = True
except Exception:  # pragma: no cover - GUI unavailable (e.g. headless daemon)
    HAS_TK = False

# --------------------------------------------------------------------------- #
# Optional system-tray support (pystray + Pillow). Degrades gracefully.
# --------------------------------------------------------------------------- #
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except Exception:  # pragma: no cover - tray is optional
    HAS_TRAY = False


# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #
USER_APP_DIR = os.path.join(os.path.expanduser("~"), ".appblocker")
SYSTEM_APP_DIR = "/etc/appblocker"

# These are set by configure_paths() before anything touches the filesystem.
SYSTEM_MODE = False
APP_DIR = USER_APP_DIR
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
BLOCKED_FILE = os.path.join(APP_DIR, "blocked.json")


def configure_paths(system_mode: bool):
    """Point the global state paths at either the per-user or system dir."""
    global SYSTEM_MODE, APP_DIR, CONFIG_FILE, BLOCKED_FILE
    SYSTEM_MODE = system_mode
    APP_DIR = SYSTEM_APP_DIR if system_mode else USER_APP_DIR
    CONFIG_FILE = os.path.join(APP_DIR, "config.json")
    BLOCKED_FILE = os.path.join(APP_DIR, "blocked.json")


MONITOR_INTERVAL = 5  # seconds between kill sweeps

COLOR_BLOCKED = "#c0392b"   # red — blocked right now
COLOR_ACTIVE = "#27ae60"    # green — free
COLOR_SCHEDULE = "#e67e22"  # orange — scheduled but not currently in a window
COLOR_BG = "#f4f6f7"
COLOR_HEADER = "#2c3e50"
COLOR_ACCENT = "#2980b9"

# Default browsers to pre-populate. For each: (display name, candidate launcher
# names to locate with `which`, runtime process names to actually match).
# The launcher name is often NOT the running process name — e.g. the
# "brave-browser" launcher runs a process called "brave", and "google-chrome"
# runs "chrome" — so we must match the real process names.
DEFAULT_APPS = [
    ("Firefox", ["firefox", "firefox-esr"], ["firefox", "firefox-esr"]),
    ("Chromium", ["chromium", "chromium-browser"],
     ["chromium", "chromium-browse", "chromium-browser"]),
    ("Google Chrome", ["google-chrome", "google-chrome-stable", "chrome"],
     ["chrome", "google-chrome"]),
    ("Brave", ["brave-browser", "brave", "brave-browser-stable"],
     ["brave", "brave-browser"]),
]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def ensure_app_dir():
    os.makedirs(APP_DIR, exist_ok=True)
    if SYSTEM_MODE:
        # In system mode the config must be readable/writable by root only so
        # children cannot inspect the password hash or edit the blocklist.
        # World-execute (0711) lets the daemon traverse but not list/read.
        try:
            os.chmod(APP_DIR, 0o711)
        except PermissionError:
            pass


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def which(name: str):
    """Return the resolved path of an executable using `which`, else None."""
    try:
        out = subprocess.run(
            ["which", name],
            capture_output=True, text=True, timeout=5,
        )
        path = out.stdout.strip()
        if out.returncode == 0 and path:
            return path
    except Exception:
        pass
    return None


def detect_executable(candidates):
    """Given candidate names, return (path, basename) of the first found."""
    for cand in candidates:
        path = which(cand)
        if path:
            return path, os.path.basename(path)
    # Nothing found — report the first candidate name as the expected one.
    return None, candidates[0]


def load_json(path, default):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path, data):
    ensure_app_dir()
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    if SYSTEM_MODE:
        # config.json holds the password hash — keep it root-only (0600).
        try:
            os.chmod(tmp, 0o600)
        except PermissionError:
            pass
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Users, schedules, and "is this app blocked right now" logic.
# These are shared by both the GUI and the headless daemon so they always
# agree on what "blocked" means.
# --------------------------------------------------------------------------- #
import pwd  # stdlib; safe on all Linux

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]  # 0=Mon (tm_wday)

# Login shells that mean "this is not an interactive human account".
_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/sync", ""}


def list_human_users():
    """
    Return a sorted list of (username, uid) for real human login accounts:
    UID in [1000, 60000) with a genuine login shell. Excludes system/service
    accounts. The invoking user is always included.
    """
    users = {}
    try:
        for p in pwd.getpwall():
            if 1000 <= p.pw_uid < 60000 and p.pw_shell not in _NOLOGIN_SHELLS:
                users[p.pw_name] = p.pw_uid
    except Exception:
        pass
    # Always include whoever is running us (covers unusual UID setups).
    try:
        me = pwd.getpwuid(os.getuid())
        users.setdefault(me.pw_name, me.pw_uid)
    except Exception:
        pass
    return sorted(users.items(), key=lambda kv: kv[0].lower())


def usernames_to_uids(names):
    """Map a list of usernames to a set of UIDs, skipping unknown names."""
    uids = set()
    for name in names:
        try:
            uids.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            pass
    return uids


def _parse_hhmm(text):
    """'HH:MM' -> minutes since midnight, or None if malformed."""
    try:
        hh, mm = text.strip().split(":")
        return int(hh) * 60 + int(mm)
    except Exception:
        return None


def schedule_active(schedule, now=None):
    """
    True if the current local time falls inside any window of `schedule`.

    A window is {"days": [0..6], "start": "HH:MM", "end": "HH:MM"} where 0=Mon.
    Windows where end <= start are treated as spanning midnight (e.g. a
    21:00-07:00 bedtime block covers late evening through early morning).
    """
    if not schedule:
        return False
    lt = now or time.localtime()
    cur = lt.tm_hour * 60 + lt.tm_min
    wday = lt.tm_wday  # 0 = Monday
    prev_wday = (wday - 1) % 7
    for win in schedule:
        days = win.get("days", [])
        start = _parse_hhmm(win.get("start", ""))
        end = _parse_hhmm(win.get("end", ""))
        if start is None or end is None:
            continue
        if start < end:
            if wday in days and start <= cur < end:
                return True
        else:
            # Overnight window: active late on its start day, and early on the
            # following day.
            if wday in days and cur >= start:
                return True
            if prev_wday in days and cur < end:
                return True
    return False


def schedule_summary(schedule):
    """Human-friendly one-line description of a schedule."""
    if not schedule:
        return "no windows"
    parts = []
    for win in schedule:
        days = win.get("days", [])
        label = ",".join(DAY_NAMES[d] for d in sorted(days) if 0 <= d < 7)
        parts.append(f"{label or '—'} {win.get('start','?')}-{win.get('end','?')}")
    return "; ".join(parts)


def effective_blocked(app, now=None):
    """
    Whether `app` is blocked *right now*, independent of which user owns a
    process. Centralizes the three modes:
      manual   -> the stored on/off flag (block until unblocked)
      timer    -> the stored on/off flag (the monitor clears it on expiry)
      schedule -> whether the current time is inside a scheduled window
    """
    mode = app.get("mode", "manual")
    if mode == "schedule":
        return schedule_active(app.get("schedule") or [], now=now)
    return bool(app.get("blocked"))


def app_target_uids(app):
    """
    Set of UIDs this app's block applies to, or None for 'all users'.
    An empty target_users list means 'all users'.
    """
    names = app.get("target_users") or []
    if not names:
        return None
    return usernames_to_uids(names)


def app_target_label(app):
    names = app.get("target_users") or []
    if not names:
        return "All users"
    return ", ".join(names)


def app_match_terms(app):
    """The list of strings used to recognise this app's processes."""
    terms = app.get("match_terms")
    if terms:
        return [t for t in terms if t]
    pn = app.get("proc_name")
    return [pn] if pn else []


def _term_matches_process(term, comm, exe_base):
    """
    True if `term` identifies a process given its /proc 'comm' and the
    basename of its executable. Both comm and exe_base are lowercase.
    /proc comm is truncated to 15 chars, so compare truncated too.
    """
    t = term.lower()
    if not t:
        return False
    if comm == t or exe_base == t:
        return True
    # comm is capped at 15 chars by the kernel; match the truncated form.
    if len(t) > 15 and comm and comm == t[:15]:
        return True
    return False


def app_matches(app, comm, exe_base, cmdline):
    """
    Whether a process (lowercase comm, exe basename, full command line)
    matches `app`. Two match styles:
      * "process"     -> the process/executable name equals a term
      * "commandline" -> a term appears anywhere in the command line
                         (used for PWAs and custom launch commands)
    """
    terms = app_match_terms(app)
    if app.get("match_type") == "commandline":
        return any(t.lower() in cmdline for t in terms)
    return any(_term_matches_process(t, comm, exe_base) for t in terms)


# --------------------------------------------------------------------------- #
# Website blocking (machine-wide, via /etc/hosts).
# Blocked domains are written into a clearly-marked, self-contained block so we
# never disturb the rest of the file. Requires root (system mode).
# --------------------------------------------------------------------------- #
HOSTS_FILE = "/etc/hosts"
HOSTS_BEGIN = "# >>> AppBlocker blocked websites (managed — do not edit) >>>"
HOSTS_END = "# <<< AppBlocker blocked websites <<<"
SINKHOLE = "0.0.0.0"


def normalize_domain(text):
    """Reduce user input to a bare domain: strip scheme, path, and leading www."""
    d = (text or "").strip().lower()
    for scheme in ("https://", "http://"):
        if d.startswith(scheme):
            d = d[len(scheme):]
    d = d.split("/")[0].split("?")[0].split("#")[0].strip()
    if d.startswith("www."):
        d = d[4:]
    return d


def _build_hosts_block(domains):
    lines = [HOSTS_BEGIN]
    seen = set()
    for raw in domains:
        d = normalize_domain(raw)
        if not d or d in seen:
            continue
        seen.add(d)
        lines.append(f"{SINKHOLE} {d}")
        lines.append(f"{SINKHOLE} www.{d}")
    lines.append(HOSTS_END)
    return "\n".join(lines) + "\n"


def _strip_managed_block(content):
    """Return /etc/hosts content with any existing AppBlocker block removed."""
    if HOSTS_BEGIN in content and HOSTS_END in content:
        pre = content.split(HOSTS_BEGIN)[0]
        post = content.split(HOSTS_END, 1)[1]
        return pre.rstrip("\n") + "\n" + post.lstrip("\n")
    return content


ADULT_LIST_PATHS = [
    "/usr/share/appblocker/adult-domains.txt",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "packaging", "adult-domains.txt"),
]
_ADULT_CACHE = None


def load_adult_domains():
    """Load the bundled adult-content blocklist (cached). Returns a set."""
    global _ADULT_CACHE
    if _ADULT_CACHE is not None:
        return _ADULT_CACHE
    domains = set()
    for path in ADULT_LIST_PATHS:
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        d = normalize_domain(line)
                        if d:
                            domains.add(d)
            break
        except OSError:
            continue
    _ADULT_CACHE = domains
    return domains


def sync_blocked_websites(domains):
    """
    Make /etc/hosts reflect `domains` (blocklist mode). Only the managed block
    is touched. Returns True if the file changed. Needs root; silently no-ops
    if it can't write.
    """
    try:
        with open(HOSTS_FILE, "r") as fh:
            content = fh.read()
    except Exception:
        return False
    base = _strip_managed_block(content)
    if domains:
        new = base.rstrip("\n") + "\n\n" + _build_hosts_block(domains)
    else:
        new = base.rstrip("\n") + "\n"
    if new == content:
        return False
    try:
        tmp = HOSTS_FILE + ".appblocker.tmp"
        with open(tmp, "w") as fh:
            fh.write(new)
        os.chmod(tmp, 0o644)
        os.replace(tmp, HOSTS_FILE)
        return True
    except Exception as exc:
        sys.stderr.write(f"[websites] could not update {HOSTS_FILE}: {exc}\n")
        return False


# --------------------------------------------------------------------------- #
# Browser lockdown — disable private/incognito browsing and (Chromium) block
# history deletion, via each browser's managed-policy mechanism. Root only.
# --------------------------------------------------------------------------- #
POLICY_BASE = "/"                    # overridable in tests
POLICY_MARKER = "appblocker"
CHROMIUM_POLICY_DIRS = {
    "chrome": "etc/opt/chrome/policies/managed",
    "chromium": "etc/chromium/policies/managed",
    "brave": "etc/brave/policies/managed",
}
FIREFOX_POLICY_REL = "etc/firefox/policies"
_BROWSER_CMDS = {
    "chrome": ["google-chrome", "google-chrome-stable", "chrome"],
    "chromium": ["chromium", "chromium-browser"],
    "brave": ["brave-browser", "brave", "brave-browser-stable"],
    "firefox": ["firefox", "firefox-esr"],
}
# Flatpak app ids for the same browsers. Flatpak browsers aren't on PATH and
# run sandboxed, so they need separate detection and a filesystem override to
# see the host managed-policy directory.
_FLATPAK_IDS = {
    "chrome": "com.google.Chrome",
    "chromium": "org.chromium.Chromium",
    "brave": "com.brave.Browser",
    "firefox": "org.mozilla.firefox",
}


def _browser_installed(key):
    return any(which(n) for n in _BROWSER_CMDS.get(key, []))


def _flatpak_installed(app_id):
    if not which("flatpak"):
        return False
    try:
        return subprocess.run(["flatpak", "info", app_id],
                              capture_output=True, timeout=8).returncode == 0
    except Exception:
        return False


_FLATPAK_OVERRIDE_STATE = {}   # app_id -> last-applied enable flag (per process)


def _flatpak_policy_access(app_id, host_policy_dir, enable):
    """Grant/revoke a Flatpak browser read access to a host policy directory.

    Sandboxed browsers can't see /etc/<browser>/policies, so managed policies
    are ignored until we expose that directory into the sandbox. Applied once
    per state per run (the lockdown sweep calls this every few seconds, but the
    flatpak override is persistent, so we don't need to re-run it each time).
    """
    if not which("flatpak"):
        return
    if _FLATPAK_OVERRIDE_STATE.get(app_id) == bool(enable):
        return
    arg = (f"--filesystem={host_policy_dir}:ro" if enable
           else f"--nofilesystem={host_policy_dir}")
    try:
        subprocess.run(["flatpak", "override", "--system", arg, app_id],
                       capture_output=True, timeout=15)
        _FLATPAK_OVERRIDE_STATE[app_id] = bool(enable)
    except Exception as exc:
        sys.stderr.write(f"[lockdown] flatpak override {app_id}: {exc}\n")


def _write_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def _file_is_ours(path):
    try:
        with open(path) as fh:
            return json.load(fh).get("_managed_by") == POLICY_MARKER
    except Exception:
        return False


def apply_browser_lockdown(enabled):
    """
    Enable/disable the incognito + history-deletion lockdown by writing (or
    removing) managed-policy files for each installed browser. Only files we
    created (marked) are ever removed or overwritten. Returns changed paths.
    """
    changed = []
    chromium_policy = {
        "IncognitoModeAvailability": 1,      # 1 = incognito disabled
        "AllowDeletingBrowserHistory": False,
        "_managed_by": POLICY_MARKER,
    }
    for key, rel in CHROMIUM_POLICY_DIRS.items():
        path = os.path.join(POLICY_BASE, rel, "appblocker.json")
        fp_id = _FLATPAK_IDS.get(key)
        is_flatpak = bool(fp_id) and _flatpak_installed(fp_id)
        want = enabled and (_browser_installed(key) or is_flatpak)
        try:
            if want:
                if not (os.path.exists(path) and _file_is_ours(path) and
                        json.load(open(path)) == chromium_policy):
                    _write_json_file(path, chromium_policy)
                    changed.append(path)
            elif os.path.exists(path) and _file_is_ours(path):
                os.remove(path)
                changed.append(path)
        except Exception as exc:
            sys.stderr.write(f"[lockdown] {path}: {exc}\n")

    # Firefox reads policies.json from the system dir (/etc/firefox/policies)
    # AND from a 'distribution' folder next to the program binary. Some builds
    # (e.g. the newer XDG-dirs Firefox) honour only the latter, so we write
    # both. Only files we created (marked) are ever removed or overwritten.
    ff_policy = {"policies": {"DisablePrivateBrowsing": True},
                 "_managed_by": POLICY_MARKER}
    ff_paths = [os.path.join(POLICY_BASE, FIREFOX_POLICY_REL, "policies.json")]
    for progdir in _firefox_program_dirs():
        ff_paths.append(os.path.join(progdir, "distribution", "policies.json"))
    ff_flatpak = _flatpak_installed(_FLATPAK_IDS["firefox"])
    want = enabled and (_browser_installed("firefox") or ff_flatpak)
    for ff_path in ff_paths:
        try:
            exists = os.path.exists(ff_path)
            if want:
                if exists and _file_is_ours(ff_path) and \
                        json.load(open(ff_path)) == ff_policy:
                    pass  # already correct — leave it (keeps this idempotent)
                elif not exists or _file_is_ours(ff_path):
                    _write_json_file(ff_path, ff_policy)
                    changed.append(ff_path)
                else:
                    sys.stderr.write(
                        f"[lockdown] {ff_path} exists and is not ours; "
                        "leaving it alone.\n")
            elif exists and _file_is_ours(ff_path):
                os.remove(ff_path)
                changed.append(ff_path)
        except Exception as exc:
            sys.stderr.write(f"[lockdown] {ff_path}: {exc}\n")
    return changed


def apply_site_block_policy(domains):
    """Block `domains` INSIDE Chromium browsers (Brave/Chrome/Chromium) via the
    enterprise URLBlocklist managed policy.

    Unlike /etc/hosts this is enforced by the browser itself: it takes effect on
    already-open tabs within seconds (the browser reloads its policy files on
    change), it can't be bypassed by Secure DNS (DoH) or a VPN, and a child
    can't turn it off. /etc/hosts still runs alongside it to cover other apps.

    `domains` = the currently-effective blocked hosts. Only marked files are
    ever written/removed. Returns changed paths.
    """
    entries = sorted(set(d for d in domains if d))
    policy = {"URLBlocklist": entries, "_managed_by": POLICY_MARKER}
    changed = []
    for key, rel in CHROMIUM_POLICY_DIRS.items():
        path = os.path.join(POLICY_BASE, rel, "appblocker-sites.json")
        fp_id = _FLATPAK_IDS.get(key)
        is_flatpak = bool(fp_id) and _flatpak_installed(fp_id)
        want = bool(entries) and (_browser_installed(key) or is_flatpak)
        try:
            if want:
                if not (os.path.exists(path) and _file_is_ours(path) and
                        json.load(open(path)) == policy):
                    _write_json_file(path, policy)
                    changed.append(path)
            elif os.path.exists(path) and _file_is_ours(path):
                os.remove(path)
                changed.append(path)
        except Exception as exc:
            sys.stderr.write(f"[siteblock] {path}: {exc}\n")
    return changed


def sync_flatpak_policy_overrides(active):
    """Expose (or hide) the host policy dirs to Flatpak browsers so they can see
    the managed-policy files. Single owner of the override state, so the
    lockdown and site-block policies don't fight over it."""
    for key, rel in CHROMIUM_POLICY_DIRS.items():
        fp_id = _FLATPAK_IDS.get(key)
        if fp_id and _flatpak_installed(fp_id):
            _flatpak_policy_access(fp_id, "/" + os.path.dirname(rel), active)
    ff_id = _FLATPAK_IDS.get("firefox")
    if ff_id and _flatpak_installed(ff_id):
        _flatpak_policy_access(ff_id, "/" + FIREFOX_POLICY_REL, active)


def _firefox_program_dirs():
    """Directories that hold the Firefox binary (where it reads distribution/)."""
    dirs = set()
    for name in ("firefox", "firefox-esr"):
        p = which(name)
        if not p:
            continue
        try:
            real = os.path.realpath(p)
        except OSError:
            real = p
        d = os.path.dirname(real)
        # A wrapper in a generic bin dir isn't the program dir; skip it and
        # rely on the well-known candidates below.
        if d and d not in ("/usr/bin", "/bin", "/usr/local/bin", "/sbin"):
            dirs.add(d)
    for cand in ("/usr/lib/firefox", "/usr/lib/firefox-esr",
                 "/usr/lib64/firefox", "/opt/firefox"):
        if os.path.isdir(cand):
            dirs.add(cand)
    return dirs


# --------------------------------------------------------------------------- #
# Website-visit monitoring.
# Reads each user's browser history (Firefox / Chrome / Chromium / Brave),
# records visits into a small SQLite log, supports per-user/site/day queries
# with approximate time-on-site, and raises email alerts on watched sites.
# --------------------------------------------------------------------------- #
MONITOR_HISTORY_INTERVAL = 45     # seconds between history imports
VISIT_IDLE_CAP = 1800             # cap a single visit's duration at 30 min
ALERT_DEBOUNCE = 600              # don't re-alert same user+site within 10 min
ATTEMPT_DEBOUNCE = 300            # don't re-log same user+app block within 5 min
TAMPER_GAP = 900                  # a monitoring gap over 15 min = "was off"
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def history_db_path():
    return os.path.join(APP_DIR, "history.db")


def domain_of(url):
    """Bare domain from a URL (lowercased, no www), or '' for non-web URLs."""
    try:
        p = urlparse(url)
    except Exception:
        return ""
    if p.scheme not in ("http", "https"):
        return ""
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


# Query-string parameters that carry a user's search terms on common sites
# (Google/DuckDuckGo=q, YouTube=search_query, Yahoo=p, Amazon=k, eBay=_nkw, ...).
SEARCH_PARAMS = ("q", "search_query", "query", "search", "p", "k", "_nkw",
                 "wd", "text")


def extract_search_query(url):
    """Return the search terms embedded in a URL, or '' if it isn't a search."""
    try:
        p = urlparse(url)
    except Exception:
        return ""
    if p.scheme not in ("http", "https") or not p.query:
        return ""
    qs = parse_qs(p.query)
    for key in SEARCH_PARAMS:
        vals = qs.get(key)
        if vals and vals[0].strip():
            return vals[0].strip()
    return ""


# --------------------------------------------------------------------------- #
# New-domain novelty detection: alert when a child visits a domain they've
# never visited before, or haven't visited in the last X days. This is purely
# additive — it reads the same `visits` log that powers every existing metric
# and never changes how visits are recorded or queried.
# --------------------------------------------------------------------------- #
NEWDOM_ALERT_CAP = 40           # max real-time new-domain emails per day (anti-flood)

# Ultra-common domains never count as "new" — they'd be noise (a child loading
# Google, a CDN or an analytics beacon isn't a discovery). Matched against the
# bare domain and any subdomain of it.
NEWDOM_IGNORE = {
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "doubleclick.net", "youtube.com", "ytimg.com", "ggpht.com", "gvt1.com",
    "gvt2.com", "gmail.com", "bing.com", "bing.net", "microsoft.com",
    "live.com", "office.com", "windows.com", "msn.com", "apple.com",
    "icloud.com", "cloudflare.com", "cloudflareinsights.com", "cloudfront.net",
    "akamaihd.net", "akamai.net", "fbcdn.net", "facebook.com", "fbsbx.com",
    "instagram.com", "cdninstagram.com", "mozilla.com", "mozilla.org",
    "mozilla.net", "firefox.com", "duckduckgo.com", "wikipedia.org",
    "wikimedia.org", "jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
}


def _is_common_domain(dom):
    """True if `dom` is (a subdomain of) an ultra-common domain we never flag."""
    if not dom:
        return True
    for base in NEWDOM_IGNORE:
        if dom == base or dom.endswith("." + base):
            return True
    return False


def iter_history_sources(home):
    """
    Yield (browser_label, kind, db_path) for a user's home directory.
    kind is 'firefox' (places.sqlite) or 'chromium' (History).
    Covers apt, snap and flatpak install locations.
    """
    ff_bases = [
        f"{home}/.mozilla/firefox",
        f"{home}/.config/mozilla/firefox",   # newer XDG-dirs Firefox builds
        f"{home}/snap/firefox/common/.mozilla/firefox",
        f"{home}/.var/app/org.mozilla.firefox/.mozilla/firefox",
    ]
    for base in ff_bases:
        for db in glob.glob(f"{base}/*/places.sqlite"):
            yield ("firefox", "firefox", db)

    chromium = {
        "chrome": [f"{home}/.config/google-chrome"],
        "chromium": [
            f"{home}/.config/chromium",
            f"{home}/snap/chromium/common/chromium",
            f"{home}/.var/app/org.chromium.Chromium/config/chromium",
        ],
        "brave": [
            f"{home}/.config/BraveSoftware/Brave-Browser",
            f"{home}/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
        ],
    }
    for label, bases in chromium.items():
        for base in bases:
            for db in glob.glob(f"{base}/*/History"):
                yield (label, "chromium", db)


def _read_browser_history(kind, db_path, since_native):
    """
    Read visits newer than `since_native` (the browser's own time units).
    Returns (rows, max_native) where rows = [(epoch_seconds, url, title)].
    Copies the DB (and WAL/SHM) first so we can read it while the browser runs.
    """
    rows = []
    max_native = since_native
    tmpdir = tempfile.mkdtemp(prefix="appblocker-hist-")
    try:
        copy = os.path.join(tmpdir, "db")
        shutil.copyfile(db_path, copy)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                try:
                    shutil.copyfile(db_path + suffix, copy + suffix)
                except Exception:
                    pass
        conn = sqlite3.connect(copy)
        try:
            cur = conn.cursor()
            if kind == "firefox":
                cur.execute(
                    "SELECT v.visit_date, p.url, p.title "
                    "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place "
                    "WHERE v.visit_date > ? ORDER BY v.visit_date", (since_native,))
                for visit_date, url, title in cur.fetchall():
                    if visit_date is None:
                        continue
                    max_native = max(max_native, visit_date)
                    rows.append((visit_date / 1_000_000.0, url, title or ""))
            else:  # chromium family
                cur.execute(
                    "SELECT v.visit_time, u.url, u.title "
                    "FROM visits v JOIN urls u ON u.id = v.url "
                    "WHERE v.visit_time > ? ORDER BY v.visit_time", (since_native,))
                for visit_time, url, title in cur.fetchall():
                    if visit_time is None:
                        continue
                    max_native = max(max_native, visit_time)
                    epoch = visit_time / 1_000_000.0 - CHROME_EPOCH_OFFSET
                    rows.append((epoch, url, title or ""))
        finally:
            conn.close()
    except Exception as exc:
        sys.stderr.write(f"[monitor] read {db_path}: {exc}\n")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return rows, max_native


class HistoryStore:
    """SQLite-backed log of website visits, queried by the GUI viewer."""

    def __init__(self, path=None):
        self.path = path or history_db_path()
        ensure_app_dir()
        self._init()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self):
        conn = self._connect()
        try:
            conn.executescript(
                "CREATE TABLE IF NOT EXISTS visits ("
                " username TEXT, domain TEXT, url TEXT, title TEXT, ts INTEGER);"
                "CREATE INDEX IF NOT EXISTS i_visits_user_ts ON visits(username, ts);"
                "CREATE INDEX IF NOT EXISTS i_visits_domain ON visits(domain);"
                "CREATE TABLE IF NOT EXISTS cursors ("
                " source TEXT PRIMARY KEY, last INTEGER);"
                "CREATE TABLE IF NOT EXISTS attempts ("
                " username TEXT, app TEXT, ts INTEGER);"
                "CREATE INDEX IF NOT EXISTS i_attempts_ts ON attempts(ts);"
                # New-domain novelty detection (purely additive — the visits
                # table above is never touched by this feature).
                "CREATE TABLE IF NOT EXISTS known_domains ("
                " username TEXT, domain TEXT, last_ts INTEGER,"
                " PRIMARY KEY(username, domain));"
                "CREATE TABLE IF NOT EXISTS new_domain_events ("
                " username TEXT, domain TEXT, ts INTEGER);"
                "CREATE INDEX IF NOT EXISTS i_newdom_ts ON new_domain_events(ts);")
            conn.commit()
        finally:
            conn.close()
        if SYSTEM_MODE:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def get_cursor(self, source):
        conn = self._connect()
        try:
            r = conn.execute("SELECT last FROM cursors WHERE source=?",
                             (source,)).fetchone()
            return r[0] if r else 0
        finally:
            conn.close()

    def add_visits(self, username, rows, source, last_native):
        """rows = [(epoch, url, title)]. Stores web visits, updates the cursor."""
        conn = self._connect()
        try:
            data = []
            for epoch, url, title in rows:
                dom = domain_of(url)
                if dom:
                    data.append((username, dom, url, title, int(epoch)))
            if data:
                conn.executemany(
                    "INSERT INTO visits(username,domain,url,title,ts) "
                    "VALUES (?,?,?,?,?)", data)
            conn.execute(
                "INSERT INTO cursors(source,last) VALUES(?,?) "
                "ON CONFLICT(source) DO UPDATE SET last=excluded.last",
                (source, int(last_native)))
            conn.commit()
            return len(data)
        finally:
            conn.close()

    def users(self):
        conn = self._connect()
        try:
            return [r[0] for r in conn.execute(
                "SELECT DISTINCT username FROM visits ORDER BY username")]
        finally:
            conn.close()

    # Alert watermark: the newest visit timestamp we've already checked for
    # alerts. Kept separate from the per-browser import cursors so that a GUI
    # "Refresh" (which imports but doesn't alert) can't hide visits from the
    # alerting pass. Stored in the cursors table under a reserved key.
    ALERT_KEY = "__alert_watermark__"

    def get_alert_watermark(self):
        return self.get_cursor(self.ALERT_KEY)

    def set_alert_watermark(self, ts):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO cursors(source,last) VALUES(?,?) "
                "ON CONFLICT(source) DO UPDATE SET last=excluded.last",
                (self.ALERT_KEY, int(ts)))
            conn.commit()
        finally:
            conn.close()

    def visits_since(self, ts):
        """(username, domain, url, ts) for visits strictly newer than `ts`."""
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT username, domain, url, ts FROM visits WHERE ts > ? "
                "ORDER BY ts", (int(ts),)).fetchall()
        finally:
            conn.close()

    # -- new-domain novelty detection -------------------------------------- #
    # Watermark of the newest visit already checked for new-domain novelty.
    # Kept separate from the alert/import cursors so this feature is fully
    # additive and can be enabled without disturbing anything else.
    NEWDOM_KEY = "__newdom_ts__"

    def get_newdom_watermark(self):
        return self.get_cursor(self.NEWDOM_KEY)

    def set_newdom_watermark(self, ts):
        self.set_state(self.NEWDOM_KEY, int(ts))

    def seed_known_domains(self):
        """Mark every domain already in the visit log as 'known' (baseline).

        Called once when new-domain alerting is first enabled so the child's
        entire browsing past isn't reported as new. Records each domain's most
        recent past visit as its last-seen time.
        """
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO known_domains(username, domain, last_ts) "
                "SELECT username, domain, MAX(ts) FROM visits "
                "WHERE domain <> '' GROUP BY username, domain "
                "ON CONFLICT(username, domain) DO UPDATE SET "
                "last_ts=MAX(last_ts, excluded.last_ts)")
            conn.commit()
        finally:
            conn.close()

    def domain_last_seen(self, username, domain):
        """Last-seen epoch for (username, domain), or None if never recorded."""
        conn = self._connect()
        try:
            r = conn.execute(
                "SELECT last_ts FROM known_domains WHERE username=? AND domain=?",
                (username, domain)).fetchone()
            return r[0] if r else None
        finally:
            conn.close()

    def all_known_domains(self):
        """(username, domain, last_ts) for every known domain on this machine.

        Used to seed the household-shared ledger so other machines learn what
        this one has already seen.
        """
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT username, domain, last_ts FROM known_domains").fetchall()
        finally:
            conn.close()

    def mark_domain_seen(self, username, domain, ts):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO known_domains(username, domain, last_ts) "
                "VALUES(?,?,?) ON CONFLICT(username, domain) DO UPDATE SET "
                "last_ts=MAX(last_ts, excluded.last_ts)",
                (username, domain, int(ts)))
            conn.commit()
        finally:
            conn.close()

    def add_new_domain_event(self, username, domain, ts):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO new_domain_events(username, domain, ts) "
                "VALUES(?,?,?)", (username, domain, int(ts)))
            conn.commit()
        finally:
            conn.close()

    def new_domain_events_since(self, ts):
        """(username, domain, ts) new-domain events strictly newer than `ts`."""
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT username, domain, ts FROM new_domain_events "
                "WHERE ts > ? ORDER BY ts", (int(ts),)).fetchall()
        finally:
            conn.close()

    # -- generic state (heartbeat, digest timestamp) via the cursors table --
    def get_state(self, key):
        return self.get_cursor(key)

    def set_state(self, key, value):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO cursors(source,last) VALUES(?,?) "
                "ON CONFLICT(source) DO UPDATE SET last=excluded.last",
                (key, int(value)))
            conn.commit()
        finally:
            conn.close()

    # -- retention ---------------------------------------------------------- #
    def prune(self, days):
        """Delete visits/attempts older than `days`. Returns rows removed.

        The SQLite file itself won't shrink (freed pages are reused), so it
        settles at roughly one retention-window's worth rather than growing
        forever. days <= 0 means keep everything.
        """
        try:
            days = int(days)
        except (TypeError, ValueError):
            return 0
        if days <= 0:
            return 0
        cutoff = int(time.time()) - days * 86400
        conn = self._connect()
        try:
            n = conn.execute("DELETE FROM visits WHERE ts < ?", (cutoff,)).rowcount or 0
            n += conn.execute("DELETE FROM attempts WHERE ts < ?", (cutoff,)).rowcount or 0
            # Old new-domain events expire too, but known_domains is kept: it is
            # long-term memory of what's been seen, which is exactly what the
            # "not visited in X days" check needs.
            n += conn.execute("DELETE FROM new_domain_events WHERE ts < ?",
                              (cutoff,)).rowcount or 0
            conn.commit()
            return n
        finally:
            conn.close()

    # -- blocked attempts --------------------------------------------------- #
    def add_attempt(self, username, app, ts):
        conn = self._connect()
        try:
            conn.execute("INSERT INTO attempts(username,app,ts) VALUES(?,?,?)",
                         (username, app, int(ts)))
            conn.commit()
        finally:
            conn.close()

    def attempts(self, username=None, start_day=None, end_day=None, limit=5000):
        sql = "SELECT username, app, ts FROM attempts WHERE 1=1"
        args = []
        if username and username != "All users":
            sql += " AND username=?"
            args.append(username)
        lo, hi = self._range(start_day, end_day)
        if lo is not None:
            sql += " AND ts >= ?"
            args.append(lo)
        if hi is not None:
            sql += " AND ts < ?"
            args.append(hi)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        conn = self._connect()
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    @staticmethod
    def _range(start_day, end_day):
        """Convert (YYYY-MM-DD, YYYY-MM-DD) to an inclusive epoch [lo, hi)."""
        lo = hi = None
        if start_day:
            lo = int(time.mktime(time.strptime(start_day, "%Y-%m-%d")))
        if end_day:
            hi = int(time.mktime(time.strptime(end_day, "%Y-%m-%d"))) + 86400
        return lo, hi

    def query(self, username=None, domain_like=None, start_day=None,
              end_day=None, limit=5000):
        """Return visit rows (username, domain, url, ts) matching filters."""
        sql = "SELECT username, domain, url, ts FROM visits WHERE 1=1"
        args = []
        if username and username != "All users":
            sql += " AND username=?"
            args.append(username)
        if domain_like:
            sql += " AND domain LIKE ?"
            args.append(f"%{domain_like.lower()}%")
        lo, hi = self._range(start_day, end_day)
        if lo is not None:
            sql += " AND ts >= ?"
            args.append(lo)
        if hi is not None:
            sql += " AND ts < ?"
            args.append(hi)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        conn = self._connect()
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def site_durations(self, username=None, start_day=None, end_day=None):
        """
        Approximate time-on-site per domain: sum the gaps between a user's
        consecutive visits, capping each gap at VISIT_IDLE_CAP. Returns a list
        of (domain, visit_count, approx_seconds) sorted by time desc.
        """
        sql = "SELECT username, domain, ts FROM visits WHERE 1=1"
        args = []
        if username and username != "All users":
            sql += " AND username=?"
            args.append(username)
        lo, hi = self._range(start_day, end_day)
        if lo is not None:
            sql += " AND ts >= ?"
            args.append(lo)
        if hi is not None:
            sql += " AND ts < ?"
            args.append(hi)
        sql += " ORDER BY username, ts"
        conn = self._connect()
        try:
            recs = conn.execute(sql, args).fetchall()
        finally:
            conn.close()
        seconds, counts = {}, {}
        for i, (user, dom, ts) in enumerate(recs):
            counts[dom] = counts.get(dom, 0) + 1
            dur = 0
            if i + 1 < len(recs) and recs[i + 1][0] == user:
                dur = min(max(0, recs[i + 1][2] - ts), VISIT_IDLE_CAP)
            seconds[dom] = seconds.get(dom, 0) + dur
        out = [(d, counts[d], seconds.get(d, 0)) for d in counts]
        out.sort(key=lambda r: r[2], reverse=True)
        return out


def _split_recipients(text):
    """Split a recipients string on comma/semicolon/whitespace."""
    out = []
    for part in (text or "").replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part and part not in out:
            out.append(part)
    return out


def send_email(cfg, subject, body):
    """Send an email using the SMTP config dict. Raises on failure."""
    # Allow several recipients separated by comma, semicolon or space.
    recipients = _split_recipients(cfg.get("to", ""))
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("from") or cfg.get("username", "")
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    host = cfg.get("host", "")
    port = int(cfg.get("port") or 587)
    timeout = 20
    if int(cfg.get("port") or 587) == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as s:
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password", ""))
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.ehlo()
            try:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            except Exception:
                pass
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password", ""))
            s.send_message(msg)


def import_all_history(state, store):
    """
    Import new visits for every human user into `store` (logging only). This
    always runs when the daemon is up so the Activity log is never empty.
    Returns the number of visits imported.
    """
    total = 0
    for username, _uid in list_human_users():
        try:
            home = pwd.getpwnam(username).pw_dir
        except KeyError:
            continue
        if not os.path.isdir(home):
            continue
        for label, kind, db in iter_history_sources(home):
            source = f"{username}|{db}"
            since = store.get_cursor(source)
            rows, last_native = _read_browser_history(kind, db, since)
            if not rows:
                continue
            total += store.add_visits(username, rows, source, last_native)
    return total


def notify_email(email_cfg, subject, body, respect_quiet=True):
    """Send an alert email if email is configured. Returns True if sent."""
    if not (email_cfg.get("enabled") and email_cfg.get("host")
            and email_cfg.get("to")):
        return False
    if respect_quiet and _within_quiet_hours(email_cfg):
        sys.stderr.write("[monitor] quiet hours — email suppressed\n")
        return False
    send_email(email_cfg, subject, body)
    return True


def build_digest(store, since_ts):
    """Compose a per-user activity summary since `since_ts`. Returns (subj, body).

    Decluttered for quick reading: each active child leads with the flagged
    items (new websites, blocked attempts), then a compact counts line and the
    top time-on-site. Empty sections are omitted and idle children collapse to a
    single trailing line.
    """
    now = int(time.time())
    start_day = time.strftime("%Y-%m-%d", time.localtime(since_ts))
    visits = [v for v in store.query(start_day=start_day, limit=100000)
              if v[3] >= since_ts]        # (user, domain, url, ts)
    attempts = [a for a in store.attempts(start_day=start_day, limit=100000)
                if a[2] >= since_ts]      # (user, app, ts)
    # New-domain novelty events in the same window, folded in per user so the
    # daily digest is the single place new websites are reported (no separate
    # new-website email). Dedupe domains and keep first-seen order.
    new_by_user = {}
    for uname, dom, _ts in store.new_domain_events_since(since_ts):
        seen = new_by_user.setdefault(uname, [])
        if dom not in seen:
            seen.append(dom)
    active = sorted({v[0] for v in visits} | {a[0] for a in attempts}
                    | set(new_by_user))
    lines = [f"AppBlocker daily summary · "
             f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(now))}",
             f"Activity since {time.strftime('%Y-%m-%d %H:%M', time.localtime(since_ts))}",
             ""]
    if not active:
        lines.append("No activity recorded in this period.")
        return "AppBlocker daily summary", "\n".join(lines)
    for user in active:
        uv = [v for v in visits if v[0] == user]
        ua = [a for a in attempts if a[0] == user]
        searches = sum(1 for _u, _d, url, _ts in uv if extract_search_query(url))
        lines.append(user)
        nd = new_by_user.get(user) or []
        if nd:                                   # flagged items first
            shown = nd[:20]
            more = len(nd) - len(shown)
            lines.append(f"  ⚠ New websites ({len(nd)}): " + ", ".join(shown)
                         + (f", +{more} more" if more > 0 else ""))
        if ua:
            apps = {}
            for _u, app, _ts in ua:
                apps[app] = apps.get(app, 0) + 1
            lines.append("  ⚠ Blocked: "
                         + ", ".join(f"{a} ×{n}" for a, n in apps.items()))
        lines.append(f"  {len(uv)} page{'' if len(uv) == 1 else 's'} · "
                     f"{searches} search{'' if searches == 1 else 'es'}")
        durs = [d for d in store.site_durations(username=user, start_day=start_day)
                if d[2] > 0][:3]
        if durs:
            lines.append("  Most time: "
                         + " · ".join(f"{dom} ~{sec // 60}m"
                                      for dom, _cnt, sec in durs))
        lines.append("")
    idle = sorted(u for u in store.users() if u not in set(active))
    if idle:
        lines.append("No activity: " + ", ".join(idle))
    return "AppBlocker daily summary", "\n".join(lines)


def scan_and_alert(state, store, on_alert, alert_state=None):
    """
    Scan visits newer than the alert watermark and fire on_alert for watched
    sites / keywords. Independent of the import cursors, so a GUI refresh can't
    hide a visit from alerting, and alerts survive logoff/shutdown — a visit
    made just before the machine went offline is picked up the next time it's
    online (and immediately on boot), because the browser wrote it to disk.

    On the very first run the watermark starts one hour back (not "now"), so a
    just-made test visit still alerts, while days-old backlog does not flood.
    Returns the number of alerts fired.
    """
    with state.lock:
        mon = dict(state.monitor)
    watch = {normalize_domain(d) for d in mon.get("watch", []) if d}
    keywords = [k.lower() for k in mon.get("keywords", []) if k.strip()]

    wm = store.get_alert_watermark()
    if wm <= 0:
        # First run: consider the last hour "new" so a fresh visit alerts, but
        # skip older history.
        wm = int(time.time()) - 3600
        store.set_alert_watermark(wm)
    if not watch and not keywords:
        # Nothing to match; keep the watermark current so enabling later doesn't
        # replay old history.
        store.set_alert_watermark(int(time.time()))
        return 0

    fired = 0
    max_ts = wm

    def maybe_alert(username, kind, detail, epoch):
        nonlocal fired
        key = (username, kind, detail)
        now = time.time()
        if alert_state is None or now - alert_state.get(key, 0) > ALERT_DEBOUNCE:
            if alert_state is not None:
                alert_state[key] = now
            on_alert(username, kind, detail, epoch)
            fired += 1

    for username, dom, url, ts in store.visits_since(wm):
        max_ts = max(max_ts, ts)
        if dom and watch and (dom in watch or any(
                dom == w or dom.endswith("." + w) for w in watch)):
            maybe_alert(username, "site", dom, ts)
        if keywords:
            q = extract_search_query(url)
            if q and any(kw in q.lower() for kw in keywords):
                maybe_alert(username, "search", q, ts)

    if max_ts > wm:
        store.set_alert_watermark(max_ts)
    return fired


def scan_new_domains(state, store, household=None):
    """Find new-domain visits since the watermark and log them as events.

    "New" = a domain the user has never visited, OR hasn't visited in the last
    X days (X = monitor['new_domain_days']; 0 means never-seen-before only).
    Reads the shared visit log without modifying it, so every existing metric
    and log stays exactly as it was. Returns a list of new-domain event dicts
    for real-time delivery; the events are also persisted for the daily digest.

    If `household` is given (a HouseholdKnown), novelty is decided against the
    whole household's shared history, not just this machine's — so the same new
    site visited on a second machine isn't reported twice. Domains seen here are
    noted back into the household so the other machines learn them. The feature
    fails open: a None household simply falls back to per-machine behavior.
    """
    with state.lock:
        mon = dict(state.monitor)
    if not mon.get("alert_new_domains"):
        # Keep the watermark current so enabling later doesn't replay history.
        store.set_newdom_watermark(int(time.time()))
        return []
    try:
        days = max(0, int(mon.get("new_domain_days", 30)))
    except (TypeError, ValueError):
        days = 30

    wm = store.get_newdom_watermark()
    if wm <= 0:
        # First run ever: treat every domain already in history as "known"
        # (baseline) so the child's whole past isn't reported, then watch from
        # now on. No alerts fire for pre-existing history.
        store.seed_known_domains()
        store.set_newdom_watermark(int(time.time()))
        return []

    gap = days * 86400
    events = []
    max_ts = wm
    cache = {}                       # (user, dom) -> last-seen ts within this batch
    for username, dom, url, ts in store.visits_since(wm):
        max_ts = max(max_ts, ts)
        if _is_common_domain(dom):
            continue
        key = (username, dom)
        last = cache.get(key)
        if last is None:
            last = store.domain_last_seen(username, dom)
        if household is not None:
            hs = household.last_seen(username, dom)
            if hs is not None and (last is None or hs > last):
                last = hs            # a sibling machine has seen it — not new
        is_new = last is None or (gap > 0 and ts - last > gap)
        store.mark_domain_seen(username, dom, ts)
        cache[key] = ts
        if household is not None:
            household.note(username, dom, ts)
        if is_new:
            store.add_new_domain_event(username, dom, ts)
            events.append({"user": username, "domain": dom, "url": url,
                           "ts": int(ts), "last": last})
    if max_ts > wm:
        store.set_newdom_watermark(max_ts)
    return events


def _newdom_tag(ts, last):
    """Human label for how 'new' a domain is."""
    if not last:
        return "never visited before"
    days = max(1, (ts - last) // 86400)
    return f"not visited in ~{days} day{'s' if days != 1 else ''}"


def build_new_domain_alert(events):
    """Compose the real-time 'new website(s)' email. Returns (subj, body)."""
    by_user = {}
    for e in events:
        by_user.setdefault(e["user"], []).append(e)
    lines = ["AppBlocker — new website alert", ""]
    for user in sorted(by_user):
        lines.append(f"== {user} ==")
        for e in by_user[user]:
            when = time.strftime("%H:%M", time.localtime(e["ts"]))
            lines.append(f"  {e['domain']}  ({_newdom_tag(e['ts'], e['last'])}, "
                         f"at {when})")
        lines.append("")
    n = len(events)
    subj = f"[AppBlocker] {n} new website{'s' if n != 1 else ''} visited"
    return subj, "\n".join(lines)


def build_new_domain_digest(events, since_ts):
    """Daily summary of new domains seen since `since_ts`. Returns (subj, body)."""
    now = int(time.time())
    by_user = {}
    for username, dom, ts in events:
        by_user.setdefault(username, {}).setdefault(dom, []).append(ts)
    lines = [f"AppBlocker — new websites summary "
             f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(now))}",
             f"(new domains first seen since "
             f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(since_ts))})",
             ""]
    if not by_user:
        lines.append("No new websites in this period.")
    for user in sorted(by_user):
        doms = by_user[user]
        lines.append(f"== {user} — {len(doms)} new site(s) ==")
        for dom in sorted(doms, key=lambda d: min(doms[d]), reverse=True):
            first = min(doms[dom])
            when = time.strftime("%m-%d %H:%M", time.localtime(first))
            n = len(doms[dom])
            extra = f" (x{n})" if n > 1 else ""
            lines.append(f"    {dom} — first at {when}{extra}")
        lines.append("")
    return "AppBlocker daily new-website summary", "\n".join(lines)


def _within_quiet_hours(cfg, now=None):
    """True if the current local time is inside the email quiet-hours window."""
    start = _parse_hhmm(cfg.get("quiet_start", ""))
    end = _parse_hhmm(cfg.get("quiet_end", ""))
    if start is None or end is None or start == end:
        return False
    lt = now or time.localtime()
    cur = lt.tm_hour * 60 + lt.tm_min
    if start < end:
        return start <= cur < end
    return cur >= start or cur < end   # overnight window (e.g. 21:00–07:00)


class HistoryMonitor(threading.Thread):
    """Daemon thread: periodically import browser history and send alerts."""

    def __init__(self, state, store=None):
        super().__init__(daemon=True)
        self.state = state
        self.store = store
        self._stop = threading.Event()
        self._alert_state = {}
        self._last_sync = 0
        self._checked_tamper = False
        self._cmd_results = []      # recent remote-command outcomes (for the UI)
        self._newdom_day = ""       # calendar day of the real-time email counter
        self._newdom_sent = 0       # real-time new-domain emails sent today
        self._last_known_push = 0   # last household-ledger refresh (throttle)

    def stop(self):
        self._stop.set()

    def run(self):
        store = self.store or HistoryStore()
        while not self._stop.is_set():
            try:
                self.state.reload_if_changed()
                # On the first pass, see if monitoring was off for a while
                # (machine powered down or the service stopped) and report it.
                if not self._checked_tamper:
                    self._checked_tamper = True
                    self._check_tamper(store)
                # Always record history so the Activity log is never empty, then
                # run the alert scan (fires only if email + watch/keywords set).
                # This runs immediately on startup, so visits made just before
                # the machine went offline are alerted as soon as it's back on.
                import_all_history(self.state, store)
                scan_and_alert(self.state, store, self._alert,
                               self._alert_state)
                # Detect never-seen / long-unseen domains (additive: reads the
                # same visit log, records events + optional real-time email).
                self._maybe_new_domain_alert(store)
                store.set_state("__heartbeat__", int(time.time()))
                self._maybe_digest(store)
                self._maybe_new_domain_digest(store)
                self._maybe_prune(store)
                # Poll for remote-control commands from the dashboard and apply
                # them (fast — pushes an updated snapshot right after applying).
                self._poll_commands(store)
                # Opportunistically push the remote dashboard data.
                now = time.time()
                if now - self._last_sync >= SYNC_INTERVAL:
                    self._last_sync = now
                    try:
                        n = self._push_dashboard(store)
                        if n:
                            sys.stderr.write(f"[sync] pushed {n} bytes\n")
                    except Exception as exc:
                        sys.stderr.write(f"[sync] failed: {exc}\n")
            except Exception as exc:
                sys.stderr.write(f"[monitor] sweep error: {exc}\n")
            self._stop.wait(MONITOR_HISTORY_INTERVAL)

    def _push_dashboard(self, store):
        """Push data.json including the control snapshot + recent command results."""
        with self.state.lock:
            cfg = dict(self.state.sync)
        if not (cfg.get("enabled") and cfg.get("repo") and cfg.get("token")):
            return 0
        data = build_report_data(store, state=self.state,
                                 cmd_results=self._cmd_results,
                                 cmd_ts=store.get_state("__cmd_ts__") or 0)
        return push_reports_to_github(cfg, data)

    def _poll_commands(self, store):
        """Fetch, apply, and record any new remote-control commands."""
        with self.state.lock:
            cfg = dict(self.state.sync)
        if not (cfg.get("enabled") and cfg.get("control")
                and cfg.get("repo") and cfg.get("token")):
            return
        try:
            cmds = fetch_commands(cfg)
        except Exception as exc:
            sys.stderr.write(f"[control] fetch failed: {exc}\n")
            return
        cursor = store.get_state("__cmd_ts__") or 0
        pending = sorted(
            (c for c in cmds if isinstance(c, dict) and int(c.get("id", 0)) > cursor),
            key=lambda c: int(c.get("id", 0)))
        if not pending:
            return
        maxid = cursor
        for c in pending:
            cid = int(c.get("id", 0))
            maxid = max(maxid, cid)
            try:
                ok, msg = apply_remote_command(self.state, c)
            except Exception as exc:
                ok, msg = False, str(exc)
            self._cmd_results.append({
                "id": cid, "action": c.get("action", ""), "ok": bool(ok),
                "msg": msg, "at": int(time.time())})
            sys.stderr.write(
                f"[control] {'OK ' if ok else 'ERR'} {c.get('action')}: {msg}\n")
        self._cmd_results = self._cmd_results[-40:]
        store.set_state("__cmd_ts__", maxid)
        # Push immediately so the phone sees the change and the confirmation.
        try:
            self._push_dashboard(store)
        except Exception as exc:
            sys.stderr.write(f"[control] push after apply failed: {exc}\n")

    def _email_cfg(self):
        with self.state.lock:
            return dict(self.state.monitor.get("email") or {})

    def _alert(self, username, kind, detail, ts):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        if kind == "search":
            subject = f"[AppBlocker] {username} searched for flagged terms"
            body = (f"AppBlocker alert\n\nUser '{username}' ran a search that "
                    f"matched your watch keywords:\n  \"{detail}\"\n  at {when}\n")
        else:
            subject = f"[AppBlocker] {username} visited {detail}"
            body = (f"AppBlocker alert\n\nUser '{username}' visited a watched "
                    f"site:\n  {detail}\n  at {when}\n")
        sys.stderr.write(f"[monitor] ALERT ({kind}): {username} -> {detail}\n")
        try:
            notify_email(self._email_cfg(), subject, body)
        except Exception as exc:
            sys.stderr.write(f"[monitor] email failed: {exc}\n")

    def block_alert(self, username, app, ts):
        """Record a blocked-app attempt and (optionally) email it."""
        try:
            self.store.add_attempt(username, app, ts)
        except Exception as exc:
            sys.stderr.write(f"[monitor] record attempt failed: {exc}\n")
        with self.state.lock:
            mon = dict(self.state.monitor)
        sys.stderr.write(f"[monitor] BLOCKED: {username} tried {app}\n")
        if not mon.get("alert_blocked", True):
            return
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        try:
            notify_email(mon.get("email") or {},
                         f"[AppBlocker] {username} tried to open {app}",
                         f"AppBlocker alert\n\nUser '{username}' tried to open a "
                         f"blocked app:\n  {app}\n  at {when}\n(It was blocked.)\n")
        except Exception as exc:
            sys.stderr.write(f"[monitor] email failed: {exc}\n")

    def _check_tamper(self, store):
        hb = store.get_state("__heartbeat__")
        now = int(time.time())
        if hb and now - hb > TAMPER_GAP:
            gap_min = (now - hb) // 60
            frm = time.strftime("%Y-%m-%d %H:%M", time.localtime(hb))
            to = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
            sys.stderr.write(f"[monitor] monitoring gap {gap_min} min\n")
            try:
                notify_email(
                    self._email_cfg(), "[AppBlocker] Monitoring was off",
                    f"AppBlocker was not running from {frm} to {to} "
                    f"(~{gap_min} minutes) — the machine was off or the service "
                    f"was stopped. Monitoring has resumed.\n", respect_quiet=False)
            except Exception as exc:
                sys.stderr.write(f"[monitor] email failed: {exc}\n")

    def _maybe_digest(self, store):
        with self.state.lock:
            mon = dict(self.state.monitor)
        if not mon.get("digest_enabled"):
            return
        interval = max(1, int(mon.get("digest_hours", 24))) * 3600
        last = store.get_state("__digest__")
        now = int(time.time())
        if last <= 0:
            store.set_state("__digest__", now)   # start the clock, no immediate send
            return
        if now - last < interval:
            return
        subject, body = build_digest(store, last)
        try:
            if notify_email(mon.get("email") or {}, subject, body,
                            respect_quiet=False):
                store.set_state("__digest__", now)
        except Exception as exc:
            sys.stderr.write(f"[monitor] digest email failed: {exc}\n")

    def _maybe_new_domain_alert(self, store):
        """Scan for new domains and, if real-time is on, send one batched email.

        Events are logged regardless of real-time delivery so the daily digest
        (and dashboard) still sees them even during quiet hours. When household
        sharing is on, novelty is judged against every machine's history so the
        same new site isn't reported twice across the household.
        """
        with self.state.lock:
            mon = dict(self.state.monitor)
            cfg = dict(self.state.sync)
        # Load the household ledger if sharing is enabled and sync is set up.
        # Any failure -> household stays None -> per-machine behavior (fail open).
        household = None
        if (mon.get("alert_new_domains") and mon.get("new_domain_shared", True)
                and cfg.get("enabled") and cfg.get("repo") and cfg.get("token")):
            try:
                household = HouseholdKnown.load(
                    cfg, aliases=mon.get("new_domain_aliases"))
            except Exception as exc:
                sys.stderr.write(f"[monitor] household ledger load failed: {exc}\n")
                household = None
        try:
            events = scan_new_domains(self.state, store, household=household)
        except Exception as exc:
            sys.stderr.write(f"[monitor] new-domain scan failed: {exc}\n")
            return
        # One-time: contribute this machine's whole baseline so the other
        # machines stop re-alerting on sites we've long known (covers first-run
        # seeds and machines upgrading from a per-machine-only version).
        if household is not None and not store.get_state("__household_seeded__"):
            try:
                for u, d, t in store.all_known_domains():
                    household.note(u, d, t)
            except Exception as exc:
                sys.stderr.write(f"[monitor] household baseline note failed: {exc}\n")
        # Publish contributions. New domains push right away (so siblings dedupe
        # fast); routine last-seen refreshes are throttled to the sync cadence.
        if household is not None and household.dirty():
            now = time.time()
            first_seed = not store.get_state("__household_seeded__")
            if events or first_seed or (now - self._last_known_push >= SYNC_INTERVAL):
                try:
                    household.push(cfg)
                    self._last_known_push = now
                    store.set_state("__household_seeded__", 1)
                except Exception as exc:
                    sys.stderr.write(f"[monitor] household ledger push failed: {exc}\n")
        if not events:
            return
        if not mon.get("new_domain_realtime"):
            return                       # digest-only mode; events still logged
        # Anti-flood: cap real-time emails per calendar day.
        today = time.strftime("%Y-%m-%d")
        if self._newdom_day != today:
            self._newdom_day = today
            self._newdom_sent = 0
        if self._newdom_sent >= NEWDOM_ALERT_CAP:
            return
        subject, body = build_new_domain_alert(events)
        try:
            if notify_email(mon.get("email") or {}, subject, body):
                self._newdom_sent += 1
        except Exception as exc:
            sys.stderr.write(f"[monitor] new-domain email failed: {exc}\n")

    def _maybe_new_domain_digest(self, store):
        """Once a day, email a summary of every new domain seen since last time.

        Runs whenever new-domain alerting is on (independent of the general
        activity digest), so the parent always gets a daily new-website roundup.
        """
        with self.state.lock:
            mon = dict(self.state.monitor)
        if not mon.get("alert_new_domains"):
            return
        if mon.get("digest_enabled"):
            # New sites are folded into the main daily digest — don't also send
            # a separate new-website email (that would be clutter).
            return
        interval = 86400                 # daily
        last = store.get_state("__newdom_digest__")
        now = int(time.time())
        if last <= 0:
            store.set_state("__newdom_digest__", now)   # start clock, no send
            return
        if now - last < interval:
            return
        events = store.new_domain_events_since(last)
        if not events:
            store.set_state("__newdom_digest__", now)   # nothing new; reset clock
            return
        subject, body = build_new_domain_digest(events, last)
        try:
            if notify_email(mon.get("email") or {}, subject, body,
                            respect_quiet=False):
                store.set_state("__newdom_digest__", now)
        except Exception as exc:
            sys.stderr.write(f"[monitor] new-domain digest failed: {exc}\n")

    def _maybe_prune(self, store):
        """Once a day, delete history older than the configured retention."""
        with self.state.lock:
            days = int(self.state.monitor.get("history_days") or 0)
        if days <= 0:
            return                       # 0 = keep everything
        now = int(time.time())
        if now - (store.get_state("__pruned__") or 0) < 86400:
            return                       # already pruned in the last 24h
        try:
            n = store.prune(days)
            store.set_state("__pruned__", now)
            if n:
                sys.stderr.write(f"[monitor] pruned {n} history rows older "
                                 f"than {days} days\n")
        except Exception as exc:
            sys.stderr.write(f"[monitor] prune failed: {exc}\n")


# --------------------------------------------------------------------------- #
# Remote dashboard — export the activity as data.json and push it to a private
# GitHub repo. A static dashboard page (docs/index.html on GitHub Pages) reads
# it with the parent's own token, so the data is never public.
# --------------------------------------------------------------------------- #
import base64                       # noqa: E402 (grouped with the feature)
import urllib.request              # noqa: E402
import urllib.error                # noqa: E402

SYNC_INTERVAL = 300                # seconds between opportunistic dashboard syncs
REPORT_DAYS = 30                   # how many days of history to publish
REPORT_LIMIT = 6000               # cap visits so data.json stays well under 1 MB


def _control_snapshot(state):
    """Current blockable state, so the dashboard can render live controls."""
    with state.lock:
        apps = []
        for a in state.apps:
            apps.append({
                "name": a.get("name", ""),
                "proc": a.get("proc_name", ""),
                "blocked": effective_blocked(a),
                "mode": a.get("mode", "manual"),
                "targets": list(a.get("target_users") or []),
            })
        websites = list(state.websites)
        watch = list(state.monitor.get("watch") or [])
        lockdown = bool(state.lockdown.get("enabled"))
        adult = bool(state.block_adult)
        remote_enabled = bool(state.sync.get("control"))
        distractions = list(state.distractions)
        free_until = int(state.distract_free_until or 0)
        # only report per-site allows that haven't expired
        now = int(time.time())
        distract_allow = {d: int(t) for d, t in state.distract_allow.items()
                          if int(t) > now}
    try:
        human_users = [name for name, _uid in list_human_users()]
    except Exception:
        human_users = []
    return {"apps": apps, "websites": websites, "watch": watch,
            "lockdown": lockdown, "block_adult": adult,
            "human_users": human_users, "remote_enabled": remote_enabled,
            "distractions": distractions, "distract_free_until": free_until,
            "distract_allow": distract_allow}


def build_report_data(store, days=REPORT_DAYS, limit=REPORT_LIMIT,
                      state=None, cmd_results=None, cmd_ts=0):
    """Assemble the dashboard payload from the history store.

    When `state` is given, a `control` snapshot (apps / websites / lockdown /
    users) is included so the dashboard can offer remote controls, along with
    the results of recently-applied commands and the processed-command
    watermark so the phone can show confirmations.
    """
    start_day = time.strftime("%Y-%m-%d",
                              time.localtime(time.time() - days * 86400))
    rows = store.query(start_day=start_day, limit=limit + 1)
    truncated = len(rows) > limit
    rows = rows[:limit]
    visits = []
    for username, domain, url, ts in rows:
        visits.append({"u": username, "d": domain, "url": url, "ts": int(ts),
                       "q": extract_search_query(url)})
    attempts = [{"u": u, "app": app, "ts": int(ts)}
                for u, app, ts in store.attempts(start_day=start_day, limit=2000)]
    try:
        machine = os.uname().nodename
    except Exception:
        machine = ""
    now = time.time()
    users = sorted(set(store.users()) | {a["u"] for a in attempts})
    # New-domain novelty events in the window (sites the child had never
    # visited, or hadn't visited in a while). Newest first.
    win_start = int(now - days * 86400)
    new_domains = [{"u": u, "d": d, "ts": int(ts)}
                   for u, d, ts in store.new_domain_events_since(win_start)]
    new_domains.sort(key=lambda e: e["ts"], reverse=True)
    new_domains = new_domains[:2000]
    data = {
        "generated_at": int(now),
        "generated_at_str": time.strftime("%Y-%m-%d %H:%M", time.localtime(now)),
        "machine": machine or machine_id(),
        "machine_id": machine_id(),
        "days": days,
        "truncated": truncated,
        "users": users,
        "visits": visits,
        "attempts": attempts,
        "new_domains": new_domains,
        "control_results": list(cmd_results or []),
        "cmd_ts": int(cmd_ts or 0),
    }
    if state is not None:
        data["control"] = _control_snapshot(state)
        # Flag recorded visits whose domain is on the effective blocklist — these
        # are attempts to reach a blocked site (adult list or your own list). We
        # can only surface the ones the browser wrote to history, so it's a
        # best-effort view, not an airtight log.
        bl = effective_block_domains(state)
        blocked_sites = []
        if bl:
            for v in visits:
                if _domain_blocked(v.get("d") or "", bl):
                    blocked_sites.append({"u": v["u"], "d": v["d"],
                                          "url": v["url"], "ts": v["ts"]})
        data["blocked_sites"] = blocked_sites
    else:
        data["blocked_sites"] = []
    return data


def effective_block_domains(state):
    """All domains currently blocked machine-wide: your list + the adult list."""
    with state.lock:
        doms = set(state.websites)
        adult = state.block_adult
    if adult:
        doms |= load_adult_domains()
    return doms


def _domain_blocked(domain, blocklist):
    """True if `domain` or any of its parent domains is in `blocklist`."""
    d = (domain or "").lower().strip(".")
    if not d:
        return False
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in blocklist:
            return True
    return d in blocklist


def machine_id():
    """A filesystem/URL-safe id for this machine (its data filename in the repo)."""
    try:
        host = os.uname().nodename or "machine"
    except Exception:
        host = "machine"
    safe = "".join(c if (c.isalnum() or c in "._-") else "-" for c in host)
    safe = safe.strip("-._").lower()
    return safe or "machine"


def _sync_base_dir(cfg):
    """Directory (with trailing slash, or '') the per-machine files live under."""
    p = (cfg.get("path") or "data.json").strip() or "data.json"
    return (p.rsplit("/", 1)[0] + "/") if "/" in p else ""


def machine_data_path(cfg):
    """Where THIS machine publishes its data — machines/<id>.json under the base.

    Each machine writes only its own file, so several machines can share one
    repo without overwriting each other. The dashboard lists the machines/
    folder to discover them all.
    """
    return f"{_sync_base_dir(cfg)}machines/{machine_id()}.json"


def machine_commands_path(cfg):
    """The per-machine command queue the dashboard writes and this machine reads."""
    return f"{_sync_base_dir(cfg)}machines/{machine_id()}.commands.json"


def _gh_request(url, token, method="GET", body=None):
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AppBlocker",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def push_reports_to_github(cfg, data):
    """
    PUT data.json into the configured private repo. cfg keys: repo (owner/name),
    branch, path, token. Raises on failure.
    """
    repo = cfg.get("repo", "").strip()
    token = cfg.get("token", "").strip()
    path = machine_data_path(cfg)   # machines/<this-host>.json — never clobbers others
    branch = cfg.get("branch", "main").strip() or "main"
    if not repo or not token:
        raise ValueError("Dashboard repo and token are required.")
    api = f"https://api.github.com/repos/{repo}/contents/{path}"
    sha = None
    try:
        existing = _gh_request(f"{api}?ref={branch}", token)
        sha = existing.get("sha")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    body = {
        "message": f"Update activity {data.get('generated_at_str', '')}",
        "content": base64.b64encode(payload).decode("ascii"),
        "branch": branch,
    }
    if sha:
        body["sha"] = sha
    _gh_request(api, token, method="PUT", body=body)
    return len(payload)


# --------------------------------------------------------------------------- #
# Household-shared "known domains" ledger — a single small file in the same
# sync repo that every machine merges into. It lets new-domain alerts dedupe
# across a household's machines: a site that's already been seen on ANY machine
# (for that username) is no longer "new" anywhere. Scoped by username, bounded
# by age, and fail-open (unreachable ledger just falls back to per-machine).
# --------------------------------------------------------------------------- #
HOUSEHOLD_KNOWN_MAX_AGE = 180 * 86400   # drop shared domains unseen this long


def household_known_path(cfg):
    """Where the shared known-domains ledger lives, under the sync base dir."""
    return f"{_sync_base_dir(cfg)}newdomains/known.json"


def _sanitize_known_users(users):
    """Coerce a loaded ledger into {user_lower: {domain: int_ts}} (case-folded
    username so Timmy/timmy merge; last write wins on ts via max)."""
    clean = {}
    if isinstance(users, dict):
        for u, m in users.items():
            if not isinstance(m, dict):
                continue
            key = str(u).lower()
            dd = clean.setdefault(key, {})
            for dom, ts in m.items():
                try:
                    ts = int(ts)
                except (TypeError, ValueError):
                    continue
                d = str(dom)
                if ts > dd.get(d, 0):
                    dd[d] = ts
    return clean


def fetch_household_known(cfg):
    """Return (users_map, sha). users_map = {user: {domain: last_ts}}.

    Missing file -> ({}, None). Network/HTTP errors propagate to the caller,
    which treats them as "sharing unavailable" and falls back to per-machine.
    """
    repo = cfg.get("repo", "").strip()
    token = cfg.get("token", "").strip()
    branch = cfg.get("branch", "main").strip() or "main"
    if not repo or not token:
        return {}, None
    api = (f"https://api.github.com/repos/{repo}/contents/"
           f"{household_known_path(cfg)}")
    try:
        obj = _gh_request(f"{api}?ref={branch}", token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}, None
        raise
    raw = obj.get("content", "")
    if obj.get("encoding") == "base64":
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except Exception:
        return {}, obj.get("sha")
    return _sanitize_known_users(data.get("users")), obj.get("sha")


def _merge_known(base, incoming, max_age=HOUSEHOLD_KNOWN_MAX_AGE, now=None):
    """Merge `incoming` {user:{dom:ts}} into `base`, keeping the max ts and
    pruning entries older than max_age. Returns (merged, changed) where changed
    is True only if `incoming` added or advanced something (so we don't write
    the file just to prune)."""
    now = int(now if now is not None else time.time())
    cutoff = (now - max_age) if max_age else 0
    merged = {}
    for u, m in (base or {}).items():
        dd = {d: int(t) for d, t in m.items() if int(t) >= cutoff}
        if dd:
            merged[u] = dd
    changed = False
    for u, m in (incoming or {}).items():
        key = str(u).lower()
        for d, t in m.items():
            t = int(t)
            if t < cutoff:
                continue
            cur = merged.get(key, {}).get(d)
            if cur is None or t > cur:
                merged.setdefault(key, {})[d] = t
                changed = True
    return merged, changed


def write_household_known(cfg, users, sha):
    """PUT the merged ledger. Raises urllib.error.HTTPError (409/422 on a race)."""
    repo = cfg.get("repo", "").strip()
    token = cfg.get("token", "").strip()
    branch = cfg.get("branch", "main").strip() or "main"
    api = (f"https://api.github.com/repos/{repo}/contents/"
           f"{household_known_path(cfg)}")
    payload = json.dumps({"v": 1, "users": users},
                         separators=(",", ":")).encode("utf-8")
    body = {"message": "Update household known domains",
            "content": base64.b64encode(payload).decode("ascii"),
            "branch": branch}
    if sha:
        body["sha"] = sha
    _gh_request(api, token, method="PUT", body=body)
    return len(payload)


def push_household_known(cfg, updates, max_attempts=3):
    """Read-modify-write `updates` into the shared ledger with 409/422 retry.
    Returns True if a write happened, False if nothing new to contribute."""
    for attempt in range(max_attempts):
        base, sha = fetch_household_known(cfg)
        merged, changed = _merge_known(base, updates)
        if not changed:
            return False
        try:
            write_household_known(cfg, merged, sha)
            return True
        except urllib.error.HTTPError as exc:
            if exc.code in (409, 422) and attempt < max_attempts - 1:
                continue             # someone else wrote — re-read and retry
            raise
    return False


class HouseholdKnown:
    """In-memory view of the household ledger plus this machine's buffered
    contributions. Loaded per novelty scan; pushed back after."""

    def __init__(self, users, sha, aliases=None):
        self.users = users               # {household_id: {domain: ts}} from repo
        self.sha = sha
        self._buf = {}                   # pending {household_id: {domain: ts}}
        # local-username -> household-identity, so the same child under a
        # different login name on each machine still merges. Case-folded.
        self.aliases = {}
        for k, v in (aliases or {}).items():
            lk, lv = str(k).strip().lower(), str(v).strip().lower()
            if lk and lv and lk != lv:
                self.aliases[lk] = lv

    @classmethod
    def load(cls, cfg, aliases=None):
        users, sha = fetch_household_known(cfg)
        return cls(users, sha, aliases=aliases)

    def _hid(self, user):
        """Map a local username to its household identity (alias or itself)."""
        u = str(user).lower()
        return self.aliases.get(u, u)

    def last_seen(self, user, domain):
        key = self._hid(user)
        vals = []
        v = (self.users.get(key) or {}).get(domain)
        if v is not None:
            vals.append(v)
        b = (self._buf.get(key) or {}).get(domain)
        if b is not None:
            vals.append(b)
        return max(vals) if vals else None

    def note(self, user, domain, ts):
        key = self._hid(user)
        ts = int(ts)
        cur = self.last_seen(user, domain)
        if cur is None or ts > cur:
            self._buf.setdefault(key, {})[domain] = ts

    def dirty(self):
        return bool(self._buf)

    def push(self, cfg, max_attempts=3):
        """Send buffered contributions. On success, fold them into the local
        view and clear the buffer. Returns True if a write happened."""
        if not self._buf:
            return False
        sent = push_household_known(cfg, self._buf, max_attempts=max_attempts)
        for u, m in self._buf.items():
            dst = self.users.setdefault(u, {})
            for d, t in m.items():
                if t > dst.get(d, 0):
                    dst[d] = t
        self._buf = {}
        return sent


def sync_reports(state, store):
    """Build and push the dashboard data if sync is enabled. Returns bytes sent."""
    with state.lock:
        cfg = dict(state.sync)
    if not cfg.get("enabled") or not cfg.get("repo") or not cfg.get("token"):
        return 0
    data = build_report_data(store, state=state,
                             cmd_ts=store.get_state("__cmd_ts__") or 0)
    return push_reports_to_github(cfg, data)


# --------------------------------------------------------------------------- #
# Remote control — the phone (dashboard) appends commands to commands.json in
# the same private repo; the daemon polls that file and applies them. Only the
# phone writes commands.json and only the machine writes data.json, so the two
# never collide. Commands carry a millisecond `id`; the machine remembers the
# highest id it has processed (a watermark in its local store) so each command
# runs exactly once.
# --------------------------------------------------------------------------- #
def fetch_commands(cfg):
    """Read this machine's pending command list from the repo (maybe empty)."""
    repo = cfg.get("repo", "").strip()
    token = cfg.get("token", "").strip()
    branch = cfg.get("branch", "main").strip() or "main"
    if not repo or not token:
        return []
    api = f"https://api.github.com/repos/{repo}/contents/{machine_commands_path(cfg)}"
    try:
        obj = _gh_request(f"{api}?ref={branch}", token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []            # no commands file yet — nothing queued
        raise
    raw = obj.get("content", "")
    if obj.get("encoding") == "base64":
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except Exception:
        return []
    cmds = data.get("commands") if isinstance(data, dict) else data
    return cmds if isinstance(cmds, list) else []


def apply_remote_command(state, cmd):
    """
    Apply one command dict to the shared AppState. The 5-second enforcement
    sweep (which both daemon threads share) then propagates website / lockdown /
    kill effects, so we only mutate state here. Returns (ok, message).
    """
    action = str(cmd.get("action", ""))

    def find_app(proc):
        key = str(proc or "").lower()
        with state.lock:
            for i, a in enumerate(state.apps):
                if (a.get("proc_name", "") or "").lower() == key:
                    return i, a.get("name", "")
        return None, None

    if action in ("block_app", "unblock_app"):
        idx, name = find_app(cmd.get("app"))
        if idx is None:
            return False, f"app '{cmd.get('app')}' not found"
        if action == "unblock_app":
            state.unblock(idx)
            return True, f"unblocked {name}"
        mode = cmd.get("mode", "manual")
        if mode not in ("manual", "timer"):
            return False, "only manual/timer blocks are supported remotely"
        minutes = cmd.get("minutes")
        state.apply_block(idx, mode, minutes=minutes,
                          target_users=cmd.get("users") or [])
        return True, f"blocked {name}"

    if action == "quick_block":
        mode = cmd.get("mode", "manual")
        if mode not in ("manual", "timer"):
            return False, "only manual/timer blocks are supported remotely"
        with state.lock:
            n = len(state.apps)
        for i in range(n):
            state.apply_block(i, mode, minutes=cmd.get("minutes"),
                              target_users=cmd.get("users") or [])
        return True, f"blocked all {n} app(s)"

    if action == "unblock_all":
        with state.lock:
            n = len(state.apps)
        for i in range(n):
            state.unblock(i)
        return True, "unblocked all apps"

    if action == "add_website":
        dom = normalize_domain(cmd.get("domain", ""))
        if not dom:
            return False, "invalid domain"
        with state.lock:
            cur = list(state.websites)
        if dom not in cur:
            cur.append(dom)
        state.set_websites(cur)
        return True, f"blocked website {dom}"

    if action == "remove_website":
        dom = normalize_domain(cmd.get("domain", ""))
        with state.lock:
            cur = [d for d in state.websites if d != dom]
        state.set_websites(cur)
        return True, f"unblocked website {dom}"

    if action in ("add_watch", "remove_watch"):
        dom = normalize_domain(cmd.get("domain", ""))
        if action == "add_watch" and not dom:
            return False, "invalid domain"
        with state.lock:
            mon = dict(state.monitor)
            watch = list(mon.get("watch") or [])
        if action == "add_watch":
            if dom not in watch:
                watch.append(dom)
            msg = f"watching {dom}"
        else:
            watch = [d for d in watch if d != dom]
            msg = f"stopped watching {dom}"
        mon["watch"] = watch
        state.set_monitor(mon)
        return True, msg

    if action == "set_lockdown":
        en = bool(cmd.get("enabled"))
        state.set_lockdown(en)
        return True, f"browser lockdown {'on' if en else 'off'}"

    if action == "set_block_adult":
        en = bool(cmd.get("enabled"))
        state.set_block_adult(en)
        return True, f"adult blocklist {'on' if en else 'off'}"

    if action in ("add_distraction", "remove_distraction"):
        dom = normalize_domain(cmd.get("domain", ""))
        if action == "add_distraction" and not dom:
            return False, "invalid domain"
        with state.lock:
            cur = list(state.distractions)
        if action == "add_distraction":
            if dom not in cur:
                cur.append(dom)
            msg = f"added distraction {dom}"
        else:
            cur = [d for d in cur if d != dom]
            msg = f"removed distraction {dom}"
        state.set_distractions(cur)
        return True, msg

    if action == "grant_free_time":
        until = state.grant_free_time(cmd.get("minutes"))
        if until:
            return True, ("free time until "
                          + time.strftime("%H:%M", time.localtime(until)))
        return True, "free time ended — distractions re-locked"

    if action == "end_free_time":
        state.end_free_time()
        return True, "distractions re-locked"

    if action == "allow_distraction":
        dom = state.allow_distraction(cmd.get("domain", ""), cmd.get("minutes"))
        if not dom:
            return False, "invalid domain"
        mins = cmd.get("minutes")
        return True, (f"allowed {dom} for {mins} min" if mins
                      else f"re-blocked {dom}")

    return False, f"unknown action '{action}'"


# --------------------------------------------------------------------------- #
# Process monitor — kills blocked apps in the background.
# --------------------------------------------------------------------------- #
class ProcessMonitor(threading.Thread):
    """
    Background daemon thread. Every MONITOR_INTERVAL seconds it scans /proc
    and kills any running process whose executable name matches a currently
    blocked app. It also enforces timer expiry (auto-unblock).

    `state` is the shared AppState instance; access to it is guarded by
    `state.lock`.
    """

    def __init__(self, state, on_change=None, on_block=None):
        super().__init__(daemon=True)
        self.state = state
        self.on_change = on_change  # called (from this thread) when state changes
        self.on_block = on_block    # on_block(username, app_name, ts) on a kill
        self._block_seen = {}       # (user, app) -> last-reported time (debounce)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            try:
                self._sweep()
            except Exception as exc:  # never let the monitor die
                sys.stderr.write(f"[monitor] error: {exc}\n")
            self._stop.wait(MONITOR_INTERVAL)

    # -- internals ---------------------------------------------------------- #
    def _sweep(self):
        # Pick up edits made by another process (the GUI editing the shared
        # blocklist, or, for the GUI, the daemon expiring a timer).
        reloaded = self.state.reload_if_changed()
        changed_timer = self._expire_timers()

        # One scan of the process table — reused for trigger evaluation and
        # for the kill pass so a fast-launching child can't slip between scans.
        procs = list(self._iter_processes())  # [(pid, comm, uid, exe_base, cmd)]

        with self.state.lock:
            apps = [dict(a) for a in self.state.apps]
            trigger_rules = [dict(r) for r in self.state.rules]

        # Look up an app (with its match rules) by its stored proc_name key.
        apps_by_key = {}
        for a in apps:
            key = (a.get("proc_name") or "").lower()
            if key:
                apps_by_key.setdefault(key, a)

        def resolve(ref):
            """A rule references an app by name; fall back to a process match."""
            return apps_by_key.get((ref or "").lower()) or \
                {"match_type": "process", "match_terms": [ref], "proc_name": ref}

        # Active blockers: list of (matcher_app, uids_or_None). uids None = all.
        blockers = []
        for app in apps:
            if effective_blocked(app):
                blockers.append((app, app_target_uids(app)))

        # Dynamic trigger rules: while a trigger app is running for some user,
        # block its target apps for exactly the user(s) running the trigger,
        # and (machine-wide) block any websites the rule lists.
        #
        # PWA / web-app triggers (match_type "commandline") are detected by the
        # user's open WINDOWS, not by a process carrying the URL: a Chromium PWA
        # opened while the browser is already running leaves no lasting process
        # with its URL, and one opened first leaves that URL in the browser
        # process even after the PWA window is closed. The window is the only
        # signal that tracks the PWA actually being open.
        human_uids = {uid for _n, uid in list_human_users()}
        proc_uids = {uid for _p, _c, uid, _e, _cmd in procs}
        win_cache = {}

        def windows_for(uid):
            if uid not in win_cache:
                win_cache[uid] = self._list_user_windows(uid)
            return win_cache[uid]

        dynamic_sites = set()
        for rule in trigger_rules:
            if not rule.get("enabled", True):
                continue
            trig_app = resolve(rule.get("trigger"))
            if trig_app.get("match_type") == "commandline":
                terms = [t.lower() for t in app_match_terms(trig_app) if t]
                active_uids = set()
                for uid in (proc_uids & human_uids):
                    wins = windows_for(uid)
                    if wins is None:            # X not queryable — fall back
                        if any(app_matches(trig_app, comm, exe, cmd)
                               for _p, comm, u2, exe, cmd in procs if u2 == uid):
                            active_uids.add(uid)
                    elif any(t in w for t in terms for w in wins):
                        active_uids.add(uid)
            else:
                active_uids = {
                    uid for _pid, comm, uid, exe, cmd in procs
                    if app_matches(trig_app, comm, exe, cmd)
                }
            if not active_uids:
                continue
            allowed = rule.get("users") or []
            if allowed:
                active_uids &= usernames_to_uids(allowed)
            if not active_uids:
                continue
            trig_key = (trig_app.get("proc_name") or "").lower()
            for target in rule.get("targets", []):
                tgt_app = resolve(target)
                if (tgt_app.get("proc_name") or "").lower() == trig_key:
                    continue  # never kill the trigger itself
                blockers.append((tgt_app, set(active_uids)))
            dynamic_sites.update(rule.get("block_sites") or [])

        if blockers:
            for pid, comm, uid, exe, cmd in procs:
                for app, uids in blockers:
                    if (uids is None or uid in uids) and \
                            app_matches(app, comm, exe, cmd):
                        self._kill(pid)
                        self._record_attempt(uid, app)
                        break

        # Keep /etc/hosts in sync (system mode, root only). The effective list
        # is the always-on websites plus any added by currently-active trigger
        # rules. Cheap: only rewrites the file when it actually differs.
        if SYSTEM_MODE:
            with self.state.lock:
                domains = set(self.state.websites)
                lockdown_on = self.state.lockdown.get("enabled")
                adult_on = self.state.block_adult
                web_scheds = [dict(s) for s in self.state.web_schedules]
                distractions = list(self.state.distractions)
                free_until = self.state.distract_free_until
                allow = dict(self.state.distract_allow)
            domains |= dynamic_sites
            if adult_on:
                domains |= load_adult_domains()
            # Scheduled "downtime" blocks: add each schedule's sites while the
            # current time is inside one of its windows.
            for sch in web_scheds:
                if schedule_active(sch.get("schedule") or []):
                    domains |= set(sch.get("sites") or [])
            # Distractions: blocked by default unless free time is granted or the
            # specific site has an unexpired allow. Auto re-locks when they lapse
            # because this recomputes every sweep.
            domains |= active_distractions(distractions, free_until, allow)
            sync_blocked_websites(sorted(domains))
            # Block the same sites INSIDE the browser (URLBlocklist policy) so it
            # takes hold on already-open tabs without a reload and survives DoH —
            # /etc/hosts above still covers non-browser apps.
            apply_browser_lockdown(lockdown_on)
            apply_site_block_policy(domains)
            # Expose the policy dirs to Flatpak browsers when we have anything
            # for them to read.
            sync_flatpak_policy_overrides(bool(lockdown_on) or bool(domains))

        if (changed_timer or reloaded) and self.on_change:
            self.on_change()

    def _expire_timers(self):
        """Auto-unblock any timer that has elapsed. Returns True if changed."""
        now = time.time()
        changed = False
        with self.state.lock:
            for app in self.state.apps:
                if app.get("mode") != "timer":
                    continue
                end = app.get("timer_end")
                if app.get("blocked") and end and now >= end:
                    app["blocked"] = False
                    app["mode"] = "manual"
                    app["timer_end"] = None
                    changed = True
            if changed:
                self.state.save_locked()
        return changed

    def _user_x_env(self, uid):
        """DISPLAY / XAUTHORITY for a uid's graphical session, read from one of
        its session processes' environment, or None if it has no X session."""
        try:
            home = pwd.getpwuid(uid).pw_dir
        except Exception:
            home = None
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            base = f"/proc/{pid}"
            try:
                if os.stat(base).st_uid != uid:
                    continue
                with open(f"{base}/environ", "rb") as fh:
                    raw = fh.read()
            except Exception:
                continue
            disp = xauth = None
            for e in raw.split(b"\0"):
                if e.startswith(b"DISPLAY="):
                    disp = e[8:].decode("utf-8", "replace")
                elif e.startswith(b"XAUTHORITY="):
                    xauth = e[11:].decode("utf-8", "replace")
            if disp:
                if not xauth and home:
                    xauth = os.path.join(home, ".Xauthority")
                return {"DISPLAY": disp, "XAUTHORITY": xauth}
        return None

    def _list_user_windows(self, uid):
        """Lowercased 'wm_class title' strings for a user's open windows, or
        None if the X session can't be queried (caller falls back to /proc).

        This is how PWA / web-app triggers are detected reliably: a Chromium
        PWA opened while the browser is already running leaves no lasting
        process carrying its URL, but its window is always present while open.
        """
        if not which("wmctrl"):
            return None
        env = self._user_x_env(uid)
        if not env:
            return None
        run_env = dict(os.environ)
        run_env["DISPLAY"] = env["DISPLAY"]
        if env.get("XAUTHORITY"):
            run_env["XAUTHORITY"] = env["XAUTHORITY"]
        try:
            out = subprocess.run(["wmctrl", "-lx"], capture_output=True,
                                 text=True, timeout=5, env=run_env)
        except Exception:
            return None
        if out.returncode != 0:
            return None
        wins = []
        for line in out.stdout.splitlines():
            parts = line.split(None, 4)   # winid desktop wm_class host title
            if len(parts) < 3:
                continue
            wm_class = parts[2]
            title = parts[4] if len(parts) >= 5 else ""
            wins.append((wm_class + " " + title).lower())
        return wins

    @staticmethod
    def _iter_processes():
        """
        Yield (pid, comm, uid, exe_base, cmdline) for every process via /proc.
        All string fields are lowercase. comm is the kernel process name,
        exe_base is the basename of the real executable, cmdline is the full
        command line (used to match PWAs / custom launch commands).
        """
        my_pid = os.getpid()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == my_pid:
                continue
            # Owner UID of the process (so we can target specific users).
            try:
                uid = os.stat(f"/proc/{entry}").st_uid
            except OSError:
                continue
            comm = ""
            try:
                with open(f"/proc/{entry}/comm", "r") as fh:
                    comm = fh.read().strip().lower()
            except Exception:
                pass
            exe_base = ""
            try:
                exe_base = os.path.basename(
                    os.readlink(f"/proc/{entry}/exe")).lower()
            except Exception:
                pass
            cmdline = ""
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    cmdline = fh.read().replace(b"\x00", b" ").decode(
                        "utf-8", "replace").strip().lower()
            except Exception:
                pass
            if not comm and exe_base:
                comm = exe_base
            if comm or exe_base or cmdline:
                yield pid, comm, uid, exe_base, cmdline

    def _record_attempt(self, uid, app):
        """Report a blocked-app attempt (debounced per user+app)."""
        if not self.on_block:
            return
        name = app.get("name") or app.get("proc_name") or "app"
        try:
            username = pwd.getpwuid(uid).pw_name
        except (KeyError, OverflowError):
            username = str(uid)
        key = (username, name)
        now = time.time()
        if now - self._block_seen.get(key, 0) < ATTEMPT_DEBOUNCE:
            return
        self._block_seen[key] = now
        try:
            self.on_block(username, name, now)
        except Exception as exc:
            sys.stderr.write(f"[monitor] on_block error: {exc}\n")

    @staticmethod
    def _kill(pid):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                return
            except PermissionError:
                return
            time.sleep(0.05)
            try:
                os.kill(pid, 0)  # still alive?
            except OSError:
                return  # gone


# --------------------------------------------------------------------------- #
# Application state
# --------------------------------------------------------------------------- #
class AppState:
    """
    Holds the list of blockable apps and persists them to blocked.json.

    Each app entry is a dict:
        {
          "name": "Firefox",
          "path": "/usr/bin/firefox",
          "proc_name": "firefox",
          "blocked": False,               # current on/off for manual & timer
          "mode": "manual" | "timer" | "schedule",
          "timer_end": None | <epoch seconds>,
          "target_users": [],             # [] = all users, else list of names
          "schedule": [],                 # list of {days, start, end} windows
          "match_type": "process",        # "process" or "commandline"
          "match_terms": ["firefox"]      # names (process) or substrings (cmd)
        }
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.apps = []
        self.rules = []   # auto-block trigger rules (see _normalize_rules)
        self.websites = []  # blocked website domains (machine-wide)
        self.monitor = self._default_monitor()  # website-visit monitoring config
        self.lockdown = {"enabled": False}      # browser incognito lockdown
        self.sync = self._default_sync()        # remote dashboard (GitHub) sync
        self.block_adult = False                # built-in adult-content blocklist
        self.web_schedules = []                 # scheduled website blocks (downtime)
        # "Distractions": sites blocked by default (machine-wide) that the parent
        # can temporarily unlock. free_until = epoch while ALL are lifted ("free
        # time"); allow = {domain: epoch} for per-site temporary allows.
        self.distractions = []
        self.distract_free_until = 0
        self.distract_allow = {}
        self._mtime = None
        self.load()

    @staticmethod
    def _default_sync():
        return {"enabled": False, "repo": "", "branch": "main",
                "path": "data.json", "token": "", "control": False}

    def _normalize_sync(self, value):
        cfg = self._default_sync()
        if isinstance(value, dict):
            cfg["enabled"] = bool(value.get("enabled"))
            cfg["control"] = bool(value.get("control"))
            for k in ("repo", "branch", "path", "token"):
                if value.get(k):
                    cfg[k] = str(value[k]).strip()
        return cfg

    @staticmethod
    def _default_monitor():
        return {
            "enabled": True,        # history is always recorded by the daemon
            "watch": [],            # domains that trigger an alert
            "keywords": [],         # search terms that trigger a safety alert
            "alert_blocked": True,  # email when a child tries a blocked app
            "digest_enabled": False,   # daily summary email
            "digest_hours": 24,        # digest interval
            "alert_new_domains": False,  # alert on never-seen / long-unseen sites
            "new_domain_days": 30,     # "new" if not seen in this many days (0=never-seen only)
            "new_domain_realtime": True,  # also send real-time (else digest-only)
            "new_domain_shared": True,    # dedupe new-site alerts across household machines
            "new_domain_aliases": {},     # local-user -> household-id, for cross-machine merge
            "history_days": 90,        # keep this many days of history (0=forever)
            "email": {"enabled": False, "host": "", "port": 587,
                      "username": "", "password": "", "from": "", "to": "",
                      "quiet_start": "", "quiet_end": ""},
        }

    def _normalize_monitor(self, value):
        mon = self._default_monitor()
        if isinstance(value, dict):
            mon["enabled"] = bool(value.get("enabled"))
            mon["watch"] = [normalize_domain(d) for d in value.get("watch", [])
                            if normalize_domain(d)]
            mon["keywords"] = [k.strip() for k in value.get("keywords", [])
                               if k and k.strip()]
            mon["alert_blocked"] = bool(value.get("alert_blocked", True))
            mon["digest_enabled"] = bool(value.get("digest_enabled", False))
            try:
                mon["digest_hours"] = max(1, int(value.get("digest_hours", 24)))
            except (TypeError, ValueError):
                mon["digest_hours"] = 24
            mon["alert_new_domains"] = bool(value.get("alert_new_domains", False))
            try:
                mon["new_domain_days"] = max(0, int(value.get("new_domain_days", 30)))
            except (TypeError, ValueError):
                mon["new_domain_days"] = 30
            mon["new_domain_realtime"] = bool(
                value.get("new_domain_realtime", True))
            mon["new_domain_shared"] = bool(
                value.get("new_domain_shared", True))
            aliases = value.get("new_domain_aliases") or {}
            clean_aliases = {}
            if isinstance(aliases, dict):
                for k, v in aliases.items():
                    lk, lv = str(k).strip().lower(), str(v).strip().lower()
                    if lk and lv and lk != lv:
                        clean_aliases[lk] = lv
            mon["new_domain_aliases"] = clean_aliases
            try:
                mon["history_days"] = max(0, int(value.get("history_days", 90)))
            except (TypeError, ValueError):
                mon["history_days"] = 90
            email = value.get("email") or {}
            if isinstance(email, dict):
                mon["email"].update({k: email.get(k, mon["email"][k])
                                     for k in mon["email"]})
        return mon

    # -- persistence -------------------------------------------------------- #
    @staticmethod
    def _file_mtime():
        try:
            return os.path.getmtime(BLOCKED_FILE)
        except OSError:
            return None

    @staticmethod
    def _normalize(apps):
        """Fill in defaults for entries written by older versions."""
        for app in apps:
            app.setdefault("blocked", False)
            app.setdefault("mode", "manual")
            app.setdefault("timer_end", None)
            app.setdefault("target_users", [])
            app.setdefault("schedule", [])
            app.setdefault("match_type", "process")
            if not app.get("match_terms"):
                pn = app.get("proc_name")
                app["match_terms"] = [pn] if pn else []
        return apps

    @staticmethod
    def _normalize_rules(rules):
        """
        Auto-block trigger rule:
            {
              "name": "While gaming, block browsers",
              "enabled": True,
              "trigger": "steam",        # proc name that, while running...
              "targets": ["firefox"],    # ...causes these proc names to block
              "block_sites": ["x.com"],  # ...and these websites to be blocked
              "users": []                # [] = any user, else specific names
            }
        Target apps are blocked only for the user(s) running the trigger;
        website blocks are machine-wide (the hosts file is global) but only
        while the trigger is running.
        """
        clean = []
        for r in rules or []:
            if not isinstance(r, dict) or not r.get("trigger"):
                continue
            r.setdefault("name", "")
            r.setdefault("enabled", True)
            r.setdefault("targets", [])
            r.setdefault("users", [])
            r["block_sites"] = [normalize_domain(d) for d in r.get("block_sites", [])
                                if normalize_domain(d)]
            clean.append(r)
        return clean

    @staticmethod
    def _normalize_websites(value):
        out = []
        for d in value or []:
            nd = normalize_domain(d)
            if nd and nd not in out:
                out.append(nd)
        return out

    @staticmethod
    def _normalize_distract_allow(value):
        """Per-site temporary allows: {domain: epoch}. Drops past/invalid ones."""
        out = {}
        if isinstance(value, dict):
            now = int(time.time())
            for k, v in value.items():
                d = normalize_domain(k)
                try:
                    t = int(v)
                except (TypeError, ValueError):
                    continue
                if d and t > now:
                    out[d] = t
        return out

    def _apply_distract(self, data):
        """Load the distraction fields from a parsed blocked.json dict."""
        self.distractions = self._normalize_websites(data.get("distractions"))
        try:
            self.distract_free_until = int(data.get("distract_free_until") or 0)
        except (TypeError, ValueError):
            self.distract_free_until = 0
        self.distract_allow = self._normalize_distract_allow(
            data.get("distract_allow"))

    @staticmethod
    def _normalize_web_schedules(value):
        """Scheduled website blocks: [{name, sites:[domains], schedule:[windows]}]."""
        clean = []
        for s in value or []:
            if not isinstance(s, dict):
                continue
            sites = []
            for d in s.get("sites") or []:
                nd = normalize_domain(d)
                if nd and nd not in sites:
                    sites.append(nd)
            windows = []
            for w in s.get("schedule") or []:
                if not isinstance(w, dict):
                    continue
                days = []
                for d in w.get("days") or []:
                    try:
                        days.append(int(d))
                    except (TypeError, ValueError):
                        pass
                windows.append({"days": days, "start": str(w.get("start", "")),
                                "end": str(w.get("end", ""))})
            if sites and windows:
                clean.append({"name": str(s.get("name", "")),
                              "sites": sites, "schedule": windows})
        return clean

    def load(self):
        data = load_json(BLOCKED_FILE, None)
        if data and isinstance(data, dict) and "apps" in data:
            self.apps = self._normalize(data["apps"])
            self.rules = self._normalize_rules(data.get("rules"))
            self.websites = self._normalize_websites(data.get("websites"))
            self.monitor = self._normalize_monitor(data.get("monitor"))
            self.lockdown = {"enabled": bool(
                (data.get("lockdown") or {}).get("enabled"))}
            self.sync = self._normalize_sync(data.get("sync"))
            self.block_adult = bool(data.get("block_adult"))
            self.web_schedules = self._normalize_web_schedules(
                data.get("web_schedules"))
            self._apply_distract(data)
            self._mtime = self._file_mtime()
        else:
            self.apps = self._default_apps()
            self.rules = []
            self.websites = []
            self.monitor = self._default_monitor()
            self.lockdown = {"enabled": False}
            self.sync = self._default_sync()
            self.block_adult = False
            self.web_schedules = []
            self.distractions = []
            self.distract_free_until = 0
            self.distract_allow = {}
            self.save()

    def reload_if_changed(self):
        """
        Re-read blocked.json if it changed on disk since we last wrote/read it.
        Lets the daemon and the GUI share one blocklist file. Returns True if
        the in-memory state was replaced.
        """
        mtime = self._file_mtime()
        if mtime is None or mtime == self._mtime:
            return False
        data = load_json(BLOCKED_FILE, None)
        if data and isinstance(data, dict) and "apps" in data:
            with self.lock:
                self.apps = self._normalize(data["apps"])
                self.rules = self._normalize_rules(data.get("rules"))
                self.websites = self._normalize_websites(data.get("websites"))
                self.monitor = self._normalize_monitor(data.get("monitor"))
                self.lockdown = {"enabled": bool(
                    (data.get("lockdown") or {}).get("enabled"))}
                self.sync = self._normalize_sync(data.get("sync"))
                self.block_adult = bool(data.get("block_adult"))
                self.web_schedules = self._normalize_web_schedules(
                    data.get("web_schedules"))
                self._apply_distract(data)
                self._mtime = mtime
            return True
        return False

    def save(self):
        with self.lock:
            self.save_locked()

    def save_locked(self):
        save_json(BLOCKED_FILE, {"apps": self.apps, "rules": self.rules,
                                 "websites": self.websites,
                                 "monitor": self.monitor,
                                 "lockdown": self.lockdown,
                                 "sync": self.sync,
                                 "block_adult": self.block_adult,
                                 "web_schedules": self.web_schedules,
                                 "distractions": self.distractions,
                                 "distract_free_until": self.distract_free_until,
                                 "distract_allow": self.distract_allow})
        self._mtime = self._file_mtime()

    @staticmethod
    def _default_apps():
        apps = []
        for name, candidates, terms in DEFAULT_APPS:
            path, _proc = detect_executable(candidates)
            apps.append({
                "name": name,
                "path": path or "",
                "proc_name": terms[0],      # primary runtime process name
                "match_type": "process",
                "match_terms": list(terms),  # all runtime names to match
                "blocked": False,
                "mode": "manual",
                "timer_end": None,
                "target_users": [],
                "schedule": [],
            })
        return apps

    # -- mutations ---------------------------------------------------------- #
    def add_app(self, name, path, match_type="process", match_terms=None):
        """
        Add a custom app.
            match_type == "process"     -> match by executable/process name
            match_type == "commandline" -> match a substring of the command
                                           line (use for PWAs / custom commands)
        """
        if match_type == "commandline":
            terms = [t for t in (match_terms or []) if t]
            proc = (name or (terms[0] if terms else "app")).lower()
        else:
            proc = os.path.basename(path) if path else name.lower()
            terms = [t for t in (match_terms or [proc]) if t]
        with self.lock:
            self.apps.append({
                "name": name,
                "path": path,
                "proc_name": proc,
                "match_type": match_type,
                "match_terms": terms,
                "blocked": False,
                "mode": "manual",
                "timer_end": None,
                "target_users": [],
                "schedule": [],
            })
            self.save_locked()

    def remove_app(self, index):
        with self.lock:
            if 0 <= index < len(self.apps):
                del self.apps[index]
                self.save_locked()

    def apply_block(self, index, mode, minutes=None, target_users=None,
                    schedule=None):
        """
        Apply a block configuration to an app.
            mode == "manual"   -> blocked until unblocked
            mode == "timer"    -> blocked for `minutes`, then auto-unblock
            mode == "schedule" -> blocked during the given weekly windows
        target_users: list of usernames ([] / None = all users).
        """
        with self.lock:
            app = self.apps[index]
            app["target_users"] = list(target_users or [])
            app["mode"] = mode
            if mode == "timer":
                app["blocked"] = True
                app["timer_end"] = time.time() + max(1, int(minutes or 1)) * 60
                app["schedule"] = []
            elif mode == "schedule":
                app["blocked"] = False
                app["timer_end"] = None
                app["schedule"] = list(schedule or [])
            else:  # manual
                app["blocked"] = True
                app["timer_end"] = None
                app["schedule"] = []
            self.save_locked()

    def unblock(self, index):
        with self.lock:
            app = self.apps[index]
            app["blocked"] = False
            app["mode"] = "manual"
            app["timer_end"] = None
            app["schedule"] = []
            self.save_locked()

    def any_blocked(self):
        with self.lock:
            return any(effective_blocked(a) for a in self.apps)

    # -- auto-block rules --------------------------------------------------- #
    def add_rule(self, rule):
        with self.lock:
            self.rules.append(rule)
            self.save_locked()

    def update_rule(self, index, rule):
        with self.lock:
            if 0 <= index < len(self.rules):
                self.rules[index] = rule
                self.save_locked()

    def remove_rule(self, index):
        with self.lock:
            if 0 <= index < len(self.rules):
                del self.rules[index]
                self.save_locked()

    def toggle_rule(self, index, enabled):
        with self.lock:
            if 0 <= index < len(self.rules):
                self.rules[index]["enabled"] = enabled
                self.save_locked()

    # -- blocked websites --------------------------------------------------- #
    def set_websites(self, domains):
        with self.lock:
            self.websites = self._normalize_websites(domains)
            self.save_locked()
            return list(self.websites)

    # -- monitoring --------------------------------------------------------- #
    def set_monitor(self, monitor):
        with self.lock:
            self.monitor = self._normalize_monitor(monitor)
            self.save_locked()
            return dict(self.monitor)

    def set_lockdown(self, enabled):
        with self.lock:
            self.lockdown = {"enabled": bool(enabled)}
            self.save_locked()
            return dict(self.lockdown)

    def set_sync(self, cfg):
        with self.lock:
            self.sync = self._normalize_sync(cfg)
            self.save_locked()
            return dict(self.sync)

    def set_block_adult(self, enabled):
        with self.lock:
            self.block_adult = bool(enabled)
            self.save_locked()
            return self.block_adult

    # -- scheduled website blocks (downtime) -------------------------------- #
    def add_web_schedule(self, sched):
        with self.lock:
            self.web_schedules.append(sched)
            self.web_schedules = self._normalize_web_schedules(self.web_schedules)
            self.save_locked()

    def update_web_schedule(self, index, sched):
        with self.lock:
            if 0 <= index < len(self.web_schedules):
                self.web_schedules[index] = sched
                self.web_schedules = self._normalize_web_schedules(
                    self.web_schedules)
                self.save_locked()

    def remove_web_schedule(self, index):
        with self.lock:
            if 0 <= index < len(self.web_schedules):
                del self.web_schedules[index]
                self.save_locked()

    # -- distractions (blocked by default, grantable) ----------------------- #
    def set_distractions(self, domains):
        with self.lock:
            self.distractions = self._normalize_websites(domains)
            self.save_locked()
            return list(self.distractions)

    def grant_free_time(self, minutes):
        """Lift ALL distraction blocks for `minutes` (0/neg ends free time).
        Returns the epoch it runs until (0 = not active)."""
        try:
            m = int(minutes)
        except (TypeError, ValueError):
            m = 0
        with self.lock:
            self.distract_free_until = int(time.time()) + m * 60 if m > 0 else 0
            self.save_locked()
            return self.distract_free_until

    def end_free_time(self):
        """Re-lock everything now: clear the free-time grant and per-site allows."""
        with self.lock:
            self.distract_free_until = 0
            self.distract_allow = {}
            self.save_locked()

    def allow_distraction(self, domain, minutes):
        """Temporarily allow one distraction domain for `minutes` (0 removes it).
        Returns the normalized domain, or '' if invalid."""
        d = normalize_domain(domain)
        if not d:
            return ""
        try:
            m = int(minutes)
        except (TypeError, ValueError):
            m = 0
        with self.lock:
            if m > 0:
                self.distract_allow[d] = int(time.time()) + m * 60
            else:
                self.distract_allow.pop(d, None)
            self.save_locked()
        return d


def active_distractions(distractions, free_until, allow, now=None):
    """Distraction domains that should be blocked right now: all of them, unless
    a free-time grant is active (then none), minus any with an unexpired per-site
    allow. Pure function of its inputs for easy testing."""
    now = int(now if now is not None else time.time())
    if free_until and now < int(free_until):
        return set()
    allow = allow or {}
    return {d for d in (distractions or []) if int(allow.get(d, 0)) <= now}


# --------------------------------------------------------------------------- #
# Password handling
# --------------------------------------------------------------------------- #
class PasswordManager:
    def __init__(self):
        self.config = load_json(CONFIG_FILE, {})

    @property
    def is_set(self):
        return bool(self.config.get("password_hash"))

    def set_password(self, password):
        self.config["password_hash"] = hash_password(password)
        save_json(CONFIG_FILE, self.config)

    def verify(self, password):
        return self.config.get("password_hash") == hash_password(password)


def prompt_for_password(root, pm: PasswordManager) -> bool:
    """
    Modal gate before the main UI. Returns True if authenticated.
    On first run, prompts to SET a password.
    """
    if not pm.is_set:
        messagebox.showinfo(
            "Welcome to AppBlocker",
            "First run setup.\n\nPlease create a parent password. You'll need "
            "it to unblock apps and change settings.",
        )
        while True:
            pw1 = simpledialog.askstring(
                "Set Password", "Create a password:", show="*", parent=root)
            if pw1 is None:
                return False
            if len(pw1) < 4:
                messagebox.showwarning(
                    "Too short", "Password must be at least 4 characters.")
                continue
            pw2 = simpledialog.askstring(
                "Confirm Password", "Re-enter the password:",
                show="*", parent=root)
            if pw2 is None:
                return False
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords did not match.")
                continue
            pm.set_password(pw1)
            messagebox.showinfo("Done", "Password set. Keep it secret!")
            return True
    else:
        for _ in range(3):
            pw = simpledialog.askstring(
                "AppBlocker — Login", "Enter parent password:",
                show="*", parent=root)
            if pw is None:
                return False
            if pm.verify(pw):
                return True
            messagebox.showerror("Wrong password", "Incorrect. Try again.")
        return False


# --------------------------------------------------------------------------- #
# Main application window
# --------------------------------------------------------------------------- #
class AppBlockerUI:
    def __init__(self, root, state, monitor, pm):
        self.root = root
        self.state = state
        self.monitor = monitor
        self.pm = pm
        self.rows = []  # widgets per app row, rebuilt on refresh
        self.tray_icon = None
        # Human accounts we can target. Only meaningful in system mode (root can
        # kill other users' processes); in user mode blocks apply to self.
        self.users = list_human_users()

        root.title("AppBlocker" + ("  —  System (all users)" if SYSTEM_MODE
                                   else ""))
        root.geometry("720x540")
        root.minsize(640, 480)
        root.configure(bg=COLOR_BG)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_styles()
        self._build_header()
        self._build_toolbar()
        self._build_list()
        self._build_footer()

        self.refresh()
        self._tick()  # start countdown / status refresher

        # Make sure the window comes to the foreground on launch (some desktops,
        # especially under pkexec, open it behind other windows).
        self.root.after(80, lambda: self._to_front(self.root))

        if HAS_TRAY:
            self._setup_tray()

    @staticmethod
    def _to_front(win):
        """Force a window to the foreground and give it focus."""
        try:
            win.deiconify()
            win.lift()
            win.attributes("-topmost", True)
            win.after(400, lambda: win.attributes("-topmost", False))
            win.focus_force()
        except Exception:
            pass

    def _present(self, win, grab=True):
        """Standard setup for a dialog: modal, on top, focused, foreground."""
        try:
            win.transient(self.root)
            if grab:
                win.grab_set()
        except Exception:
            pass
        self._to_front(win)

    @staticmethod
    def _scroll_body(win):
        """
        Return a frame inside a vertical-scroll area filling `win`. Pack the
        bottom action bar BEFORE calling this so it stays pinned; put the form
        content into the returned frame so it scrolls if it's taller than the
        window (keeps everything reachable on small screens).
        """
        outer = tk.Frame(win, bg=COLOR_BG)
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=COLOR_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=COLOR_BG)
        body.bind("<Configure>",
                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        bid = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(bid, width=e.width))
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return body

    # -- styling ------------------------------------------------------------ #
    def _build_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background="white", relief="flat")
        style.configure("TLabel", background=COLOR_BG)
        style.configure("Header.TLabel", background=COLOR_HEADER,
                        foreground="white", font=("Helvetica", 18, "bold"))
        style.configure("Sub.TLabel", background=COLOR_HEADER,
                        foreground="#bdc3c7", font=("Helvetica", 10))

    def _build_header(self):
        header = tk.Frame(self.root, bg=COLOR_HEADER)
        header.pack(fill="x", side="top")
        tk.Label(header, text="🔒 AppBlocker", bg=COLOR_HEADER, fg="white",
                 font=("Helvetica", 20, "bold")).pack(
                     side="left", padx=16, pady=12)
        self.status_lbl = tk.Label(
            header, text="", bg=COLOR_HEADER, fg="#ecf0f1",
            font=("Helvetica", 11))
        self.status_lbl.pack(side="right", padx=16)

    def _build_toolbar(self):
        # A flow layout that wraps buttons onto more rows when the window is
        # narrow, so no button is ever cut off regardless of window size.
        bar = tk.Frame(self.root, bg=COLOR_BG)
        bar.pack(fill="x", padx=10, pady=(10, 2))
        self._toolbar = bar
        self._toolbar_buttons = []
        self._toolbar_width = 0

        def mk(text, cmd, color, active):
            b = tk.Button(bar, text=text, command=cmd, bg=color, fg="white",
                          activebackground=active, font=("Helvetica", 11),
                          relief="flat", padx=10, pady=7, cursor="hand2")
            self._toolbar_buttons.append(b)

        mk("⚡ Quick Block: Browsers", self.quick_block_browsers,
           COLOR_BLOCKED, "#922b21")
        mk("🔓 Unblock All", self.unblock_all, COLOR_ACTIVE, "#1e8449")
        mk("➕ Add App", self.add_app_dialog, COLOR_ACCENT, "#1f618d")
        mk("⛓ Auto-Block Rules", self.rules_dialog, "#8e44ad", "#6c3483")
        if SYSTEM_MODE:
            mk("🌐 Block Websites", self.websites_dialog, "#16a085", "#0e6655")
            mk("🎯 Distractions", self.distractions_dialog, "#d35400", "#a04000")
            mk("⏰ Site Schedules", self.web_schedule_dialog, "#11998e", "#0b6b64")
            mk("📊 Activity", self.activity_dialog, "#2c3e50", "#1b2631")
            mk("🔒 Lockdown", self.lockdown_dialog, "#7f8c8d", "#616a6b")
        mk("💾 Backup", self.backup_dialog, "#34495e", "#2c3e50")

        bar.bind("<Configure>", lambda e: self._reflow_toolbar(e.width))
        self.root.after(0, lambda: self._reflow_toolbar(bar.winfo_width()))

    def _reflow_toolbar(self, width):
        if width <= 1 or abs(width - self._toolbar_width) < 4:
            return  # avoid needless reflow loops
        self._toolbar_width = width
        row = col = 0
        used = 0
        for b in self._toolbar_buttons:
            b.grid_forget()
        for b in self._toolbar_buttons:
            bw = b.winfo_reqwidth() + 8
            if col > 0 and used + bw > width:
                row += 1
                col = 0
                used = 0
            b.grid(row=row, column=col, padx=3, pady=3, sticky="w")
            col += 1
            used += bw

    def _build_list(self):
        container = tk.Frame(self.root, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=14, pady=6)

        canvas = tk.Canvas(container, bg=COLOR_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical",
                                  command=canvas.yview)
        self.list_frame = tk.Frame(canvas, bg=COLOR_BG)

        self.list_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        self._canvas_window = canvas.create_window(
            (0, 0), window=self.list_frame, anchor="nw")
        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(self._canvas_window, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_footer(self):
        footer = tk.Frame(self.root, bg=COLOR_BG)
        footer.pack(fill="x", side="bottom", padx=14, pady=8)
        if SYSTEM_MODE:
            msg = ("System-wide mode (root) — blocking is enforced for ALL "
                   "users by the background service.")
        else:
            msg = "Monitor running — blocked apps are killed within a few seconds."
        tk.Label(footer, text=msg, bg=COLOR_BG, fg="#7f8c8d",
                 font=("Helvetica", 9)).pack(side="left")
        tk.Button(footer, text="Change Password",
                  command=self.change_password, relief="flat",
                  bg=COLOR_BG, fg=COLOR_ACCENT, cursor="hand2",
                  font=("Helvetica", 9, "underline")).pack(side="right")

    # -- rendering ---------------------------------------------------------- #
    def refresh(self):
        for child in self.list_frame.winfo_children():
            child.destroy()
        self.rows = []

        with self.state.lock:
            apps = list(self.state.apps)

        # Column header
        head = tk.Frame(self.list_frame, bg=COLOR_BG)
        head.pack(fill="x", pady=(0, 4))
        tk.Label(head, text="Application", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 10, "bold"), width=18, anchor="w").pack(
                     side="left", padx=(8, 0))
        tk.Label(head, text="Status", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 10, "bold"), width=14).pack(side="right",
                                                                padx=(0, 8))

        for idx, app in enumerate(apps):
            self._render_row(idx, app)

        self._update_global_status()

    @staticmethod
    def _is_configured(app):
        """Does this app currently have an active block rule of any kind?"""
        if app.get("mode") == "schedule":
            return bool(app.get("schedule"))
        return bool(app.get("blocked"))

    def _row_colors(self, app):
        """(strip/status color) for an app, by its right-now state."""
        if effective_blocked(app):
            return COLOR_BLOCKED
        if app.get("mode") == "schedule" and app.get("schedule"):
            return COLOR_SCHEDULE
        return COLOR_ACTIVE

    def _render_row(self, idx, app):
        eff = effective_blocked(app)
        color = self._row_colors(app)
        card = tk.Frame(self.list_frame, bg="white", bd=0,
                        highlightbackground="#dfe4ea", highlightthickness=1)
        card.pack(fill="x", pady=3, ipady=4)

        # left: color strip
        strip = tk.Frame(card, bg=color, width=6)
        strip.pack(side="left", fill="y")

        # right: status + buttons — packed BEFORE the expanding info block so
        # they are always reserved space and never pushed off a narrow window.
        right = tk.Frame(card, bg="white")
        right.pack(side="right", padx=10)

        # name + path + (target/schedule detail)
        info = tk.Frame(card, bg="white")
        info.pack(side="left", fill="x", expand=True, padx=10, pady=4)
        tk.Label(info, text=app["name"], bg="white", fg=COLOR_HEADER,
                 font=("Helvetica", 12, "bold"), anchor="w").pack(
                     fill="x")
        path_text = app["path"] or f"(not installed — expects '{app['proc_name']}')"
        tk.Label(info, text=path_text, bg="white", fg="#95a5a6",
                 font=("Helvetica", 9), anchor="w").pack(fill="x")

        detail = self._row_detail(app)
        if detail:
            tk.Label(info, text=detail, bg="white", fg="#7f8c8d",
                     font=("Helvetica", 9, "italic"), anchor="w").pack(fill="x")

        status_lbl = tk.Label(
            right, text=self._status_text(app),
            bg=color, fg="white", font=("Helvetica", 10, "bold"),
            padx=10, pady=3)
        status_lbl.pack(side="top", pady=(0, 4))

        btns = tk.Frame(right, bg="white")
        btns.pack(side="top")
        if self._is_configured(app):
            tk.Button(btns, text="Unblock", command=lambda i=idx: self.unblock(i),
                      bg=COLOR_ACTIVE, fg="white", relief="flat",
                      font=("Helvetica", 9, "bold"), padx=8, cursor="hand2"
                      ).pack(side="left", padx=2)
        else:
            tk.Button(btns, text="Block", command=lambda i=idx: self.block(i),
                      bg=COLOR_BLOCKED, fg="white", relief="flat",
                      font=("Helvetica", 9, "bold"), padx=8, cursor="hand2"
                      ).pack(side="left", padx=2)
        tk.Button(btns, text="✕", command=lambda i=idx: self.remove(i),
                  bg="white", fg="#95a5a6", relief="flat",
                  font=("Helvetica", 9), cursor="hand2").pack(side="left")

        self.rows.append({"status_lbl": status_lbl, "idx": idx, "eff": eff})

    def _row_detail(self, app):
        """Small italic subtitle summarizing target users and schedule."""
        bits = []
        if SYSTEM_MODE:
            bits.append(f"Users: {app_target_label(app)}")
        if app.get("mode") == "schedule" and app.get("schedule"):
            bits.append(f"Schedule: {schedule_summary(app['schedule'])}")
        if app.get("match_type") == "commandline":
            bits.append("Web app: " + ", ".join(app_match_terms(app)))
        return "   ·   ".join(bits)

    @staticmethod
    def _status_text(app):
        mode = app.get("mode", "manual")
        if mode == "schedule":
            if not app.get("schedule"):
                return "● Active"
            return ("🔒 Blocked now" if schedule_active(app["schedule"])
                    else "⏰ Scheduled")
        if not app.get("blocked"):
            return "● Active"
        if mode == "timer" and app.get("timer_end"):
            remaining = int(app["timer_end"] - time.time())
            if remaining < 0:
                remaining = 0
            mm, ss = divmod(remaining, 60)
            hh, mm = divmod(mm, 60)
            if hh:
                return f"⏱ {hh:d}:{mm:02d}:{ss:02d}"
            return f"⏱ {mm:d}:{ss:02d}"
        return "🔒 Blocked"

    def _update_global_status(self):
        blocked = self.state.any_blocked()
        if blocked:
            self.status_lbl.config(text="● BLOCKING ACTIVE", fg="#e74c3c")
        else:
            self.status_lbl.config(text="● All apps active", fg="#2ecc71")
        if self.tray_icon:
            self._update_tray_icon(blocked)

    # -- periodic tick ------------------------------------------------------ #
    def _tick(self):
        """Update countdown labels without rebuilding the whole list."""
        # In system mode the daemon may also be editing the shared blocklist
        # (e.g. expiring a timer); pick up its changes.
        if self.state.reload_if_changed():
            self.refresh()
            self.root.after(1000, self._tick)
            return
        with self.state.lock:
            apps = list(self.state.apps)
        needs_rebuild = False
        for row in self.rows:
            idx = row["idx"]
            if idx >= len(apps):
                needs_rebuild = True
                break
            app = apps[idx]
            # If the effective state flipped (timer expired, or a schedule
            # window started/ended), recolor by rebuilding the whole list.
            if effective_blocked(app) != row["eff"]:
                needs_rebuild = True
                break
            row["status_lbl"].config(text=self._status_text(app))
        if needs_rebuild:
            self.refresh()
        self._update_global_status()
        self.root.after(1000, self._tick)

    # -- actions ------------------------------------------------------------ #
    def block(self, idx):
        with self.state.lock:
            app = dict(self.state.apps[idx])
        cfg = self._ask_block_config(app)
        if cfg is None:  # cancelled
            return
        self.state.apply_block(
            idx, cfg["mode"], minutes=cfg.get("minutes"),
            target_users=cfg.get("target_users"), schedule=cfg.get("schedule"))
        self.refresh()

    def unblock(self, idx):
        if not self._authenticate("Unblocking requires the parent password."):
            return
        self.state.unblock(idx)
        self.refresh()

    def remove(self, idx):
        with self.state.lock:
            name = self.state.apps[idx]["name"] if idx < len(self.state.apps) else ""
        if not messagebox.askyesno("Remove", f"Remove '{name}' from the list?"):
            return
        self.state.remove_app(idx)
        self.refresh()

    def quick_block_browsers(self):
        """Block every listed app with one shared block configuration."""
        cfg = self._ask_block_config(None, title="Quick Block Browsers")
        if cfg is None:
            return
        with self.state.lock:
            for i in range(len(self.state.apps)):
                self.state.apply_block(
                    i, cfg["mode"], minutes=cfg.get("minutes"),
                    target_users=cfg.get("target_users"),
                    schedule=cfg.get("schedule"))
        self.refresh()

    def unblock_all(self):
        if not self._authenticate("Unblocking requires the parent password."):
            return
        with self.state.lock:
            for i in range(len(self.state.apps)):
                self.state.unblock(i)
        self.refresh()

    def add_app_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Add Application")
        win.configure(bg=COLOR_BG)
        win.geometry("500x460")
        win.minsize(420, 360)
        self._present(win)

        # Pin the action bar to the bottom first, then a scrollable body so the
        # Add/Cancel buttons are always reachable regardless of window size.
        btnbar = tk.Frame(win, bg=COLOR_BG)
        btnbar.pack(side="bottom", fill="x", padx=18, pady=14)
        outer = self._scroll_body(win)

        tk.Label(outer, text="Add a custom app to block", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 13, "bold")).pack(
                     pady=(14, 6))

        kind = tk.StringVar(value="process")
        body = tk.Frame(outer, bg=COLOR_BG)
        body.pack(fill="x", padx=18)

        tk.Label(body, text="Name:", bg=COLOR_BG).grid(
            row=0, column=0, sticky="w", pady=4)
        name_var = tk.StringVar()
        tk.Entry(body, textvariable=name_var, width=40).grid(
            row=0, column=1, columnspan=2, pady=4, sticky="we")
        body.columnconfigure(1, weight=1)

        tk.Radiobutton(outer, text="An installed program (pick its file)",
                       variable=kind, value="process", bg=COLOR_BG,
                       anchor="w").pack(fill="x", padx=18, pady=(8, 0))

        prog = tk.Frame(outer, bg=COLOR_BG)
        prog.pack(fill="x", padx=36)
        path_var = tk.StringVar()
        tk.Entry(prog, textvariable=path_var).pack(
            side="left", fill="x", expand=True)

        def browse():
            p = filedialog.askopenfilename(title="Select the program")
            if p:
                path_var.set(p)
                kind.set("process")
                if not name_var.get():
                    name_var.set(os.path.basename(p).title())

        tk.Button(prog, text="Browse…", command=browse, relief="flat",
                  bg=COLOR_ACCENT, fg="white", cursor="hand2").pack(
                      side="left", padx=(6, 0))

        tk.Radiobutton(outer, text="A web app / PWA, or a custom command",
                       variable=kind, value="commandline", bg=COLOR_BG,
                       anchor="w").pack(fill="x", padx=18, pady=(10, 0))
        cmd = tk.Frame(outer, bg=COLOR_BG)
        cmd.pack(fill="x", padx=36)
        match_var = tk.StringVar()
        tk.Entry(cmd, textvariable=match_var).pack(fill="x")
        tk.Label(outer, text="Enter the web address (or any unique text from the "
                 "launch command). A PWA on the desktop is your browser opened "
                 "with a web address, so paste that address here — e.g. "
                 "youtube.com or app.roblox.com.", bg=COLOR_BG, fg="#7f8c8d",
                 wraplength=440, justify="left").pack(padx=20, pady=(2, 0))

        def save():
            name = name_var.get().strip()
            if not name:
                messagebox.showwarning("Missing", "Please enter a name.",
                                       parent=win)
                return
            if kind.get() == "commandline":
                term = match_var.get().strip()
                if not term:
                    messagebox.showwarning(
                        "Missing", "Enter the web address / command text to "
                        "match.", parent=win)
                    return
                self.state.add_app(name, "", match_type="commandline",
                                   match_terms=[term])
            else:
                path = path_var.get().strip()
                if not path:
                    detected = which(name.lower())
                    if detected:
                        path = detected
                self.state.add_app(name, path)
            win.destroy()
            self.refresh()

        # `btnbar` was pinned to the bottom before the scrollable body above.
        tk.Button(btnbar, text="Add", command=save, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(btnbar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    # -- auto-block rules UI ------------------------------------------------ #
    def _app_choices(self):
        with self.state.lock:
            return [(a.get("name", ""), a.get("proc_name", ""))
                    for a in self.state.apps if a.get("proc_name")]

    def _proc_to_name(self):
        return {proc.lower(): name for name, proc in self._app_choices()}

    def _rule_summary(self, rule):
        p2n = self._proc_to_name()
        trig = rule.get("trigger", "")
        trig_name = p2n.get(trig.lower(), trig)
        targets = rule.get("targets", [])
        parts = [p2n.get(t.lower(), t) for t in targets]
        sites = rule.get("block_sites") or []
        if sites:
            parts.append("websites: " + ", ".join(sites))
        what = ", ".join(parts) or "(nothing)"
        who = ", ".join(rule.get("users") or []) or "any user"
        return f"While {trig_name} is running  →  block {what}\nfor {who}"

    def rules_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Auto-Block Rules")
        win.configure(bg=COLOR_BG)
        win.geometry("560x460")
        self._present(win)

        tk.Label(win, text="Auto-Block Rules", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text="While a chosen app is running for a user, the apps "
                 "you pick get blocked for that same user.", bg=COLOR_BG,
                 fg="#7f8c8d", wraplength=520, justify="left").pack(
                     padx=16, pady=(0, 8))

        # Pin the action bar to the bottom FIRST so "Add Rule"/"Close" are
        # always visible regardless of how many rules are listed.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=14, pady=12)

        # Scrollable list so many rules never push the buttons off-screen.
        container = tk.Frame(win, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=14)
        canvas = tk.Canvas(container, bg=COLOR_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        listwrap = tk.Frame(canvas, bg=COLOR_BG)
        listwrap.bind("<Configure>",
                      lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win_id = canvas.create_window((0, 0), window=listwrap, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(win_id, width=e.width))
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        def render():
            for c in listwrap.winfo_children():
                c.destroy()
            with self.state.lock:
                rules = list(self.state.rules)
            if not rules:
                tk.Label(listwrap, text="No rules yet. Click “Add Rule”.",
                         bg=COLOR_BG, fg="#95a5a6").pack(pady=20)
                return
            for i, rule in enumerate(rules):
                card = tk.Frame(listwrap, bg="white", highlightbackground="#dfe4ea",
                                highlightthickness=1)
                card.pack(fill="x", pady=3)
                en = tk.BooleanVar(value=rule.get("enabled", True))
                tk.Checkbutton(
                    card, variable=en, bg="white",
                    command=lambda idx=i, v=en: self._toggle_rule(idx, v, render)
                ).pack(side="left", padx=4)
                # Pack the fixed action buttons BEFORE the expanding summary so
                # they can never be squeezed off the right edge.
                tk.Button(card, text="✕", relief="flat", bg="white", fg="#95a5a6",
                          cursor="hand2",
                          command=lambda idx=i: self._delete_rule(idx, render)
                          ).pack(side="right", padx=4)
                tk.Button(card, text="Edit", relief="flat", bg="white",
                          fg=COLOR_ACCENT, cursor="hand2",
                          command=lambda idx=i: self._edit_rule(win, idx, render)
                          ).pack(side="right")
                tk.Label(card, text=self._rule_summary(rule), bg="white",
                         fg=COLOR_HEADER, justify="left", anchor="w",
                         font=("Helvetica", 10)).pack(
                             side="left", fill="x", expand=True, padx=6, pady=6)

        tk.Button(bar, text="＋ Add Rule",
                  command=lambda: self._edit_rule(win, None, render),
                  bg="#8e44ad", fg="white", relief="flat", padx=14, pady=6,
                  cursor="hand2").pack(side="left")
        tk.Button(bar, text="Close", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right")
        render()

    def _toggle_rule(self, idx, var, on_done):
        if not var.get():  # disabling a protection -> require the parent
            if not self._authenticate("Disabling a rule requires the password."):
                var.set(True)
                return
        self.state.toggle_rule(idx, var.get())
        on_done()

    def _delete_rule(self, idx, on_done):
        if not self._authenticate("Deleting a rule requires the password."):
            return
        self.state.remove_rule(idx)
        on_done()

    def _edit_rule(self, parent, index, on_done):
        choices = self._app_choices()
        if not choices:
            messagebox.showinfo("Add apps first",
                                "Add the apps you want to use before creating "
                                "a rule.", parent=parent)
            return
        with self.state.lock:
            existing = dict(self.state.rules[index]) if index is not None else {}
        name_to_proc = {name: proc for name, proc in choices}
        proc_to_name = {proc.lower(): name for name, proc in choices}

        win = tk.Toplevel(parent)
        win.title("Edit Rule" if index is not None else "New Rule")
        win.configure(bg=COLOR_BG)
        win.geometry("460x600")
        win.minsize(380, 360)
        self._present(win)

        # Pin the Save/Cancel bar to the bottom, then put the (potentially long)
        # form in a scrollable body so Save is always reachable.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)
        body = self._scroll_body(win)

        tk.Label(body, text="When this app is running…", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(14, 2))
        trigger_var = tk.StringVar()
        cur_trig = existing.get("trigger", "")
        trigger_var.set(proc_to_name.get(cur_trig.lower(),
                                          choices[0][0] if choices else ""))
        ttk.Combobox(body, textvariable=trigger_var,
                     values=[n for n, _ in choices], state="readonly").pack(
                         fill="x", padx=18)

        tk.Label(body, text="…automatically block these apps:", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(12, 2))
        tgt_wrap = tk.Frame(body, bg=COLOR_BG)
        tgt_wrap.pack(fill="x", padx=24)
        cur_targets = {t.lower() for t in existing.get("targets", [])}
        target_vars = []
        for name, proc in choices:
            v = tk.BooleanVar(value=proc.lower() in cur_targets)
            tk.Checkbutton(tgt_wrap, text=name, variable=v, bg=COLOR_BG,
                           anchor="w").pack(fill="x")
            target_vars.append((proc, v))

        sites_var = None
        if SYSTEM_MODE:
            tk.Label(body, text="…and block these websites (comma-separated):",
                     bg=COLOR_BG, fg=COLOR_HEADER,
                     font=("Helvetica", 11, "bold")).pack(
                         anchor="w", padx=18, pady=(12, 2))
            sites_var = tk.StringVar(
                value=", ".join(existing.get("block_sites") or []))
            tk.Entry(body, textvariable=sites_var).pack(fill="x", padx=24)
            tk.Label(body, text="e.g. youtube.com, tiktok.com — blocked for the "
                     "whole computer while the trigger runs.", bg=COLOR_BG,
                     fg="#7f8c8d", wraplength=400, justify="left").pack(
                         anchor="w", padx=24)

        # users (system mode)
        user_vars = {}
        if SYSTEM_MODE:
            tk.Label(body, text="For these users:", bg=COLOR_BG, fg=COLOR_HEADER,
                     font=("Helvetica", 11, "bold")).pack(
                         anchor="w", padx=18, pady=(12, 2))
            cur_users = set(existing.get("users") or [])
            any_var = tk.BooleanVar(value=not cur_users)

            def toggle_any():
                if any_var.get():
                    for v in user_vars.values():
                        v.set(False)

            tk.Checkbutton(body, text="Any user", variable=any_var,
                           command=toggle_any, bg=COLOR_BG, anchor="w").pack(
                               fill="x", padx=24)
            ufr = tk.Frame(body, bg=COLOR_BG)
            ufr.pack(fill="x", padx=40)
            for uname, _uid in self.users:
                v = tk.BooleanVar(value=uname in cur_users)
                tk.Checkbutton(ufr, text=uname, variable=v,
                               command=lambda: any_var.set(False), bg=COLOR_BG,
                               anchor="w").pack(fill="x")
                user_vars[uname] = v

        name_var = tk.StringVar(value=existing.get("name", ""))
        nfr = tk.Frame(body, bg=COLOR_BG)
        nfr.pack(fill="x", padx=18, pady=(12, 0))
        tk.Label(nfr, text="Label (optional):", bg=COLOR_BG).pack(side="left")
        tk.Entry(nfr, textvariable=name_var).pack(side="left", fill="x",
                                                  expand=True, padx=6)

        def save():
            trig_proc = name_to_proc.get(trigger_var.get(), "")
            if not trig_proc:
                messagebox.showwarning("Pick a trigger",
                                       "Choose the app that triggers the rule.",
                                       parent=win)
                return
            targets = [proc for proc, v in target_vars if v.get()]
            sites = []
            if sites_var is not None:
                sites = [normalize_domain(s) for s in sites_var.get().replace(
                    ";", ",").split(",") if normalize_domain(s)]
            if not targets and not sites:
                messagebox.showwarning(
                    "Nothing to block",
                    "Choose at least one app or website to block.", parent=win)
                return
            rule = {
                "name": name_var.get().strip(),
                "enabled": True,
                "trigger": trig_proc,
                "targets": targets,
                "block_sites": sites,
                "users": [u for u, v in user_vars.items() if v.get()],
            }
            if index is None:
                self.state.add_rule(rule)
            else:
                self.state.update_rule(index, rule)
            win.destroy()
            on_done()

        # `bar` was pinned to the bottom before the scrollable body above.
        tk.Button(bar, text="Save Rule", command=save, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    # -- website monitoring UI --------------------------------------------- #
    def lockdown_dialog(self):
        with self.state.lock:
            cur = self.state.lockdown.get("enabled", False)
        win = tk.Toplevel(self.root)
        win.title("Browser Lockdown")
        win.configure(bg=COLOR_BG)
        win.geometry("460x340")
        win.minsize(400, 300)
        self._present(win)

        tk.Label(win, text="🔒 Browser Lockdown", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 6))
        var = tk.BooleanVar(value=cur)
        tk.Checkbutton(
            win, variable=var, bg=COLOR_BG, anchor="w",
            font=("Helvetica", 11),
            text="Disable private/incognito browsing and block clearing of "
                 "history").pack(fill="x", padx=20)
        tk.Label(win, text="Applies to Chrome, Chromium, Brave and Firefox on "
                 "this computer, for all users, using each browser's official "
                 "policy system. Takes effect after the browser is restarted. "
                 "Blocking history-deletion applies to Chrome/Chromium/Brave.\n\n"
                 "This makes the Activity monitoring reliable — a child can't "
                 "hide browsing with incognito or by clearing history.",
                 bg=COLOR_BG, fg="#7f8c8d", wraplength=410,
                 justify="left").pack(padx=20, pady=(8, 0))

        def save():
            self.state.set_lockdown(var.get())
            apply_browser_lockdown(var.get())  # apply immediately (we are root)
            messagebox.showinfo(
                "Saved", "Lockdown " + ("enabled." if var.get() else "disabled.")
                + "\nRestart open browsers for it to take effect.", parent=win)
            win.destroy()

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=14)
        tk.Button(bar, text="Save", command=save, bg=COLOR_ACTIVE, fg="white",
                  relief="flat", padx=16, pady=6, cursor="hand2").pack(
                      side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    def sync_dialog(self):
        with self.state.lock:
            cfg = dict(self.state.sync)
        win = tk.Toplevel(self.root)
        win.title("Remote Dashboard (GitHub)")
        win.configure(bg=COLOR_BG)
        win.geometry("520x540")
        win.minsize(440, 380)
        self._present(win)

        # Pin the action bar first, then a scrollable body so Save/Sync/Cancel
        # stay reachable at any window size.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=16, pady=14)
        body = self._scroll_body(win)

        tk.Label(body, text="☁ Remote Dashboard", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(body, text="This machine pushes the activity to a PRIVATE GitHub "
                 "repo as data.json. Open the dashboard page (GitHub Pages) on "
                 "your phone/PC and it reads that data with your own token — the "
                 "data is never public.", bg=COLOR_BG, fg="#7f8c8d",
                 wraplength=470, justify="left").pack(padx=16, pady=(0, 8))

        enabled = tk.BooleanVar(value=cfg.get("enabled", False))
        tk.Checkbutton(body, text="Enable pushing activity to GitHub",
                       variable=enabled, bg=COLOR_BG,
                       font=("Helvetica", 11, "bold")).pack(anchor="w", padx=16)

        form = tk.Frame(body, bg=COLOR_BG)
        form.pack(fill="x", padx=16, pady=(6, 0))
        fields = [("Private repo (owner/name)", "repo"), ("Branch", "branch"),
                  ("File path", "path"), ("Write token", "token")]
        vars_ = {}
        for i, (label, key) in enumerate(fields):
            tk.Label(form, text=label + ":", bg=COLOR_BG).grid(
                row=i, column=0, sticky="w", pady=3)
            v = tk.StringVar(value=str(cfg.get(key, "") or ""))
            show = "*" if key == "token" else None
            tk.Entry(form, textvariable=v, width=34, show=show).grid(
                row=i, column=1, sticky="we", pady=3)
            vars_[key] = v
        form.columnconfigure(1, weight=1)
        tk.Label(body, text="Token: a fine-grained GitHub token limited to that "
                 "one private repo with Contents: Read and write. Keep it secret; "
                 "it's stored root-only on this machine.", bg=COLOR_BG,
                 fg="#7f8c8d", wraplength=470, justify="left").pack(
                     padx=16, pady=(6, 0))

        control = tk.BooleanVar(value=cfg.get("control", False))
        tk.Checkbutton(body, text="Allow remote control from the dashboard",
                       variable=control, bg=COLOR_BG,
                       font=("Helvetica", 11, "bold")).pack(
                           anchor="w", padx=16, pady=(10, 0))
        tk.Label(body, text="When on, the daemon also checks the repo for "
                 "commands from the dashboard (block/unblock apps, block "
                 "websites, panic buttons, lockdown) and applies them within a "
                 "minute. The dashboard needs the same read+write token. Leave "
                 "off for a view-only dashboard.", bg=COLOR_BG, fg="#7f8c8d",
                 wraplength=470, justify="left").pack(padx=16, pady=(0, 4))

        status = tk.Label(body, text="", bg=COLOR_BG, fg=COLOR_HEADER,
                          wraplength=470, justify="left")
        status.pack(padx=16, pady=(8, 0))

        def collect():
            return {"enabled": enabled.get(),
                    "control": control.get(),
                    "repo": vars_["repo"].get().strip(),
                    "branch": vars_["branch"].get().strip() or "main",
                    "path": vars_["path"].get().strip() or "data.json",
                    "token": vars_["token"].get().strip()}

        def save():
            self.state.set_sync(collect())
            messagebox.showinfo("Saved", "Dashboard settings saved.", parent=win)
            win.destroy()

        def sync_now():
            self.state.set_sync(collect())
            status.config(text="Pushing…")
            win.update_idletasks()
            try:
                n = push_reports_to_github(
                    collect(), build_report_data(HistoryStore(), state=self.state))
                status.config(text=f"✓ Pushed {n} bytes to {collect()['repo']}.")
            except Exception as exc:
                status.config(text=f"✗ {exc}")

        # `bar` was pinned to the bottom before the scrollable body above.
        tk.Button(bar, text="Save", command=save, bg=COLOR_ACTIVE, fg="white",
                  relief="flat", padx=16, pady=6, cursor="hand2").pack(
                      side="right")
        tk.Button(bar, text="Sync now", command=sync_now, bg=COLOR_ACCENT,
                  fg="white", relief="flat", padx=12, pady=6,
                  cursor="hand2").pack(side="right", padx=8)
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="left")

    def activity_dialog(self):
        store = HistoryStore()
        win = tk.Toplevel(self.root)
        win.title("Website Activity")
        win.configure(bg=COLOR_BG)
        win.geometry("820x640")
        win.minsize(560, 420)
        self._present(win, grab=False)  # non-modal so filters stay interactive

        # Bottom action bar is packed FIRST (side=bottom) so it is always
        # visible even when the tables above are tall / the window is small.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=12, pady=10)

        # Filters row
        top = tk.Frame(win, bg=COLOR_BG)
        top.pack(fill="x", padx=12, pady=(12, 4))
        tk.Label(top, text="User:", bg=COLOR_BG).pack(side="left")
        users = ["All users"] + store.users()
        user_var = tk.StringVar(value="All users")
        ttk.Combobox(top, textvariable=user_var, values=users, width=12,
                     state="readonly").pack(side="left", padx=(2, 8))
        today = time.strftime("%Y-%m-%d")
        tk.Label(top, text="From:", bg=COLOR_BG).pack(side="left")
        from_var = tk.StringVar(value=today)
        tk.Entry(top, textvariable=from_var, width=11).pack(side="left", padx=2)
        tk.Label(top, text="To:", bg=COLOR_BG).pack(side="left")
        to_var = tk.StringVar(value=today)
        tk.Entry(top, textvariable=to_var, width=11).pack(side="left", padx=2)
        tk.Label(top, text="Site:", bg=COLOR_BG).pack(side="left", padx=(8, 0))
        site_var = tk.StringVar()
        tk.Entry(top, textvariable=site_var, width=14).pack(side="left", padx=2)
        tk.Label(top, text="(dates blank = all time)", bg=COLOR_BG,
                 fg="#95a5a6", font=("Helvetica", 8)).pack(side="left", padx=6)

        # Stats (top sites by approx time) + searches + detailed visit list
        mid = tk.Frame(win, bg=COLOR_BG)
        mid.pack(fill="both", expand=True, padx=12, pady=6)

        tk.Label(mid, text="Time per site (approx.)", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 10, "bold")).pack(
                     anchor="w")
        stats = ttk.Treeview(mid, columns=("site", "visits", "time"),
                             show="headings", height=6)
        for c, t, w in (("site", "Site", 320), ("visits", "Visits", 80),
                        ("time", "Approx. time", 120)):
            stats.heading(c, text=t)
            stats.column(c, width=w, anchor="w")
        stats.pack(fill="x")

        tk.Label(mid, text="Searches", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(8, 0))
        searches = ttk.Treeview(mid, columns=("when", "user", "site", "q"),
                                show="headings", height=5)
        for c, t, w in (("when", "When", 130), ("user", "User", 90),
                        ("site", "Where", 130), ("q", "Searched for", 340)):
            searches.heading(c, text=t)
            searches.column(c, width=w, anchor="w")
        searches.pack(fill="x")

        tk.Label(mid, text="Blocked-app attempts", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(8, 0))
        attempts = ttk.Treeview(mid, columns=("when", "user", "app"),
                                show="headings", height=4)
        for c, t, w in (("when", "When", 150), ("user", "User", 110),
                        ("app", "Tried to open", 300)):
            attempts.heading(c, text=t)
            attempts.column(c, width=w, anchor="w")
        attempts.pack(fill="x")

        tk.Label(mid, text="Visits (most recent first)", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 10, "bold")).pack(
                     anchor="w", pady=(8, 0))
        cols = ("when", "user", "site")
        tree = ttk.Treeview(mid, columns=cols, show="headings")
        for c, t, w in (("when", "When", 150), ("user", "User", 110),
                        ("site", "Page", 420)):
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        def fmt_dur(sec):
            m = sec // 60
            if m >= 60:
                return f"{m // 60}h {m % 60}m"
            return f"{m}m" if m else "<1m"

        def refresh():
            user = user_var.get()
            start = from_var.get().strip() or None
            end = to_var.get().strip() or None
            try:
                rows = store.query(username=user,
                                   domain_like=site_var.get().strip(),
                                   start_day=start, end_day=end)
                durs = store.site_durations(username=user, start_day=start,
                                            end_day=end)
                atts = store.attempts(username=user, start_day=start,
                                      end_day=end)
            except Exception as exc:
                messagebox.showerror("Query error", str(exc), parent=win)
                return
            stats.delete(*stats.get_children())
            for dom, cnt, sec in durs[:40]:
                stats.insert("", "end", values=(dom, cnt, fmt_dur(sec)))
            attempts.delete(*attempts.get_children())
            for username_a, app, ts in atts:
                attempts.insert("", "end", values=(
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)),
                    username_a, app))
            searches.delete(*searches.get_children())
            tree.delete(*tree.get_children())
            for username, domain, url, ts in rows:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
                tree.insert("", "end", values=(when, username, url[:200]))
                q = extract_search_query(url)
                if q:
                    searches.insert("", "end",
                                    values=(when, username, domain, q[:200]))

        for v in (user_var, from_var, to_var, site_var):
            v.trace_add("write", lambda *_: refresh())

        # `bar` was created and packed at the bottom near the top of this method.
        tk.Button(bar, text="🔔 Alerts & Email…", command=self.monitor_settings_dialog,
                  bg=COLOR_ACCENT, fg="white", relief="flat", padx=12, pady=6,
                  cursor="hand2").pack(side="left")
        tk.Button(bar, text="☁ Remote Dashboard…", command=self.sync_dialog,
                  bg="#8e44ad", fg="white", relief="flat", padx=12, pady=6,
                  cursor="hand2").pack(side="left", padx=8)
        tk.Button(bar, text="Refresh now", command=lambda: (
            self._import_history_now(), refresh()), relief="flat",
            padx=12, pady=6, cursor="hand2").pack(side="left", padx=8)
        tk.Button(bar, text="Close", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right")

        # Draw the window immediately, then pull the latest history and refresh
        # so it's never empty on open (no need to hit Refresh manually).
        refresh()
        win.after(50, lambda: (self._import_history_now(), refresh()))

    def _import_history_now(self):
        try:
            import_all_history(self.state, HistoryStore())
        except Exception as exc:
            messagebox.showerror("Import error", str(exc), parent=self.root)

    def monitor_settings_dialog(self):
        with self.state.lock:
            mon = dict(self.state.monitor)
            email = dict(mon.get("email") or {})
        win = tk.Toplevel(self.root)
        win.title("Monitoring — Alerts & Email")
        win.configure(bg=COLOR_BG)
        win.geometry("520x680")
        win.minsize(420, 380)
        self._present(win)

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=16, pady=14)
        body = self._scroll_body(win)

        tk.Label(body, text="Browsing history is always recorded (see "
                 "📊 Activity). Set watched sites / keywords + email below to "
                 "get alerts.", bg=COLOR_BG, fg="#7f8c8d", wraplength=470,
                 justify="left").pack(anchor="w", padx=16, pady=(12, 6))

        tk.Label(body, text="Alert me when these sites are visited "
                 "(one per line):", bg=COLOR_BG, fg=COLOR_HEADER).pack(
                     anchor="w", padx=16)
        watch = tk.Text(body, height=4, width=46, font=("monospace", 11))
        watch.pack(fill="x", padx=16)
        watch.insert("1.0", "\n".join(mon.get("watch", [])))

        tk.Label(body, text="Alert me when a search contains these words "
                 "(one per line):", bg=COLOR_BG, fg=COLOR_HEADER).pack(
                     anchor="w", padx=16, pady=(8, 0))
        keywords = tk.Text(body, height=4, width=46, font=("monospace", 11))
        keywords.pack(fill="x", padx=16)
        keywords.insert("1.0", "\n".join(mon.get("keywords", [])))

        # New-domain novelty detection — catches sites you never listed, by
        # flagging domains the child has never visited (or not in a while).
        newdom_on = tk.BooleanVar(value=mon.get("alert_new_domains", False))
        tk.Checkbutton(body, variable=newdom_on, bg=COLOR_BG, anchor="w",
                       text="Alert me about brand-new websites (never visited "
                       "before, or not recently)").pack(fill="x", padx=16,
                                                        pady=(10, 0))
        nrow = tk.Frame(body, bg=COLOR_BG)
        nrow.pack(fill="x", padx=32)
        tk.Label(nrow, text="Treat as new if not visited in the last",
                 bg=COLOR_BG).pack(side="left")
        new_domain_days = tk.StringVar(value=str(mon.get("new_domain_days", 30)))
        tk.Spinbox(nrow, from_=0, to=3650, width=4, textvariable=new_domain_days
                   ).pack(side="left", padx=4)
        tk.Label(nrow, text="days (0 = only ever never-seen sites)", bg=COLOR_BG,
                 fg="#7f8c8d").pack(side="left")
        newdom_rt = tk.BooleanVar(value=mon.get("new_domain_realtime", True))
        tk.Checkbutton(body, variable=newdom_rt, bg=COLOR_BG, anchor="w",
                       text="Send new-site alerts in real time (they're always "
                       "in the daily summary too)").pack(fill="x", padx=32)
        newdom_shared = tk.BooleanVar(value=mon.get("new_domain_shared", True))
        tk.Checkbutton(body, variable=newdom_shared, bg=COLOR_BG, anchor="w",
                       text="Share history across our machines (don't alert twice "
                       "for the same new site) — needs the dashboard repo set up"
                       ).pack(fill="x", padx=32)
        tk.Label(body, text="Merge users across machines (only if the same child "
                 "logs in under different names). One per line: local = household",
                 bg=COLOR_BG, fg="#7f8c8d", wraplength=460, justify="left").pack(
                     anchor="w", padx=48, pady=(2, 0))
        newdom_alias = tk.Text(body, height=2, width=38, font=("monospace", 10))
        newdom_alias.pack(fill="x", padx=48)
        newdom_alias.insert("1.0", "\n".join(
            f"{k} = {v}" for k, v in (mon.get("new_domain_aliases") or {}).items()))

        alert_blocked = tk.BooleanVar(value=mon.get("alert_blocked", True))
        tk.Checkbutton(body, variable=alert_blocked, bg=COLOR_BG, anchor="w",
                       text="Email me when a child tries to open a blocked app"
                       ).pack(fill="x", padx=16, pady=(6, 0))
        digest_on = tk.BooleanVar(value=mon.get("digest_enabled", False))
        drow = tk.Frame(body, bg=COLOR_BG)
        drow.pack(fill="x", padx=16)
        tk.Checkbutton(drow, variable=digest_on, bg=COLOR_BG,
                       text="Email me a summary every").pack(side="left")
        digest_hours = tk.StringVar(value=str(mon.get("digest_hours", 24)))
        tk.Spinbox(drow, from_=1, to=168, width=4, textvariable=digest_hours
                   ).pack(side="left", padx=4)
        tk.Label(drow, text="hours", bg=COLOR_BG).pack(side="left")

        hrow = tk.Frame(body, bg=COLOR_BG)
        hrow.pack(fill="x", padx=16, pady=(6, 0))
        tk.Label(hrow, text="Keep browsing history for", bg=COLOR_BG).pack(
            side="left")
        history_days = tk.StringVar(value=str(mon.get("history_days", 90)))
        tk.Spinbox(hrow, from_=0, to=3650, width=5, textvariable=history_days
                   ).pack(side="left", padx=4)
        tk.Label(hrow, text="days (0 = keep forever). Older entries are "
                 "auto-deleted.", bg=COLOR_BG, fg="#7f8c8d").pack(side="left")

        em_on = tk.BooleanVar(value=email.get("enabled", False))
        tk.Checkbutton(body, text="Send email alerts (SMTP)", variable=em_on,
                       bg=COLOR_BG, font=("Helvetica", 11, "bold")).pack(
                           anchor="w", padx=16, pady=(10, 2))
        form = tk.Frame(body, bg=COLOR_BG)
        form.pack(fill="x", padx=16)
        fields = [("SMTP server", "host"), ("Port", "port"),
                  ("Username", "username"), ("Password", "password"),
                  ("From address", "from"),
                  ("Send alerts to (comma-sep)", "to"),
                  ("Quiet hours start (HH:MM)", "quiet_start"),
                  ("Quiet hours end (HH:MM)", "quiet_end")]
        vars_ = {}
        for i, (label, key) in enumerate(fields):
            tk.Label(form, text=label + ":", bg=COLOR_BG).grid(
                row=i, column=0, sticky="w", pady=2)
            v = tk.StringVar(value=str(email.get(key, "") or ""))
            show = "*" if key == "password" else None
            tk.Entry(form, textvariable=v, width=32, show=show).grid(
                row=i, column=1, sticky="we", pady=2)
            vars_[key] = v
        form.columnconfigure(1, weight=1)
        tk.Label(body, text="Tip: Gmail = smtp.gmail.com, port 587, app password. "
                 "You can send alerts to two parents by separating addresses "
                 "with commas. Quiet hours mute emails overnight (leave blank "
                 "for none).", bg=COLOR_BG, fg="#7f8c8d", wraplength=470,
                 justify="left").pack(padx=16, pady=(4, 0))

        def collect():
            mon["enabled"] = True  # recording is always on now
            mon["watch"] = [ln for ln in watch.get("1.0", tk.END).splitlines()
                            if ln.strip()]
            mon["keywords"] = [ln for ln in keywords.get(
                "1.0", tk.END).splitlines() if ln.strip()]
            mon["alert_blocked"] = alert_blocked.get()
            mon["alert_new_domains"] = newdom_on.get()
            try:
                mon["new_domain_days"] = max(0, int(new_domain_days.get()))
            except ValueError:
                mon["new_domain_days"] = 30
            mon["new_domain_realtime"] = newdom_rt.get()
            mon["new_domain_shared"] = newdom_shared.get()
            aliases = {}
            for ln in newdom_alias.get("1.0", tk.END).splitlines():
                if "=" in ln:
                    lk, lv = ln.split("=", 1)
                    lk, lv = lk.strip().lower(), lv.strip().lower()
                    if lk and lv and lk != lv:
                        aliases[lk] = lv
            mon["new_domain_aliases"] = aliases
            mon["digest_enabled"] = digest_on.get()
            try:
                mon["digest_hours"] = max(1, int(digest_hours.get()))
            except ValueError:
                mon["digest_hours"] = 24
            try:
                mon["history_days"] = max(0, int(history_days.get()))
            except ValueError:
                mon["history_days"] = 90
            em = {"enabled": em_on.get()}
            for key, v in vars_.items():
                em[key] = v.get().strip()
            mon["email"] = em
            return mon

        def save():
            self.state.set_monitor(collect())
            messagebox.showinfo("Saved", "Monitoring settings saved.", parent=win)
            win.destroy()

        def test():
            self.state.set_monitor(collect())
            with self.state.lock:
                cfg = dict(self.state.monitor.get("email") or {})
            try:
                send_email(cfg, "[AppBlocker] Test email",
                           "This is a test from AppBlocker. Email alerts work.")
                messagebox.showinfo("Sent", f"Test email sent to {cfg.get('to')}.",
                                    parent=win)
            except Exception as exc:
                messagebox.showerror("Email failed", str(exc), parent=win)

        # `bar` was pinned to the bottom before the scrollable body above.
        tk.Button(bar, text="Save", command=save, bg=COLOR_ACTIVE, fg="white",
                  relief="flat", padx=16, pady=6, cursor="hand2").pack(
                      side="right")
        tk.Button(bar, text="Send test email", command=test, bg=COLOR_ACCENT,
                  fg="white", relief="flat", padx=12, pady=6,
                  cursor="hand2").pack(side="right", padx=8)
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="left")

    # -- blocked websites UI ------------------------------------------------ #
    def websites_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Block Websites")
        win.configure(bg=COLOR_BG)
        win.geometry("480x520")
        win.minsize(420, 380)
        self._present(win)

        # Pin the Save/Cancel bar to the bottom BEFORE the expanding text box so
        # it can never be pushed off-screen.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)

        tk.Label(win, text="🌐 Blocked Websites", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text="These websites are blocked in every browser, for "
                 "everyone on this computer. Enter one domain per line "
                 "(e.g. youtube.com).", bg=COLOR_BG, fg="#7f8c8d",
                 wraplength=440, justify="left").pack(padx=18, pady=(0, 8))

        # Fixed rows below the text box are packed to the bottom first so the
        # text box only expands into the space that is genuinely left over.
        note = tk.Label(win, text="Note: this is machine-wide. A browser using "
                        "“secure DNS” (DoH) or a VPN can bypass it.", bg=COLOR_BG,
                        fg="#b9770e", wraplength=440, justify="left")
        note.pack(side="bottom", padx=18, pady=(6, 8))

        adult_var = tk.BooleanVar(value=self.state.block_adult)
        n_adult = len(load_adult_domains())
        tk.Checkbutton(
            win, variable=adult_var, bg=COLOR_BG, anchor="w",
            text=f"Also block a built-in adult-content list ({n_adult} sites)"
        ).pack(side="bottom", fill="x", padx=18, pady=(8, 0))

        txt = tk.Text(win, height=14, width=44, font=("monospace", 11))
        txt.pack(fill="both", expand=True, padx=18)
        with self.state.lock:
            txt.insert("1.0", "\n".join(self.state.websites))

        def save():
            raw = txt.get("1.0", tk.END)
            domains = [line for line in raw.splitlines() if line.strip()]
            saved = self.state.set_websites(domains)
            self.state.set_block_adult(adult_var.get())
            # Apply immediately (we are root in system mode); the daemon also
            # keeps it in sync, but this gives instant feedback.
            effective = set(saved)
            if adult_var.get():
                effective |= load_adult_domains()
            sync_blocked_websites(sorted(effective))
            messagebox.showinfo(
                "Saved", f"{len(saved)} website(s) blocked"
                + (f" + adult list ({n_adult})" if adult_var.get() else "")
                + ".\n\nChanges take effect right away (reload open tabs).",
                parent=win)
            win.destroy()

        # `bar` was pinned to the bottom before the text box above.
        tk.Button(bar, text="Save", command=save, bg=COLOR_ACTIVE, fg="white",
                  relief="flat", padx=16, pady=6, cursor="hand2").pack(
                      side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    # -- distractions (blocked by default, grantable) ----------------------- #
    def distractions_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Distractions")
        win.configure(bg=COLOR_BG)
        win.geometry("500x600")
        win.minsize(440, 460)
        self._present(win)

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)

        tk.Label(win, text="🎯 Distractions", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text="These sites are blocked by default for everyone on "
                 "this computer, so schoolwork on any site stays distraction-"
                 "free. You can grant free time or temporarily allow one site — "
                 "they re-lock automatically when it runs out.", bg=COLOR_BG,
                 fg="#7f8c8d", wraplength=460, justify="left").pack(
                     padx=18, pady=(0, 8))

        status = tk.Label(win, text="", bg=COLOR_BG, fg=COLOR_HEADER,
                          wraplength=460, justify="left",
                          font=("Helvetica", 11, "bold"))
        status.pack(padx=18, pady=(0, 4))

        def refresh_status():
            with self.state.lock:
                fu = self.state.distract_free_until
                al = dict(self.state.distract_allow)
                n = len(self.state.distractions)
            now = int(time.time())
            if fu and now < fu:
                status.config(text="🟢 Free time — all distractions unlocked "
                              f"until {time.strftime('%H:%M', time.localtime(fu))}.")
            else:
                active = {d: t for d, t in al.items() if t > now}
                base = f"🔒 Blocked by default ({n} site(s))."
                if active:
                    parts = ", ".join(
                        f"{d} → {time.strftime('%H:%M', time.localtime(t))}"
                        for d, t in active.items())
                    base += f"  Temporarily allowed: {parts}"
                status.config(text=base)

        # --- grant free time / re-lock ---
        grow = tk.Frame(win, bg=COLOR_BG)
        grow.pack(fill="x", padx=18, pady=(2, 0))
        tk.Label(grow, text="Grant free time for", bg=COLOR_BG).pack(side="left")
        free_min = tk.StringVar(value="30")
        tk.Spinbox(grow, from_=1, to=1440, width=5, textvariable=free_min).pack(
            side="left", padx=4)
        tk.Label(grow, text="min", bg=COLOR_BG).pack(side="left")

        def do_grant():
            try:
                m = max(1, int(free_min.get()))
            except ValueError:
                m = 30
            self.state.grant_free_time(m)
            refresh_status()

        def do_end():
            self.state.end_free_time()
            refresh_status()

        tk.Button(grow, text="Grant", command=do_grant, bg="#27ae60", fg="white",
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(
                      side="left", padx=6)
        tk.Button(grow, text="Re-lock now", command=do_end, bg=COLOR_BLOCKED,
                  fg="white", relief="flat", padx=10, pady=4,
                  cursor="hand2").pack(side="left")

        # --- temporarily allow one site ---
        arow = tk.Frame(win, bg=COLOR_BG)
        arow.pack(fill="x", padx=18, pady=(8, 0))
        tk.Label(arow, text="Allow one site", bg=COLOR_BG).pack(side="left")
        allow_site = tk.StringVar()
        tk.Entry(arow, textvariable=allow_site, width=18).pack(side="left", padx=4)
        tk.Label(arow, text="for", bg=COLOR_BG).pack(side="left")
        allow_min = tk.StringVar(value="20")
        tk.Spinbox(arow, from_=1, to=1440, width=5, textvariable=allow_min).pack(
            side="left", padx=4)
        tk.Label(arow, text="min", bg=COLOR_BG).pack(side="left")

        def do_allow():
            try:
                m = max(1, int(allow_min.get()))
            except ValueError:
                m = 20
            d = self.state.allow_distraction(allow_site.get(), m)
            if d:
                allow_site.set("")
                refresh_status()
            else:
                messagebox.showwarning("Invalid", "Enter a domain to allow.",
                                       parent=win)

        tk.Button(arow, text="Allow", command=do_allow, bg=COLOR_ACCENT,
                  fg="white", relief="flat", padx=12, pady=4,
                  cursor="hand2").pack(side="left", padx=6)

        tk.Label(win, text="Distraction sites (one domain per line):", bg=COLOR_BG,
                 fg=COLOR_HEADER).pack(anchor="w", padx=18, pady=(10, 2))
        txt = tk.Text(win, height=10, width=44, font=("monospace", 11))
        txt.pack(fill="both", expand=True, padx=18)
        with self.state.lock:
            txt.insert("1.0", "\n".join(self.state.distractions))

        refresh_status()

        def save():
            raw = txt.get("1.0", tk.END)
            domains = [ln for ln in raw.splitlines() if ln.strip()]
            saved = self.state.set_distractions(domains)
            refresh_status()
            messagebox.showinfo(
                "Saved", f"{len(saved)} distraction site(s) saved.\n\nThey're "
                "blocked by default; changes take effect within a few seconds.",
                parent=win)
            win.destroy()

        tk.Button(bar, text="Save list", command=save, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Close", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    # -- scheduled website blocks (downtime) -------------------------------- #
    def web_schedule_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Scheduled Website Blocks")
        win.configure(bg=COLOR_BG)
        win.geometry("560x480")
        win.minsize(460, 380)
        self._present(win)

        tk.Label(win, text="⏰ Scheduled Website Blocks", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 14, "bold")).pack(
                     pady=(14, 2))
        tk.Label(win, text="Block chosen websites only during set times (e.g. "
                 "homework hours or bedtime). This runs on top of your always-on "
                 "blocks and any auto-block rules — a site is blocked if ANY of "
                 "them applies.", bg=COLOR_BG, fg="#7f8c8d", wraplength=520,
                 justify="left").pack(padx=16, pady=(0, 8))

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=14, pady=12)

        container = tk.Frame(win, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=14)
        canvas = tk.Canvas(container, bg=COLOR_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        listwrap = tk.Frame(canvas, bg=COLOR_BG)
        listwrap.bind("<Configure>",
                      lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        wid = canvas.create_window((0, 0), window=listwrap, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        def render():
            for c in listwrap.winfo_children():
                c.destroy()
            with self.state.lock:
                scheds = [dict(s) for s in self.state.web_schedules]
            if not scheds:
                tk.Label(listwrap, text="No scheduled blocks yet. Click "
                         "“＋ Add Schedule”.", bg=COLOR_BG, fg="#95a5a6").pack(
                             pady=20)
                return
            for i, sch in enumerate(scheds):
                card = tk.Frame(listwrap, bg="white",
                                highlightbackground="#dfe4ea", highlightthickness=1)
                card.pack(fill="x", pady=3)
                tk.Button(card, text="✕", relief="flat", bg="white", fg="#95a5a6",
                          cursor="hand2",
                          command=lambda idx=i: self._delete_web_schedule(idx, render)
                          ).pack(side="right", padx=4)
                tk.Button(card, text="Edit", relief="flat", bg="white",
                          fg=COLOR_ACCENT, cursor="hand2",
                          command=lambda idx=i: self._edit_web_schedule(win, idx, render)
                          ).pack(side="right")
                name = sch.get("name") or ", ".join(sch.get("sites") or [])
                summary = (f"{name}\n{', '.join(sch.get('sites') or [])}\n"
                           f"{schedule_summary(sch.get('schedule') or [])}")
                tk.Label(card, text=summary, bg="white", fg=COLOR_HEADER,
                         justify="left", anchor="w", font=("Helvetica", 10)).pack(
                             side="left", fill="x", expand=True, padx=6, pady=6)

        tk.Button(bar, text="＋ Add Schedule",
                  command=lambda: self._edit_web_schedule(win, None, render),
                  bg="#11998e", fg="white", relief="flat", padx=14, pady=6,
                  cursor="hand2").pack(side="left")
        tk.Button(bar, text="Close", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right")
        render()

    def _delete_web_schedule(self, idx, on_done):
        if not self._authenticate("Deleting a schedule requires the password."):
            return
        self.state.remove_web_schedule(idx)
        on_done()

    def _edit_web_schedule(self, parent, index, on_done):
        with self.state.lock:
            existing = (dict(self.state.web_schedules[index])
                        if index is not None else {})

        win = tk.Toplevel(parent)
        win.title("Edit Schedule" if index is not None else "New Schedule")
        win.configure(bg=COLOR_BG)
        win.geometry("460x600")
        win.minsize(400, 420)
        self._present(win)

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)
        body = self._scroll_body(win)

        tk.Label(body, text="Block these websites (one per line):", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(14, 2))
        sites = tk.Text(body, height=5, width=42, font=("monospace", 11))
        sites.pack(fill="x", padx=18)
        sites.insert("1.0", "\n".join(existing.get("sites") or []))

        tk.Label(body, text="During these times:", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(12, 2))
        windows = list(existing.get("schedule") or [])
        listbox = tk.Listbox(body, height=4)
        listbox.pack(fill="x", padx=18)

        def redraw():
            listbox.delete(0, tk.END)
            for w in windows:
                listbox.insert(tk.END, schedule_summary([w]))

        def add_window():
            w = self._ask_schedule_window(win)
            if w:
                windows.append(w)
                redraw()

        def remove_window():
            sel = listbox.curselection()
            if sel:
                del windows[sel[0]]
                redraw()

        sbtns = tk.Frame(body, bg=COLOR_BG)
        sbtns.pack(fill="x", padx=18, pady=4)
        tk.Button(sbtns, text="＋ Add window", command=add_window, relief="flat",
                  bg=COLOR_ACCENT, fg="white", cursor="hand2").pack(side="left")
        tk.Button(sbtns, text="－ Remove", command=remove_window, relief="flat",
                  cursor="hand2").pack(side="left", padx=6)
        redraw()

        name_var = tk.StringVar(value=existing.get("name", ""))
        nfr = tk.Frame(body, bg=COLOR_BG)
        nfr.pack(fill="x", padx=18, pady=(12, 0))
        tk.Label(nfr, text="Label (optional):", bg=COLOR_BG).pack(side="left")
        tk.Entry(nfr, textvariable=name_var).pack(side="left", fill="x",
                                                  expand=True, padx=6)

        def save():
            domains = [normalize_domain(ln) for ln in
                       sites.get("1.0", tk.END).splitlines()
                       if normalize_domain(ln)]
            if not domains:
                messagebox.showwarning("No sites", "Enter at least one website.",
                                       parent=win)
                return
            if not windows:
                messagebox.showwarning("No times", "Add at least one time window.",
                                       parent=win)
                return
            sch = {"name": name_var.get().strip(), "sites": domains,
                   "schedule": windows}
            if index is None:
                self.state.add_web_schedule(sch)
            else:
                self.state.update_web_schedule(index, sch)
            win.destroy()
            on_done()

        tk.Button(bar, text="Save", command=save, bg=COLOR_ACTIVE, fg="white",
                  relief="flat", padx=16, pady=6, cursor="hand2").pack(
                      side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    def change_password(self):
        if not self._authenticate("Enter current password to change it."):
            return
        pw1 = simpledialog.askstring("New Password", "New password:",
                                     show="*", parent=self.root)
        if not pw1:
            return
        if len(pw1) < 4:
            messagebox.showwarning("Too short", "At least 4 characters.")
            return
        pw2 = simpledialog.askstring("Confirm", "Re-enter new password:",
                                     show="*", parent=self.root)
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords did not match.")
            return
        self.pm.set_password(pw1)
        messagebox.showinfo("Done", "Password updated.")

    # -- backup / restore --------------------------------------------------- #
    def backup_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Backup / Restore Settings")
        win.configure(bg=COLOR_BG)
        win.geometry("460x340")
        win.minsize(400, 300)
        self._present(win)

        tk.Label(win, text="💾 Backup / Restore", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 6))
        tk.Label(win, text="Copy your whole setup to another machine: Export "
                 "here, move the file to the new machine (USB / cloud), then "
                 "Import it there. It carries your apps, rules, blocked "
                 "websites, monitoring, dashboard settings and the parent "
                 "password.", bg=COLOR_BG, fg="#7f8c8d", wraplength=410,
                 justify="left").pack(padx=20)

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=14)
        tk.Button(bar, text="Close", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right")

        box = tk.Frame(win, bg=COLOR_BG)
        box.pack(fill="both", expand=True, padx=20, pady=10)
        tk.Button(box, text="⭳  Export settings to a file…",
                  command=lambda: self._export_settings_gui(win),
                  bg=COLOR_ACCENT, fg="white", relief="flat", pady=8,
                  cursor="hand2").pack(fill="x", pady=6)
        tk.Button(box, text="⭱  Import settings from a file…",
                  command=lambda: self._import_settings_gui(win),
                  bg=COLOR_BLOCKED, fg="white", relief="flat", pady=8,
                  cursor="hand2").pack(fill="x", pady=6)
        tk.Label(box, text="The exported file contains your password, email "
                 "password and dashboard token — keep it private and delete "
                 "it after copying.", bg=COLOR_BG, fg="#b9770e", wraplength=410,
                 justify="left").pack(pady=(6, 0))

    def _export_settings_gui(self, parent):
        if not self._authenticate("Exporting settings requires the password."):
            return
        path = filedialog.asksaveasfilename(
            parent=parent, title="Export settings to…",
            defaultextension=".json", initialfile="appblocker-settings.json")
        if not path:
            return
        try:
            export_settings(path)
            messagebox.showinfo(
                "Exported", f"Settings saved to:\n{path}\n\nMove this file to "
                "the other machine and use Import there. It contains secrets — "
                "keep it private and delete it afterwards.", parent=parent)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=parent)

    def _import_settings_gui(self, parent):
        if not self._authenticate("Importing settings requires the password."):
            return
        path = filedialog.askopenfilename(
            parent=parent, title="Import settings from…")
        if not path:
            return
        if not messagebox.askyesno(
                "Replace all settings?",
                "This replaces ALL settings on THIS machine (apps, rules, "
                "websites, monitoring, dashboard and the parent password) with "
                "the ones in the file. Continue?", parent=parent):
            return
        try:
            import_settings(path)
            self.state.load()                       # re-read the new blocklist
            self.pm.config = load_json(CONFIG_FILE, {})  # pick up new password
            self.refresh()
            messagebox.showinfo(
                "Imported", "Settings imported and applied. If the parent "
                "password came from the other machine, use that one now.\n\n"
                "Note: if this machine's user accounts are named differently, "
                "double-check any per-user targeting.", parent=parent)
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc), parent=parent)

    # -- helpers ------------------------------------------------------------ #
    def _ask_block_config(self, app, title="Block App"):
        """
        Ask for a full block configuration. Returns a dict:
            {"mode": "manual"|"timer"|"schedule",
             "minutes": int, "target_users": [names], "schedule": [windows]}
        or None if cancelled. `app` (or None) seeds the current values.
        """
        app = app or {}
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=COLOR_BG)
        win.geometry("480x560")
        win.minsize(420, 380)
        self._present(win)
        result = {"value": None}

        # Pin the Block/Cancel bar to the bottom first, then a scrollable body so
        # the buttons are always reachable no matter how tall the form gets.
        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=14)

        tk.Label(win, text=title, bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 6))

        mode = tk.StringVar(value=app.get("mode", "manual")
                            if self._is_configured(app) else "manual")
        minutes_var = tk.StringVar(value="30")

        body = self._scroll_body(win)

        # --- Mode selection ------------------------------------------------ #
        tk.Label(body, text="When to block", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 10, "bold"), anchor="w").pack(fill="x",
                                                                  pady=(4, 2))
        tk.Radiobutton(body, text="Until I unblock it (manual)",
                       variable=mode, value="manual", bg=COLOR_BG,
                       anchor="w").pack(fill="x")
        timer_row = tk.Frame(body, bg=COLOR_BG)
        timer_row.pack(fill="x")
        tk.Radiobutton(timer_row, text="Timer for", variable=mode,
                       value="timer", bg=COLOR_BG).pack(side="left")
        tk.Spinbox(timer_row, from_=1, to=1440, width=6,
                   textvariable=minutes_var).pack(side="left", padx=6)
        tk.Label(timer_row, text="minutes", bg=COLOR_BG).pack(side="left")
        tk.Radiobutton(body, text="On a weekly schedule", variable=mode,
                       value="schedule", bg=COLOR_BG, anchor="w").pack(fill="x")

        # --- Schedule windows --------------------------------------------- #
        sched_frame = tk.Frame(body, bg=COLOR_BG)
        sched_frame.pack(fill="x", padx=(24, 0), pady=(2, 6))
        windows = list(app.get("schedule") or [])

        listbox = tk.Listbox(sched_frame, height=4)
        listbox.pack(fill="x", side="top")

        def redraw_windows():
            listbox.delete(0, tk.END)
            for w in windows:
                listbox.insert(tk.END, schedule_summary([w]))

        def add_window():
            w = self._ask_schedule_window(win)
            if w:
                windows.append(w)
                redraw_windows()
                mode.set("schedule")

        def remove_window():
            sel = listbox.curselection()
            if sel:
                del windows[sel[0]]
                redraw_windows()

        sbtns = tk.Frame(sched_frame, bg=COLOR_BG)
        sbtns.pack(fill="x", side="top", pady=2)
        tk.Button(sbtns, text="＋ Add window", command=add_window,
                  relief="flat", bg=COLOR_ACCENT, fg="white",
                  cursor="hand2").pack(side="left")
        tk.Button(sbtns, text="－ Remove", command=remove_window,
                  relief="flat", cursor="hand2").pack(side="left", padx=6)
        tk.Label(sbtns, text="(blocked DURING these windows)", bg=COLOR_BG,
                 fg="#95a5a6", font=("Helvetica", 8)).pack(side="left", padx=4)
        redraw_windows()

        # --- Target users (system mode only) ------------------------------ #
        user_vars = {}
        if SYSTEM_MODE:
            tk.Label(body, text="Apply to users", bg=COLOR_BG, fg=COLOR_HEADER,
                     font=("Helvetica", 10, "bold"), anchor="w").pack(
                         fill="x", pady=(8, 2))
            current = set(app.get("target_users") or [])
            all_var = tk.BooleanVar(value=not current)

            def toggle_all():
                if all_var.get():
                    for v in user_vars.values():
                        v.set(False)

            tk.Checkbutton(body, text="All users", variable=all_var,
                           command=toggle_all, bg=COLOR_BG,
                           anchor="w").pack(fill="x")
            ufr = tk.Frame(body, bg=COLOR_BG)
            ufr.pack(fill="x", padx=(20, 0))
            for uname, _uid in self.users:
                v = tk.BooleanVar(value=uname in current)

                def _clear_all(_=None):
                    all_var.set(False)

                cb = tk.Checkbutton(ufr, text=uname, variable=v,
                                    command=_clear_all, bg=COLOR_BG, anchor="w")
                cb.pack(fill="x")
                user_vars[uname] = v
            if not self.users:
                tk.Label(ufr, text="(no other human accounts detected)",
                         bg=COLOR_BG, fg="#95a5a6").pack(fill="x")
        else:
            tk.Label(body, text="(Blocks apply to your account. Install the "
                     "system service to manage other users.)", bg=COLOR_BG,
                     fg="#95a5a6", wraplength=420, justify="left").pack(
                         fill="x", pady=(8, 0))

        # --- Confirm / cancel --------------------------------------------- #
        def confirm():
            m = mode.get()
            cfg = {"mode": m, "minutes": 30, "schedule": [], "target_users": []}
            if m == "timer":
                try:
                    cfg["minutes"] = max(1, int(minutes_var.get()))
                except ValueError:
                    cfg["minutes"] = 1
            elif m == "schedule":
                if not windows:
                    messagebox.showwarning(
                        "No windows",
                        "Add at least one schedule window, or pick another "
                        "mode.", parent=win)
                    return
                cfg["schedule"] = windows
            if SYSTEM_MODE:
                chosen = [u for u, v in user_vars.items() if v.get()]
                cfg["target_users"] = chosen  # [] means all users
            result["value"] = cfg
            win.destroy()

        # `bar` was pinned to the bottom before the scrollable body above.
        tk.Button(bar, text="Block", command=confirm, bg=COLOR_BLOCKED,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

        win.wait_window()
        return result["value"]

    def _ask_schedule_window(self, parent):
        """Sub-dialog: pick days + start/end. Returns a window dict or None."""
        win = tk.Toplevel(parent)
        win.title("Schedule window")
        win.configure(bg=COLOR_BG)
        win.geometry("360x320")
        win.minsize(340, 300)
        self._present(win)
        result = {"value": None}

        tk.Label(win, text="Block on these days", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 11, "bold")).pack(pady=(12, 4))
        day_vars = []
        dfr = tk.Frame(win, bg=COLOR_BG)
        dfr.pack(pady=2)
        for i, dname in enumerate(DAY_NAMES):
            v = tk.BooleanVar(value=i < 5)  # default Mon–Fri
            tk.Checkbutton(dfr, text=dname, variable=v, bg=COLOR_BG).grid(
                row=0, column=i, padx=1)
            day_vars.append(v)

        trow = tk.Frame(win, bg=COLOR_BG)
        trow.pack(pady=12)
        tk.Label(trow, text="From", bg=COLOR_BG).grid(row=0, column=0, padx=4)
        start_var = tk.StringVar(value="08:00")
        tk.Entry(trow, textvariable=start_var, width=7).grid(row=0, column=1)
        tk.Label(trow, text="to", bg=COLOR_BG).grid(row=0, column=2, padx=4)
        end_var = tk.StringVar(value="15:00")
        tk.Entry(trow, textvariable=end_var, width=7).grid(row=0, column=3)
        tk.Label(win, text="Times are 24-hour (HH:MM). An end time earlier than "
                 "the start spans midnight.", bg=COLOR_BG, fg="#95a5a6",
                 wraplength=320, justify="left").pack(padx=16)

        def confirm():
            days = [i for i, v in enumerate(day_vars) if v.get()]
            if not days:
                messagebox.showwarning("No days", "Pick at least one day.",
                                       parent=win)
                return
            if _parse_hhmm(start_var.get()) is None or \
                    _parse_hhmm(end_var.get()) is None:
                messagebox.showwarning("Bad time", "Use HH:MM 24-hour format.",
                                       parent=win)
                return
            result["value"] = {"days": days, "start": start_var.get().strip(),
                               "end": end_var.get().strip()}
            win.destroy()

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=16, pady=12)
        tk.Button(bar, text="Add", command=confirm, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=14, pady=5,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=10, pady=5, cursor="hand2").pack(side="right", padx=6)

        win.wait_window()
        return result["value"]

    def _authenticate(self, prompt="Enter parent password:"):
        pw = simpledialog.askstring("Authenticate", prompt, show="*",
                                    parent=self.root)
        if pw is None:
            return False
        if self.pm.verify(pw):
            return True
        messagebox.showerror("Wrong password", "Incorrect password.")
        return False

    # -- system tray -------------------------------------------------------- #
    def _make_tray_image(self, blocked):
        size = 64
        img = Image.new("RGB", (size, size), "white")
        d = ImageDraw.Draw(img)
        color = COLOR_BLOCKED if blocked else COLOR_ACTIVE
        # padlock body
        d.rectangle([16, 28, 48, 56], fill=color)
        # shackle
        d.arc([20, 8, 44, 40], start=180, end=360, fill=color, width=5)
        # keyhole
        d.ellipse([28, 36, 36, 44], fill="white")
        return img

    def _setup_tray(self):
        try:
            blocked = self.state.any_blocked()
            menu = pystray.Menu(
                pystray.MenuItem("Show", self._tray_show, default=True),
                pystray.MenuItem("Unblock All", lambda: self.root.after(
                    0, self.unblock_all)),
                pystray.MenuItem("Quit", self._tray_quit),
            )
            self.tray_icon = pystray.Icon(
                "AppBlocker", self._make_tray_image(blocked),
                "AppBlocker", menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except Exception as exc:
            sys.stderr.write(f"[tray] disabled: {exc}\n")
            self.tray_icon = None

    def _update_tray_icon(self, blocked):
        try:
            self.tray_icon.icon = self._make_tray_image(blocked)
            self.tray_icon.title = (
                "AppBlocker — BLOCKING" if blocked else "AppBlocker — idle")
        except Exception:
            pass

    def _tray_show(self, *_):
        self.root.after(0, self._restore_window)

    def _restore_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_quit(self, *_):
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.after(0, self._really_quit)

    # -- window lifecycle --------------------------------------------------- #
    def on_close(self):
        """Closing the window."""
        if self.tray_icon:
            self.root.withdraw()
            return
        if SYSTEM_MODE:
            # The root systemd service enforces the rules independently of this
            # window, so closing it is completely safe — blocking continues and
            # resumes automatically on every boot.
            messagebox.showinfo(
                "AppBlocker keeps running",
                "You can close this window safely.\n\n"
                "The background service keeps enforcing your rules for all "
                "users, and starts automatically every time the computer is "
                "turned on. Reopen \"AppBlocker (Admin)\" only when you want to "
                "change the rules.")
            self._really_quit()
            return
        # User mode: there is no background service, so blocking only runs while
        # this app is open.
        if self.state.any_blocked():
            keep = messagebox.askyesno(
                "Keep blocking?",
                "Apps are still blocked. Keep AppBlocker running in the "
                "background to enforce blocking?\n\n"
                "Yes = minimize and keep blocking\nNo = quit (stops blocking)\n\n"
                "Tip: install the system service (sudo ./install.sh or the .deb) "
                "to block all users automatically at every startup.")
            if keep:
                self.root.iconify()
                return
        self._really_quit()

    def _really_quit(self):
        try:
            self.monitor.stop()
        except Exception:
            pass
        self.root.destroy()


# --------------------------------------------------------------------------- #
# Settings backup / restore — move a fully-customized setup to another machine
# --------------------------------------------------------------------------- #
SETTINGS_EXPORT_VERSION = 1


def _invoking_user_ids():
    """(uid, gid) of the human who launched us via pkexec/sudo, or None.

    The admin GUI runs as root (polkit), so files it creates would be owned by
    root and unreadable by the user's own apps (e.g. their file manager or a
    Drive uploader). We use this to hand exported files back to that user.
    """
    for var in ("PKEXEC_UID", "SUDO_UID"):
        val = os.environ.get(var)
        if val and val.isdigit():
            uid = int(val)
            try:
                gid = pwd.getpwuid(uid).pw_gid
            except KeyError:
                gid = uid
            return uid, gid
    return None


def export_settings(path):
    """Write a portable settings bundle (blocklist + password config) to `path`.

    Contains secrets — the parent password hash, the email password and the
    dashboard token — so it is kept owner-only (0600). When exported by the
    root admin GUI, ownership is handed to the human who launched it so their
    own apps can read and move the file; otherwise it stays root-only and
    unreadable outside root (which is what breaks uploading it to Drive).
    """
    bundle = {
        "appblocker_settings": SETTINGS_EXPORT_VERSION,
        "blocked": load_json(BLOCKED_FILE, {}),
        "config": load_json(CONFIG_FILE, {}),
    }
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(bundle, fh, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    # Give the file to the real user so they can read/move it (still 0600, so
    # it's private to them — not world-readable).
    ids = _invoking_user_ids()
    if ids and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(path, ids[0], ids[1])
        except OSError:
            pass
    return path


def import_settings(path, include_password=True):
    """Load a bundle written by export_settings into this machine's config."""
    bundle = load_json(path, None)
    if not isinstance(bundle, dict) or "blocked" not in bundle:
        raise ValueError("That doesn't look like an AppBlocker settings file.")
    blocked = bundle.get("blocked") or {}
    if not isinstance(blocked, dict) or "apps" not in blocked:
        raise ValueError("The settings file is missing the blocklist.")
    ensure_app_dir()
    save_json(BLOCKED_FILE, blocked)
    if include_password and isinstance(bundle.get("config"), dict) and bundle["config"]:
        save_json(CONFIG_FILE, bundle["config"])
    return True


# --------------------------------------------------------------------------- #
# Headless root daemon (system mode)
# --------------------------------------------------------------------------- #
def run_daemon():
    """
    Headless enforcement loop, intended to run as root under systemd.

    It reads the shared blocklist from /etc/appblocker/blocked.json and kills
    matching processes for EVERY user on the machine (root can signal any
    process). It re-reads the file every sweep, so changes made by the admin
    GUI take effect within a few seconds without restarting the service.
    """
    if os.geteuid() != 0:
        sys.stderr.write(
            "[daemon] warning: not running as root — can only kill processes "
            "owned by the current user. Install via install.sh for system-wide "
            "enforcement.\n")

    ensure_app_dir()
    state = AppState()
    store = HistoryStore()           # shared by the history monitor and kill log
    history = HistoryMonitor(state, store)  # history logging + alerts + digests
    # The kill sweep reports blocked-app attempts to the history monitor, which
    # logs them and (optionally) emails.
    monitor = ProcessMonitor(state, on_block=history.block_alert)

    # Run the sweep loop in the foreground so systemd supervises this process
    # directly (Type=simple). Translate SIGTERM into a clean stop.
    def _handle_term(signum, frame):
        monitor.stop()
        history.stop()

    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)

    sys.stderr.write(
        f"[daemon] AppBlocker enforcement running (uid={os.geteuid()}, "
        f"blocklist={BLOCKED_FILE})\n")
    sys.stderr.flush()

    history.start()  # background thread
    # ProcessMonitor.run() is the same sweep loop the GUI uses in a thread; we
    # just call it inline here so the daemon has no extra moving parts.
    monitor.run()
    history.stop()

    # Final catch-up on shutdown: import any last visits and push the dashboard
    # once more, so activity right up to power-off shows up without waiting for
    # the next boot. Best-effort — the network may already be going down, in
    # which case the push on the next startup is the backstop.
    try:
        import_all_history(state, store)
        n = sync_reports(state, store)
        sys.stderr.write(f"[sync] shutdown push: {n} bytes\n" if n
                         else "[sync] shutdown: nothing to push\n")
    except Exception as exc:
        sys.stderr.write(f"[sync] shutdown push failed: {exc}\n")

    sys.stderr.write("[daemon] stopped\n")


# --------------------------------------------------------------------------- #
# GUI entry point
# --------------------------------------------------------------------------- #
def run_gui():
    if not HAS_TK:
        sys.stderr.write(
            "AppBlocker GUI needs tkinter. Install it with:\n"
            "  Debian/Ubuntu: sudo apt install python3-tk\n"
            "  Fedora:        sudo dnf install python3-tkinter\n")
        sys.exit(1)

    ensure_app_dir()

    root = tk.Tk()
    root.withdraw()  # hide until authenticated

    pm = PasswordManager()
    if not prompt_for_password(root, pm):
        root.destroy()
        sys.exit(0)

    state = AppState()

    # The monitor needs to refresh the UI from its own thread; route through
    # the tk event loop via `after`.
    ui_ref = {}

    def on_monitor_change():
        if "ui" in ui_ref:
            root.after(0, ui_ref["ui"].refresh)

    monitor = ProcessMonitor(state, on_change=on_monitor_change)
    monitor.start()

    root.deiconify()
    ui = AppBlockerUI(root, state, monitor, pm)
    ui_ref["ui"] = ui

    root.mainloop()


def main():
    parser = argparse.ArgumentParser(
        prog="appblocker",
        description="Block applications (especially browsers) for kids.")
    parser.add_argument(
        "--daemon", action="store_true",
        help="run the headless root enforcement daemon (used by systemd)")
    parser.add_argument(
        "--system", action="store_true",
        help="GUI edits the system-wide blocklist in /etc/appblocker "
             "(requires root; implied when run as root)")
    parser.add_argument(
        "--web-clear", action="store_true",
        help="emergency: remove all AppBlocker website blocks from /etc/hosts")
    parser.add_argument(
        "--web-status", action="store_true",
        help="print the currently blocked websites and exit")
    parser.add_argument(
        "--email-test", action="store_true",
        help="send a test email using the saved monitoring settings")
    parser.add_argument(
        "--import-history", action="store_true",
        help="import browser history once now (normally the daemon does this)")
    parser.add_argument(
        "--lockdown-clear", action="store_true",
        help="emergency: remove AppBlocker's browser incognito-lockdown policies")
    parser.add_argument(
        "--sync-now", action="store_true",
        help="build and push the remote dashboard data to GitHub once")
    parser.add_argument(
        "--export-settings", metavar="FILE",
        help="save all settings (apps, rules, websites, email, dashboard, "
             "password) to FILE, to copy to another machine")
    parser.add_argument(
        "--import-settings", metavar="FILE",
        help="load settings previously saved with --export-settings")
    args = parser.parse_args()

    if args.lockdown_clear:
        changed = apply_browser_lockdown(False)
        print(f"Removed {len(changed)} lockdown policy file(s)." if changed
              else "No AppBlocker lockdown policies were present.")
        return

    if args.sync_now:
        configure_paths(system_mode=True)
        st = AppState()
        if not st.sync.get("repo") or not st.sync.get("token"):
            print("No dashboard settings saved. Configure them in the app first.")
            return
        try:
            n = push_reports_to_github(
                st.sync, build_report_data(HistoryStore(), state=st))
            print(f"Pushed {n} bytes to {st.sync['repo']}.")
        except Exception as exc:
            print(f"Sync failed: {exc}")
        return

    if args.email_test:
        configure_paths(system_mode=True)
        st = AppState()
        cfg = st.monitor.get("email") or {}
        if not cfg.get("host") or not cfg.get("to"):
            print("No email settings saved. Configure them in the app first.")
            return
        try:
            send_email(cfg, "[AppBlocker] Test email",
                       "This is a test from AppBlocker. Email alerts work.")
            print(f"Test email sent to {cfg.get('to')}.")
        except Exception as exc:
            print(f"Failed to send test email: {exc}")
        return

    if args.import_history:
        configure_paths(system_mode=True)
        st = AppState()
        n = import_all_history(st, HistoryStore())
        print(f"Imported {n} new visit(s).")
        return

    if args.web_clear:
        changed = sync_blocked_websites([])
        apply_site_block_policy([])          # also drop the in-browser URLBlocklist
        sync_flatpak_policy_overrides(False)
        print("Cleared AppBlocker website blocks from /etc/hosts and browsers."
              if changed else "Cleared AppBlocker in-browser website blocks.")
        return

    if args.web_status:
        configure_paths(system_mode=True)
        st = AppState()
        if st.websites:
            print("Blocked websites:")
            for d in st.websites:
                print(f"  {d}")
        else:
            print("No websites are blocked.")
        return

    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)

    if args.export_settings:
        configure_paths(system_mode=(args.system or is_root))
        try:
            export_settings(args.export_settings)
            print(f"Exported settings to {args.export_settings}")
            print("This file contains secrets (password, email password, "
                  "dashboard token) — keep it private and delete it after "
                  "copying it to the other machine.")
        except Exception as exc:
            print(f"Export failed: {exc}")
        return

    if args.import_settings:
        configure_paths(system_mode=(args.system or is_root))
        try:
            import_settings(args.import_settings)
            print(f"Imported settings from {args.import_settings}.")
            print("Restart the service to apply now:  sudo systemctl restart "
                  "appblocker")
        except Exception as exc:
            print(f"Import failed: {exc}")
        return

    # The daemon is always system-wide. The GUI is system-wide when asked, or
    # automatically when launched as root; otherwise it stays per-user.
    if args.daemon:
        configure_paths(system_mode=True)
        run_daemon()
        return

    configure_paths(system_mode=(args.system or is_root))
    run_gui()


if __name__ == "__main__":
    main()
