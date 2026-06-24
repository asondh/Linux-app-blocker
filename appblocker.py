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
import argparse
import threading
import subprocess

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

    def __init__(self, state, on_change=None):
        super().__init__(daemon=True)
        self.state = state
        self.on_change = on_change  # called (from this thread) when state changes
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
        # block its target apps for exactly the user(s) running the trigger.
        for rule in trigger_rules:
            if not rule.get("enabled", True):
                continue
            trig_app = resolve(rule.get("trigger"))
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

        if blockers:
            for pid, comm, uid, exe, cmd in procs:
                for app, uids in blockers:
                    if (uids is None or uid in uids) and \
                            app_matches(app, comm, exe, cmd):
                        self._kill(pid)
                        break

        # Keep /etc/hosts in sync with the blocked-website list (system mode,
        # root only). Cheap: only rewrites the file when it actually differs.
        if SYSTEM_MODE:
            with self.state.lock:
                domains = list(self.state.websites)
            sync_blocked_websites(domains)

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
        self._mtime = None
        self.load()

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
              "users": []                # [] = any user, else specific names
            }
        Targets are blocked only for the user(s) actually running the trigger.
        """
        clean = []
        for r in rules or []:
            if not isinstance(r, dict) or not r.get("trigger"):
                continue
            r.setdefault("name", "")
            r.setdefault("enabled", True)
            r.setdefault("targets", [])
            r.setdefault("users", [])
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

    def load(self):
        data = load_json(BLOCKED_FILE, None)
        if data and isinstance(data, dict) and "apps" in data:
            self.apps = self._normalize(data["apps"])
            self.rules = self._normalize_rules(data.get("rules"))
            self.websites = self._normalize_websites(data.get("websites"))
            self._mtime = self._file_mtime()
        else:
            self.apps = self._default_apps()
            self.rules = []
            self.websites = []
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
                self._mtime = mtime
            return True
        return False

    def save(self):
        with self.lock:
            self.save_locked()

    def save_locked(self):
        save_json(BLOCKED_FILE, {"apps": self.apps, "rules": self.rules,
                                 "websites": self.websites})
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

        if HAS_TRAY:
            self._setup_tray()

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
        bar = tk.Frame(self.root, bg=COLOR_BG)
        bar.pack(fill="x", padx=14, pady=(12, 4))

        tk.Button(bar, text="⚡ Quick Block: Browsers",
                  command=self.quick_block_browsers,
                  bg=COLOR_BLOCKED, fg="white", activebackground="#922b21",
                  font=("Helvetica", 11, "bold"), relief="flat",
                  padx=12, pady=8, cursor="hand2").pack(side="left")

        tk.Button(bar, text="🔓 Unblock All", command=self.unblock_all,
                  bg=COLOR_ACTIVE, fg="white", activebackground="#1e8449",
                  font=("Helvetica", 11, "bold"), relief="flat",
                  padx=12, pady=8, cursor="hand2").pack(side="left", padx=8)

        tk.Button(bar, text="➕ Add App", command=self.add_app_dialog,
                  bg=COLOR_ACCENT, fg="white", activebackground="#1f618d",
                  font=("Helvetica", 11), relief="flat",
                  padx=12, pady=8, cursor="hand2").pack(side="right")

        tk.Button(bar, text="⛓ Auto-Block Rules", command=self.rules_dialog,
                  bg="#8e44ad", fg="white", activebackground="#6c3483",
                  font=("Helvetica", 11), relief="flat",
                  padx=12, pady=8, cursor="hand2").pack(side="right", padx=8)

        if SYSTEM_MODE:
            tk.Button(bar, text="🌐 Block Websites",
                      command=self.websites_dialog,
                      bg="#16a085", fg="white", activebackground="#0e6655",
                      font=("Helvetica", 11), relief="flat",
                      padx=12, pady=8, cursor="hand2").pack(side="right")

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

        # right: status + buttons
        right = tk.Frame(card, bg="white")
        right.pack(side="right", padx=10)

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
        win.geometry("500x420")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Add a custom app to block", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 13, "bold")).pack(
                     pady=(14, 6))

        kind = tk.StringVar(value="process")
        body = tk.Frame(win, bg=COLOR_BG)
        body.pack(fill="x", padx=18)

        tk.Label(body, text="Name:", bg=COLOR_BG).grid(
            row=0, column=0, sticky="w", pady=4)
        name_var = tk.StringVar()
        tk.Entry(body, textvariable=name_var, width=40).grid(
            row=0, column=1, columnspan=2, pady=4, sticky="we")
        body.columnconfigure(1, weight=1)

        tk.Radiobutton(win, text="An installed program (pick its file)",
                       variable=kind, value="process", bg=COLOR_BG,
                       anchor="w").pack(fill="x", padx=18, pady=(8, 0))

        prog = tk.Frame(win, bg=COLOR_BG)
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

        tk.Radiobutton(win, text="A web app / PWA, or a custom command",
                       variable=kind, value="commandline", bg=COLOR_BG,
                       anchor="w").pack(fill="x", padx=18, pady=(10, 0))
        cmd = tk.Frame(win, bg=COLOR_BG)
        cmd.pack(fill="x", padx=36)
        match_var = tk.StringVar()
        tk.Entry(cmd, textvariable=match_var).pack(fill="x")
        tk.Label(win, text="Enter the web address (or any unique text from the "
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

        btnbar = tk.Frame(win, bg=COLOR_BG)
        btnbar.pack(side="bottom", fill="x", padx=18, pady=14)
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
        tnames = ", ".join(p2n.get(t.lower(), t) for t in targets) or "(none)"
        who = ", ".join(rule.get("users") or []) or "any user"
        return f"While {trig_name} is running  →  block {tnames}\nfor {who}"

    def rules_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Auto-Block Rules")
        win.configure(bg=COLOR_BG)
        win.geometry("560x460")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Auto-Block Rules", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text="While a chosen app is running for a user, the apps "
                 "you pick get blocked for that same user.", bg=COLOR_BG,
                 fg="#7f8c8d", wraplength=520, justify="left").pack(
                     padx=16, pady=(0, 8))

        listwrap = tk.Frame(win, bg=COLOR_BG)
        listwrap.pack(fill="both", expand=True, padx=14)

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
                tk.Label(card, text=self._rule_summary(rule), bg="white",
                         fg=COLOR_HEADER, justify="left", anchor="w",
                         font=("Helvetica", 10)).pack(
                             side="left", fill="x", expand=True, padx=6, pady=6)
                tk.Button(card, text="✕", relief="flat", bg="white", fg="#95a5a6",
                          cursor="hand2",
                          command=lambda idx=i: self._delete_rule(idx, render)
                          ).pack(side="right", padx=4)
                tk.Button(card, text="Edit", relief="flat", bg="white",
                          fg=COLOR_ACCENT, cursor="hand2",
                          command=lambda idx=i: self._edit_rule(win, idx, render)
                          ).pack(side="right")

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(fill="x", padx=14, pady=12)
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
        win.geometry("460x560")
        win.transient(parent)
        win.grab_set()

        tk.Label(win, text="When this app is running…", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(14, 2))
        trigger_var = tk.StringVar()
        cur_trig = existing.get("trigger", "")
        trigger_var.set(proc_to_name.get(cur_trig.lower(),
                                          choices[0][0] if choices else ""))
        ttk.Combobox(win, textvariable=trigger_var,
                     values=[n for n, _ in choices], state="readonly").pack(
                         fill="x", padx=18)

        tk.Label(win, text="…automatically block these apps:", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 11, "bold")).pack(
                     anchor="w", padx=18, pady=(12, 2))
        tgt_wrap = tk.Frame(win, bg=COLOR_BG)
        tgt_wrap.pack(fill="x", padx=24)
        cur_targets = {t.lower() for t in existing.get("targets", [])}
        target_vars = []
        for name, proc in choices:
            v = tk.BooleanVar(value=proc.lower() in cur_targets)
            tk.Checkbutton(tgt_wrap, text=name, variable=v, bg=COLOR_BG,
                           anchor="w").pack(fill="x")
            target_vars.append((proc, v))

        # users (system mode)
        user_vars = {}
        if SYSTEM_MODE:
            tk.Label(win, text="For these users:", bg=COLOR_BG, fg=COLOR_HEADER,
                     font=("Helvetica", 11, "bold")).pack(
                         anchor="w", padx=18, pady=(12, 2))
            cur_users = set(existing.get("users") or [])
            any_var = tk.BooleanVar(value=not cur_users)

            def toggle_any():
                if any_var.get():
                    for v in user_vars.values():
                        v.set(False)

            tk.Checkbutton(win, text="Any user", variable=any_var,
                           command=toggle_any, bg=COLOR_BG, anchor="w").pack(
                               fill="x", padx=24)
            ufr = tk.Frame(win, bg=COLOR_BG)
            ufr.pack(fill="x", padx=40)
            for uname, _uid in self.users:
                v = tk.BooleanVar(value=uname in cur_users)
                tk.Checkbutton(ufr, text=uname, variable=v,
                               command=lambda: any_var.set(False), bg=COLOR_BG,
                               anchor="w").pack(fill="x")
                user_vars[uname] = v

        name_var = tk.StringVar(value=existing.get("name", ""))
        nfr = tk.Frame(win, bg=COLOR_BG)
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
            if not targets:
                messagebox.showwarning("Pick targets",
                                       "Choose at least one app to block.",
                                       parent=win)
                return
            rule = {
                "name": name_var.get().strip(),
                "enabled": True,
                "trigger": trig_proc,
                "targets": targets,
                "users": [u for u, v in user_vars.items() if v.get()],
            }
            if index is None:
                self.state.add_rule(rule)
            else:
                self.state.update_rule(index, rule)
            win.destroy()
            on_done()

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)
        tk.Button(bar, text="Save Rule", command=save, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Cancel", command=win.destroy, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

    # -- blocked websites UI ------------------------------------------------ #
    def websites_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Block Websites")
        win.configure(bg=COLOR_BG)
        win.geometry("480x520")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="🌐 Blocked Websites", bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 2))
        tk.Label(win, text="These websites are blocked in every browser, for "
                 "everyone on this computer. Enter one domain per line "
                 "(e.g. youtube.com).", bg=COLOR_BG, fg="#7f8c8d",
                 wraplength=440, justify="left").pack(padx=18, pady=(0, 8))

        txt = tk.Text(win, height=14, width=44, font=("monospace", 11))
        txt.pack(fill="both", expand=True, padx=18)
        with self.state.lock:
            txt.insert("1.0", "\n".join(self.state.websites))

        tk.Label(win, text="Note: this is machine-wide. A browser using "
                 "“secure DNS” (DoH) or a VPN can bypass it.", bg=COLOR_BG,
                 fg="#b9770e", wraplength=440, justify="left").pack(
                     padx=18, pady=(6, 0))

        def save():
            raw = txt.get("1.0", tk.END)
            domains = [line for line in raw.splitlines() if line.strip()]
            saved = self.state.set_websites(domains)
            # Apply immediately (we are root in system mode); the daemon also
            # keeps it in sync, but this gives instant feedback.
            sync_blocked_websites(saved)
            messagebox.showinfo(
                "Saved", f"{len(saved)} website(s) blocked.\n\nChanges take "
                "effect right away (you may need to reload open tabs).",
                parent=win)
            win.destroy()

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)
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
        win.transient(self.root)
        win.grab_set()
        result = {"value": None}

        tk.Label(win, text=title, bg=COLOR_BG, fg=COLOR_HEADER,
                 font=("Helvetica", 14, "bold")).pack(pady=(14, 6))

        mode = tk.StringVar(value=app.get("mode", "manual")
                            if self._is_configured(app) else "manual")
        minutes_var = tk.StringVar(value="30")

        body = tk.Frame(win, bg=COLOR_BG)
        body.pack(fill="both", expand=True, padx=20)

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

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=14)
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
        win.geometry("360x300")
        win.transient(parent)
        win.grab_set()
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
    monitor = ProcessMonitor(state)

    # Run the sweep loop in the foreground so systemd supervises this process
    # directly (Type=simple). Translate SIGTERM into a clean stop.
    def _handle_term(signum, frame):
        monitor.stop()

    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)

    sys.stderr.write(
        f"[daemon] AppBlocker enforcement running (uid={os.geteuid()}, "
        f"blocklist={BLOCKED_FILE})\n")
    sys.stderr.flush()

    # ProcessMonitor.run() is the same sweep loop the GUI uses in a thread; we
    # just call it inline here so the daemon has no extra moving parts.
    monitor.run()
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
    args = parser.parse_args()

    if args.web_clear:
        changed = sync_blocked_websites([])
        print("Cleared AppBlocker website blocks from /etc/hosts."
              if changed else "No AppBlocker website blocks were present.")
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

    # The daemon is always system-wide. The GUI is system-wide when asked, or
    # automatically when launched as root; otherwise it stays per-user.
    if args.daemon:
        configure_paths(system_mode=True)
        run_daemon()
        return

    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    configure_paths(system_mode=(args.system or is_root))
    run_gui()


if __name__ == "__main__":
    main()
