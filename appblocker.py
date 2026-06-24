#!/usr/bin/env python3
"""
AppBlocker — a parent-friendly Linux desktop app to block applications
(especially web browsers) for a configurable amount of time.

Design goals:
  * Pure Python standard library + tkinter (no required third-party deps).
  * No sudo required. Blocking works by running a background monitor thread
    that kills any process whose name matches a blocked app every few seconds.
  * Password protected (SHA-256 hash stored in ~/.appblocker/config.json).
  * Optional system tray icon if pystray + Pillow are installed.

All persistent state lives in ~/.appblocker/.

Author: AppBlocker
License: MIT
"""

import os
import sys
import json
import time
import signal
import hashlib
import threading
import subprocess

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

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
APP_DIR = os.path.join(os.path.expanduser("~"), ".appblocker")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
BLOCKED_FILE = os.path.join(APP_DIR, "blocked.json")

MONITOR_INTERVAL = 5  # seconds between kill sweeps

COLOR_BLOCKED = "#c0392b"   # red
COLOR_ACTIVE = "#27ae60"    # green
COLOR_BG = "#f4f6f7"
COLOR_HEADER = "#2c3e50"
COLOR_ACCENT = "#2980b9"

# Default browsers to pre-populate. For each we list candidate executable
# names; the first one found on PATH is used.
DEFAULT_APPS = [
    ("Firefox", ["firefox", "firefox-esr"]),
    ("Chromium", ["chromium", "chromium-browser"]),
    ("Google Chrome", ["google-chrome", "google-chrome-stable", "chrome"]),
    ("Brave", ["brave-browser", "brave", "brave-browser-stable"]),
]


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def ensure_app_dir():
    os.makedirs(APP_DIR, exist_ok=True)


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
    os.replace(tmp, path)


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
        changed_timer = self._expire_timers()

        with self.state.lock:
            blocked_names = {
                app["proc_name"].lower()
                for app in self.state.apps
                if app.get("blocked")
            }

        if blocked_names:
            for pid, comm in self._iter_processes():
                if comm.lower() in blocked_names:
                    self._kill(pid)

        if changed_timer and self.on_change:
            self.on_change()

    def _expire_timers(self):
        """Auto-unblock any timer that has elapsed. Returns True if changed."""
        now = time.time()
        changed = False
        with self.state.lock:
            for app in self.state.apps:
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
        """Yield (pid, comm) for every process via /proc."""
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == os.getpid():
                continue
            comm = None
            try:
                with open(f"/proc/{entry}/comm", "r") as fh:
                    comm = fh.read().strip()
            except Exception:
                # Fall back to the basename of the executable path.
                try:
                    exe = os.readlink(f"/proc/{entry}/exe")
                    comm = os.path.basename(exe)
                except Exception:
                    continue
            if comm:
                yield pid, comm

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
          "blocked": False,
          "mode": "manual" | "timer",
          "timer_end": None | <epoch seconds>
        }
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.apps = []
        self.load()

    # -- persistence -------------------------------------------------------- #
    def load(self):
        data = load_json(BLOCKED_FILE, None)
        if data and isinstance(data, dict) and "apps" in data:
            self.apps = data["apps"]
        else:
            self.apps = self._default_apps()
            self.save()

    def save(self):
        with self.lock:
            self.save_locked()

    def save_locked(self):
        save_json(BLOCKED_FILE, {"apps": self.apps})

    @staticmethod
    def _default_apps():
        apps = []
        for name, candidates in DEFAULT_APPS:
            path, proc = detect_executable(candidates)
            apps.append({
                "name": name,
                "path": path or "",
                "proc_name": proc,
                "blocked": False,
                "mode": "manual",
                "timer_end": None,
            })
        return apps

    # -- mutations ---------------------------------------------------------- #
    def add_app(self, name, path):
        proc = os.path.basename(path) if path else name.lower()
        with self.lock:
            self.apps.append({
                "name": name,
                "path": path,
                "proc_name": proc,
                "blocked": False,
                "mode": "manual",
                "timer_end": None,
            })
            self.save_locked()

    def remove_app(self, index):
        with self.lock:
            if 0 <= index < len(self.apps):
                del self.apps[index]
                self.save_locked()

    def block(self, index, minutes=None):
        with self.lock:
            app = self.apps[index]
            app["blocked"] = True
            if minutes and minutes > 0:
                app["mode"] = "timer"
                app["timer_end"] = time.time() + minutes * 60
            else:
                app["mode"] = "manual"
                app["timer_end"] = None
            self.save_locked()

    def unblock(self, index):
        with self.lock:
            app = self.apps[index]
            app["blocked"] = False
            app["mode"] = "manual"
            app["timer_end"] = None
            self.save_locked()

    def any_blocked(self):
        with self.lock:
            return any(a.get("blocked") for a in self.apps)


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

        root.title("AppBlocker")
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

    def _render_row(self, idx, app):
        blocked = app.get("blocked")
        card = tk.Frame(self.list_frame, bg="white", bd=0,
                        highlightbackground="#dfe4ea", highlightthickness=1)
        card.pack(fill="x", pady=3, ipady=4)

        # left: color strip
        strip = tk.Frame(card, bg=COLOR_BLOCKED if blocked else COLOR_ACTIVE,
                         width=6)
        strip.pack(side="left", fill="y")

        # name + path
        info = tk.Frame(card, bg="white")
        info.pack(side="left", fill="x", expand=True, padx=10, pady=4)
        tk.Label(info, text=app["name"], bg="white", fg=COLOR_HEADER,
                 font=("Helvetica", 12, "bold"), anchor="w").pack(
                     fill="x")
        path_text = app["path"] or f"(not installed — expects '{app['proc_name']}')"
        tk.Label(info, text=path_text, bg="white", fg="#95a5a6",
                 font=("Helvetica", 9), anchor="w").pack(fill="x")

        # right: status + buttons
        right = tk.Frame(card, bg="white")
        right.pack(side="right", padx=10)

        status_text = self._status_text(app)
        status_lbl = tk.Label(
            right, text=status_text,
            bg=COLOR_BLOCKED if blocked else COLOR_ACTIVE,
            fg="white", font=("Helvetica", 10, "bold"),
            padx=10, pady=3)
        status_lbl.pack(side="top", pady=(0, 4))

        btns = tk.Frame(right, bg="white")
        btns.pack(side="top")
        if blocked:
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

        self.rows.append({"status_lbl": status_lbl, "idx": idx})

    @staticmethod
    def _status_text(app):
        if not app.get("blocked"):
            return "● Active"
        if app.get("mode") == "timer" and app.get("timer_end"):
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
        with self.state.lock:
            apps = list(self.state.apps)
        needs_rebuild = False
        for row in self.rows:
            idx = row["idx"]
            if idx >= len(apps):
                needs_rebuild = True
                break
            app = apps[idx]
            text = self._status_text(app)
            # If a timer app became unblocked (by the monitor), rebuild.
            if not app.get("blocked") and "Active" not in row["status_lbl"]["text"] \
                    and row["status_lbl"]["bg"] == COLOR_BLOCKED:
                needs_rebuild = True
                break
            row["status_lbl"].config(text=text)
        if needs_rebuild:
            self.refresh()
        self._update_global_status()
        self.root.after(1000, self._tick)

    # -- actions ------------------------------------------------------------ #
    def block(self, idx):
        minutes = self._ask_timer()
        if minutes is None:  # cancelled
            return
        self.state.block(idx, minutes if minutes > 0 else None)
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
        """Block every app that looks like a browser, with one timer prompt."""
        minutes = self._ask_timer(title="Quick Block Browsers")
        if minutes is None:
            return
        with self.state.lock:
            for i in range(len(self.state.apps)):
                self.state.apps[i]  # noqa
        # Block all currently-listed apps (the default list is browsers).
        with self.state.lock:
            for app in self.state.apps:
                app["blocked"] = True
                if minutes and minutes > 0:
                    app["mode"] = "timer"
                    app["timer_end"] = time.time() + minutes * 60
                else:
                    app["mode"] = "manual"
                    app["timer_end"] = None
            self.state.save_locked()
        self.refresh()

    def unblock_all(self):
        if not self._authenticate("Unblocking requires the parent password."):
            return
        with self.state.lock:
            for app in self.state.apps:
                app["blocked"] = False
                app["mode"] = "manual"
                app["timer_end"] = None
            self.state.save_locked()
        self.refresh()

    def add_app_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Add Application")
        win.configure(bg=COLOR_BG)
        win.geometry("460x220")
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Add a custom app to block", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 13, "bold")).pack(
                     pady=(14, 8))

        frm = tk.Frame(win, bg=COLOR_BG)
        frm.pack(fill="x", padx=18)

        tk.Label(frm, text="Name:", bg=COLOR_BG).grid(
            row=0, column=0, sticky="w", pady=4)
        name_var = tk.StringVar()
        tk.Entry(frm, textvariable=name_var, width=36).grid(
            row=0, column=1, columnspan=2, pady=4, sticky="we")

        tk.Label(frm, text="Path:", bg=COLOR_BG).grid(
            row=1, column=0, sticky="w", pady=4)
        path_var = tk.StringVar()
        tk.Entry(frm, textvariable=path_var, width=26).grid(
            row=1, column=1, pady=4, sticky="we")

        def browse():
            p = filedialog.askopenfilename(title="Select executable")
            if p:
                path_var.set(p)
                if not name_var.get():
                    name_var.set(os.path.basename(p).title())

        tk.Button(frm, text="Browse…", command=browse, relief="flat",
                  bg=COLOR_ACCENT, fg="white", cursor="hand2").grid(
                      row=1, column=2, padx=(6, 0), pady=4)

        frm.columnconfigure(1, weight=1)

        def save():
            name = name_var.get().strip()
            path = path_var.get().strip()
            if not name:
                messagebox.showwarning("Missing", "Please enter a name.", parent=win)
                return
            # If a name without a path is given, try to auto-detect.
            if not path:
                detected = which(name.lower())
                if detected:
                    path = detected
            self.state.add_app(name, path)
            win.destroy()
            self.refresh()

        btnbar = tk.Frame(win, bg=COLOR_BG)
        btnbar.pack(fill="x", padx=18, pady=16)
        tk.Button(btnbar, text="Add", command=save, bg=COLOR_ACTIVE,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(btnbar, text="Cancel", command=win.destroy, relief="flat",
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
    def _ask_timer(self, title="Set Timer"):
        """
        Ask the user for an optional timer.
        Returns: 0 for manual (no timer), >0 minutes for timer, None if cancelled.
        """
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=COLOR_BG)
        win.geometry("380x230")
        win.transient(self.root)
        win.grab_set()
        result = {"value": None}

        tk.Label(win, text="How long should it stay blocked?", bg=COLOR_BG,
                 fg=COLOR_HEADER, font=("Helvetica", 12, "bold")).pack(
                     pady=(16, 10))

        mode = tk.StringVar(value="manual")
        body = tk.Frame(win, bg=COLOR_BG)
        body.pack(fill="x", padx=24)

        tk.Radiobutton(body, text="Manual — until I unblock it",
                       variable=mode, value="manual", bg=COLOR_BG,
                       anchor="w").pack(fill="x", pady=2)
        timer_row = tk.Frame(body, bg=COLOR_BG)
        timer_row.pack(fill="x", pady=2)
        tk.Radiobutton(timer_row, text="Timer for", variable=mode,
                       value="timer", bg=COLOR_BG).pack(side="left")
        minutes_var = tk.StringVar(value="30")
        tk.Spinbox(timer_row, from_=1, to=1440, width=6,
                   textvariable=minutes_var).pack(side="left", padx=6)
        tk.Label(timer_row, text="minutes", bg=COLOR_BG).pack(side="left")

        def confirm():
            if mode.get() == "timer":
                try:
                    m = int(minutes_var.get())
                    result["value"] = max(1, m)
                except ValueError:
                    result["value"] = 1
            else:
                result["value"] = 0
            win.destroy()

        def cancel():
            result["value"] = None
            win.destroy()

        bar = tk.Frame(win, bg=COLOR_BG)
        bar.pack(side="bottom", fill="x", padx=24, pady=16)
        tk.Button(bar, text="Block", command=confirm, bg=COLOR_BLOCKED,
                  fg="white", relief="flat", padx=16, pady=6,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Cancel", command=cancel, relief="flat",
                  padx=12, pady=6, cursor="hand2").pack(side="right", padx=8)

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
        """Closing the window minimizes (to tray if available)."""
        if self.tray_icon:
            self.root.withdraw()
            return
        if self.state.any_blocked():
            keep = messagebox.askyesno(
                "Keep blocking?",
                "Apps are still blocked. Keep AppBlocker running in the "
                "background to enforce blocking?\n\n"
                "Yes = minimize and keep blocking\nNo = quit (stops blocking)")
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
# Entry point
# --------------------------------------------------------------------------- #
def main():
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


if __name__ == "__main__":
    main()
