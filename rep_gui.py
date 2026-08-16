#!/usr/bin/env python3
"""
ThreatLens — GUI Version
Clean black & white theme, Windows-native tkinter interface.
"""

import sys
import os
import json
import threading
import time
from datetime import datetime
from tkinter import (
    Tk, Toplevel, Frame, Label, Entry, Button, Text, Checkbutton,
    BooleanVar, StringVar, Scrollbar, END, BOTH, LEFT, RIGHT, X, Y,
    WORD, DISABLED, NORMAL, HORIZONTAL, VERTICAL, font as tkfont,
)
from tkinter import ttk

# Add tool directory to path (for PyInstaller bundle)
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BUNDLE_DIR)

# Logo paths
LOGO_64 = os.path.join(BUNDLE_DIR, "logo_64.png")
LOGO_512 = os.path.join(BUNDLE_DIR, "logo_512.png")

# ═══════════════════════════════════════════════════════════════════
# Theme — RGB(16, 32, 51) Navy Dark Theme
# ═══════════════════════════════════════════════════════════════════

# RGB(16, 32, 51) = #102033 — deep navy blue
NAVY = "#102033"
NAVY_LIGHT = "#1a2d42"
NAVY_DARK = "#0a1520"

THEME_COLORS = {
    "BG":           NAVY,          # Main background (RGB 16,32,51)
    "BG_SECONDARY": NAVY_LIGHT,    # Slightly lighter navy
    "BG_INPUT":     "#1a2d42",     # Input fields
    "BG_BUTTON":    "#1e3a5f",     # Navy buttons
    "BG_BUTTON_HOVER": "#2a4a70",  # Hover state
    "BG_HEADER":    NAVY_DARK,     # Darker navy header
    "BG_OUTPUT":    "#0d1b2a",     # Output area (darker)
    "BG_STATUS":    "#0a1520",     # Status bar

    "FG":           "#e0e8f0",     # Light text
    "FG_DIM":       "#7a8a9a",     # Muted text
    "FG_ACCENT":    "#4a9eff",     # Bright blue accent
    "FG_MUTED":     "#556677",     # Very muted

    "BORDER":       "#2a3a4a",     # Dark border
    "BORDER_FOCUS": "#4a9eff",     # Blue focus border

    "CRITICAL":     "#EF4444",     # Red
    "HIGH":         "#F97316",     # Orange
    "MEDIUM":       "#EAB308",     # Yellow
    "LOW":          "#22C55E",     # Green
    "INFO":         "#4a9eff",     # Blue
}

class Theme:
    # Fonts
    FONT_FAMILY     = "Consolas"
    FONT_FAMILY_UI  = "Segoe UI"
    FONT_SIZE       = 10
    FONT_SIZE_SMALL = 9
    FONT_SIZE_TITLE = 14

# Set all color attributes on Theme class
for _k, _v in THEME_COLORS.items():
    setattr(Theme, _k, _v)


# ═══════════════════════════════════════════════════════════════════
# Redirect stdout/stderr to the GUI Text widget
# ═══════════════════════════════════════════════════════════════════

class TextRedirector:
    """Redirect print output to a tkinter Text widget."""
    def __init__(self, text_widget, tag="stdout"):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, string):
        try:
            self.text_widget.after(0, self._append, string)
        except Exception:
            pass

    def _append(self, string):
        self.text_widget.configure(state=NORMAL)
        self.text_widget.insert(END, string, self.tag)
        self.text_widget.see(END)
        self.text_widget.configure(state=DISABLED)

    def flush(self):
        pass


# ═══════════════════════════════════════════════════════════════════
# Main Application
# ═══════════════════════════════════════════════════════════════════

class RepToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ThreatLens v1.0")
        self.root.geometry("900x720")
        self.root.minsize(750, 550)
        self.root.configure(bg=Theme.BG)

        # Remove window icon (clean look) — set a generic icon if available
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # State
        self.running = False
        self.last_results = None
        self.api_keys = self._load_api_keys()
        self.report_format = "txt"  # default
        self.all_results = []  # accumulated results for bulk export
        import threading as _threading
        self.stop_event = _threading.Event()


        self._build_ui()
        self._setup_tags()

        # Hot-reload any saved API keys into config at startup
        if self.api_keys:
            try:
                import config as cfg
                cfg.VIRUSTOTAL_KEY = self.api_keys.get("virustotal", cfg.VIRUSTOTAL_KEY)
                cfg.ABUSEIPDB_KEY = self.api_keys.get("abuseipdb", cfg.ABUSEIPDB_KEY)
                cfg.SHODAN_KEY = self.api_keys.get("shodan", cfg.SHODAN_KEY)
                cfg.OTX_KEY = self.api_keys.get("otx", cfg.OTX_KEY)
                cfg.IPINFO_KEY = self.api_keys.get("ipinfo", cfg.IPINFO_KEY)
            except Exception:
                pass

    def _build_ui(self):
        """Construct the entire UI."""

        # ─── Header Bar ────────────────────────────────────────
        header = Frame(self.root, bg=Theme.BG_HEADER, height=48)
        header.pack(fill=X, side="top")
        header.pack_propagate(False)

        # Logo
        try:
            from PIL import Image, ImageTk
            if os.path.exists(LOGO_64):
                _logo_img = Image.open(LOGO_64).resize((32, 32), Image.LANCZOS)
                self._logo_photo = ImageTk.PhotoImage(_logo_img)
                Label(header, image=self._logo_photo,
                      bg=Theme.BG_HEADER).pack(side=LEFT, padx=(12, 6), pady=8)
        except Exception:
            pass

        Label(
            header, text="ThreatLens",
            bg=Theme.BG_HEADER, fg=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY_UI, 13, "bold"),
            anchor="w", padx=16,
        ).pack(side=LEFT, fill=BOTH, expand=True)

        self.settings_btn = Button(
            header, text="\u2699  SETTINGS",
            bg=Theme.BG_HEADER, fg="#ffffff",
            activebackground=Theme.BG_BUTTON_HOVER, activeforeground="#ffffff", 
            font=(Theme.FONT_FAMILY_UI, 9),
            relief="flat", bd=0, padx=12, pady=4,
            cursor="hand2",
            command=self._show_settings,
        )
        self.settings_btn.pack(side=RIGHT, padx=(0, 4))

        Label(
            header, text="v1.0",
            bg=Theme.BG_HEADER, fg=Theme.FG_MUTED,
            font=(Theme.FONT_FAMILY_UI, 10),
            anchor="e", padx=16,
        ).pack(side=RIGHT)

        # ─── Input Section ─────────────────────────────────────
        input_frame = Frame(self.root, bg=Theme.BG_SECONDARY, padx=12, pady=10)
        input_frame.pack(fill=X)

        # Row 1: Target input
        row1 = Frame(input_frame, bg=Theme.BG_SECONDARY)
        row1.pack(fill=X, pady=(0, 6))

        Label(
            row1, text="TARGET",
            bg=Theme.BG_SECONDARY, fg=Theme.FG_DIM,
            font=(Theme.FONT_FAMILY_UI, 9, "bold"),
            width=10, anchor="w",
        ).pack(side=LEFT)

        self.target_var = StringVar()
        self.target_entry = Entry(
            row1,
            textvariable=self.target_var,
            bg=Theme.BG_INPUT, fg=Theme.FG_ACCENT,
            insertbackground=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY, 11),
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=Theme.BORDER,
            highlightcolor=Theme.BORDER_FOCUS,
        )
        self.target_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 8), ipady=6)
        self.target_entry.bind("<Return>", lambda e: self._on_analyze())

        self.analyze_btn = Button(
            row1, text="ANALYZE",
            bg=Theme.FG_ACCENT, fg=Theme.BG,
            activebackground=Theme.FG_DIM, activeforeground=Theme.BG,
            font=(Theme.FONT_FAMILY_UI, 10, "bold"),
            relief="flat", bd=0, padx=20, pady=6,
            cursor="hand2",
            command=self._on_analyze,
        )
        self.analyze_btn.pack(side=RIGHT, padx=(0, 4))

        self.stop_btn = Button(
            row1, text="STOP",
            bg="#cc0000", fg="#ffffff",
            activebackground="#990000", activeforeground="#ffffff",
            font=(Theme.FONT_FAMILY_UI, 10, "bold"), relief="flat",
            padx=14, pady=6, cursor="hand2",
            command=self._on_stop,
        )
        self.stop_btn.pack(side=RIGHT, padx=(0, 4))
        self.stop_btn.pack_forget()  # hidden until analysis starts

        self.bulk_btn = Button(
            row1, text="BULK",
            bg=Theme.BG_BUTTON, fg=Theme.FG,
            activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY_UI, 10), relief="flat", padx=14, pady=6,
            cursor="hand2", highlightthickness=1, highlightbackground=Theme.BORDER,
            command=self._show_bulk_dialog,
        )
        self.bulk_btn.pack(side=RIGHT, padx=(0, 4))

        self.subs_btn = Button(
            row1, text="SUBS",
            bg=Theme.BG_BUTTON, fg=Theme.FG,
            activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY_UI, 10), relief="flat", padx=14, pady=6,
            cursor="hand2", highlightthickness=1, highlightbackground=Theme.BORDER,
            command=self._on_subdomains,
        )
        self.subs_btn.pack(side=RIGHT, padx=(0, 4))

        self.report_btn = Button(
            row1, text="REPORT",
            bg=Theme.BG_BUTTON, fg=Theme.FG,
            activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY_UI, 10),
            relief="flat", bd=0, padx=14, pady=6,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=Theme.BORDER,
            command=self._on_report,
        )
        self.report_btn.pack(side=RIGHT, padx=(0, 4))

        self.clear_btn = Button(
            row1, text="CLEAR",
            bg=Theme.BG_BUTTON, fg=Theme.FG_DIM,
            activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG,
            font=(Theme.FONT_FAMILY_UI, 10),
            relief="flat", bd=0, padx=14, pady=6,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=Theme.BORDER,
            command=self._on_clear,
        )
        self.clear_btn.pack(side=RIGHT)

        # Row 2: Options
        row2 = Frame(input_frame, bg=Theme.BG_SECONDARY)
        row2.pack(fill=X)

        Label(
            row2, text="OPTIONS",
            bg=Theme.BG_SECONDARY, fg=Theme.FG_DIM,
            font=(Theme.FONT_FAMILY_UI, 9, "bold"),
            width=10, anchor="w",
        ).pack(side=LEFT)

        self.skip_ports_var = BooleanVar(value=False)
        self.skip_tor_var = BooleanVar(value=False)
        self.json_var = BooleanVar(value=False)

        for var, text in [
            (self.skip_ports_var, "Skip Port Scan"),
            (self.skip_tor_var, "Skip TOR Check"),
            (self.json_var, "JSON Output"),
        ]:
            cb = Checkbutton(
                row2, text=text,
                variable=var,
                bg=Theme.BG_SECONDARY, fg=Theme.FG_DIM,
                selectcolor=Theme.BG_INPUT,
                activebackground=Theme.BG_SECONDARY,
                activeforeground=Theme.FG,
                font=(Theme.FONT_FAMILY_UI, 9),
                relief="flat", bd=0,
                cursor="hand2",
            )
            cb.pack(side=LEFT, padx=(0, 16))

        # Report format toggle
        Label(row2, text="Report:", bg=Theme.BG_SECONDARY, fg=Theme.FG_DIM,
              font=(Theme.FONT_FAMILY_UI, 9)).pack(side=LEFT, padx=(12, 4))

        self.fmt_var = StringVar(value="TXT")
        self.fmt_btn = Button(
            row2, text="TXT",
            bg=Theme.FG_ACCENT, fg=Theme.BG,
            activebackground=Theme.FG_DIM, activeforeground=Theme.BG,
            font=(Theme.FONT_FAMILY_UI, 9, "bold"), relief="flat",
            width=5, cursor="hand2",
            command=self._toggle_format,
        )
        self.fmt_btn.pack(side=LEFT)

        # ─── Separator ─────────────────────────────────────────
        sep = Frame(self.root, bg=Theme.BORDER, height=1)
        sep.pack(fill=X)

        # ─── Output Area ───────────────────────────────────────
        output_frame = Frame(self.root, bg=Theme.BG)
        output_frame.pack(fill=BOTH, expand=True)

        # Scrollbar
        scrollbar = Scrollbar(output_frame, orient=VERTICAL)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.output_text = Text(
            output_frame,
            bg=Theme.BG_OUTPUT, fg=Theme.FG,
            font=(Theme.FONT_FAMILY, 10),
            relief="flat", bd=0,
            wrap=WORD,
            insertbackground=Theme.FG,
            selectbackground=Theme.BORDER_FOCUS,
            selectforeground=Theme.FG_ACCENT,
            yscrollcommand=scrollbar.set,
            padx=12, pady=8,
            state=DISABLED,
        )
        self.output_text.pack(fill=BOTH, expand=True)
        scrollbar.config(command=self.output_text.yview)

        # ─── Status Bar ────────────────────────────────────────
        status_frame = Frame(self.root, bg=Theme.BG_STATUS, height=28)
        status_frame.pack(fill=X, side="bottom")
        status_frame.pack_propagate(False)

        self.status_var = StringVar(value="Ready. Enter an IP address or domain to analyze.")
        Label(
            status_frame,
            textvariable=self.status_var,
            bg=Theme.BG_STATUS, fg=Theme.FG_DIM,
            font=(Theme.FONT_FAMILY_UI, 9),
            anchor="w", padx=12,
        ).pack(side=LEFT, fill=BOTH, expand=True)

        # Progress bar (indeterminate style)
        self.progress = ttk.Progressbar(
            status_frame, orient=HORIZONTAL, length=120, mode="indeterminate",
        )
        self.progress.pack(side=RIGHT, padx=12, pady=4)

        # Style the progress bar
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.Horizontal.TProgressbar",
            background=Theme.FG_ACCENT,
            troughcolor=Theme.BG_INPUT,
            borderwidth=0,
            lightcolor=Theme.FG_ACCENT,
            darkcolor=Theme.FG_ACCENT,
        )
        self.progress.configure(style="Custom.Horizontal.TProgressbar")

    def _setup_tags(self):
        """Configure text tags for colored output."""
        t = self.output_text
        t.tag_configure("stdout", foreground=Theme.FG)
        t.tag_configure("stderr", foreground=Theme.CRITICAL)
        t.tag_configure("header", foreground=Theme.FG_ACCENT, font=(Theme.FONT_FAMILY, 11, "bold"))
        t.tag_configure("section", foreground=Theme.INFO, font=(Theme.FONT_FAMILY, 10, "bold"))
        t.tag_configure("success", foreground=Theme.LOW)
        t.tag_configure("warning", foreground=Theme.MEDIUM)
        t.tag_configure("danger", foreground=Theme.CRITICAL)
        t.tag_configure("info", foreground=Theme.INFO)
        t.tag_configure("dim", foreground=Theme.FG_DIM)
        t.tag_configure("accent", foreground=Theme.FG_ACCENT, font=(Theme.FONT_FAMILY, 10, "bold"))
        t.tag_configure("badge_critical", foreground=Theme.BG, background=Theme.CRITICAL,
                         font=(Theme.FONT_FAMILY, 10, "bold"))
        t.tag_configure("badge_high", foreground=Theme.BG, background=Theme.HIGH,
                         font=(Theme.FONT_FAMILY, 10, "bold"))
        t.tag_configure("badge_medium", foreground=Theme.BG, background=Theme.MEDIUM,
                         font=(Theme.FONT_FAMILY, 10, "bold"))
        t.tag_configure("badge_low", foreground=Theme.BG, background=Theme.LOW,
                         font=(Theme.FONT_FAMILY, 10, "bold"))

    # ─── Output Helpers ────────────────────────────────────────

    def _write(self, text, tag="stdout"):
        self.output_text.configure(state=NORMAL)
        self.output_text.insert(END, text, tag)
        self.output_text.see(END)
        self.output_text.configure(state=DISABLED)

    def _writeln(self, text="", tag="stdout"):
        self._write(text + "\n", tag)

    def _write_header(self, text):
        self._writeln(f"\n{'=' * 68}", "dim")
        self._writeln(f"  {text}", "header")
        self._writeln(f"{'=' * 68}", "dim")
        self._writeln()

    def _write_section(self, text):
        self._writeln(f"\n--- {text} {'─' * (55 - len(text))}", "section")

    def _write_kv(self, key, value, tag="stdout"):
        self._writeln(f"  {key + ':':<22s} {value}", tag)

    def _write_status(self, source, msg, tag="dim"):
        self._writeln(f"  [{source}] {msg}", tag)

    def _write_badge(self, classification, score):
        tag = f"badge_{classification.lower()}"
        self._writeln(f"  [{classification} ({score}/100)]", tag)

    # ─── API Key Management ───────────────────────────────────

    def _keys_file_path(self):
        """Path to api_keys.json — persistent user location."""
        try:
            from config import APPDATA_DIR
            return str(APPDATA_DIR / "api_keys.json")
        except ImportError:
            return os.path.join(BUNDLE_DIR, "api_keys.json")

    def _load_api_keys(self):
        """Load API keys from api_keys.json."""
        path = self._keys_file_path()
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_api_keys(self, keys):
        """Save API keys to api_keys.json."""
        path = self._keys_file_path()
        with open(path, "w") as f:
            json.dump(keys, f, indent=2)
        self.api_keys = keys

    def _mask_key(self, key):
        """Mask an API key: show only last 4 characters."""
        if not key or len(key) < 8:
            return key if key else ""
        return "\u2022" * (len(key) - 4) + key[-4:]

    # ─── Settings Dialog ─────────────────────────────────────

    def _show_settings(self):
        """Open the API key settings dialog."""
        dialog = Toplevel(self.root)
        dialog.title("Settings — API Keys")
        dialog.geometry("520x440")
        dialog.configure(bg=Theme.BG)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Dark title bar
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
            )
        except Exception:
            pass

        # Center on parent
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 260
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 220
        dialog.geometry(f"+{x}+{y}")

        # ── Header ─────────────────────────────────────────
        hdr = Frame(dialog, bg=Theme.BG_HEADER, height=40)
        hdr.pack(fill=X)
        hdr.pack_propagate(False)
        Label(hdr, text="  API KEY CONFIGURATION",
              bg=Theme.BG_HEADER, fg=Theme.FG_ACCENT,
              font=(Theme.FONT_FAMILY_UI, 11, "bold")).pack(side=LEFT, padx=12)

        # ── Body ────────────────────────────────────────────
        body = Frame(dialog, bg=Theme.BG, padx=20, pady=12)
        body.pack(fill=BOTH, expand=True)

        Label(body, text="Enter API keys below. Keys are masked after saving.\nFree-tier sources (IPInfo, OTX) work without keys.",
              bg=Theme.BG, fg=Theme.FG_DIM,
              font=(Theme.FONT_FAMILY_UI, 9), justify=LEFT, anchor="w").pack(fill=X, pady=(0, 12))

        # API key definitions: (json_key, label, description)
        api_defs = [
            ("virustotal", "VirusTotal", "virustotal.com/gui/my-apikey"),
            ("abuseipdb", "AbuseIPDB", "abuseipdb.com/account/api"),
            ("shodan", "Shodan", "account.shodan.io"),
            ("otx", "AlienVault OTX", "otx.alienvault.com/api"),
            ("ipinfo", "IPInfo", "ipinfo.io/account/token"),
        ]

        # Build field widgets
        key_vars = {}      # json_key -> StringVar (actual value)
        entry_widgets = {} # json_key -> Entry widget
        show_states = {}   # json_key -> BooleanVar (show/hide toggle)

        for json_key, label, url in api_defs:
            row = Frame(body, bg=Theme.BG)
            row.pack(fill=X, pady=3)

            # Label
            Label(row, text=label, bg=Theme.BG, fg=Theme.FG,
                  font=(Theme.FONT_FAMILY_UI, 9, "bold"), width=14, anchor="w").pack(side=LEFT)

            # Current saved value
            current = self.api_keys.get(json_key, "")
            var = StringVar(value=current)
            key_vars[json_key] = var

            # Entry
            entry = Entry(row, textvariable=var,
                          bg=Theme.BG_INPUT, fg=Theme.FG_ACCENT,
                          insertbackground=Theme.FG_ACCENT,
                          font=(Theme.FONT_FAMILY, 10), relief="flat",
                          highlightthickness=1, highlightbackground=Theme.BORDER,
                          highlightcolor=Theme.BORDER_FOCUS, show="\u2022")
            entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 6), ipady=4)
            entry_widgets[json_key] = entry

            # Show/Hide toggle
            show_var = BooleanVar(value=False)
            show_states[json_key] = show_var

            def _toggle(key=json_key, sv=show_var, e=entry):
                if sv.get():
                    e.configure(show="\u2022")
                    sv.set(False)
                else:
                    e.configure(show="")
                    sv.set(True)

            toggle_btn = Button(row, text="SHOW", width=5,
                                bg=Theme.BG_BUTTON, fg=Theme.FG_DIM,
                                activebackground=Theme.BG_BUTTON_HOVER,
                                activeforeground=Theme.FG,
                                font=(Theme.FONT_FAMILY_UI, 8), relief="flat",
                                cursor="hand2", command=_toggle,
                                highlightthickness=1, highlightbackground=Theme.BORDER)
            toggle_btn.pack(side=LEFT)

            # URL hint
            Label(body, text=f"  {url}", bg=Theme.BG, fg=Theme.FG_MUTED,
                  font=(Theme.FONT_FAMILY_UI, 8), anchor="w").pack(fill=X, padx=(14, 0))

        # ── Buttons ─────────────────────────────────────────
        btn_frame = Frame(dialog, bg=Theme.BG, padx=20, pady=12)
        btn_frame.pack(fill=X, side="bottom")

        # Separator
        Frame(dialog, bg=Theme.BORDER, height=1).pack(fill=X, side="bottom")

        def _on_save():
            # Collect non-empty keys
            new_keys = {}
            for json_key, var in key_vars.items():
                val = var.get().strip()
                if val:
                    new_keys[json_key] = val

            self._save_api_keys(new_keys)

            # Hot-reload into config module so analysis picks them up immediately
            try:
                import config as cfg
                cfg.VIRUSTOTAL_KEY = new_keys.get("virustotal", "")
                cfg.ABUSEIPDB_KEY = new_keys.get("abuseipdb", "")
                cfg.SHODAN_KEY = new_keys.get("shodan", "")
                cfg.OTX_KEY = new_keys.get("otx", "")
                cfg.IPINFO_KEY = new_keys.get("ipinfo", "")
            except Exception:
                pass

            count = len(new_keys)
            self.status_var.set(f"Settings saved: {count} API key(s) configured.")
            self._writeln(f"  Settings saved: {count} API key(s) configured.\n", "success")
            dialog.destroy()

        def _on_clear_all():
            for var in key_vars.values():
                var.set("")

        def _on_cancel():
            dialog.destroy()

        Button(btn_frame, text="SAVE", bg=Theme.FG_ACCENT, fg=Theme.BG,
               activebackground=Theme.FG_DIM, activeforeground=Theme.BG,
               font=(Theme.FONT_FAMILY_UI, 10, "bold"), relief="flat",
               padx=24, pady=6, cursor="hand2", command=_on_save).pack(side=RIGHT)

        Button(btn_frame, text="CANCEL", bg=Theme.BG_BUTTON, fg=Theme.FG,
               activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG,
               font=(Theme.FONT_FAMILY_UI, 10), relief="flat",
               padx=16, pady=6, cursor="hand2", command=_on_cancel,
               highlightthickness=1, highlightbackground=Theme.BORDER).pack(side=RIGHT, padx=(0, 8))

        Button(btn_frame, text="CLEAR ALL", bg=Theme.BG_BUTTON, fg=Theme.FG_DIM,
               activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG,
               font=(Theme.FONT_FAMILY_UI, 9), relief="flat",
               padx=10, pady=6, cursor="hand2", command=_on_clear_all,
               highlightthickness=1, highlightbackground=Theme.BORDER).pack(side=LEFT)

        # ── Status indicator (show which keys are set) ──────
        configured = [k for k, v in self.api_keys.items() if v]
        if configured:
            Label(btn_frame, text=f"Configured: {', '.join(configured)}",
                  bg=Theme.BG, fg=Theme.FG_MUTED,
                  font=(Theme.FONT_FAMILY_UI, 8)).pack(side=LEFT, padx=(12, 0))

    def _show_bulk_dialog(self):
        """Open dialog for bulk IP/domain input."""
        dialog = Toplevel(self.root)
        dialog.title("Bulk Analyze")
        dialog.geometry("500x420")
        dialog.configure(bg=Theme.BG)
        dialog.resizable(False, False)
        dialog.transient(self.root)

        # Dark title bar
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 250
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 210
        dialog.geometry(f"+{x}+{y}")

        # Header
        hdr = Frame(dialog, bg=Theme.BG_HEADER, height=40)
        hdr.pack(fill=X)
        hdr.pack_propagate(False)
        Label(hdr, text="  BULK ANALYZE",
              bg=Theme.BG_HEADER, fg=Theme.FG_ACCENT,
              font=(Theme.FONT_FAMILY_UI, 11, "bold")).pack(side=LEFT, padx=12)

        body = Frame(dialog, bg=Theme.BG, padx=16, pady=10)
        body.pack(fill=BOTH, expand=True)

        Label(body, text="Enter one IP or domain per line:",
              bg=Theme.BG, fg=Theme.FG_DIM,
              font=(Theme.FONT_FAMILY_UI, 9)).pack(anchor="w")

        text_widget = Text(body, bg=Theme.BG_INPUT, fg=Theme.FG_ACCENT,
                          insertbackground=Theme.FG_ACCENT,
                          font=(Theme.FONT_FAMILY, 10), relief="flat",
                          highlightthickness=1, highlightbackground=Theme.BORDER,
                          highlightcolor=Theme.BORDER_FOCUS,
                          wrap="none", padx=8, pady=8)
        text_widget.pack(fill=BOTH, expand=True, pady=(4, 8))

        # Count label
        count_var = StringVar(value="0 targets")
        Label(body, textvariable=count_var, bg=Theme.BG, fg=Theme.FG_MUTED,
              font=(Theme.FONT_FAMILY_UI, 9)).pack(anchor="w")

        def _update_count(event=None):
            content = text_widget.get("1.0", END).strip()
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            count_var.set(f"{len(lines)} target(s)")

        text_widget.bind("<KeyRelease>", _update_count)

        # Options checkboxes (mirror main window options)
        opt_frame = Frame(body, bg=Theme.BG)
        opt_frame.pack(fill=X, pady=(8, 4))

        bulk_skip_ports = BooleanVar(value=self.skip_ports_var.get())
        bulk_skip_tor = BooleanVar(value=self.skip_tor_var.get())
        bulk_json = BooleanVar(value=self.json_var.get())

        for var, text in [(bulk_skip_ports, "Skip Port Scan"),
                          (bulk_skip_tor, "Skip TOR Check"),
                          (bulk_json, "JSON Output")]:
            Checkbutton(opt_frame, text=text, variable=var,
                       bg=Theme.BG, fg=Theme.FG_DIM,
                       selectcolor=Theme.BG_INPUT,
                       activebackground=Theme.BG,
                       activeforeground=Theme.FG,
                       font=(Theme.FONT_FAMILY_UI, 9),
                       relief="flat", cursor="hand2").pack(side=LEFT, padx=(0, 12))

        btn_frame = Frame(dialog, bg=Theme.BG, padx=16, pady=10)
        btn_frame.pack(fill=X, side="bottom")
        Frame(dialog, bg=Theme.BORDER, height=1).pack(fill=X, side="bottom")

        def _on_ok():
            content = text_widget.get("1.0", END).strip()
            targets = [l.strip() for l in content.splitlines() if l.strip()]
            if not targets:
                return
            # Apply bulk dialog options to main checkboxes
            self.skip_ports_var.set(bulk_skip_ports.get())
            self.skip_tor_var.set(bulk_skip_tor.get())
            self.json_var.set(bulk_json.get())
            dialog.destroy()
            self._start_bulk_analysis(targets)

        def _on_cancel():
            dialog.destroy()

        # OK button (primary action)
        ok_btn = Button(btn_frame, text="OK",
               bg=Theme.FG_ACCENT, fg=Theme.BG,
               activebackground=Theme.FG_DIM, activeforeground=Theme.BG,
               font=(Theme.FONT_FAMILY_UI, 10, "bold"), relief="flat",
               padx=24, pady=6, cursor="hand2", command=_on_ok)
        ok_btn.pack(side=RIGHT)

        # Cancel button
        cancel_btn = Button(btn_frame, text="CANCEL",
               bg=Theme.BG_BUTTON, fg=Theme.FG,
               activebackground=Theme.BG_BUTTON_HOVER, activeforeground=Theme.FG,
               font=(Theme.FONT_FAMILY_UI, 10), relief="flat",
               padx=16, pady=6, cursor="hand2", command=_on_cancel,
               highlightthickness=1, highlightbackground=Theme.BORDER)
        cancel_btn.pack(side=RIGHT, padx=(0, 8))

        # Bind Enter key to OK
        dialog.bind("<Return>", lambda e: _on_ok())
        # Bind Escape key to Cancel
        dialog.bind("<Escape>", lambda e: _on_cancel())

        # Focus the text widget
        text_widget.focus_set()

    def _start_bulk_analysis(self, targets):
        """Set up UI and start bulk analysis."""
        # Clear output area
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)

        # Set UI state
        self.running = True
        self.stop_event.clear()
        self.stop_btn.pack(side=RIGHT, padx=(0, 4))
        self.analyze_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.report_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.bulk_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.subs_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.progress.start(10)

        # Reset accumulator and start
        self.all_results = []
        self._bulk_targets = targets
        self._bulk_index = 0
        self._writeln(f"  BULK ANALYSIS: {len(targets)} target(s)\n", "accent")
        self.status_var.set(f"Starting bulk analysis of {len(targets)} target(s)...")
        self._run_next_bulk()

    def _run_next_bulk(self):
        if self.stop_event.is_set():
            total = len(self.all_results)
            self.root.after(0, lambda: self._writeln(f"\n  [STOP] Bulk analysis cancelled. {total} target(s) completed.", "danger"))
            self.root.after(0, self._finish_analysis)
            return
        if not hasattr(self, '_bulk_targets') or self._bulk_index >= len(self._bulk_targets):
            # All done — show summary
            total = len(self.all_results)
            self.root.after(0, lambda: self._writeln(f"\n{'='*68}", "dim"))
            self.root.after(0, lambda: self._writeln(f"  BULK ANALYSIS COMPLETE: {total} target(s) analyzed", "accent"))
            self.root.after(0, lambda: self._writeln(f"{'='*68}", "dim"))
            self.root.after(0, lambda: self._writeln(f"  Click REPORT to export all {total} findings.", "info"))
            self.root.after(0, lambda: self.status_var.set(f"Bulk complete: {total} target(s). Click REPORT to export."))
            self.root.after(0, self._finish_analysis)
            return

        target = self._bulk_targets[self._bulk_index]
        total = len(self._bulk_targets)
        idx = self._bulk_index + 1

        self.root.after(0, lambda: self._writeln(f"\n{'='*68}", "dim"))
        self.root.after(0, lambda: self._writeln(f"  [{idx}/{total}] {target}", "accent"))
        self.root.after(0, lambda: self._writeln(f"{'='*68}", "dim"))
        self.root.after(0, lambda: self.status_var.set(f"Bulk [{idx}/{total}]: Analyzing {target}..."))

        # Run analysis in thread
        def _analyze_one():
            try:
                self._run_single_analysis(target)
            except Exception as e:
                self.root.after(0, lambda: self._writeln(f"  Error: {e}", "danger"))
            finally:
                self._bulk_index += 1
                self.root.after(100, self._run_next_bulk)

        threading.Thread(target=_analyze_one, daemon=True).start()

    def _run_single_analysis(self, target):
        """Run analysis for a single target and accumulate results."""
        import re
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target))
        is_domain = bool(re.match(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target))

        if not is_ip and not is_domain:
            self.root.after(0, lambda: self._writeln(f"  Skipping invalid target: {target}", "warning"))
            return

        from api_sources import (
            query_ipinfo, query_otx_ip, query_otx_domain,
            query_abuseipdb, query_virustotal_ip, query_virustotal_domain,
            query_shodan, query_threatfox, query_urlhaus_host, check_tor_exit,
        )
        from dns_recon import full_ip_recon, full_domain_recon
        from risk_engine import calculate_ip_risk, calculate_domain_risk

        skip_ports = self.skip_ports_var.get()
        skip_tor = self.skip_tor_var.get()
        json_output = self.json_var.get()
        results = {"target": target, "target_type": "ip" if is_ip else "domain"}
        start_time = time.time()

        def wl(text="", tag="stdout"):
            self.root.after(0, lambda t=text, tg=tag: self._writeln(t, tg))
        def wst(source, msg, tag="dim"):
            self.root.after(0, lambda s=source, m=msg, t=tag: self._write_status(s, m, t))

        if is_ip:
            results["ipinfo"] = query_ipinfo(target)
            if self._should_stop():
                return
            results["otx"] = query_otx_ip(target)
            if self._should_stop():
                return
            results["abuseipdb"] = query_abuseipdb(target)
            if self._should_stop():
                return
            results["vt"] = query_virustotal_ip(target)
            if self._should_stop():
                return
            results["shodan"] = query_shodan(target)
            if self._should_stop():
                return
            results["threatfox"] = query_threatfox(target)
            if self._should_stop():
                return
            results["urlhaus"] = query_urlhaus_host(target)

            for src, data in [("IPInfo", results["ipinfo"]), ("OTX", results["otx"]),
                              ("AbuseIPDB", results["abuseipdb"]), ("VT", results["vt"]),
                              ("Shodan", results["shodan"]), ("ThreatFox", results["threatfox"]),
                              ("URLhaus", results["urlhaus"])]:
                if data.get("error"):
                    wst(src, data["error"], "warning")
                else:
                    wst(src, "OK", "success")

            if skip_ports:
                results["recon"] = {"port_scan": {"open_ports": [], "error": "Skipped"},
                                    "reverse_dns": {"hostnames": [], "has_rdns": False}}
            else:
                results["recon"] = full_ip_recon(target)

            # TOR check
            if not skip_tor:
                wst("TOR", "Checking...")
                is_tor = check_tor_exit(target)
                results["is_tor"] = is_tor
                wst("TOR", "EXIT NODE" if is_tor else "Not a TOR exit", "danger" if is_tor else "success")
            else:
                results["is_tor"] = False

            results["risk"] = calculate_ip_risk(
                ipinfo=results.get("ipinfo"), otx=results.get("otx"),
                abuseipdb=results.get("abuseipdb"), vt=results.get("vt"),
                shodan=results.get("shodan"), threatfox=results.get("threatfox"),
                urlhaus=results.get("urlhaus"), recon=results.get("recon"),
                is_tor=results.get("is_tor", False))

        else:
            results["otx"] = query_otx_domain(target)
            if self._should_stop():
                return
            results["vt"] = query_virustotal_domain(target)
            if self._should_stop():
                return
            results["threatfox"] = query_threatfox(target)
            if self._should_stop():
                return
            results["urlhaus"] = query_urlhaus_host(target)

            if skip_ports:
                from dns_recon import resolve_dns, whois_lookup
                results["recon"] = {"dns": resolve_dns(target), "whois": whois_lookup(target),
                                    "port_scan": {"open_ports": [], "error": "Skipped"},
                                    "resolved_ips": []}
                results["recon"]["resolved_ips"] = results["recon"]["dns"].get("a_records", [])
            else:
                results["recon"] = full_domain_recon(target)

            if results["recon"].get("resolved_ips"):
                results["ipinfo"] = query_ipinfo(results["recon"]["resolved_ips"][0])

            results["risk"] = calculate_domain_risk(
                domain=target, otx=results.get("otx"), vt=results.get("vt"),
                threatfox=results.get("threatfox"), urlhaus=results.get("urlhaus"),
                recon=results.get("recon"))

        elapsed = round(time.time() - start_time, 1)
        results["elapsed_seconds"] = elapsed

        risk = results["risk"]
        cls = risk["classification"]
        score = risk["score"]
        is_good = risk.get("is_known_good", False)

        cls_tag = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning", "LOW": "success"}.get(cls, "dim")
        status = "KNOWN LEGITIMATE" if is_good else cls
        wl(f"  Risk: {status} ({score}/100) [{elapsed}s]", cls_tag)

        if risk.get("not_checked_sources"):
            wl(f"  NOT CHECKED: {', '.join(risk['not_checked_sources'])}", "warning")

        # JSON output
        if json_output:
            json_out = {k: v for k, v in results.items() if k != "is_tor"}
            import json as _json
            wl(f"\n  JSON Output:", "info")
            wl(_json.dumps(json_out, indent=2, default=str))

        # Accumulate
        self.all_results.append(results)
        self.last_results = results  # keep single-result export working too

    def _on_subdomains(self):
        """Enumerate subdomains for the current domain target, then analyze all."""
        target = self.target_var.get().strip()
        if not target:
            self.status_var.set("Enter a domain first (e.g., example.com)")
            return

        import re
        if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
            self.status_var.set("SUBS only works with domain names (e.g., example.com)")
            return

        # Clear output
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)

        self.running = True
        self.subs_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.analyze_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.progress.start(10)
        self.status_var.set(f"Enumerating subdomains for {target}...")

        def _run():
            try:
                from subdomain_enum import enumerate_subdomains

                self.root.after(0, lambda: self._write_header("SUBDOMAIN ENUMERATION"))
                self.root.after(0, lambda: self._writeln(f"  Domain: {target}", "accent"))
                self.root.after(0, lambda: self._writeln(f"  Scanning crt.sh, OTX, Shodan, VirusTotal...\n"))

                result = enumerate_subdomains(target)

                subs = result.get("subdomains", [])
                sub_ips = result.get("subdomain_ips", {})
                elapsed = result.get("elapsed", 0)

                # Show results
                self.root.after(0, lambda: self._writeln(f"  Found {len(subs)} subdomain(s) in {elapsed}s", "success"))

                for src in result.get("sources_used", []):
                    self.root.after(0, lambda s=src: self._writeln(f"    Source: {s}", "info"))
                for src in result.get("sources_failed", []):
                    self.root.after(0, lambda s=src: self._writeln(f"    Failed: {s}", "warning"))

                if subs:
                    self.root.after(0, lambda: self._writeln(f"\n  {'Subdomain':<45s} {'IP(s)'}", "accent"))
                    self.root.after(0, lambda: self._writeln(f"  {'─'*70}", "dim"))
                    for sub in subs:
                        ips = sub_ips.get(sub, [])
                        ip_str = ", ".join(ips[:3]) if ips else "no resolution"
                        self.root.after(0, lambda s=sub, i=ip_str: self._writeln(f"  {s:<45s} {i}"))

                    self.root.after(0, lambda: self._writeln(f"\n  Analyzing {len(subs)} subdomain(s)...\n", "accent"))

                    # Analyze each subdomain
                    self.all_results = []
                    for idx, sub in enumerate(subs, 1):
                        self.root.after(0, lambda i=idx, s=sub: self._writeln(
                            f"  [{i}/{len(subs)}] {s}", "stdout"))
                        self.root.after(0, lambda i=idx, s=sub: self.status_var.set(
                            f"Subs [{i}/{len(subs)}]: Analyzing {s}..."))

                        # Run analysis in the same thread
                        self._run_single_analysis(sub)

                    # Summary
                    total = len(self.all_results)
                    self.root.after(0, lambda: self._writeln(f"\n{'='*68}", "dim"))
                    self.root.after(0, lambda: self._writeln(
                        f"  SUBDOMAIN SCAN COMPLETE: {total} subdomain(s) analyzed", "accent"))
                    self.root.after(0, lambda: self._writeln(f"{'='*68}", "dim"))
                    self.root.after(0, lambda: self._writeln(
                        f"  Click REPORT to export all {total} findings.", "info"))
                else:
                    self.root.after(0, lambda: self._writeln(
                        f"  No subdomains found for {target}", "warning"))

            except Exception as e:
                self.root.after(0, lambda: self._writeln(f"  Error: {e}", "danger"))
            finally:
                self.root.after(0, self._finish_analysis)

        threading.Thread(target=_run, daemon=True).start()

    def _on_stop(self):
        """Cancel running analysis."""
        self.stop_event.set()
        self.status_var.set("Stopping...")

    def _should_stop(self):
        """Recursively apply theme to widget tree."""
        try:
            wtype = widget.winfo_class()
            if wtype in ("Frame", "Toplevel"):
                widget.configure(bg=Theme.BG)
            elif wtype == "Label":
                parent_bg = Theme.BG
                try:
                    parent_bg = widget.master.cget("bg")
                except:
                    pass
                widget.configure(bg=parent_bg)
            elif wtype == "Entry":
                widget.configure(bg=Theme.BG_INPUT, fg=Theme.FG_ACCENT,
                               insertbackground=Theme.FG_ACCENT,
                               highlightbackground=Theme.BORDER,
                               highlightcolor=Theme.BORDER_FOCUS)
            elif wtype == "Button":
                pass  # buttons keep their specific colors
            elif wtype == "Text":
                widget.configure(bg=Theme.BG_OUTPUT, fg=Theme.FG,
                               insertbackground=Theme.FG)
            elif wtype == "Checkbutton":
                parent_bg = Theme.BG
                try:
                    parent_bg = widget.master.cget("bg")
                except:
                    pass
                widget.configure(bg=parent_bg, fg=Theme.FG_DIM,
                               selectcolor=Theme.BG_INPUT,
                               activebackground=parent_bg)
        except:
            pass

        for child in widget.winfo_children():
            self._apply_to_widget(child)

    def _should_stop(self):
        """Check if stop was requested. Returns True if should stop."""
        return self.stop_event.is_set()

    def _toggle_format(self):
        """Toggle report format between TXT and DOCX."""
        current = self.fmt_var.get()
        if current == "TXT":
            self.fmt_var.set("DOCX")
            self.fmt_btn.configure(text="DOCX", bg=Theme.BG_BUTTON, fg=Theme.FG)
        else:
            self.fmt_var.set("TXT")
            self.fmt_btn.configure(text="TXT", bg=Theme.FG_ACCENT, fg=Theme.BG)

    # ─── Button Handlers ───────────────────────────────────────

    def _on_analyze(self):
        target = self.target_var.get().strip()
        if not target:
            self.status_var.set("Error: No target specified.")
            return
        if self.running:
            return

        # Clear output and reset results
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)
        self.all_results = []  # clear previous bulk results

        self.running = True
        self.stop_event.clear()
        self.stop_btn.pack(side=RIGHT, padx=(0, 4))
        self.analyze_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.report_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.progress.start(10)
        self.status_var.set(f"Analyzing {target}...")

        thread = threading.Thread(target=self._run_analysis, args=(target,), daemon=True)
        thread.start()

    def _on_report(self):
        # Determine what to export: bulk results or single result
        results_list = self.all_results if self.all_results else (
            [self.last_results] if self.last_results else [])

        if not results_list:
            self.status_var.set("No analysis results. Run an analysis first.")
            return

        fmt = self.fmt_var.get().lower()
        count = len(results_list)
        if count > 1:
            default_name = f"Bulk_Report_{count}targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        else:
            target = results_list[0].get("target", "unknown")
            safe = target.replace(":", "-").replace("/", "-").replace("\\", "-").replace(".", "_")
            default_name = f"TI_Report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"

        output_path = os.path.join(BUNDLE_DIR, default_name)
        self.status_var.set(f"Generating {fmt.upper()} report ({count} target(s))...")

        def gen():
            try:
                if count == 1:
                    # Single target report
                    r = results_list[0]
                    kwargs = dict(
                        target=r["target"], target_type=r["target_type"],
                        risk_assessment=r["risk"], ipinfo=r.get("ipinfo"),
                        otx=r.get("otx"), abuseipdb=r.get("abuseipdb"),
                        vt=r.get("vt"), shodan=r.get("shodan"),
                        threatfox=r.get("threatfox"), urlhaus=r.get("urlhaus"),
                        recon=r.get("recon"), output_path=output_path,
                    )
                    if fmt == "docx":
                        from report_gen import generate_report
                        path = generate_report(**kwargs)
                    else:
                        from report_gen import generate_txt_report
                        path = generate_txt_report(**kwargs)
                else:
                    # Bulk report: generate combined
                    if fmt == "docx":
                        from report_gen import generate_bulk_docx_report
                        path = generate_bulk_docx_report(results_list, output_path)
                    else:
                        from report_gen import generate_bulk_txt_report
                        path = generate_bulk_txt_report(results_list, output_path)

                self.root.after(0, lambda: self.status_var.set(f"Report saved: {path}"))
                self.root.after(0, lambda: self._writeln(f"\n  Report saved: {os.path.abspath(path)}", "success"))
            except Exception as e:
                import traceback
                self.root.after(0, lambda: self.status_var.set(f"Report error: {e}"))
                self.root.after(0, lambda: self._writeln(f"\n  Report error: {e}", "danger"))

        threading.Thread(target=gen, daemon=True).start()

    def _on_clear(self):
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)
        self.last_results = None
        self.status_var.set("Ready. Enter an IP address or domain to analyze.")

    # ─── Analysis Engine (runs in background thread) ───────────

    def _run_analysis(self, target):
        try:
            import re
            is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target))
            is_domain = bool(re.match(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target
            ))

            if not is_ip and not is_domain:
                self.root.after(0, lambda: self._writeln("Error: Invalid target. Enter a valid IP or domain.", "danger"))
                self.root.after(0, self._finish_analysis)
                return

            from api_sources import (
                query_ipinfo, query_otx_ip, query_otx_domain,
                query_abuseipdb, query_virustotal_ip, query_virustotal_domain,
                query_shodan, query_threatfox, query_urlhaus_host, check_tor_exit,
            )
            from dns_recon import full_ip_recon, full_domain_recon
            from risk_engine import calculate_ip_risk, calculate_domain_risk

            skip_ports = self.skip_ports_var.get()
            skip_tor = self.skip_tor_var.get()
            results = {"target": target, "target_type": "ip" if is_ip else "domain"}
            start_time = time.time()

            def w(text, tag="stdout"):
                self.root.after(0, lambda: self._write(text, tag))
            def wl(text="", tag="stdout"):
                self.root.after(0, lambda: self._writeln(text, tag))
            def wh(text):
                self.root.after(0, lambda: self._write_header(text))
            def ws(text):
                self.root.after(0, lambda: self._write_section(text))
            def wkv(key, value, tag="stdout"):
                self.root.after(0, lambda: self._write_kv(key, value, tag))
            def wst(source, msg, tag="dim"):
                self.root.after(0, lambda: self._write_status(source, msg, tag))

            wh("INVESTIGATION STARTED")
            wl(f"  Target:     {target}")
            wl(f"  Type:       {'IP Address' if is_ip else 'Domain'}")
            wl(f"  Timestamp:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            wl()

            # ── Phase 1: OSINT ─────────────────────────────────
            ws("Phase 1: OSINT Intelligence Collection")

            if is_ip:
                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("IPInfo", "Querying...")
                results["ipinfo"] = query_ipinfo(target)
                ipinfo = results["ipinfo"]
                if ipinfo.get("error"):
                    wst("IPInfo", ipinfo["error"], "danger")
                else:
                    wst("IPInfo", f"{ipinfo.get('country','')} | {ipinfo.get('asn','')} | {ipinfo.get('isp','')}", "success")

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("OTX", "Querying...")
                results["otx"] = query_otx_ip(target)
                otx = results["otx"]
                tag = "danger" if otx.get("pulse_count", 0) > 0 else "success"
                wst("OTX", f"{otx.get('pulse_count',0)} pulse(s), {otx.get('malware_count',0)} malware", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("AbuseIPDB", "Querying...")
                results["abuseipdb"] = query_abuseipdb(target)
                ab = results["abuseipdb"]
                if ab.get("error"):
                    wst("AbuseIPDB", ab["error"], "warning")
                else:
                    acs = ab.get("abuse_confidence_score", 0)
                    tag = "danger" if acs >= 50 else "warning" if acs > 0 else "success"
                    wst("AbuseIPDB", f"Confidence: {acs}% ({ab.get('total_reports',0)} reports)", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("VirusTotal", "Querying...")
                results["vt"] = query_virustotal_ip(target)
                vt = results["vt"]
                if vt.get("error"):
                    wst("VirusTotal", vt["error"], "warning")
                else:
                    mal = vt.get("malicious", 0)
                    total = mal + vt.get("suspicious", 0) + vt.get("harmless", 0) + vt.get("undetected", 0)
                    tag = "danger" if mal > 0 else "success"
                    wst("VirusTotal", f"{mal}/{total} detections", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("Shodan", "Querying...")
                results["shodan"] = query_shodan(target)
                sh = results["shodan"]
                if sh.get("error"):
                    wst("Shodan", sh["error"], "warning")
                else:
                    vulns = sh.get("vulns", [])
                    tag = "danger" if vulns else "success"
                    wst("Shodan", f"{len(sh.get('ports',[]))} port(s), {len(vulns)} CVE(s)", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("ThreatFox", "Querying...")
                results["threatfox"] = query_threatfox(target)
                tf = results["threatfox"]
                if tf.get("error"):
                    wst("ThreatFox", tf["error"], "warning")
                else:
                    tag = "danger" if tf.get("ioc_count", 0) > 0 else "success"
                    wst("ThreatFox", f"{tf.get('ioc_count',0)} IOC(s)", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("URLhaus", "Querying...")
                results["urlhaus"] = query_urlhaus_host(target)
                uh = results["urlhaus"]
                if uh.get("error"):
                    wst("URLhaus", uh["error"], "warning")
                else:
                    tag = "danger" if uh.get("is_listed") else "success"
                    wst("URLhaus", f"Listed: {'YES' if uh.get('is_listed') else 'No'}", tag)

                if not skip_tor:
                    wst("TOR", "Checking...")
                    is_tor = check_tor_exit(target)
                    results["is_tor"] = is_tor
                    wst("TOR", "EXIT NODE" if is_tor else "Not a TOR exit", "danger" if is_tor else "success")
                else:
                    results["is_tor"] = False

            else:  # Domain
                wst("OTX", "Querying...")
                results["otx"] = query_otx_domain(target)
                otx = results["otx"]
                tag = "danger" if otx.get("pulse_count", 0) > 0 else "success"
                wst("OTX", f"{otx.get('pulse_count',0)} pulse(s)", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("VirusTotal", "Querying...")
                results["vt"] = query_virustotal_domain(target)
                vt = results["vt"]
                if vt.get("error"):
                    wst("VirusTotal", vt["error"], "warning")
                else:
                    mal = vt.get("malicious", 0)
                    total = mal + vt.get("suspicious", 0) + vt.get("harmless", 0) + vt.get("undetected", 0)
                    tag = "danger" if mal > 0 else "success"
                    wst("VirusTotal", f"{mal}/{total} detections", tag)

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("ThreatFox", "Querying...")
                results["threatfox"] = query_threatfox(target)
                tf = results["threatfox"]
                if tf.get("error"):
                    wst("ThreatFox", tf["error"], "warning")
                else:
                    wst("ThreatFox", f"{tf.get('ioc_count',0)} IOC(s)", "danger" if tf.get("ioc_count",0) > 0 else "success")

                if self._should_stop():
                    self.root.after(0, self._finish_analysis)
                    return

                wst("URLhaus", "Querying...")
                results["urlhaus"] = query_urlhaus_host(target)
                uh = results["urlhaus"]
                if uh.get("error"):
                    wst("URLhaus", uh["error"], "warning")
                else:
                    wst("URLhaus", f"Listed: {'YES' if uh.get('is_listed') else 'No'}", "danger" if uh.get("is_listed") else "success")

            # ── Phase 2: Recon ─────────────────────────────────
            ws("Phase 2: Network Reconnaissance")

            if is_ip:
                if skip_ports:
                    wst("Recon", "Port scan skipped", "dim")
                    from dns_recon import reverse_dns, whois_lookup
                    results["recon"] = {
                        "reverse_dns": reverse_dns(target),
                        "whois": whois_lookup(target),
                        "port_scan": {"open_ports": [], "error": "Skipped"},
                    }
                else:
                    wst("Recon", "Running full IP reconnaissance...")
                    results["recon"] = full_ip_recon(target)

                rdns = results["recon"].get("reverse_dns", {})
                hostnames = rdns.get("hostnames", [])
                tag = "success" if hostnames else "warning"
                wst("rDNS", ", ".join(hostnames) if hostnames else "No PTR record", tag)

                open_ports = results["recon"].get("port_scan", {}).get("open_ports", [])
                wst("Ports", f"{len(open_ports)} open: {', '.join(str(p) for p in open_ports[:10])}" if open_ports else "None open",
                    "warning" if open_ports else "success")

                results["ipinfo"] = results.get("ipinfo") or query_ipinfo(target)
            else:
                if skip_ports:
                    wst("Recon", "Running DNS + WHOIS (ports skipped)...")
                    from dns_recon import resolve_dns, whois_lookup
                    results["recon"] = {
                        "dns": resolve_dns(target),
                        "whois": whois_lookup(target),
                        "port_scan": {"open_ports": [], "error": "Skipped"},
                        "resolved_ips": [],
                    }
                    results["recon"]["resolved_ips"] = results["recon"]["dns"].get("a_records", [])
                else:
                    wst("Recon", "Running full domain reconnaissance...")
                    results["recon"] = full_domain_recon(target)

                dns = results["recon"].get("dns", {})
                a_records = dns.get("a_records", [])
                wst("DNS A", ", ".join(a_records) if a_records else "None", "success" if a_records else "warning")

                if a_records:
                    results["ipinfo"] = query_ipinfo(a_records[0])

            # ── Phase 3: Risk Assessment ───────────────────────
            ws("Phase 3: Risk Assessment")

            if is_ip:
                results["risk"] = calculate_ip_risk(
                    ipinfo=results.get("ipinfo"), otx=results.get("otx"),
                    abuseipdb=results.get("abuseipdb"), vt=results.get("vt"),
                    shodan=results.get("shodan"), threatfox=results.get("threatfox"),
                    urlhaus=results.get("urlhaus"), recon=results.get("recon"),
                    is_tor=results.get("is_tor", False),
                )
            else:
                results["risk"] = calculate_domain_risk(
                    domain=target,
                    otx=results.get("otx"), vt=results.get("vt"),
                    threatfox=results.get("threatfox"), urlhaus=results.get("urlhaus"),
                    recon=results.get("recon"),
                )

            elapsed = round(time.time() - start_time, 1)
            results["elapsed_seconds"] = elapsed

            # ── Print Results ──────────────────────────────────
            risk = results["risk"]
            wh("RESULTS")

            wl(f"  Target:     {target}")
            wl(f"  Type:       {'IP' if is_ip else 'DOMAIN'}")
            wl(f"  Duration:   {elapsed}s")

            # Known-good indicator
            if risk.get("is_known_good"):
                wl(f"  Status:     KNOWN LEGITIMATE - {risk.get('known_good_reason', '')}", "success")
            wl()

            # Source verification status
            source_statuses = risk.get("source_statuses", {})
            not_checked = risk.get("not_checked_sources", [])
            if source_statuses:
                wl("  Source Verification:", "accent")
                for src, status in source_statuses.items():
                    if status == "CHECKED":
                        wl(f"    {src:<16s} CHECKED", "success")
                    else:
                        wl(f"    {src:<16s} NOT CHECKED", "warning")
                wl()

            # Risk badge
            classification = risk["classification"]
            score = risk["score"]
            badge_tag = f"badge_{classification.lower()}"
            w(f"  Risk: ", "accent")
            self.root.after(0, lambda: self._write_badge(classification, score))
            wl()

            # Not-checked warning
            if not_checked:
                wl(f"  WARNING: Sources NOT checked: {', '.join(not_checked)}", "warning")
                wl(f"  Assessment may be incomplete. Add API keys in SETTINGS.", "warning")
                wl()

            # Mitigations
            if risk.get("mitigations"):
                wl("  Mitigating Factors:", "accent")
                for m in risk["mitigations"]:
                    wl(f"    * {m}", "success")
                wl()

            # Score breakdown
            signals = risk.get("signals", [])
            if signals:
                wl("  Score Breakdown:", "accent")
                for sig in signals[:8]:
                    bar_len = int(30 * sig["weight"] / 100)
                    bar = "█" * bar_len + "░" * (30 - bar_len)
                    sev = sig["severity"]
                    sev_tag = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning", "LOW": "success"}.get(sev, "dim")
                    wl(f"  {sig['source']:<18s} {bar} +{sig['weight']}", sev_tag)
                    wl(f"    {sig['signal']}", "dim")
                wl()

            # Threat signals detail
            if signals:
                wl("  Threat Signals:", "accent")
                for i, sig in enumerate(signals, 1):
                    sev = sig["severity"]
                    sev_tag = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning", "LOW": "success"}.get(sev, "dim")
                    tier = sig.get("tier", "?")
                    interp = sig.get("interpretation", "")
                    w(f"  {i:2d}. ", "stdout")
                    w(f"[{sev}]", sev_tag)
                    wl(f" {sig['source']}: {sig['signal']} (+{sig['weight']}) T{tier}")
                    if interp:
                        wl(f"      {interp}", "dim")
            else:
                wl("  No significant threat signals detected.", "success")

            # OTX Pulses
            otx = results.get("otx")
            if otx and not otx.get("error") and otx.get("pulses"):
                ws("OTX Threat Pulses")
                for p in otx["pulses"][:8]:
                    wl(f"  >>> {p['name']}", "danger")
                    wl(f"      Date: {p.get('created','')} | Tags: {', '.join(p.get('tags',[]))}", "dim")

            # Open Ports
            port_scan = results.get("recon", {}).get("port_scan", {})
            if port_scan and port_scan.get("open_ports") and not port_scan.get("error"):
                from config import HIGH_RISK_PORTS
                ws("Open Ports")
                for p in port_scan["open_ports"]:
                    svc = HIGH_RISK_PORTS.get(p, "Unknown")
                    risk_flag = " [HIGH RISK]" if p in HIGH_RISK_PORTS else ""
                    tag = "danger" if p in HIGH_RISK_PORTS else "stdout"
                    wl(f"  Port {p} - {svc}{risk_flag}", tag)

            # CVEs
            sh = results.get("shodan")
            if sh and not sh.get("error") and sh.get("vulns"):
                ws("Known CVEs (Shodan)")
                for cve in sh["vulns"][:10]:
                    wl(f"  * {cve}", "danger")

            # Recommended Actions
            ws("Recommended Actions")
            for i, action in enumerate(risk.get("recommended_actions", []), 1):
                wl(f"  {i}. {action}")

            # IOC Summary
            ws("IOC Summary")
            action = "BLOCK" if classification in ("CRITICAL", "HIGH") else "MONITOR"
            action_tag = "danger" if action == "BLOCK" else "warning"
            w(f"  {target:<40s} {'IP' if is_ip else 'DOMAIN':<8s} {classification:<10s} ", "stdout")
            wl(action, action_tag)

            wl()
            wl(f"{'─' * 68}", "dim")
            wl(f"  Investigation completed in {elapsed}s", "dim")
            wl(f"{'─' * 68}", "dim")

            self.last_results = results

            # JSON output
            if self.json_var.get():
                ws("JSON Output")
                json_out = {k: v for k, v in results.items() if k != "is_tor"}
                wl(json.dumps(json_out, indent=2, default=str))

        except Exception as e:
            self.root.after(0, lambda: self._writeln(f"\nError: {e}", "danger"))
            import traceback
            self.root.after(0, lambda: self._writeln(traceback.format_exc(), "dim"))

        finally:
            self.root.after(0, self._finish_analysis)

    def _finish_analysis(self):
        self.running = False
        self.stop_event.clear()
        self.stop_btn.pack_forget()
        self.analyze_btn.configure(state=NORMAL, fg=Theme.BG)
        self.report_btn.configure(state=NORMAL, fg=Theme.FG)
        self.bulk_btn.configure(state=NORMAL, fg=Theme.FG)
        self.subs_btn.configure(state=NORMAL, fg=Theme.FG)
        self.progress.stop()
        self.status_var.set("Analysis complete." if self.last_results else "Ready.")


# ═══════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    root = Tk()

    # Dark title bar on Windows 10/11
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
        )
    except Exception:
        pass

    app = RepToolApp(root)

    # Center window
    root.update_idletasks()
    w = root.winfo_width()
    h = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (w // 2)
    y = (root.winfo_screenheight() // 2) - (h // 2)
    root.geometry(f"+{x}+{y}")

    root.mainloop()


if __name__ == "__main__":
    main()
