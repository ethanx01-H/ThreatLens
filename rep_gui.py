#!/usr/bin/env python3
"""
IP/Domain Reputation Tool — GUI Version
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

# ═══════════════════════════════════════════════════════════════════
# Theme Colors — Clean Black & White
# ═══════════════════════════════════════════════════════════════════

class Theme:
    BG              = "#0d0d0d"
    BG_SECONDARY    = "#141414"
    BG_INPUT        = "#1a1a1a"
    BG_BUTTON       = "#1a1a1a"
    BG_BUTTON_HOVER = "#2a2a2a"
    BG_HEADER       = "#000000"
    BG_OUTPUT       = "#0a0a0a"
    BG_STATUS       = "#111111"

    FG              = "#e0e0e0"
    FG_DIM          = "#808080"
    FG_ACCENT       = "#ffffff"
    FG_MUTED        = "#555555"

    BORDER          = "#2a2a2a"
    BORDER_FOCUS    = "#555555"

    CRITICAL        = "#ff4444"
    HIGH            = "#ff8844"
    MEDIUM          = "#ffcc44"
    LOW             = "#44cc44"
    INFO            = "#4488ff"

    FONT_FAMILY     = "Consolas"
    FONT_FAMILY_UI  = "Segoe UI"
    FONT_SIZE       = 10
    FONT_SIZE_SMALL = 9
    FONT_SIZE_TITLE = 14


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
        self.root.title("IP/Domain Reputation Tool v1.0")
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

        self._build_ui()
        self._setup_tags()

    def _build_ui(self):
        """Construct the entire UI."""

        # ─── Header Bar ────────────────────────────────────────
        header = Frame(self.root, bg=Theme.BG_HEADER, height=48)
        header.pack(fill=X, side="top")
        header.pack_propagate(False)

        Label(
            header, text="IP/DOMAIN REPUTATION TOOL",
            bg=Theme.BG_HEADER, fg=Theme.FG_ACCENT,
            font=(Theme.FONT_FAMILY_UI, 13, "bold"),
            anchor="w", padx=16,
        ).pack(side=LEFT, fill=BOTH, expand=True)

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

    # ─── Button Handlers ───────────────────────────────────────

    def _on_analyze(self):
        target = self.target_var.get().strip()
        if not target:
            self.status_var.set("Error: No target specified.")
            return
        if self.running:
            return

        # Clear output
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)

        self.running = True
        self.analyze_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.report_btn.configure(state=DISABLED, fg=Theme.FG_MUTED)
        self.progress.start(10)
        self.status_var.set(f"Analyzing {target}...")

        thread = threading.Thread(target=self._run_analysis, args=(target,), daemon=True)
        thread.start()

    def _on_report(self):
        if not self.last_results:
            self.status_var.set("No analysis results. Run an analysis first.")
            return

        target = self.last_results.get("target", "unknown")
        safe_target = target.replace(":", "-").replace("/", "-").replace("\\", "-").replace(".", "_")
        default_name = f"TI_Report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        output_path = os.path.join(BUNDLE_DIR, default_name)

        self.status_var.set("Generating DOCX report...")

        def gen():
            try:
                from report_gen import generate_report
                r = self.last_results
                path = generate_report(
                    target=r["target"],
                    target_type=r["target_type"],
                    risk_assessment=r["risk"],
                    ipinfo=r.get("ipinfo"),
                    otx=r.get("otx"),
                    abuseipdb=r.get("abuseipdb"),
                    vt=r.get("vt"),
                    shodan=r.get("shodan"),
                    threatfox=r.get("threatfox"),
                    urlhaus=r.get("urlhaus"),
                    recon=r.get("recon"),
                    output_path=output_path,
                )
                self.root.after(0, lambda: self.status_var.set(f"Report saved: {path}"))
                self.root.after(0, lambda: self._writeln(f"\n  Report saved: {os.path.abspath(path)}", "success"))
            except Exception as e:
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
                wst("IPInfo", "Querying...")
                results["ipinfo"] = query_ipinfo(target)
                ipinfo = results["ipinfo"]
                if ipinfo.get("error"):
                    wst("IPInfo", ipinfo["error"], "danger")
                else:
                    wst("IPInfo", f"{ipinfo.get('country','')} | {ipinfo.get('asn','')} | {ipinfo.get('isp','')}", "success")

                wst("OTX", "Querying...")
                results["otx"] = query_otx_ip(target)
                otx = results["otx"]
                tag = "danger" if otx.get("pulse_count", 0) > 0 else "success"
                wst("OTX", f"{otx.get('pulse_count',0)} pulse(s), {otx.get('malware_count',0)} malware", tag)

                wst("AbuseIPDB", "Querying...")
                results["abuseipdb"] = query_abuseipdb(target)
                ab = results["abuseipdb"]
                if ab.get("error"):
                    wst("AbuseIPDB", ab["error"], "warning")
                else:
                    acs = ab.get("abuse_confidence_score", 0)
                    tag = "danger" if acs >= 50 else "warning" if acs > 0 else "success"
                    wst("AbuseIPDB", f"Confidence: {acs}% ({ab.get('total_reports',0)} reports)", tag)

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

                wst("Shodan", "Querying...")
                results["shodan"] = query_shodan(target)
                sh = results["shodan"]
                if sh.get("error"):
                    wst("Shodan", sh["error"], "warning")
                else:
                    vulns = sh.get("vulns", [])
                    tag = "danger" if vulns else "success"
                    wst("Shodan", f"{len(sh.get('ports',[]))} port(s), {len(vulns)} CVE(s)", tag)

                wst("ThreatFox", "Querying...")
                results["threatfox"] = query_threatfox(target)
                tf = results["threatfox"]
                if tf.get("error"):
                    wst("ThreatFox", tf["error"], "warning")
                else:
                    tag = "danger" if tf.get("ioc_count", 0) > 0 else "success"
                    wst("ThreatFox", f"{tf.get('ioc_count',0)} IOC(s)", tag)

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

                wst("ThreatFox", "Querying...")
                results["threatfox"] = query_threatfox(target)
                tf = results["threatfox"]
                if tf.get("error"):
                    wst("ThreatFox", tf["error"], "warning")
                else:
                    wst("ThreatFox", f"{tf.get('ioc_count',0)} IOC(s)", "danger" if tf.get("ioc_count",0) > 0 else "success")

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
            wl()

            # Risk badge
            classification = risk["classification"]
            score = risk["score"]
            badge_tag = f"badge_{classification.lower()}"
            w(f"  Risk: ", "accent")
            self.root.after(0, lambda: self._write_badge(classification, score))
            wl()
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
                    w(f"  {i:2d}. ", "stdout")
                    w(f"[{sev}]", sev_tag)
                    wl(f" {sig['source']}: {sig['signal']} (+{sig['weight']})")
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
        self.analyze_btn.configure(state=NORMAL, fg=Theme.BG)
        self.report_btn.configure(state=NORMAL, fg=Theme.FG)
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
