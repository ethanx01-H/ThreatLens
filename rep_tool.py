#!/usr/bin/env python3
"""
IP/Domain Reputation Tool v1.0 — SOC L3 Analyst
Multi-source OSINT investigation with risk scoring and professional reporting.

Usage:
    python3 rep_tool.py <target> [options]
    python3 rep_tool.py 1.2.3.4
    python3 rep_tool.py evil-domain.com --report
    python3 rep_tool.py 10.0.0.1 --report --output /tmp/report.docx
    python3 rep_tool.py suspicious.site.com --json --skip-ports

Supports: IP addresses and domain names
Sources:  AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo,
          ThreatFox (abuse.ch), URLhaus (abuse.ch), TOR exit list
"""

import argparse
import json
import re
import sys
import os
import time
from datetime import datetime

# Add tool directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import BANNER, REPORT_CLASSIFICATION, REPORT_ORG, KNOWN_BAD_ASNS
from api_sources import (
    query_ipinfo, query_otx_ip, query_otx_domain,
    query_abuseipdb, query_virustotal_ip, query_virustotal_domain,
    query_shodan, query_threatfox, query_urlhaus_host, check_tor_exit,
)
from dns_recon import full_ip_recon, full_domain_recon
from risk_engine import calculate_ip_risk, calculate_domain_risk, get_risk_badge
from report_gen import generate_report


# ═══════════════════════════════════════════════════════════════════
# Input Validation
# ═══════════════════════════════════════════════════════════════════

def is_ip(target: str) -> bool:
    """Check if target is an IPv4 or IPv6 address."""
    # IPv4
    ipv4 = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target)
    if ipv4:
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 (simplified check)
    ipv6 = re.match(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$', target)
    return bool(ipv6)


def is_domain(target: str) -> bool:
    """Check if target looks like a valid domain name."""
    domain_pattern = re.match(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
        target,
    )
    return bool(domain_pattern)


# ═══════════════════════════════════════════════════════════════════
# Terminal Output Formatting
# ═══════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GRN  = "\033[42m"
    BG_YEL  = "\033[43m"
    BG_BLU  = "\033[44m"


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.CYAN}{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}{Colors.RESET}\n")


def print_subsection(title: str):
    """Print a subsection header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}--- {title} ---{Colors.RESET}\n")


def print_kv(key: str, value, indent: int = 2):
    """Print a key-value pair."""
    spaces = " " * indent
    print(f"{spaces}{Colors.BOLD}{key}:{Colors.RESET} {value}")


def print_status(source: str, status: str, color: str = ""):
    """Print a source query status line."""
    if color:
        print(f"  {Colors.DIM}[{source}]{Colors.RESET} {color}{status}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[{source}]{Colors.RESET} {status}")


def print_risk_badge_terminal(classification: str, score: int):
    """Print a colored risk badge in terminal."""
    badges = {
        "CRITICAL": f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} CRITICAL ({score}/100) {Colors.RESET}",
        "HIGH":     f"{Colors.YELLOW}{Colors.BOLD}  HIGH ({score}/100)  {Colors.RESET}",
        "MEDIUM":   f"{Colors.YELLOW}  MEDIUM ({score}/100)  {Colors.RESET}",
        "LOW":      f"{Colors.GREEN}{Colors.BOLD}   LOW ({score}/100)   {Colors.RESET}",
    }
    print(f"\n  {badges.get(classification, classification)}\n")


def print_bar(label: str, value: int, max_val: int = 100, width: int = 40):
    """Print a text-based progress bar."""
    filled = int(width * value / max_val) if max_val > 0 else 0
    empty = width - filled
    if value >= 80:
        color = Colors.RED
    elif value >= 60:
        color = Colors.YELLOW
    elif value >= 35:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN
    bar = f"{'█' * filled}{'░' * empty}"
    print(f"  {label:20s} {color}{bar}{Colors.RESET} {value}/{max_val}")


# ═══════════════════════════════════════════════════════════════════
# Main Investigation Orchestrator
# ═══════════════════════════════════════════════════════════════════

def investigate_ip(ip: str, skip_ports: bool = False, skip_tor: bool = False) -> dict:
    """Run full investigation on an IP address."""
    results = {}
    start_time = time.time()

    # ── Phase 1: OSINT API Queries (parallel-ish) ──────────────
    print_subsection("Phase 1: OSINT Intelligence Collection")

    print_status("IPInfo", "Querying geolocation & ASN...")
    results["ipinfo"] = query_ipinfo(ip)
    if results["ipinfo"].get("error"):
        print_status("IPInfo", results["ipinfo"]["error"], Colors.RED)
    else:
        info = results["ipinfo"]
        print_status("IPInfo", f"{info.get('country', 'N/A')} | {info.get('asn', '')} | {info.get('isp', '')}", Colors.GREEN)

    print_status("OTX", "Querying AlienVault threat pulses...")
    results["otx"] = query_otx_ip(ip)
    if results["otx"].get("error"):
        print_status("OTX", results["otx"]["error"], Colors.RED)
    else:
        pc = results["otx"]["pulse_count"]
        mc = results["otx"]["malware_count"]
        color = Colors.RED if pc > 0 else Colors.GREEN
        print_status("OTX", f"{pc} pulse(s), {mc} malware sample(s)", color)

    print_status("AbuseIPDB", "Querying abuse confidence...")
    results["abuseipdb"] = query_abuseipdb(ip)
    if results["abuseipdb"].get("error"):
        print_status("AbuseIPDB", results["abuseipdb"]["error"], Colors.YELLOW)
    else:
        acs = results["abuseipdb"]["abuse_confidence_score"]
        tr = results["abuseipdb"]["total_reports"]
        color = Colors.RED if acs >= 50 else Colors.YELLOW if acs > 0 else Colors.GREEN
        print_status("AbuseIPDB", f"Confidence: {acs}% ({tr} reports)", color)

    print_status("VirusTotal", "Querying detection ratio...")
    results["vt"] = query_virustotal_ip(ip)
    if results["vt"].get("error"):
        print_status("VirusTotal", results["vt"]["error"], Colors.YELLOW)
    else:
        mal = results["vt"]["malicious"]
        total = mal + results["vt"]["suspicious"] + results["vt"]["harmless"] + results["vt"]["undetected"]
        color = Colors.RED if mal > 0 else Colors.GREEN
        print_status("VirusTotal", f"{mal}/{total} detections", color)

    print_status("Shodan", "Querying open ports & vulns...")
    results["shodan"] = query_shodan(ip)
    if results["shodan"].get("error"):
        print_status("Shodan", results["shodan"]["error"], Colors.YELLOW)
    else:
        ports = results["shodan"].get("ports", [])
        vulns = results["shodan"].get("vulns", [])
        print_status("Shodan", f"{len(ports)} port(s), {len(vulns)} CVE(s)", Colors.GREEN if not vulns else Colors.RED)

    print_status("ThreatFox", "Searching IOC database...")
    results["threatfox"] = query_threatfox(ip)
    if results["threatfox"].get("error"):
        print_status("ThreatFox", results["threatfox"]["error"], Colors.YELLOW)
    else:
        ic = results["threatfox"]["ioc_count"]
        color = Colors.RED if ic > 0 else Colors.GREEN
        print_status("ThreatFox", f"{ic} IOC association(s)", color)

    print_status("URLhaus", "Checking malicious URL database...")
    results["urlhaus"] = query_urlhaus_host(ip)
    if results["urlhaus"].get("error"):
        print_status("URLhaus", results["urlhaus"]["error"], Colors.YELLOW)
    else:
        listed = results["urlhaus"]["is_listed"]
        color = Colors.RED if listed else Colors.GREEN
        print_status("URLhaus", f"Listed: {'YES' if listed else 'No'}", color)

    # TOR check
    results["is_tor"] = False
    if not skip_tor:
        print_status("TOR", "Checking exit node list...")
        results["is_tor"] = check_tor_exit(ip)
        if results["is_tor"]:
            print_status("TOR", "EXIT NODE DETECTED", Colors.RED)
        else:
            print_status("TOR", "Not a TOR exit node", Colors.GREEN)

    # ── Phase 2: Network Reconnaissance ────────────────────────
    print_subsection("Phase 2: Network Reconnaissance")
    if skip_ports:
        print_status("Port Scan", "Skipped (--skip-ports)", Colors.DIM)
        results["recon"] = {
            "reverse_dns": {"hostnames": [], "has_rdns": False},
            "whois": {},
            "port_scan": {"open_ports": [], "error": "Skipped"},
        }
    else:
        print_status("Recon", "Running full IP reconnaissance...")
        results["recon"] = full_ip_recon(ip)
        rdns = results["recon"].get("reverse_dns", {})
        hostnames = rdns.get("hostnames", [])
        print_status("rDNS", ", ".join(hostnames) if hostnames else "No PTR record",
                     Colors.GREEN if hostnames else Colors.YELLOW)
        open_ports = results["recon"].get("port_scan", {}).get("open_ports", [])
        print_status("Ports", f"{len(open_ports)} open: {', '.join(str(p) for p in open_ports[:10])}" if open_ports else "No open ports",
                     Colors.RED if any(p in {21, 23, 445, 3389, 5900} for p in open_ports) else Colors.GREEN if not open_ports else Colors.YELLOW)

    # ── Phase 3: Risk Assessment ───────────────────────────────
    print_subsection("Phase 3: Risk Assessment")
    results["risk"] = calculate_ip_risk(
        ipinfo=results.get("ipinfo"),
        otx=results.get("otx"),
        abuseipdb=results.get("abuseipdb"),
        vt=results.get("vt"),
        shodan=results.get("shodan"),
        threatfox=results.get("threatfox"),
        urlhaus=results.get("urlhaus"),
        recon=results.get("recon"),
        is_tor=results.get("is_tor", False),
    )

    elapsed = round(time.time() - start_time, 1)
    results["elapsed_seconds"] = elapsed
    results["target"] = ip
    results["target_type"] = "ip"

    return results


def investigate_domain(domain: str, skip_ports: bool = False) -> dict:
    """Run full investigation on a domain name."""
    results = {}
    start_time = time.time()

    # ── Phase 1: OSINT API Queries ─────────────────────────────
    print_subsection("Phase 1: OSINT Intelligence Collection")

    print_status("OTX", "Querying AlienVault threat pulses...")
    results["otx"] = query_otx_domain(domain)
    if results["otx"].get("error"):
        print_status("OTX", results["otx"]["error"], Colors.RED)
    else:
        pc = results["otx"]["pulse_count"]
        color = Colors.RED if pc > 0 else Colors.GREEN
        print_status("OTX", f"{pc} pulse(s), {results['otx']['malware_count']} malware", color)

    print_status("VirusTotal", "Querying domain analysis...")
    results["vt"] = query_virustotal_domain(domain)
    if results["vt"].get("error"):
        print_status("VirusTotal", results["vt"]["error"], Colors.YELLOW)
    else:
        mal = results["vt"]["malicious"]
        total = mal + results["vt"]["suspicious"] + results["vt"]["harmless"] + results["vt"]["undetected"]
        color = Colors.RED if mal > 0 else Colors.GREEN
        print_status("VirusTotal", f"{mal}/{total} detections", color)

    print_status("ThreatFox", "Searching IOC database...")
    results["threatfox"] = query_threatfox(domain, "domain")
    if results["threatfox"].get("error"):
        print_status("ThreatFox", results["threatfox"]["error"], Colors.YELLOW)
    else:
        ic = results["threatfox"]["ioc_count"]
        print_status("ThreatFox", f"{ic} IOC association(s)", Colors.RED if ic > 0 else Colors.GREEN)

    print_status("URLhaus", "Checking malicious URL database...")
    results["urlhaus"] = query_urlhaus_host(domain)
    if results["urlhaus"].get("error"):
        print_status("URLhaus", results["urlhaus"]["error"], Colors.YELLOW)
    else:
        listed = results["urlhaus"]["is_listed"]
        print_status("URLhaus", f"Listed: {'YES' if listed else 'No'}", Colors.RED if listed else Colors.GREEN)

    # ── Phase 2: Network Reconnaissance ────────────────────────
    print_subsection("Phase 2: Network Reconnaissance")
    if skip_ports:
        print_status("Domain Recon", "Running DNS + WHOIS (ports skipped)...")
        from dns_recon import resolve_dns, whois_lookup
        results["recon"] = {
            "dns": resolve_dns(domain),
            "whois": whois_lookup(domain),
            "port_scan": {"open_ports": [], "error": "Skipped"},
            "http_probe": None,
            "resolved_ips": [],
            "reverse_dns": {"hostnames": [], "has_rdns": False},
        }
        # Still get IPs
        results["recon"]["resolved_ips"] = results["recon"]["dns"].get("a_records", [])
    else:
        print_status("Domain Recon", "Running full domain reconnaissance...")
        results["recon"] = full_domain_recon(domain)

    dns = results["recon"].get("dns", {})
    a_records = dns.get("a_records", [])
    print_status("DNS A", ", ".join(a_records) if a_records else "No A records",
                 Colors.GREEN if a_records else Colors.YELLOW)
    print_status("DNS NS", ", ".join(dns.get("ns_records", [])) if dns.get("ns_records") else "N/A")

    whois = results["recon"].get("whois", {})
    if whois.get("registrar"):
        print_status("WHOIS", f"Registrar: {whois['registrar']}, Created: {whois.get('creation_date', 'N/A')}")

    # Query IPInfo for first resolved IP
    if a_records:
        print_status("IPInfo", f"Querying geolocation for {a_records[0]}...")
        results["ipinfo"] = query_ipinfo(a_records[0])
    else:
        results["ipinfo"] = None

    # ── Phase 3: Risk Assessment ───────────────────────────────
    print_subsection("Phase 3: Risk Assessment")
    results["risk"] = calculate_domain_risk(
        otx=results.get("otx"),
        vt=results.get("vt"),
        threatfox=results.get("threatfox"),
        urlhaus=results.get("urlhaus"),
        recon=results.get("recon"),
    )

    elapsed = round(time.time() - start_time, 1)
    results["elapsed_seconds"] = elapsed
    results["target"] = domain
    results["target_type"] = "domain"

    return results


# ═══════════════════════════════════════════════════════════════════
# Terminal Report Display
# ═══════════════════════════════════════════════════════════════════

def print_full_report(results: dict):
    """Print the complete investigation report to terminal."""
    target = results["target"]
    target_type = results["target_type"]
    risk = results["risk"]
    elapsed = results.get("elapsed_seconds", 0)

    print_section("INVESTIGATION RESULTS")
    print(f"  {Colors.BOLD}Target:{Colors.RESET}     {target}")
    print(f"  {Colors.BOLD}Type:{Colors.RESET}       {target_type.upper()}")
    print(f"  {Colors.BOLD}Timestamp:{Colors.RESET}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {Colors.BOLD}Duration:{Colors.RESET}   {elapsed}s")

    # Risk badge
    print(f"\n  {Colors.BOLD}Risk Assessment:{Colors.RESET}")
    print_risk_badge_terminal(risk["classification"], risk["score"])

    # Score breakdown bar
    print(f"  {Colors.BOLD}Score Breakdown:{Colors.RESET}")
    for sig in risk["signals"][:8]:
        print_bar(sig["source"], sig["weight"], 100, 30)
        print(f"    {Colors.DIM}{sig['signal']}{Colors.RESET}")

    # IP/Domain Profile
    if target_type == "ip":
        info = results.get("ipinfo", {})
        if info and not info.get("error"):
            print_subsection("IP Profile")
            print_kv("ASN", info.get("asn", "N/A"))
            print_kv("ISP", info.get("isp", "N/A"))
            print_kv("Country", info.get("country", "N/A"))
            print_kv("City", f"{info.get('city', '')}, {info.get('region', '')}".strip(", "))
            print_kv("Cloud", f"{info.get('cloud_provider', 'N/A')} (Cloud-hosted)" if info.get("is_cloud") else "Not detected")
            print_kv("Hostname", info.get("hostname", "N/A") or "N/A")
    else:
        dns = results.get("recon", {}).get("dns", {})
        print_subsection("Domain Profile")
        print_kv("A Records", ", ".join(dns.get("a_records", [])) or "N/A")
        print_kv("MX Records", ", ".join(f"{m[0]}" for m in dns.get("mx_records", [])) or "N/A")
        print_kv("NS Records", ", ".join(dns.get("ns_records", [])) or "N/A")
        whois = results.get("recon", {}).get("whois", {})
        print_kv("Registrar", whois.get("registrar", "N/A"))
        print_kv("Created", whois.get("creation_date", "N/A"))

    # Threat Signals Detail
    print_subsection("Threat Signals")
    if risk["signals"]:
        for i, sig in enumerate(risk["signals"], 1):
            sev = sig["severity"]
            color = {"CRITICAL": Colors.RED, "HIGH": Colors.YELLOW,
                     "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN}.get(sev, "")
            print(f"  {Colors.BOLD}{i:2d}.{Colors.RESET} [{color}{sev}{Colors.RESET}] "
                  f"{sig['source']}: {sig['signal']} (weight: +{sig['weight']})")
    else:
        print(f"  {Colors.GREEN}No significant threat signals detected.{Colors.RESET}")

    # OTX Pulses
    otx = results.get("otx")
    if otx and not otx.get("error") and otx.get("pulses"):
        print_subsection("OTX Threat Pulses")
        for p in otx["pulses"][:10]:
            tags = ", ".join(p.get("tags", []))
            print(f"  {Colors.RED}>>>{Colors.RESET} {p['name']}")
            print(f"     {Colors.DIM}Date: {p.get('created', 'N/A')} | Tags: {tags}{Colors.RESET}")

    # Malware
    if otx and otx.get("malware_samples"):
        print_subsection("Associated Malware")
        for m in otx["malware_samples"][:5]:
            print(f"  {Colors.RED}*{Colors.RESET} {m.get('malware_name', 'Unknown')} "
                  f"(AV: {m.get('av_name', 'N/A')}, {m.get('date', '')})")

    # Port scan
    recon = results.get("recon", {})
    port_scan = recon.get("port_scan", {})
    if port_scan and port_scan.get("open_ports") and not port_scan.get("error"):
        print_subsection("Open Ports")
        from config import HIGH_RISK_PORTS
        for p in port_scan["open_ports"]:
            svc = HIGH_RISK_PORTS.get(p, "Unknown service")
            banner = port_scan.get("service_banners", {}).get(p, "")
            risk_flag = f"{Colors.RED}[HIGH RISK]{Colors.RESET}" if p in HIGH_RISK_PORTS else ""
            print(f"  {Colors.BOLD}Port {p}{Colors.RESET} - {svc} {risk_flag}")
            if banner:
                print(f"    {Colors.DIM}Banner: {banner[:80]}{Colors.RESET}")

    # CVEs
    shodan = results.get("shodan")
    if shodan and not shodan.get("error") and shodan.get("vulns"):
        print_subsection("Known CVEs (Shodan)")
        for cve in shodan["vulns"][:15]:
            print(f"  {Colors.RED}*{Colors.RESET} {cve}")

    # Recommended Actions
    print_subsection("Recommended Actions")
    for i, action in enumerate(risk["recommended_actions"], 1):
        print(f"  {Colors.BOLD}{i}.{Colors.RESET} {action}")

    # Mitigations
    if risk.get("mitigations"):
        print_subsection("Mitigating Factors")
        for m in risk["mitigations"]:
            print(f"  {Colors.GREEN}*{Colors.RESET} {m}")

    # IOC Summary Table
    print_subsection("IOC Summary")
    action = "BLOCK" if risk["classification"] in ("CRITICAL", "HIGH") else "MONITOR"
    color = Colors.RED if action == "BLOCK" else Colors.YELLOW
    print(f"  {target:40s} {target_type.upper():8s} {risk['classification']:10s} {color}{action}{Colors.RESET}")

    # Related IOCs
    if otx and otx.get("malware_samples"):
        for m in otx["malware_samples"][:3]:
            if m.get("hash"):
                print(f"  {m['hash'][:40]:40s} {'HASH':8s} {'HIGH':10s} {Colors.RED}BLOCK{Colors.RESET}")

    print(f"\n{Colors.DIM}{'─'*70}")
    print(f"  Investigation completed in {elapsed}s")
    print(f"{'─'*70}{Colors.RESET}\n")


# ═══════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="IP/Domain Reputation Tool — SOC L3 Analyst",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rep_tool.py 8.8.8.8
  python3 rep_tool.py 1.2.3.4 --report
  python3 rep_tool.py evil-domain.com --report --output /tmp/report.docx
  python3 rep_tool.py 10.0.0.1 --json --skip-ports
  python3 rep_tool.py suspicious.site.com --skip-ports --analyst "John Doe"

API Keys (optional, set via env vars or .env file):
  ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY,
  OTX_API_KEY, IPINFO_TOKEN

Free-tier sources (no key needed): IPInfo, OTX, ThreatFox, URLhaus
        """,
    )

    parser.add_argument("target", help="IP address or domain to investigate")
    parser.add_argument("--report", "-r", action="store_true",
                        help="Generate DOCX report")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output path for DOCX report")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--skip-ports", action="store_true",
                        help="Skip port scanning (faster)")
    parser.add_argument("--skip-tor", action="store_true",
                        help="Skip TOR exit node check")
    parser.add_argument("--analyst", type=str, default="SOC L3 Analyst",
                        help="Analyst name for report")
    parser.add_argument("--classification", type=str, default="CONFIDENTIAL",
                        help="Report classification level")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Minimal output (JSON only)")
    parser.add_argument("--batch", "-b", type=str, default=None,
                        help="File with one IP/domain per line for batch analysis")

    args = parser.parse_args()

    # Quiet mode suppresses banner
    if not args.quiet:
        print(BANNER)

    # ── Batch Mode ─────────────────────────────────────────────
    if args.batch:
        if not os.path.exists(args.batch):
            print(f"Error: Batch file not found: {args.batch}", file=sys.stderr)
            sys.exit(1)

        targets = [line.strip() for line in open(args.batch) if line.strip() and not line.startswith("#")]
        print(f"\n  Batch mode: {len(targets)} target(s) to investigate\n")

        all_results = []
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*70}")
            print(f"  [{i}/{len(targets)}] Investigating: {target}")
            print(f"{'='*70}")

            if is_ip(target):
                result = investigate_ip(target, skip_ports=args.skip_ports, skip_tor=args.skip_tor)
            elif is_domain(target):
                result = investigate_domain(target, skip_ports=args.skip_ports)
            else:
                print(f"  Skipping invalid target: {target}")
                continue

            all_results.append(result)
            print_full_report(result)

            if args.report:
                out_path = args.output or f"TI_Report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.docx"
                try:
                    path = generate_report(
                        target=target,
                        target_type=result["target_type"],
                        risk_assessment=result["risk"],
                        ipinfo=result.get("ipinfo"),
                        otx=result.get("otx"),
                        abuseipdb=result.get("abuseipdb"),
                        vt=result.get("vt"),
                        shodan=result.get("shodan"),
                        threatfox=result.get("threatfox"),
                        urlhaus=result.get("urlhaus"),
                        recon=result.get("recon"),
                        output_path=out_path,
                        analyst=args.analyst,
                        classification=args.classification,
                    )
                    print(f"  Report saved: {path}")
                except ImportError as e:
                    print(f"  Report generation skipped: {e}")

        if args.json:
            # Sanitize for JSON
            json_out = []
            for r in all_results:
                r.pop("is_tor", None)
                json_out.append(r)
            print(json.dumps(json_out, indent=2, default=str))

        print(f"\n  Batch complete: {len(all_results)} target(s) investigated.\n")
        return

    # ── Single Target Mode ─────────────────────────────────────
    target = args.target.strip()

    if is_ip(target):
        results = investigate_ip(target, skip_ports=args.skip_ports, skip_tor=args.skip_tor)
    elif is_domain(target):
        results = investigate_domain(target, skip_ports=args.skip_ports)
    else:
        print(f"{Colors.RED}Error: '{target}' is not a valid IP address or domain name.{Colors.RESET}")
        sys.exit(1)

    # Display report
    if not args.quiet:
        print_full_report(results)

    # JSON output
    if args.json or args.quiet:
        results.pop("is_tor", None)
        print(json.dumps(results, indent=2, default=str))

    # DOCX report
    if args.report:
        print_section("Generating DOCX Report...")
        try:
            path = generate_report(
                target=target,
                target_type=results["target_type"],
                risk_assessment=results["risk"],
                ipinfo=results.get("ipinfo"),
                otx=results.get("otx"),
                abuseipdb=results.get("abuseipdb"),
                vt=results.get("vt"),
                shodan=results.get("shodan"),
                threatfox=results.get("threatfox"),
                urlhaus=results.get("urlhaus"),
                recon=results.get("recon"),
                output_path=args.output,
                analyst=args.analyst,
                classification=args.classification,
            )
            print(f"\n  {Colors.GREEN}{Colors.BOLD}Report saved: {os.path.abspath(path)}{Colors.RESET}\n")
        except ImportError as e:
            print(f"\n  {Colors.RED}Report generation failed: {e}{Colors.RESET}")
            print(f"  Install with: pip install python-docx{Colors.RESET}\n")

    return results


if __name__ == "__main__":
    main()
