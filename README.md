# 🛡️ ThreatLens v1.0

<p align="center">
  <img src="anime_reputation_logo.svg" width="180" alt="ThreatLens Logo"/>
</p>

**Multi-Source Threat Intelligence Investigation**

A CLI + GUI tool for SOC analysts to investigate IP addresses and domain names using 7 OSINT sources, subdomain enumeration, wildcard search, tiered risk scoring, and professional report generation with SIEM detection rules.

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/ethanx01-H/ThreatLens.git
cd ThreatLens

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Investigate an IP
python3 rep_tool.py 1.2.3.4

# Investigate a domain with TXT report
python3 rep_tool.py suspicious-domain.com --report

# DOCX report
python3 rep_tool.py 1.2.3.4 --report --format docx

# Subdomain enumeration + analysis
python3 rep_tool.py example.com --subdomains --report

# Wildcard: scan a whole IP range
python3 rep_tool.py -w '192.168.1.*' --skip-ports

# Ctrl+C to stop at any time
```

---

## 🪟 Windows Executable

A standalone `.exe` is available — no Python installation required.

### Download

Download `ThreatLens.exe` from the [releases](https://github.com/ethanx01-H/ThreatLens/releases) page.

### Build from Source

```cmd
build_windows.bat
```

Output: `dist\ThreatLens.exe` (~17 MB standalone)

### GUI Usage

1. Double-click `ThreatLens.exe`
2. Enter an IP or domain, click **ANALYZE** (or press Enter)
3. Click **STOP** to cancel a running analysis
4. Click **SUBS** to enumerate and analyze all subdomains
5. Click **BULK** to analyze multiple targets (configure Skip Ports, Skip TOR, JSON)
6. Click **REPORT** to export (TXT or DOCX toggle)
7. Click **⚙ SETTINGS** to configure API keys (masked, persistent)

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| Enter | Start analysis / Confirm dialog |
| Escape | Cancel dialog |
| Ctrl+C | Stop running analysis (CLI) |

API keys are saved to `%APPDATA%\ThreatLens\api_keys.json` — set once, works forever.

---

## 🔍 Features

| Feature | Description |
|---------|-------------|
| **7 OSINT Sources** | AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo, ThreatFox, URLhaus |
| **Subdomain Enumeration** | crt.sh, OTX passive DNS, Shodan, VirusTotal, DNS brute force (140+ names) |
| **Wildcard Search** | `*.domain.com`, `192.168.1.*`, CIDR ranges (`10.0.0.0/24`) |
| **Network Recon** | DNS (A/AAAA/MX/NS/TXT/SOA/CNAME), reverse DNS, WHOIS, TCP port scan with banner grab |
| **HTTP/HTTPS Probe** | Server headers, TLS certificate, security header audit |
| **Risk Scoring Engine** | Tiered multi-signal scoring (0–100) with known-good whitelists |
| **Three-State Verdict** | MALICIOUS / BENIGN / NOT CHECKED per source |
| **Report Export** | TXT or DOCX — color-coded tables, IOC tables, cover page |
| **SIEM Detection Rules** | Sigma, Splunk, Elastic SIEM (EQL + KQL + JSON import) |
| **Settings Panel** | GUI API key management with masked input, persistent storage |
| **Bulk Analyze** | Queue multiple targets — all options work in all modes |
| **STOP Button** | Cancel running analysis (GUI) or Ctrl+C (CLI) |
| **TOR Detection** | Live TOR exit node list check |

---

## 📊 Risk Scoring

### Signal Tiers

| Tier | Strength | Sources |
|------|----------|---------|
| **TIER 1** | STRONG — direct malicious verdict | VT detections, AbuseIPDB ≥75%, ThreatFox C2, URLhaus listing, OTX pulses + bad tags, TOR exit |
| **TIER 2** | MODERATE — suspicious context | OTX pulses (no tags), AbuseIPDB 40–74%, Shodan CVEs, high-risk ports, new domain age |
| **TIER 3** | WEAK — passive/contextual | OTX malware associations, no reverse DNS, bulletproof ASN |

### Known-Good Whitelist

64 domains (Google, Microsoft, Cloudflare, Amazon, Apple, etc.) and 10 ASNs are whitelisted. OTX malware associations are suppressed for known-good domains. Score capped at 25 for legitimate infrastructure.

### Classification

| Level | Score | Action |
|-------|-------|--------|
| 🔴 CRITICAL | 80–100 | Block immediately, escalate |
| 🟠 HIGH | 60–79 | Block after business review |
| 🟡 MEDIUM | 35–59 | Add to monitoring watchlist |
| 🟢 LOW | 0–34 | Log for reference |

---

## 📋 Report Sections

| # | Section | Description |
|---|---------|-------------|
| 1 | Executive Summary | Risk score, classification, known-good status |
| 2 | Source Verification | ✓ CHECKED / ✗ NOT CHECKED per source |
| 3 | Indicator Profile | Geolocation, ASN, ISP, DNS, WHOIS |
| 4 | Risk Assessment | Score breakdown with bar charts, signal tiers + interpretation |
| 5 | Mitigating Factors | Whitelist, clean verdicts |
| 6 | Threat Intelligence | Per-source detail (OTX, AbuseIPDB, VT, Shodan, ThreatFox, URLhaus) |
| 7 | Network Recon | Port table, banners, HTTP headers, TLS |
| 8 | IOC Table | BLOCK/MONITOR actions with severity color-coding |
| 9 | Recommended Actions | Classification-based response playbook |
| 10 | Detection Rules | Sigma + Splunk + Elastic SIEM (EQL, KQL, JSON rule import) |
| 11 | Appendix | OSINT source URLs for manual verification |

Bulk reports include a summary table + per-target detail pages + combined IOC table.

---

## 🖥️ CLI Reference

```
usage: rep_tool.py [-h] [--report] [--format {txt,docx}] [--output OUTPUT]
                   [--skip-ports] [--skip-tor] [--analyst ANALYST]
                   [--classification CLASSIFICATION] [--quiet] [--batch BATCH]
                   [--subdomains] [--wildcard WILDCARD]
                   target
```

| Flag | Short | Description |
|------|-------|-------------|
| `--report` | `-r` | Generate report |
| `--format {txt,docx}` | `-f` | Report format (default: txt) |
| `--output OUTPUT` | `-o` | Custom output path |
| `--skip-ports` | | Skip port scanning |
| `--skip-tor` | | Skip TOR check |
| `--subdomains` | `-s` | Enumerate + analyze all subdomains |
| `--wildcard PATTERN` | `-w` | Wildcard: `*.domain.com`, `192.168.1.*`, CIDR |
| `--analyst NAME` | | Analyst name for report |
| `--classification LEVEL` | | Report classification (default: CONFIDENTIAL) |
| `--quiet` | `-q` | JSON-only output |
| `--batch FILE` | `-b` | Batch: one target per line |

### Examples

```bash
# Single IP
python3 rep_tool.py 185.220.101.1

# Domain with DOCX report
python3 rep_tool.py evil-domain.com --report -f docx

# Subdomain enumeration + analysis
python3 rep_tool.py example.com --subdomains --report

# Wildcard IP range
python3 rep_tool.py -w '10.0.0.0/24' --skip-ports

# Wildcard subdomain discovery
python3 rep_tool.py -w '*.suspicious-domain.com' --report

# Batch from file
python3 rep_tool.py --batch iocs.txt --report -f txt
```

---

## ⚙️ Configuration

### API Keys

Free-tier sources (IPInfo, OTX) work without keys. For enhanced coverage:

**GUI:** Click ⚙ SETTINGS → enter keys → SAVE (masked, persistent)

**CLI:** Set via environment variables, `.env` file, or `api_keys.json`

| Source | Free Tier | Get Key |
|--------|-----------|---------|
| IPInfo | ✅ 50k/mo | https://ipinfo.io/account/token |
| AlienVault OTX | ✅ | https://otx.alienvault.com/api |
| AbuseIPDB | ✅ 1k/day | https://www.abuseipdb.com/account/api |
| VirusTotal | ✅ 4 req/min | https://www.virustotal.com/gui/my-apikey |
| Shodan | ✅ limited | https://account.shodan.io/ |
| ThreatFox | ✅ | https://auth.abuse.ch/ |
| URLhaus | ✅ | https://auth.abuse.ch/ |

---

## 🏗️ Architecture

```
ThreatLens/
├── rep_tool.py          # CLI entry point & orchestrator
├── rep_gui.py           # GUI (tkinter, navy theme)
├── config.py            # API keys, constants, risk weights, whitelists
├── api_sources.py       # 7 OSINT API integrations with retry logic
├── dns_recon.py         # DNS, WHOIS, port scan, HTTP probe, TLS
├── risk_engine.py       # Tiered risk scoring with known-good whitelists
├── report_gen.py        # TXT + DOCX report generators (Sigma/Splunk/Elastic)
├── subdomain_enum.py    # Subdomain discovery (crt.sh, OTX, Shodan, VT, brute)
├── build_windows.bat    # One-click Windows .exe build
├── app.ico              # Application icon
├── anime_reputation_logo.svg  # Logo
├── requirements.txt
└── README.md
```

| Module | Purpose |
|--------|---------|
| `rep_tool.py` | CLI: argparse, orchestration, Ctrl+C handler |
| `rep_gui.py` | GUI: navy theme, STOP/BULK/SUBS buttons, settings dialog |
| `config.py` | APPDATA persistence, known-good domains/ASNs, API key loading |
| `api_sources.py` | OTX, AbuseIPDB, VT, Shodan, IPInfo, ThreatFox, URLhaus |
| `dns_recon.py` | DNS resolution, reverse DNS, WHOIS, port scan, HTTP/TLS probe |
| `risk_engine.py` | 3-tier scoring, whitelist suppression, NOT CHECKED states |
| `report_gen.py` | TXT + DOCX generators, bulk reports, Sigma/Splunk/Elastic rules |
| `subdomain_enum.py` | crt.sh, OTX passive DNS, Shodan, VT, DNS brute force, wildcard expand |

---

## 🎯 Use Cases

| Use Case | Description |
|----------|-------------|
| **Incident Response** | Investigate suspicious IPs/domains from SIEM alerts |
| **Threat Hunting** | Validate IOCs from threat intelligence feeds |
| **Subdomain Discovery** | Map attack surface of a target domain |
| **Proactive Defense** | Screen indicators before firewall rule changes |
| **Management Reporting** | Generate professional DOCX/TXT reports |
| **SIEM Integration** | JSON output + Elastic/Splunk/Sigma detection rules |
| **Bulk IOC Processing** | Mass-analyze indicators from threat feeds |
| **Network Mapping** | Wildcard IP range scanning with risk assessment |

---

## 🔒 Security

### API Key Storage
- Keys stored in `%APPDATA%\ThreatLens\api_keys.json` (Windows) or `~/.config/threatlens/` (Linux)
- Keys never logged or included in reports
- Keys loaded at runtime, not compiled into the exe
- Hot-reload: changing keys in Settings takes effect immediately

### Network Requests
- SSL verification disabled intentionally for HTTP probe (suspicious domains often have invalid certs)
- InsecureRequestWarning suppressed to reduce noise
- All API calls use HTTPS endpoints
- Rate limiting and retry logic on all API calls

### Input Validation
- IP addresses validated via regex before processing
- Domain names validated via regex before processing
- No shell injection vectors (no os.system, no eval, no exec)
- No path traversal vulnerabilities
- No unsafe deserialization (no pickle, yaml.load, or marshal)

### Report Safety
- Reports never include API keys
- Reports never include raw credentials
- Reports contain only OSINT-sourced threat intelligence

---

## 🤝 Contributing

Contributions welcome!
- Report bugs and feature requests via [GitHub Issues](https://github.com/ethanx01-H/ThreatLens/issues)
- Submit PRs for new OSINT source integrations
- Improve risk scoring logic or add new signal types
- Add unit tests and integration tests
- Improve documentation and add usage examples

---

## 📝 License

MIT License — Free for SOC teams, threat researchers, and security analysts.

---

*Built for security analysts and threat researchers. Tested on WSL (Ubuntu) and Windows.*
