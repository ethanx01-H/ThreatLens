# 🛡️ IP/Domain Reputation Tool v1.0

**Multi-Source Threat Intelligence Investigation**

A comprehensive CLI tool for investigating IP addresses and domain names using
7 OSINT sources, network reconnaissance, weighted risk scoring, and professional
DOCX report generation.

---

## ⚡ Quick Start

```bash
# Clone the repo
git clone https://github.com/ethanx01-H/IP-Domain-Reputation-Tool.git
cd IP-Domain-Reputation-Tool

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Investigate an IP
python3 rep_tool.py 1.2.3.4

# Investigate a domain with DOCX report
python3 rep_tool.py suspicious-domain.com --report

# Quick scan (skip port scanning for speed)
python3 rep_tool.py 10.0.0.1 --skip-ports

# JSON output for SIEM integration
python3 rep_tool.py 8.8.8.8 --json --skip-ports --quiet
```

---

## 🔍 Features

| Feature | Description |
|---------|-------------|
| **7 OSINT Sources** | AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo, ThreatFox, URLhaus |
| **Network Recon** | DNS resolution, reverse DNS, WHOIS, TCP port scanning with banner grabbing |
| **HTTP/HTTPS Probe** | Server headers, TLS certificate analysis, security header audit |
| **Risk Scoring Engine** | Multi-signal weighted scoring (0–100) with CRITICAL/HIGH/MEDIUM/LOW classification |
| **DOCX Reports** | Management-level reports with cover page, KPI dashboard, color-coded tables |
| **Detection Rules** | Auto-generated Sigma rules and Splunk queries per indicator |
| **IOC Tables** | BLOCK/MONITOR actions with severity color-coding |
| **TOR Detection** | Live TOR exit node list check |
| **Batch Mode** | Process multiple indicators from a file |
| **JSON Output** | Machine-readable output for SIEM/pipeline integration |

---

## 📊 Risk Scoring

The engine aggregates signals from all sources with weighted scoring:

| Signal Source | Weight | Max |
|--------------|--------|-----|
| OTX Threat Pulses | 15/pulse | 75 |
| OTX High-Risk Tags (botnet, C2, malware) | 8/tag | varies |
| AbuseIPDB Confidence Score | 25% scaled | 25 |
| VirusTotal Detections | 20/vendor | 100 |
| Shodan CVEs | 10/CVE | 30 |
| ThreatFox IOC Associations | 15/IOC | 45 |
| URLhaus Listing | 15 flat | 15 |
| High-Risk Open Ports | 5/port | 15 |
| No Reverse DNS (active host) | 5 flat | 5 |
| Known Bad ASN | 10 flat | 10 |
| TOR Exit Node | 15 flat | 15 |

**Classification Thresholds:**
- 🔴 **CRITICAL (80–100)** — Active threat confirmed. Block immediately.
- 🟠 **HIGH (60–79)** — Strong indicators. Block after business review.
- 🟡 **MEDIUM (35–59)** — Suspicious. Add to monitoring watchlist.
- 🟢 **LOW (0–34)** — Minimal indicators. Log for reference.

---

## 📋 DOCX Report Sections

The `--report` flag generates a professional Word document containing:

1. **Cover Page** — Classification, target, risk badge, metadata
2. **Table of Contents**
3. **Executive Summary** — KPI dashboard with color-coded status
4. **Risk Assessment Dashboard** — Signal breakdown table
5. **Indicator Profile** — Geolocation, ASN, ISP, DNS, WHOIS
6. **Threat Intelligence Findings** — Per-source analysis (OTX, AbuseIPDB, VT, Shodan, ThreatFox, URLhaus)
7. **Network Reconnaissance** — Port scan results, banners, HTTP probe, security headers
8. **IOC Table** — All indicators with BLOCK/MONITOR actions
9. **Recommended Actions** — Classification-based response playbook
10. **Detection Rules** — Sigma + Splunk queries
11. **Appendix** — OSINT source URLs for manual verification

---

## ⚙️ Configuration

### API Keys

Free-tier sources (IPInfo, AlienVault OTX) work without keys. For enhanced
coverage, set API keys via environment variables or create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your keys
```

| Source | Free Tier | Get Key |
|--------|-----------|---------|
| IPInfo | ✅ (50k/mo) | https://ipinfo.io/account/token |
| AlienVault OTX | ✅ | https://otx.alienvault.com/api |
| AbuseIPDB | ✅ (1k/day) | https://www.abuseipdb.com/account/api |
| VirusTotal | ✅ (4 req/min) | https://www.virustotal.com/gui/my-apikey |
| ShodAN | ✅ (limited) | https://account.shodan.io/ |
| ThreatFox | ✅ | https://auth.abuse.ch/ |
| URLhaus | ✅ | https://auth.abuse.ch/ |

Alternatively, create `api_keys.json`:
```json
{
  "abuseipdb": "your_key",
  "virustotal": "your_key",
  "shodan": "your_key",
  "otx": "your_key",
  "ipinfo": "your_key"
}
```

---

## 🖥️ CLI Reference

```
usage: rep_tool.py [-h] [--report] [--output OUTPUT] [--json] [--skip-ports]
                   [--skip-tor] [--analyst ANALYST] [--classification CLASSIFICATION]
                   [--quiet] [--batch BATCH]
                   target

positional arguments:
  target                    IP address or domain to investigate

options:
  --report, -r              Generate professional DOCX report
  --output, -o OUTPUT       Custom output path for DOCX report
  --json, -j                Output results as JSON
  --skip-ports              Skip port scanning (faster investigation)
  --skip-tor                Skip TOR exit node list check
  --analyst ANALYST         Analyst name for report (default: Threat Intel Analyst)
  --classification LEVEL    Report classification (default: CONFIDENTIAL)
  --quiet, -q               JSON-only output, suppress terminal report
  --batch, -b FILE          Batch mode: one IP/domain per line
```

### Examples

```bash
# Basic IP investigation with terminal output
python3 rep_tool.py 185.220.101.1

# Domain with full DOCX report
python3 rep_tool.py malicious-domain.xyz --report --analyst "Ethan"

# Quick JSON for pipeline integration
python3 rep_tool.py 10.0.0.5 --json --skip-ports --skip-tor --quiet

# Batch analysis from file with reports
python3 rep_tool.py --batch iocs.txt --report

# Custom output path and classification
python3 rep_tool.py 192.168.1.100 --report -o /tmp/incident_report.docx --classification "TOP SECRET"
```

---

## 🏗️ Architecture

```
IP-Domain-Reputation-Tool/
├── rep_tool.py        # CLI entry point & investigation orchestrator
├── config.py          # API keys, constants, risk weights, port definitions
├── api_sources.py     # 7 OSINT API integrations with retry logic
├── dns_recon.py       # DNS, WHOIS, port scan, HTTP probe, TLS analysis
├── risk_engine.py     # Multi-signal weighted risk scoring engine
├── report_gen.py      # Professional DOCX report generator (python-docx)
├── requirements.txt   # Python dependencies
├── .env.example       # API key template
└── README.md          # This file
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `rep_tool.py` | CLI parsing, orchestration, terminal output formatting |
| `config.py` | API key loading (env → .env → json), constants, thresholds |
| `api_sources.py` | OTX, AbuseIPDB, VT, Shodan, IPInfo, ThreatFox, URLhaus, TOR |
| `dns_recon.py` | DNS resolution (A/AAAA/MX/NS/TXT/SOA/CNAME), reverse DNS, WHOIS, port scan, HTTP probe |
| `risk_engine.py` | Weighted scoring, classification, recommended actions |
| `report_gen.py` | DOCX generation with styled tables, color-coded severity, Sigma/Splunk rules |

---

## 🎯 Use Cases

- **Incident Response** — Investigate suspicious IPs/domains from SIEM alerts
- **Threat Hunting** — Validate IOCs from threat intelligence feeds
- **Proactive Defense** — Screen indicators before firewall rule changes
- **Management Reporting** — Generate professional DOCX reports for stakeholders
- **SIEM Integration** — JSON output for automated enrichment pipelines
- **Batch IOC Processing** — Mass-analyze indicators from threat feeds

---

## 🛠️ Dependencies

- `python-docx` — DOCX report generation
- `dnspython` — Advanced DNS resolution
- `python-whois` — WHOIS lookups
- `requests` — HTTP API calls
- `shodan` — Shodan API client (optional)

---

## 📝 License

MIT License — Free for SOC teams, threat researchers, and security analysts.

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional OSINT sources (GreyNoise, Censys, PassiveTotal)
- STIX/TAXII output format
- MISP integration for IOC sharing
- Web UI dashboard
- YARA rule generation

---

*Built for security analysts and threat researchers. Tested on WSL (Ubuntu) and Linux.*
