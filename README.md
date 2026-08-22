<p align="center">
  <img src="./ThreatLens.png" width="180" alt="ThreatLens Logo">
</p>


<h1 align="center">ThreatLens v1.0</h1>


<p align="center">
  Multi-Source Threat Intelligence Investigation
</p>


<p align="center">
  A CLI threat intelligence investigation tool for SOC analysts.
</p>


<p align="center">
  IP & Domain Reputation • OSINT • Subdomain Enumeration • Bulk Analysis • Risk Scoring • SIEM Detection
</p>


---
<p align="center">
  <a href="https://github.com/ethanx01-H/ThreatLens/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20WSL-lightgrey.svg" alt="Platform">
  <a href="https://github.com/ethanx01-H/ThreatLens/releases"><img src="https://img.shields.io/github/v/release/ethanx01-H/ThreatLens.svg" alt="Release"></a>
  <a href="https://github.com/ethanx01-H/ThreatLens/stargazers"><img src="https://img.shields.io/github/stars/ethanx01-H/ThreatLens.svg?style=social" alt="Stars"></a>
  <a href="https://github.com/ethanx01-H/ThreatLens/network/members"><img src="https://img.shields.io/github/forks/ethanx01-H/ThreatLens.svg?style=social" alt="Forks"></a>
  <img src="https://img.shields.io/badge/osint-7_sources-green.svg" alt="OSINT Sources">
  <img src="https://img.shields.io/badge/risk_scoring-tiered-red.svg" alt="Risk Scoring">
  <img src="https://img.shields.io/badge/report-DOCX%20%7C%20TXT-orange.svg" alt="Report Formats">
  <img src="https://img.shields.io/badge/detection-Sigma%20%7C%20Splunk%20%7C%20Elastic-purple.svg" alt="SIEM Rules">
</p>

---

## Quick Start

```bash
# Clone
git clone https://github.com/ethanx01-H/ThreatLens.git
cd ThreatLens

# Install dependencies
pip install -r requirements.txt

# Investigate a single IP
python3 rep_tool.py 1.2.3.4

# Investigate a domain with TXT report
python3 rep_tool.py suspicious-domain.com --report

# DOCX report (IC Incident Report template style)
python3 rep_tool.py 1.2.3.4 --report --format docx

# Bulk: multiple targets on command line
python3 rep_tool.py 1.2.3.4 5.6.7.8 evil.com --report

# Bulk: CIDR range
python3 rep_tool.py 10.0.0.0/24 --skip-ports --report

# Bulk: from file (one target per line)
python3 rep_tool.py --batch iocs.txt --report -f docx

# Subdomain enumeration + analysis
python3 rep_tool.py example.com --subdomains --report

# Wildcard: scan a whole IP range
python3 rep_tool.py -w '192.168.1.*' --skip-ports
```

---

## Features

| Feature | Description |
|---------|-------------|
| **7 OSINT Sources** | AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo, ThreatFox, URLhaus |
| **Bulk Analysis** | Multiple targets on CLI, file-based batch, CIDR ranges, wildcard patterns |
| **Subdomain Enumeration** | crt.sh, OTX passive DNS, Shodan, VirusTotal, DNS brute force (140+ names) |
| **Wildcard Search** | `*.domain.com`, `192.168.1.*`, CIDR ranges (`10.0.0.0/24`) |
| **Network Recon** | DNS (A/AAAA/MX/NS/TXT/SOA/CNAME), reverse DNS, WHOIS, TCP port scan with banner grab |
| **HTTP/HTTPS Probe** | Server headers, TLS certificate, security header audit |
| **Risk Scoring Engine** | Tiered multi-signal scoring (0-100) with known-good whitelists |
| **Three-State Verdict** | MALICIOUS / BENIGN / NOT CHECKED per source |
| **Report Export** | TXT or DOCX — IC Incident Report template style, color-coded tables, IOC tables |
| **SIEM Detection Rules** | Sigma, Splunk, Elastic SIEM (EQL + KQL + JSON import) |
| **TOR Detection** | Live TOR exit node list check |

---

## Risk Scoring

### Signal Tiers

| Tier | Strength | Sources |
|------|----------|---------|
| **TIER 1** | STRONG — direct malicious verdict | VT detections, AbuseIPDB >=75%, ThreatFox C2, URLhaus listing, OTX pulses + bad tags, TOR exit |
| **TIER 2** | MODERATE — suspicious context | OTX pulses (no tags), AbuseIPDB 40-74%, Shodan CVEs, high-risk ports, new domain age |
| **TIER 3** | WEAK — passive/contextual | OTX malware associations, no reverse DNS, bulletproof ASN |

### Known-Good Whitelist

64 domains (Google, Microsoft, Cloudflare, Amazon, Apple, etc.) and 10 ASNs are whitelisted. OTX malware associations are suppressed for known-good domains. Score capped at 25 for legitimate infrastructure.

### Classification

| Level | Score | Action |
|-------|-------|--------|
| CRITICAL | 80-100 | Block immediately, escalate |
| HIGH | 60-79 | Block after business review |
| MEDIUM | 35-59 | Add to monitoring watchlist |
| LOW | 0-34 | Log for reference |

---

## Report Sections (DOCX)

Reports follow the IC Cybersecurity Incident Report template style with Century Gothic font, orange section headers, and gray input fields.

| # | Section | Description |
|---|---------|-------------|
| 1 | Report Information | Date, analyst, classification |
| 2 | Investigation Summary | Target, type, detection method |
| 3 | IPInfo / Geolocation | Country, city, ASN, ISP, coordinates, timezone |
| 4 | Risk Assessment | Score, classification, source coverage |
| 5 | Signal Analysis | Tiered threat signals with severity |
| 6 | Threat Intelligence Findings | Source-by-source status table |
| 7 | OTX / AbuseIPDB / VT / Shodan / ThreatFox / URLhaus | Per-source detail sections with country names |
| 8 | Port Scan Results | Open ports, banners, risk levels |
| 9 | Reverse DNS | PTR records |
| 10 | IOC Table | BLOCK/MONITOR actions with severity |
| 11 | Recommended Actions | Classification-based response playbook |
| 12 | Detection Rules | Sigma + Splunk + Elastic SIEM (EQL, KQL, JSON) |
| 13 | Appendix | OSINT source URLs for manual verification |

---

## CLI Reference

```
usage: rep_tool.py [-h] [--report] [--format {txt,docx}] [--output OUTPUT]
                   [--skip-ports] [--skip-tor] [--analyst ANALYST]
                   [--classification CLASSIFICATION] [--quiet] [--batch BATCH]
                   [--subdomains] [--wildcard WILDCARD]
                   [target ...]
```

| Flag | Short | Description |
|------|-------|-------------|
| `target` | | One or more IPs/domains (space-separated for bulk) |
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

# Bulk: multiple targets on command line
python3 rep_tool.py 1.2.3.4 5.6.7.8 evil.com --report

# Bulk: CIDR range with summary table
python3 rep_tool.py 10.0.0.0/24 --skip-ports --report

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

## Configuration

### API Keys

Free-tier sources (IPInfo, OTX) work without keys. For enhanced coverage, set via environment variables, `.env` file, or `api_keys.json`.

| Source | Free Tier | Get Key |
|--------|-----------|---------|
| IPInfo | 50k/mo | https://ipinfo.io/account/token |
| AlienVault OTX | Unlimited | https://otx.alienvault.com/api |
| AbuseIPDB | 1k/day | https://www.abuseipdb.com/account/api |
| VirusTotal | 4 req/min | https://www.virustotal.com/gui/my-apikey |
| Shodan | Limited | https://account.shodan.io/ |
| ThreatFox | Unlimited | https://auth.abuse.ch/ |
| URLhaus | Unlimited | https://auth.abuse.ch/ |

---

## Architecture

```
ThreatLens/
├── rep_tool.py          # CLI entry point & orchestrator
├── config.py            # API keys, constants, risk weights, whitelists
├── api_sources.py       # 7 OSINT API integrations with retry logic
├── dns_recon.py         # DNS, WHOIS, port scan, HTTP probe, TLS
├── risk_engine.py       # Tiered risk scoring with known-good whitelists
├── report_gen.py        # TXT + DOCX report generators (Sigma/Splunk/Elastic)
├── subdomain_enum.py    # Subdomain discovery (crt.sh, OTX, Shodan, VT, brute)
├── generate_sample.py   # Generate a sample DOCX report
├── .env.example         # API key template
├── requirements.txt
└── README.md
```

| Module | Purpose |
|--------|---------|
| `rep_tool.py` | CLI: argparse, bulk analysis, orchestration, Ctrl+C handler |
| `config.py` | APPDATA persistence, known-good domains/ASNs, API key loading |
| `api_sources.py` | OTX, AbuseIPDB, VT, Shodan, IPInfo, ThreatFox, URLhaus |
| `dns_recon.py` | DNS resolution, reverse DNS, WHOIS, port scan, HTTP/TLS probe |
| `risk_engine.py` | 3-tier scoring, whitelist suppression, NOT CHECKED states |
| `report_gen.py` | TXT + DOCX generators, bulk reports, Sigma/Splunk/Elastic rules |
| `subdomain_enum.py` | crt.sh, OTX passive DNS, Shodan, VT, DNS brute force, wildcard expand |

---

## Use Cases

| Use Case | Description |
|----------|-------------|
| **Incident Response** | Investigate suspicious IPs/domains from SIEM alerts |
| **Threat Hunting** | Validate IOCs from threat intelligence feeds |
| **Bulk IOC Processing** | Mass-analyze indicators from threat feeds or CIDR ranges |
| **Subdomain Discovery** | Map attack surface of a target domain |
| **Proactive Defense** | Screen indicators before firewall rule changes |
| **Management Reporting** | Generate professional DOCX/TXT reports |
| **SIEM Integration** | JSON output + Elastic/Splunk/Sigma detection rules |
| **Network Mapping** | Wildcard IP range scanning with risk assessment |

---

## Security

### API Key Storage
- Keys stored in `%APPDATA%\ThreatLens\api_keys.json` (Windows) or `~/.config/threatlens/` (Linux)
- Keys never logged or included in reports
- Keys loaded at runtime from env vars, `.env`, or `api_keys.json`

### Input Validation
- IP addresses validated via regex before processing
- Domain names validated via regex before processing
- No shell injection vectors (no os.system, no eval, no exec)
- No path traversal vulnerabilities
- No unsafe deserialization (no pickle, yaml.load, or marshal)

---

## Contributing

Contributions welcome!
- Report bugs and feature requests via [GitHub Issues](https://github.com/ethanx01-H/ThreatLens/issues)
- Submit PRs for new OSINT source integrations
- Improve risk scoring logic or add new signal types
- Add unit tests and integration tests

---

## License

MIT License — Free for SOC teams, threat researchers, and security analysts.

---

*Built for security analysts and threat researchers. Runs on Linux, WSL, and Windows.*
