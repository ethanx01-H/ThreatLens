1|# 🛡️ ThreatLens v1.0
2|
3|<p align="center">
4|  <img src="anime_reputation_logo.svg" width="180" alt="ThreatLens Logo"/>
5|</p>
6|
7|**Multi-Source Threat Intelligence Investigation**
8|
9|A comprehensive CLI + GUI tool for SOC analysts to investigate IP addresses and
10|domain names using 7 OSINT sources, subdomain enumeration, wildcard search,
11|tiered risk scoring, and professional report generation with SIEM detection rules.
12|
13|---
14|
15|## ⚡ Quick Start
16|
17|```bash
18|# Clone
19|git clone https://github.com/ethanx01-H/ThreatLens.git
20|cd ThreatLens
21|
22|# Install dependencies
23|pip install -r requirements.txt --break-system-packages
24|
25|# Investigate an IP
26|python3 rep_tool.py 1.2.3.4
27|
28|# Investigate a domain with TXT report
29|python3 rep_tool.py suspicious-domain.com --report
30|
31|# DOCX report
32|python3 rep_tool.py 1.2.3.4 --report --format docx
33|
34|# Subdomain enumeration + analysis
35|python3 rep_tool.py example.com --subdomains --report
36|
37|# Wildcard: scan a whole IP range
38|python3 rep_tool.py -w '192.168.1.*' --skip-ports --json
39|
40|# Ctrl+C to stop at any time
41|```
42|
43|---
44|
45|## 🪟 Windows Executable
46|
47|A standalone `.exe` is available — no Python installation required.
48|
49|### Download
50|
51|Download `ThreatLens.exe` from the [releases](https://github.com/ethanx01-H/ThreatLens/releases) page.
52|
53|### Build from Source
54|
55|```cmd
56|build_windows.bat
57|```
58|
59|Output: `dist\ThreatLens.exe` (~17 MB standalone)
60|
61|### GUI Usage
62|
63|1. Double-click `ThreatLens.exe`
64|2. Enter an IP or domain, click **ANALYZE** (or press Enter)
65|3. Click **STOP** to cancel a running analysis (red button, appears during scan)
66|4. Click **SUBS** to enumerate and analyze all subdomains of a domain
67|5. Click **BULK** to analyze multiple targets — paste IPs/domains (one per line), configure options (Skip Port Scan, Skip TOR, JSON), click **OK** to start or **Cancel** to close
68|6. Click **REPORT** to export — toggle between **TXT** and **DOCX** format
69|7. Click **⚙ SETTINGS** to configure API keys (masked input, persistent storage)
70|
71|**Theme:** Eye-cool colors — soft blue (#3B82C4), light gray backgrounds, dark text. Comfortable for extended use.
72|
73|**Keyboard shortcuts:**
74|- Enter — Start analysis / Confirm dialog
75|- Escape — Cancel dialog
76|- Ctrl+C — Stop running analysis (CLI)
77|
78|API keys are saved to `%APPDATA%\ThreatLens\api_keys.json` — set once, works forever.
79|
80|---
81|
82|## 🔍 Features
83|
84|| Feature | Description |
85||---------|-------------|
86|| **7 OSINT Sources** | AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo, ThreatFox, URLhaus |
87|| **Subdomain Enumeration** | crt.sh, OTX passive DNS, Shodan, VirusTotal, DNS brute force (140+ names) |
88|| **Wildcard Search** | `*.domain.com`, `192.168.1.*`, CIDR ranges (`10.0.0.0/24`) |
89|| **Network Recon** | DNS (A/AAAA/MX/NS/TXT/SOA/CNAME), reverse DNS, WHOIS, TCP port scan with banner grab |
90|| **HTTP/HTTPS Probe** | Server headers, TLS certificate, security header audit |
91|| **Risk Scoring Engine** | Tiered multi-signal scoring (0–100) with known-good whitelists |
92|| **Three-State Verdict** | MALICIOUS / BENIGN / NOT CHECKED per source |
93|| **Report Export** | TXT or DOCX — color-coded tables, IOC tables, cover page |
94|| **SIEM Detection Rules** | Sigma, Splunk, **Elastic SIEM** (EQL + KQL + JSON import) |
95|| **Settings Panel** | GUI API key management with masked input, persistent storage |
96|| **Bulk Analyze** | Queue multiple targets — all options (skip ports, skip TOR, JSON) work in all modes |
97|| **STOP Button** | Cancel running analysis (GUI) or Ctrl+C (CLI) |
98|| **TOR Detection** | Live TOR exit node list check |
99|| **JSON Output** | Machine-readable output for SIEM/pipeline integration |
100|
101|---
102|
103|## 📊 Risk Scoring (v2 — Tiered)
104|
105|### Signal Tiers
106|
107|| Tier | Strength | Sources |
108||------|----------|---------|
109|| **TIER 1** | STRONG — direct malicious verdict | VT detections, AbuseIPDB ≥75%, ThreatFox C2, URLhaus listing, OTX pulses + bad tags, TOR exit |
110|| **TIER 2** | MODERATE — suspicious context | OTX pulses (no tags), AbuseIPDB 40–74%, Shodan CVEs, high-risk ports, new domain age |
111|| **TIER 3** | WEAK — passive/contextual | OTX malware associations, no reverse DNS, bulletproof ASN |
112|
113|### Known-Good Whitelist
114|
115|64 domains (Google, Microsoft, Cloudflare, Amazon, Apple, etc.) and 10 ASNs
116|are whitelisted. OTX malware associations are suppressed for known-good domains.
117|Score capped at 25 for legitimate infrastructure.
118|
119|### Classification
120|
121|| Level | Score | Action |
122||-------|-------|--------|
123|| 🔴 CRITICAL | 80–100 | Block immediately, escalate |
124|| 🟠 HIGH | 60–79 | Block after business review |
125|| 🟡 MEDIUM | 35–59 | Add to monitoring watchlist |
126|| 🟢 LOW | 0–34 | Log for reference |
127|
128|---
129|
130|## 📋 Report Sections (TXT & DOCX)
131|
132|1. **Executive Summary** — Risk score, classification, known-good status
133|2. **Source Verification** — ✓ CHECKED / ✗ NOT CHECKED per source
134|3. **Indicator Profile** — Geolocation, ASN, ISP, DNS, WHOIS
135|4. **Risk Assessment** — Score breakdown with bar charts, signal tiers + interpretation
136|5. **Mitigating Factors** — Whitelist, clean verdicts
137|6. **Threat Intelligence Findings** — Per-source detail (OTX, AbuseIPDB, VT, Shodan, ThreatFox, URLhaus)
138|7. **Network Reconnaissance** — Port table, banners, HTTP headers, TLS
139|8. **IOC Table** — BLOCK/MONITOR actions with severity color-coding
140|9. **Recommended Actions** — Classification-based response playbook
141|10. **Detection Rules** — Sigma + Splunk + **Elastic SIEM** (EQL, KQL, JSON rule import)
142|11. **Appendix** — OSINT source URLs for manual verification
143|
144|Bulk reports include a summary table + per-target detail pages + combined IOC table.
145|
146|---
147|
148|## 🖥️ CLI Reference
149|
150|```
151|usage: rep_tool.py [-h] [--report] [--format {txt,docx}] [--output OUTPUT]
152|                   [--json] [--skip-ports] [--skip-tor] [--analyst ANALYST]
153|                   [--classification CLASSIFICATION] [--quiet] [--batch BATCH]
154|                   [--subdomains] [--wildcard WILDCARD]
155|                   target
156|
157|positional arguments:
158|  target                    IP address or domain to investigate
159|
160|options:
161|  --report, -r              Generate report
162|  --format {txt,docx}, -f   Report format (default: txt)
163|  --output, -o OUTPUT       Custom output path
164|  --json, -j                JSON output
165|  --skip-ports              Skip port scanning
166|  --skip-tor                Skip TOR check
167|  --subdomains, -s          Enumerate + analyze all subdomains
168|  --wildcard, -w PATTERN    Wildcard: *.domain.com, 192.168.1.*, CIDR
169|  --analyst ANALYST         Analyst name for report
170|  --classification LEVEL    Report classification (default: CONFIDENTIAL)
171|  --quiet, -q               JSON-only output
172|  --batch, -b FILE          Batch: one target per line
173|```
174|
175|### Examples
176|
177|```bash
178|# Single IP
179|python3 rep_tool.py 185.220.101.1
180|
181|# Domain with DOCX report
182|python3 rep_tool.py evil-domain.com --report -f docx
183|
184|# Subdomain enumeration + analysis
185|python3 rep_tool.py example.com --subdomains --report
186|
187|# Wildcard IP range
188|python3 rep_tool.py -w '10.0.0.0/24' --skip-ports --json
189|
190|# Wildcard subdomain discovery
191|python3 rep_tool.py -w '*.suspicious-domain.com' --report
192|
193|# Batch from file
194|python3 rep_tool.py --batch iocs.txt --report -f txt
195|
196|# Stop with Ctrl+C at any time
197|```
198|
199|---
200|
201|## ⚙️ Configuration
202|
203|### API Keys
204|
205|Free-tier sources (IPInfo, OTX) work without keys. For enhanced coverage:
206|
207|**GUI:** Click ⚙ SETTINGS → enter keys → SAVE (masked, persistent)
208|
209|**CLI:** Set via environment variables, `.env` file, or `api_keys.json`:
210|
211|| Source | Free Tier | Get Key |
212||--------|-----------|---------|
213|| IPInfo | ✅ 50k/mo | https://ipinfo.io/account/token |
214|| AlienVault OTX | ✅ | https://otx.alienvault.com/api |
215|| AbuseIPDB | ✅ 1k/day | https://www.abuseipdb.com/account/api |
216|| VirusTotal | ✅ 4 req/min | https://www.virustotal.com/gui/my-apikey |
217|| Shodan | ✅ limited | https://account.shodan.io/ |
218|| ThreatFox | ✅ | https://auth.abuse.ch/ |
219|| URLhaus | ✅ | https://auth.abuse.ch/ |
220|
221|---
222|
223|## 🏗️ Architecture
224|
225|```
226|ThreatLens/
227|├── rep_tool.py          # CLI entry point & orchestrator
228|├── rep_gui.py           # GUI (tkinter, dark B&W theme)
229|├── config.py            # API keys, constants, risk weights, whitelists
230|├── api_sources.py       # 7 OSINT API integrations with retry logic
231|├── dns_recon.py         # DNS, WHOIS, port scan, HTTP probe, TLS
232|├── risk_engine.py       # Tiered risk scoring with known-good whitelists
233|├── report_gen.py        # TXT + DOCX report generators (Sigma/Splunk/Elastic)
234|├── subdomain_enum.py    # Subdomain discovery (crt.sh, OTX, Shodan, VT, brute)
235|├── build_windows.bat    # One-click Windows .exe build
236|├── app.ico              # Application icon
237|├── anime_reputation_logo.svg  # Logo
238|├── requirements.txt
239|└── README.md
240|```
241|
242|| Module | Purpose |
243||--------|---------|
244|| `rep_tool.py` | CLI: argparse, orchestration, Ctrl+C handler |
245|| `rep_gui.py` | GUI: dark theme, STOP/BULK/SUBS buttons, settings dialog |
246|| `config.py` | APPDATA persistence, known-good domains/ASNs, API key loading |
247|| `api_sources.py` | OTX, AbuseIPDB, VT, Shodan, IPInfo, ThreatFox, URLhaus (cfg at call time) |
248|| `dns_recon.py` | DNS resolution, reverse DNS, WHOIS, port scan, HTTP/TLS probe |
249|| `risk_engine.py` | 3-tier scoring, whitelist suppression, NOT CHECKED states |
250|| `report_gen.py` | TXT + DOCX generators, bulk reports, Sigma/Splunk/Elastic rules |
251|| `subdomain_enum.py` | crt.sh, OTX passive DNS, Shodan, VT, DNS brute force, wildcard expand |
252|
253|---
254|
255|## 🎯 Use Cases
256|
257|- **Incident Response** — Investigate suspicious IPs/domains from SIEM alerts
258|- **Threat Hunting** — Validate IOCs from threat intelligence feeds
259|- **Subdomain Discovery** — Map attack surface of a target domain
260|- **Proactive Defense** — Screen indicators before firewall rule changes
261|- **Management Reporting** — Generate professional DOCX/TXT reports
262|- **SIEM Integration** — JSON output + Elastic/Splunk/Sigma detection rules
263|- **Bulk IOC Processing** — Mass-analyze indicators from threat feeds
264|- **Network Mapping** — Wildcard IP range scanning with risk assessment
265|
266|---
383|
384|## 🔒 Security
385|
386|### API Key Storage
387|- Keys stored in `%APPDATA%\ThreatLens\api_keys.json` (Windows) or `~/.config/threatlens/` (Linux)
388|- Keys never logged or included in reports
389|- Keys loaded at runtime, not compiled into the exe
390|- Hot-reload: changing keys in Settings takes effect immediately
391|
392|### Network Requests
393|- SSL verification disabled intentionally for HTTP probe (suspicious domains often have invalid certs)
394|- InsecureRequestWarning suppressed to reduce noise
395|- All API calls use HTTPS endpoints
396|- Rate limiting and retry logic on all API calls
397|
398|### Input Validation
399|- IP addresses validated via regex before processing
400|- Domain names validated via regex before processing
401|- No shell injection vectors (no os.system, no eval, no exec)
402|- No path traversal vulnerabilities
403|- No unsafe deserialization (no pickle, yaml.load, or marshal)
404|
405|### Report Safety
406|- Reports never include API keys
407|- Reports never include raw credentials
408|- Reports contain only OSINT-sourced threat intelligence
409|
410|---
411|
## 🤝 Contributing

Contributions welcome!:
- Report bugs and feature requests via [GitHub Issues](https://github.com/ethanx01-H/ThreatLens/issues)
- Submit PRs for new OSINT source integrations
- Improve risk scoring logic or add new signal types
- Add unit tests and integration tests
- Improve documentation and add usage examples
421|
422|---
423|
424|## 📝 License
425|
426|MIT License — Free for SOC teams, threat researchers, and security analysts.
427|
428|---
429|
430|*Built for security analysts and threat researchers. Tested on WSL (Ubuntu) and Windows.*
431|