"""
Configuration & API Key Management for IP/Domain Reputation Tool
SOC L3 Analyst - Threat Intelligence Investigation

API keys are loaded from environment variables or a .env file.
Free-tier APIs (IPInfo, OTX, ThreatFox, URLhaus) work without keys.
"""

import os
import json
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────
TOOL_DIR = Path(__file__).parent
ENV_FILE = TOOL_DIR / ".env"
KEYS_FILE = TOOL_DIR / "api_keys.json"

# ─── API Key Sources ──────────────────────────────────────────────
# Priority: env var > .env file > api_keys.json > None (free-tier fallback)

def _load_json_keys():
    """Load keys from api_keys.json if it exists."""
    if KEYS_FILE.exists():
        try:
            return json.loads(KEYS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}

def _load_dotenv():
    """Minimal .env parser (no dependency on python-dotenv)."""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env

_json_keys = _load_json_keys()
_dotenv = _load_dotenv()

def get_key(env_var: str, json_key: str = None) -> str:
    """Get API key from env var, .env file, or api_keys.json."""
    val = os.environ.get(env_var)
    if val:
        return val
    val = _dotenv.get(env_var)
    if val:
        return val
    if json_key:
        val = _json_keys.get(json_key)
        if val:
            return val
    return ""

# ─── API Keys ─────────────────────────────────────────────────────
ABUSEIPDB_KEY = get_key("ABUSEIPDB_API_KEY", "abuseipdb")
VIRUSTOTAL_KEY = get_key("VIRUSTOTAL_API_KEY", "virustotal")
SHODAN_KEY = get_key("SHODAN_API_KEY", "shodan")
OTX_KEY = get_key("OTX_API_KEY", "otx")
IPINFO_KEY = get_key("IPINFO_TOKEN", "ipinfo")

# ─── API Endpoints ────────────────────────────────────────────────
OTX_BASE = "https://otx.alienvault.com/api/v1"
IPINFO_BASE = "https://ipinfo.io"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
SHODAN_BASE = "https://api.shodan.io"
THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
MALWAREBAZAAR_BASE = "https://mb-api.abuse.ch/api/v1"

# ─── Risk Classification Thresholds ──────────────────────────────
RISK_THRESHOLDS = {
    "CRITICAL": 80,   # score >= 80
    "HIGH":     60,   # score >= 60
    "MEDIUM":   35,   # score >= 35
    "LOW":      0,    # score < 35
}

# ─── Risk Score Weights ──────────────────────────────────────────
WEIGHTS = {
    "otx_pulses":           15,   # per pulse (capped at 5 pulses = 75)
    "otx_pulse_cap":         5,
    "abuse_confidence":     25,   # scaled by percentage
    "vt_malicious":         20,   # per vendor flagging (capped)
    "vt_malicious_cap":      5,
    "shodan_vulns":         10,   # per CVE (capped)
    "shodan_vuln_cap":       3,
    "threatfox_iocs":       15,   # per IOC association
    "urlhaus_listed":       15,   # flat bonus if listed
    "open_ports_risk":       5,   # per high-risk port
    "high_risk_ports":       3,   # cap
    "no_reverse_dns":        5,   # suspicious if cloud-hosted
    "known_bad_asn":        10,   # ASN on threat list
    "tor_exit_node":        15,   # flat bonus
}

# ─── High-Risk Ports ─────────────────────────────────────────────
HIGH_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 135: "MSRPC",
    139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    2375: "Docker-API", 9200: "Elasticsearch",
}

# ─── Ports to Scan ────────────────────────────────────────────────
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017, 2375,
]

# ─── OTX Threat Tags (weighted) ─────────────────────────────────
OTX_HIGH_TAGS = {
    "botnet", "mirai", "c2", "malware", "ransomware",
    "apt", "exploit", "backdoor", "rootkit", "keylogger",
    "honeypot", "blacklist", "scanner",
}
OTX_MEDIUM_TAGS = {
    "brute force", "phishing", "spam", "smb", "proxy",
    "tor", "vpn", "mining", "cryptominer", "ddos",
}

# ─── Known Bad ASNs (commonly associated with bulletproof hosting) ─
KNOWN_BAD_ASNS = {
    "AS14061",  # DigitalOcean (heavily abused)
    "AS16276",  # OVH
    "AS14618",  # AWS (high volume, not inherently bad)
    "AS16509",  # AWS
    "AS57043",  # HOSTKEY
    "AS49981",  # WorldStream
    "AS46664",  # VolumeDrive
    "AS36352",  # ColoCrossing
    "AS40676",  # Psychz Networks
    "AS62904",  # Eonix
    "AS42831",  # UK Dedicated Servers
    "AS20001",  # DataPipe
    "AS53667",  # FranTech Solutions (BuyVM)
    "AS44477",  # Stark Industries
    "AS48693",  # Reba Communications
    "AS51396",  # Pfcloud
}

# ─── Report Settings ──────────────────────────────────────────────
REPORT_CLASSIFICATION = "CONFIDENTIAL"
REPORT_ORG = "SOC Team"
REPORT_LANGUAGE = "en"

# ─── Scan Settings ────────────────────────────────────────────────
PORT_SCAN_TIMEOUT = 2       # seconds per port
HTTP_TIMEOUT = 10           # seconds for API calls
MAX_RETRIES = 2             # retry failed API calls
DNS_TIMEOUT = 5             # seconds for DNS queries

# ─── ASCII Banner ────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║   ____  _____ _____     _    ____                               ║
║  |  _ \| ____|_ _\ \   / \  |  _ \                              ║
║  | |_) |  _|  | | \ \ / _ \ | | | |                             ║
║  |  __/| |___ | |  \ / ___ \| |_| |                             ║
║  |_|   |_____|___| \_/_/   \_\____/  Reputation Tool v1.0       ║
║                                                                  ║
║  SOC L3 Analyst — IP/Domain Threat Intelligence Investigation    ║
║  Multi-Source OSINT | Risk Scoring | Professional Reporting      ║
╚══════════════════════════════════════════════════════════════════╝
"""
