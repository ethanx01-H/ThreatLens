"""
Configuration & API Key Management for ThreatLens
Threat Intelligence Investigation

API keys are loaded from persistent user storage (%APPDATA% on Windows).
Supports: env vars > .env file > appdata api_keys.json > bundled api_keys.json
"""

import os
import sys
import json
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────
TOOL_DIR = Path(__file__).parent
ENV_FILE = TOOL_DIR / ".env"

def _get_appdata_dir() -> Path:
    """Get persistent config directory. Fixed location, not portable."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
        return Path(base) / "ThreatLens"
    else:
        # Linux/macOS
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        return Path(base) / "threatlens"

APPDATA_DIR = _get_appdata_dir()
APPDATA_KEYS_FILE = APPDATA_DIR / "api_keys.json"
BUNDLED_KEYS_FILE = TOOL_DIR / "api_keys.json"

# Create appdata directory on import
try:
    APPDATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

# ─── API Key Sources ──────────────────────────────────────────────
# Priority: env var > .env file > appdata api_keys.json > bundled api_keys.json

def _load_json_keys():
    """Load keys from persistent appdata location, then bundled fallback."""
    # Try persistent location first
    if APPDATA_KEYS_FILE.exists():
        try:
            return json.loads(APPDATA_KEYS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    # Fallback to bundled
    if BUNDLED_KEYS_FILE.exists():
        try:
            return json.loads(BUNDLED_KEYS_FILE.read_text())
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
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   35,
    "LOW":      0,
}

# ─── Risk Score Weights (v2 — tiered) ─────────────────────────────
WEIGHTS = {
    "otx_pulses":           15,
    "otx_pulse_cap":         5,
    "abuse_confidence":     25,
    "vt_malicious":         20,
    "vt_malicious_cap":      5,
    "shodan_vulns":         10,
    "shodan_vuln_cap":       3,
    "threatfox_iocs":       15,
    "urlhaus_listed":       15,
    "open_ports_risk":       5,
    "high_risk_ports":       3,
    "no_reverse_dns":        5,
    "known_bad_asn":        10,
    "tor_exit_node":        15,
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

# ─── Known-Good Domains (suppress false positives) ────────────────
KNOWN_GOOD_DOMAINS = {
    "google.com", "googleapis.com", "google.co.uk", "google.de", "google.fr",
    "google.co.jp", "google.com.au", "google.ca", "google.com.br",
    "googleapis.com", "gstatic.com", "ggpht.com", "googleusercontent.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "outlook.com", "microsoftonline.com",
    "azure.com", "azurewebsites.net", "blob.core.windows.net",
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    "cloudflare.com", "cloudflare-dns.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "github.com", "githubusercontent.com",
    "twitter.com", "x.com", "twimg.com",
    "netflix.com", "nflxvideo.net",
    "akamai.com", "akamaized.net", "akamaihd.net",
    "fastly.net", "fastly.com",
    "linkedin.com",
    "wikipedia.org", "wikimedia.org",
    "mozilla.org", "mozilla.com",
    "ubuntu.com", "debian.org",
    "stackoverflow.com",
    "reddit.com", "redd.it",
    "zoom.us", "zoom.com",
    "slack.com",
    "dropbox.com",
}

# ─── Known-Good ASNs (major cloud/CDN providers) ──────────────────
KNOWN_GOOD_ASNS = {
    "AS15169",  # Google LLC
    "AS16509",  # Amazon (AWS)
    "AS14618",  # Amazon (AWS us-east)
    "AS8075",   # Microsoft Corporation
    "AS13335",  # Cloudflare
    "AS714",    # Apple Inc.
    "AS32934",  # Facebook/Meta
    "AS2906",   # Netflix
    "AS20940",  # Akamai
    "AS54113",  # Fastly
    "AS16509",  # AWS
}

# ─── Known Bad ASNs (bulletproof hosting — REMOVED major cloud) ───
KNOWN_BAD_ASNS = {
    "AS57043",  # HOSTKEY
    "AS49981",  # WorldStream
    "AS46664",  # VolumeDrive
    "AS36352",  # ColoCrossing
    "AS40676",  # Psychz Networks
    "AS62904",  # Eonix
    "AS42831",  # UK Dedicated Servers
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
PORT_SCAN_TIMEOUT = 2
HTTP_TIMEOUT = 10
MAX_RETRIES = 2
DNS_TIMEOUT = 5

# ─── ASCII Banner ────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║   _____ _                    _    _                              ║
║  |_   _| |__  _ __ ___  __ _| | _| |     Lens                   ║
║    | | | '_ \| '__/ _ \/ _` | |/ / |                             ║
║    | | | | | | | |  __/ (_| |   <| |___  v1.0                    ║
║    |_| |_| |_|_|  \___|\__,_|_|\_\_____|                        ║
║                                                                  ║
║  Threat Intelligence Investigation                               ║
║  Multi-Source OSINT | Risk Scoring | Professional Reporting      ║
╚══════════════════════════════════════════════════════════════════╝
"""
