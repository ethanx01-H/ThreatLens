"""
Subdomain Enumeration Module
Discovers subdomains using multiple free/paid sources:
  - crt.sh (Certificate Transparency) — free, no auth
  - AlienVault OTX passive DNS — free, no auth
  - Shodan DNS resolve — requires API key
  - VirusTotal subdomains — requires API key
  - DNS brute force (optional) — uses common wordlist
"""

import socket
import time
import requests
from typing import Dict, List, Set, Any
import config as cfg


def enumerate_subdomains(domain: str, methods: List[str] = None,
                         wordlist_path: str = None) -> Dict[str, Any]:
    """
    Enumerate subdomains for a given domain using multiple methods.
    Returns dict with discovered subdomains, IPs, and source info.
    """
    if methods is None:
        methods = ["crtsh", "otx", "shodan", "vt"]

    result = {
        "domain": domain,
        "subdomains": set(),
        "subdomain_ips": {},
        "sources_used": [],
        "sources_failed": [],
        "total_unique": 0,
        "elapsed": 0,
        "error": None,
    }

    start = time.time()

    # ── crt.sh (Certificate Transparency) ──────────────────────
    if "crtsh" in methods:
        subs = _query_crtsh(domain)
        if subs is not None:
            result["subdomains"].update(subs)
            result["sources_used"].append(f"crt.sh ({len(subs)})")
        else:
            result["sources_failed"].append("crt.sh")

    # ── AlienVault OTX passive DNS ─────────────────────────────
    if "otx" in methods:
        subs = _query_otx_passive(domain)
        if subs is not None:
            result["subdomains"].update(subs)
            result["sources_used"].append(f"OTX ({len(subs)})")
        else:
            result["sources_failed"].append("OTX")

    # ── Shodan DNS resolve ─────────────────────────────────────
    if "shodan" in methods and cfg.SHODAN_KEY:
        subs = _query_shodan_dns(domain)
        if subs is not None:
            result["subdomains"].update(subs)
            result["sources_used"].append(f"Shodan ({len(subs)})")
        else:
            result["sources_failed"].append("Shodan")

    # ── VirusTotal subdomains ──────────────────────────────────
    if "vt" in methods and cfg.VIRUSTOTAL_KEY:
        subs = _query_vt_subdomains(domain)
        if subs is not None:
            result["subdomains"].update(subs)
            result["sources_used"].append(f"VirusTotal ({len(subs)})")
        else:
            result["sources_failed"].append("VirusTotal")

    # ── DNS brute force (optional) ─────────────────────────────
    if "brute" in methods:
        subs = _dns_bruteforce(domain, wordlist_path)
        if subs:
            result["subdomains"].update(subs)
            result["sources_used"].append(f"BruteForce ({len(subs)})")

    # ── Resolve IPs for discovered subdomains ──────────────────
    resolved = 0
    for sub in sorted(result["subdomains"]):
        try:
            ips = socket.getaddrinfo(sub, None, socket.AF_INET)
            ip_list = list(set(addr[4][0] for addr in ips))
            if ip_list:
                result["subdomain_ips"][sub] = ip_list
                resolved += 1
        except (socket.gaierror, OSError):
            result["subdomain_ips"][sub] = []

    result["subdomains"] = sorted(result["subdomains"])
    result["total_unique"] = len(result["subdomains"])
    result["total_resolved"] = resolved
    result["elapsed"] = round(time.time() - start, 1)

    return result


def _query_crtsh(domain: str) -> Set[str]:
    """Query crt.sh Certificate Transparency logs."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith("." + domain) or line == domain:
                        # Skip wildcards
                        if not line.startswith("*"):
                            subs.add(line)
        return subs
    except Exception:
        return None


def _query_otx_passive(domain: str) -> Set[str]:
    """Query AlienVault OTX for passive DNS records."""
    subs = set()
    headers = {}
    if cfg.OTX_KEY:
        headers["X-OTX-API-KEY"] = cfg.OTX_KEY

    try:
        url = f"{cfg.OTX_BASE}/indicators/domain/{domain}/passive_dns"
        resp = requests.get(url, headers=headers, timeout=cfg.HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower().strip()
                if hostname and (hostname.endswith("." + domain) or hostname == domain):
                    subs.add(hostname)
        return subs
    except Exception:
        return None


def _query_shodan_dns(domain: str) -> Set[str]:
    """Query Shodan DNS resolve for subdomains."""
    subs = set()
    try:
        url = f"{cfg.SHODAN_BASE}/dns/domain/{domain}"
        params = {"key": cfg.SHODAN_KEY}
        resp = requests.get(url, params=params, timeout=cfg.HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("subdomains", []):
                full = f"{entry}.{domain}".lower()
                subs.add(full)
        return subs
    except Exception:
        return None


def _query_vt_subdomains(domain: str) -> Set[str]:
    """Query VirusTotal for subdomains."""
    subs = set()
    headers = {"x-apikey": cfg.VIRUSTOTAL_KEY}

    try:
        url = f"{cfg.VIRUSTOTAL_BASE}/domains/{domain}/subdomains"
        resp = requests.get(url, headers=headers, timeout=cfg.HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("data", []):
                sub_id = entry.get("id", "").lower()
                if sub_id and sub_id.endswith("." + domain):
                    subs.add(sub_id)
        return subs
    except Exception:
        return None


def _dns_bruteforce(domain: str, wordlist_path: str = None) -> Set[str]:
    """DNS brute force with common subdomain wordlist."""
    subs = set()

    # Default wordlist — common subdomains
    default_words = [
        "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "webmail",
        "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "relay",
        "remote", "vpn", "gateway", "proxy", "firewall",
        "dev", "staging", "test", "qa", "uat", "demo", "sandbox",
        "api", "api2", "rest", "graphql", "ws", "websocket",
        "app", "app2", "mobile", "web", "portal", "dashboard",
        "admin", "administrator", "cpanel", "whm", "panel",
        "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
        "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "ci", "cd",
        "blog", "cms", "wiki", "docs", "help", "support", "kb",
        "cdn", "static", "media", "img", "images", "assets", "files",
        "shop", "store", "ecommerce", "pay", "payment", "billing",
        "auth", "login", "sso", "oauth", "ldap", "ad", "okta",
        "monitor", "nagios", "zabbix", "grafana", "prometheus", "kibana",
        "backup", "bak", "old", "archive", "legacy",
        "vpn2", "rdp", "ssh", "sftp", "telnet",
        "crm", "erp", "hr", "jira", "confluence", "slack",
        "exchange", "owa", "outlook", "autodiscover",
        "cloud", "aws", "azure", "gcp", "s3", "blob",
        "vpn3", "internal", "intranet", "extranet", "corp",
        "m", "mobile2", "wap", "wss",
        "smtp2", "mail2", "mx3",
        "www2", "www3",
        "beta", "alpha", "rc", "nightly", "canary",
        "status", "health", "ping", "uptime",
    ]

    if wordlist_path:
        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except (OSError, IOError):
            words = default_words
    else:
        words = default_words

    for word in words:
        sub = f"{word}.{domain}"
        try:
            socket.getaddrinfo(sub, None, socket.AF_INET)
            subs.add(sub)
        except (socket.gaierror, OSError):
            pass

    return subs


def wildcard_expand(pattern: str) -> List[str]:
    """
    Expand a wildcard pattern into a list of targets.
    Supports:
      *.example.com  → enumerate subdomains of example.com
      192.168.1.*    → 192.168.1.1 through 192.168.1.254
      10.0.0.0/24    → 10.0.0.1 through 10.0.0.254
    """
    targets = []

    # Subdomain wildcard: *.example.com
    if pattern.startswith("*."):
        domain = pattern[2:]
        result = enumerate_subdomains(domain, methods=["crtsh", "otx"])
        targets = result.get("subdomains", [])
        if not targets:
            targets = [domain]  # fallback to base domain

    # IP wildcard: 192.168.1.*
    elif pattern.endswith(".*"):
        base = pattern[:-2]
        for i in range(1, 255):
            targets.append(f"{base}.{i}")

    # CIDR: 10.0.0.0/24
    elif "/" in pattern:
        try:
            import ipaddress
            network = ipaddress.ip_network(pattern, strict=False)
            targets = [str(h) for h in network.hosts()]
        except ValueError:
            targets = [pattern]

    else:
        targets = [pattern]

    return targets
