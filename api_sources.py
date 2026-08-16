"""
OSINT API Sources Module
Queries multiple threat intelligence platforms for IP/domain reputation.
Supports: AlienVault OTX, AbuseIPDB, VirusTotal, Shodan, IPInfo,
          ThreatFox (abuse.ch), URLhaus (abuse.ch), TOR exit nodes
"""

import json
import time
import requests
from typing import Dict, List, Optional, Any
import config as cfg
# NOTE: Keys are read from cfg at CALL TIME (not import time)
# so GUI hot-reload works without restarting.


# ─── Status Codes ──────────────────────────────────────────────────
# Used by query functions to report the outcome of each API call.
# Consumers (risk_engine, report_gen) use these to differentiate
# "no API key" from "rate limited" from "server error", etc.

class SourceStatus:
    """Enum-like constants for source query status."""
    SUCCESS = "SUCCESS"
    NOT_FOUND = "NOT_FOUND"
    NO_API_KEY = "NO_API_KEY"
    RATE_LIMITED = "RATE_LIMITED"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    TIMEOUT = "TIMEOUT"
    SERVER_ERROR = "SERVER_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"


def _classify_http_error(status_code: int) -> str:
    """Map HTTP status code to a SourceStatus constant."""
    if status_code == 401:
        return SourceStatus.UNAUTHORIZED
    elif status_code == 403:
        return SourceStatus.FORBIDDEN
    elif status_code == 404:
        return SourceStatus.NOT_FOUND
    elif status_code == 429:
        return SourceStatus.RATE_LIMITED
    elif 500 <= status_code < 600:
        return SourceStatus.SERVER_ERROR
    return SourceStatus.INVALID_RESPONSE


def _get(url: str, headers: dict = None, params: dict = None,
         timeout: int = cfg.HTTP_TIMEOUT) -> tuple:
    """HTTP GET with retry logic. Returns (data, status_code_or_None)."""
    last_status = None
    for attempt in range(cfg.MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=headers, params=params,
                                timeout=timeout)
            if resp.status_code == 200:
                try:
                    return resp.json(), 200
                except json.JSONDecodeError:
                    return None, SourceStatus.INVALID_RESPONSE
            elif resp.status_code == 429:
                last_status = 429
                time.sleep(2 ** attempt)
                continue
            else:
                return None, resp.status_code
        except requests.Timeout:
            last_status = SourceStatus.TIMEOUT
            if attempt < cfg.MAX_RETRIES:
                time.sleep(1)
            else:
                return None, SourceStatus.TIMEOUT
        except requests.RequestException:
            last_status = SourceStatus.NETWORK_ERROR
            if attempt < cfg.MAX_RETRIES:
                time.sleep(1)
            else:
                return None, SourceStatus.NETWORK_ERROR
    # Exhausted retries on 429
    return None, last_status or SourceStatus.RATE_LIMITED


def _post(url: str, data: dict = None, json_body: dict = None,
          headers: dict = None, timeout: int = cfg.HTTP_TIMEOUT) -> tuple:
    """HTTP POST with retry logic. Returns (data, status_code_or_None)."""
    last_status = None
    for attempt in range(cfg.MAX_RETRIES + 1):
        try:
            resp = requests.post(url, data=data, json=json_body,
                                 headers=headers, timeout=timeout)
            if resp.status_code == 200:
                try:
                    return resp.json(), 200
                except json.JSONDecodeError:
                    return None, SourceStatus.INVALID_RESPONSE
            elif resp.status_code == 429:
                last_status = 429
                time.sleep(2 ** attempt)
                continue
            else:
                return None, resp.status_code
        except requests.Timeout:
            last_status = SourceStatus.TIMEOUT
            if attempt < cfg.MAX_RETRIES:
                time.sleep(1)
            else:
                return None, SourceStatus.TIMEOUT
        except requests.RequestException:
            last_status = SourceStatus.NETWORK_ERROR
            if attempt < cfg.MAX_RETRIES:
                time.sleep(1)
            else:
                return None, SourceStatus.NETWORK_ERROR
    return None, last_status or SourceStatus.RATE_LIMITED


# ═══════════════════════════════════════════════════════════════════
# IPInfo — Geolocation, ASN, ISP
# ═══════════════════════════════════════════════════════════════════

def query_ipinfo(ip: str) -> Dict[str, Any]:
    """Query IPInfo.io for geolocation and ASN data."""
    result = {
        "source": "IPInfo",
        "ip": ip,
        "hostname": "",
        "city": "",
        "region": "",
        "country": "",
        "loc": "",
        "org": "",
        "asn": "",
        "isp": "",
        "timezone": "",
        "is_cloud": False,
        "cloud_provider": "",
        "error": None,
    }

    headers = {}
    if cfg.IPINFO_KEY:
        headers["Authorization"] = f"Bearer {cfg.IPINFO_KEY}"

    url = f"{cfg.IPINFO_BASE}/{ip}/json"
    data, resp = _get(url, headers=headers)

    if not data:
        result["error"] = "Failed to query IPInfo"
        return result

    result["hostname"] = data.get("hostname", "")
    result["city"] = data.get("city", "")
    result["region"] = data.get("region", "")
    result["country"] = data.get("country", "")
    result["loc"] = data.get("loc", "")
    result["org"] = data.get("org", "")
    result["timezone"] = data.get("timezone", "")

    # Parse ASN and ISP from org field
    org = data.get("org", "")
    if org:
        parts = org.split(" ", 1)
        result["asn"] = parts[0] if parts else ""
        result["isp"] = parts[1] if len(parts) > 1 else ""

    # Detect cloud providers
    hostname = result["hostname"].lower()
    cloud_patterns = {
        "amazonaws.com": "AWS", "aws.amazon": "AWS",
        "digitalocean.com": "DigitalOcean",
        "linode.com": "Linode/Akamai", "members.linode.com": "Linode/Akamai",
        "vultr.com": "Vultr", "choopa.com": "Vultr",
        "googleusercontent.com": "GCP",
        "azure": "Azure", "cloudapp.azure.com": "Azure",
        "ovh.net": "OVH", "ovhcloud.com": "OVH",
        "hetzner": "Hetzner",
        "contabo": "Contabo",
    }
    for pattern, provider in cloud_patterns.items():
        if pattern in hostname or pattern in org.lower():
            result["is_cloud"] = True
            result["cloud_provider"] = provider
            break

    return result


# ═══════════════════════════════════════════════════════════════════
# AlienVault OTX — Threat Pulses, Malware, URLs
# ═══════════════════════════════════════════════════════════════════

def query_otx_ip(ip: str) -> Dict[str, Any]:
    """Query AlienVault OTX for IP threat intelligence."""
    result = {
        "source": "AlienVault OTX",
        "ip": ip,
        "pulse_count": 0,
        "pulses": [],
        "malware_count": 0,
        "malware_samples": [],
        "url_count": 0,
        "urls": [],
        "reputation": 0,
        "country": "",
        "asn": "",
        "all_tags": [],
        "error": None,
    }

    headers = {}
    if cfg.OTX_KEY:
        headers["X-OTX-API-KEY"] = cfg.OTX_KEY

    # --- General info + pulses ---
    general, resp = _get(f"{cfg.OTX_BASE}/indicators/IPv4/{ip}/general", headers=headers)
    if general:
        pi = general.get("pulse_info", {})
        result["pulse_count"] = pi.get("count", 0)
        result["reputation"] = general.get("reputation", 0)
        result["country"] = general.get("country_name", "")
        result["asn"] = general.get("asn", "")

        for p in pi.get("pulses", [])[:20]:
            pulse = {
                "name": p.get("name", ""),
                "created": p.get("created", "")[:10],
                "tags": p.get("tags", []),
                "description": p.get("description", "")[:300],
                "references": p.get("references", [])[:5],
            }
            result["pulses"].append(pulse)
            result["all_tags"].extend(p.get("tags", []))
    else:
        result["error"] = "Failed to query OTX"

    # --- Malware samples ---
    malware, resp = _get(f"{cfg.OTX_BASE}/indicators/IPv4/{ip}/malware", headers=headers)
    if malware:
        result["malware_count"] = malware.get("count", 0)
        for m in malware.get("data", [])[:10]:
            detections = m.get("detections", {})
            result["malware_samples"].append({
                "hash": m.get("hash", ""),
                "av_name": detections.get("av", ""),
                "malware_name": detections.get("name", ""),
                "date": m.get("created", "")[:10],
            })

    # --- Malicious URLs ---
    urls, resp = _get(f"{cfg.OTX_BASE}/indicators/IPv4/{ip}/url_list", headers=headers)
    if urls:
        result["url_count"] = urls.get("count", 0)
        for u in urls.get("url_list", [])[:10]:
            result["urls"].append({
                "url": u.get("url", ""),
                "date": u.get("date", "")[:10],
                "status": u.get("httpcode", ""),
            })

    return result


def query_otx_domain(domain: str) -> Dict[str, Any]:
    """Query AlienVault OTX for domain threat intelligence."""
    result = {
        "source": "AlienVault OTX",
        "domain": domain,
        "pulse_count": 0,
        "pulses": [],
        "malware_count": 0,
        "malware_samples": [],
        "url_count": 0,
        "urls": [],
        "all_tags": [],
        "error": None,
    }

    headers = {}
    if cfg.OTX_KEY:
        headers["X-OTX-API-KEY"] = cfg.OTX_KEY

    general, resp = _get(f"{cfg.OTX_BASE}/indicators/domain/{domain}/general", headers=headers)
    if general:
        pi = general.get("pulse_info", {})
        result["pulse_count"] = pi.get("count", 0)
        for p in pi.get("pulses", [])[:20]:
            result["pulses"].append({
                "name": p.get("name", ""),
                "created": p.get("created", "")[:10],
                "tags": p.get("tags", []),
                "description": p.get("description", "")[:300],
            })
            result["all_tags"].extend(p.get("tags", []))
    else:
        result["error"] = "Failed to query OTX for domain"

    malware, resp = _get(f"{cfg.OTX_BASE}/indicators/domain/{domain}/malware", headers=headers)
    if malware:
        result["malware_count"] = malware.get("count", 0)
        for m in malware.get("data", [])[:10]:
            result["malware_samples"].append({
                "hash": m.get("hash", ""),
                "av_name": m.get("detections", {}).get("av", ""),
                "malware_name": m.get("detections", {}).get("name", ""),
                "date": m.get("created", "")[:10],
            })

    urls, resp = _get(f"{cfg.OTX_BASE}/indicators/domain/{domain}/url_list", headers=headers)
    if urls:
        result["url_count"] = urls.get("count", 0)
        for u in urls.get("url_list", [])[:10]:
            result["urls"].append({
                "url": u.get("url", ""),
                "date": u.get("date", "")[:10],
            })

    return result


# ═══════════════════════════════════════════════════════════════════
# AbuseIPDB — Abuse Confidence Score
# ═══════════════════════════════════════════════════════════════════

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """Query AbuseIPDB for abuse confidence score and reports."""
    result = {
        "source": "AbuseIPDB",
        "ip": ip,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "num_distinct_users": 0,
        "last_reported_at": "",
        "is_public": False,
        "is_whitelisted": False,
        "isp": "",
        "domain": "",
        "country_code": "",
        "usage_type": "",
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    if not cfg.ABUSEIPDB_KEY:
        result["error"] = "No AbuseIPDB API key configured"
        result["status"] = SourceStatus.NO_API_KEY
        return result

    headers = {
        "Key": cfg.ABUSEIPDB_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",
    }

    data, resp = _get(f"{cfg.ABUSEIPDB_BASE}/check", headers=headers, params=params)
    if data and "data" in data:
        d = data["data"]
        result["abuse_confidence_score"] = d.get("abuseConfidenceScore", 0)
        result["total_reports"] = d.get("totalReports", 0)
        result["num_distinct_users"] = d.get("numDistinctUsers", 0)
        result["last_reported_at"] = d.get("lastReportedAt", "") or ""
        result["is_public"] = d.get("isPublic", False)
        result["is_whitelisted"] = d.get("isWhitelisted", False)
        result["isp"] = d.get("isp", "")
        result["domain"] = d.get("domain", "")
        result["country_code"] = d.get("countryCode", "")
        result["usage_type"] = d.get("usageType", "")
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query AbuseIPDB ({result['status']})"

    return result


# ═══════════════════════════════════════════════════════════════════
# VirusTotal — Detection Ratio, Community Score
# ═══════════════════════════════════════════════════════════════════

def query_virustotal_ip(ip: str) -> Dict[str, Any]:
    """Query VirusTotal v3 API for IP analysis."""
    result = {
        "source": "VirusTotal",
        "ip": ip,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "last_analysis_stats": {},
        "reputation": 0,
        "tags": [],
        "as_owner": "",
        "asn": 0,
        "country": "",
        "network": "",
        "whois": "",
        "last_modification_date": "",
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    if not cfg.VIRUSTOTAL_KEY:
        result["error"] = "No VirusTotal API key configured"
        result["status"] = SourceStatus.NO_API_KEY
        return result

    headers = {"x-apikey": cfg.VIRUSTOTAL_KEY}
    data, resp = _get(f"{cfg.VIRUSTOTAL_BASE}/ip_addresses/{ip}", headers=headers)

    if data and "data" in data:
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["timeout"] = stats.get("timeout", 0)
        result["last_analysis_stats"] = stats
        result["reputation"] = attrs.get("reputation", 0)
        result["tags"] = attrs.get("tags", [])
        result["as_owner"] = attrs.get("as_owner", "")
        result["asn"] = attrs.get("asn", 0)
        result["country"] = attrs.get("country", "")
        result["network"] = attrs.get("network", "")
        result["whois"] = attrs.get("whois", "")
        result["last_modification_date"] = attrs.get("last_modification_date", "")
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query VirusTotal ({result['status']})"

    return result


def query_virustotal_domain(domain: str) -> Dict[str, Any]:
    """Query VirusTotal v3 API for domain analysis."""
    result = {
        "source": "VirusTotal",
        "domain": domain,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
        "tags": [],
        "registrar": "",
        "creation_date": "",
        "last_modification_date": "",
        "categories": {},
        "last_dns_records": [],
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    if not cfg.VIRUSTOTAL_KEY:
        result["error"] = "No VirusTotal API key configured"
        result["status"] = SourceStatus.NO_API_KEY
        return result

    headers = {"x-apikey": cfg.VIRUSTOTAL_KEY}
    data, resp = _get(f"{cfg.VIRUSTOTAL_BASE}/domains/{domain}", headers=headers)

    if data and "data" in data:
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["reputation"] = attrs.get("reputation", 0)
        result["tags"] = attrs.get("tags", [])
        result["registrar"] = attrs.get("registrar", "")
        result["creation_date"] = attrs.get("creation_date", "")
        result["last_modification_date"] = attrs.get("last_modification_date", "")
        result["categories"] = attrs.get("categories", {})
        result["last_dns_records"] = attrs.get("last_dns_records", [])[:20]
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query VirusTotal for domain ({result['status']})"

    return result


# ═══════════════════════════════════════════════════════════════════
# Shodan — Open Ports, Vulns, Banners
# ═══════════════════════════════════════════════════════════════════

def query_shodan(ip: str) -> Dict[str, Any]:
    """Query Shodan for host information."""
    result = {
        "source": "Shodan",
        "ip": ip,
        "ports": [],
        "vulns": [],
        "os": "",
        "org": "",
        "isp": "",
        "hostnames": [],
        "domains": [],
        "country_code": "",
        "city": "",
        "last_update": "",
        "tags": [],
        "cpes": [],
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    if not cfg.SHODAN_KEY:
        result["error"] = "No Shodan API key configured"
        result["status"] = SourceStatus.NO_API_KEY
        return result

    params = {"key": cfg.SHODAN_KEY}
    data, resp = _get(f"{cfg.SHODAN_BASE}/shodan/host/{ip}", params=params)

    if data:
        result["ports"] = data.get("ports", [])
        result["vulns"] = data.get("vulns", [])
        result["os"] = data.get("os", "") or ""
        result["org"] = data.get("org", "")
        result["isp"] = data.get("isp", "")
        result["hostnames"] = data.get("hostnames", [])
        result["domains"] = data.get("domains", [])
        result["country_code"] = data.get("country_code", "")
        result["city"] = data.get("city", "")
        result["last_update"] = data.get("last_update", "")
        result["tags"] = data.get("tags", [])

        # Extract CPEs from service banners
        for svc in data.get("data", []):
            cpes = svc.get("cpe", [])
            if isinstance(cpes, list):
                result["cpes"].extend(cpes)
            elif isinstance(cpes, str):
                result["cpes"].append(cpes)
        result["cpes"] = list(set(result["cpes"]))[:20]
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query Shodan ({result['status']})"

    return result


# ═══════════════════════════════════════════════════════════════════
# ThreatFox (abuse.ch) — IOC lookups
# ═══════════════════════════════════════════════════════════════════

def query_threatfox(indicator: str, ioc_type: str = "ip:port") -> Dict[str, Any]:
    """Query ThreatFox for IOC associations."""
    result = {
        "source": "ThreatFox",
        "indicator": indicator,
        "ioc_count": 0,
        "iocs": [],
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    payload = {"query": "search_ioc", "search_term": indicator}
    data, resp = _post(cfg.THREATFOX_BASE, json_body=payload)

    if data and data.get("query_status") == "ok":
        for ioc in data.get("data", [])[:15]:
            result["iocs"].append({
                "ioc": ioc.get("ioc", ""),
                "ioc_type": ioc.get("ioc_type", ""),
                "threat_type": ioc.get("threat_type", ""),
                "malware": ioc.get("malware", ""),
                "malware_alias": ioc.get("malware_alias", ""),
                "confidence": ioc.get("confidence_level", 0),
                "first_seen": ioc.get("first_seen_utc", ""),
                "last_seen": ioc.get("last_seen_utc", ""),
                "reporter": ioc.get("reporter", ""),
                "tags": ioc.get("tags", []),
            })
        result["ioc_count"] = len(result["iocs"])
    elif data and data.get("query_status") == "no_result":
        result["ioc_count"] = 0
        result["status"] = SourceStatus.NOT_FOUND
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query ThreatFox ({result['status']})"

    return result


# ═══════════════════════════════════════════════════════════════════
# URLhaus (abuse.ch) — Malicious URL lookups
# ═══════════════════════════════════════════════════════════════════

def query_urlhaus_host(host: str) -> Dict[str, Any]:
    """Query URLhaus for host-based threat data."""
    result = {
        "source": "URLhaus",
        "host": host,
        "is_listed": False,
        "url_count": 0,
        "urls_online": 0,
        "urls_offline": 0,
        "blacklists": {},
        "threat": "",
        "first_seen": "",
        "last_online": "",
        "urls": [],
        "error": None,
        "status": SourceStatus.SUCCESS,
    }

    data, resp = _post(cfg.URLHAUS_BASE + "/host/", data={"host": host})

    if data:
        result["is_listed"] = data.get("query_status") == "ok"
        result["url_count"] = data.get("urls_online", 0) + data.get("urls_offline", 0)
        result["urls_online"] = data.get("urls_online", 0)
        result["urls_offline"] = data.get("urls_offline", 0)
        result["blacklists"] = data.get("blacklists", {})
        result["threat"] = data.get("threat", "")
        result["first_seen"] = data.get("first_seen", "")
        result["last_online"] = data.get("last_online", "")

        for u in data.get("urls", [])[:10]:
            result["urls"].append({
                "url": u.get("url", ""),
                "url_status": u.get("url_status", ""),
                "date_added": u.get("date_added", ""),
                "threat": u.get("threat", ""),
                "tags": u.get("tags", []),
            })
    else:
        if isinstance(resp, int):
            result["status"] = _classify_http_error(resp)
        elif isinstance(resp, str):
            result["status"] = resp
        else:
            result["status"] = SourceStatus.INVALID_RESPONSE
        result["error"] = f"Failed to query URLhaus ({result['status']})"

    return result


# ═══════════════════════════════════════════════════════════════════
# TOR Exit Node List
# ═══════════════════════════════════════════════════════════════════

def check_tor_exit(ip: str) -> bool:
    """Check if IP is a known TOR exit node."""
    try:
        resp = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=cfg.HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            exit_ips = set(resp.text.strip().splitlines())
            return ip in exit_ips
    except requests.RequestException:
        pass
    return False


def get_tor_exit_list() -> set:
    """Fetch the full TOR exit node list."""
    try:
        resp = requests.get(
            "https://check.torproject.org/torbulkexitlist",
            timeout=cfg.HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            return set(resp.text.strip().splitlines())
    except requests.RequestException:
        pass
    return set()
