"""Generate a sample ThreatLens report using the new IC template style."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report_gen import generate_report

# Mock data simulating a real investigation
sample_data = {
    "target": "185.220.101.34",
    "target_type": "ip",
    "risk_assessment": {
        "score": 72,
        "classification": "HIGH",
        "signal_count": 5,
        "is_known_good": False,
        "signals": [
            {"source": "VirusTotal", "signal": "5/72 engines flagged malicious",
             "weight": 40, "severity": "HIGH", "tier": 1,
             "interpretation": "Strong — direct engine verdict"},
            {"source": "AbuseIPDB", "signal": "Abuse confidence: 89% (234 reports)",
             "weight": 30, "severity": "CRITICAL", "tier": 1,
             "interpretation": "Strong — high abuse confidence from multiple reporters"},
            {"source": "ThreatFox", "signal": "2 direct IOC(s) — malware: Cobalt Strike",
             "weight": 30, "severity": "HIGH", "tier": 1,
             "interpretation": "Strong — direct IOC association from abuse.ch"},
            {"source": "OTX", "signal": "4 threat pulse(s) with high-risk tags: c2, malware",
             "weight": 30, "severity": "HIGH", "tier": 1,
             "interpretation": "Strong — pulses directly classify as malicious"},
            {"source": "Shodan", "signal": "3 CVE(s): CVE-2021-44228, CVE-2023-23397",
             "weight": 15, "severity": "MEDIUM", "tier": 2,
             "interpretation": "Moderate — vulnerable but not necessarily malicious"},
        ],
        "mitigations": [],
        "recommended_actions": [
            "Block IP 185.220.101.34 at perimeter firewall immediately",
            "Check proxy/firewall logs for historical connections to this IP",
            "Scan endpoints for Cobalt Strike beacon indicators",
            "Report to hosting abuse contact: abuse@hosting-provider.com",
            "Add to SIEM watchlist for 90-day monitoring",
        ],
        "source_statuses": {
            "IPInfo": "SUCCESS", "OTX": "SUCCESS", "AbuseIPDB": "SUCCESS",
            "VirusTotal": "SUCCESS", "Shodan": "SUCCESS",
            "ThreatFox": "SUCCESS", "URLhaus": "NOT_FOUND",
        },
        "not_checked_sources": [],
        "coverage": {"checked": 6, "total": 7, "percentage": 85.7},
        "confidence": 85,
    },
    "ipinfo": {
        "ip": "185.220.101.34", "hostname": "tor-exit.example.com",
        "city": "Frankfurt", "region": "Hesse", "country": "DE",
        "loc": "50.1109,8.6821", "org": "AS24940 Hetzner Online GmbH",
        "asn": "AS24940", "isp": "Hetzner Online GmbH",
        "timezone": "Europe/Berlin", "is_cloud": True, "cloud_provider": "Hetzner",
        "error": None,
    },
    "otx": {
        "source": "AlienVault OTX", "pulse_count": 4,
        "pulses": [
            {"name": "Cobalt Strike C2 Infrastructure", "created": "2025-12-01",
             "tags": ["c2", "cobalt-strike", "malware"]},
            {"name": "Known Tor Exit Nodes", "created": "2025-11-15",
             "tags": ["tor", "proxy"]},
            {"name": "APT29 Infrastructure", "created": "2025-10-20",
             "tags": ["apt", "russia"]},
            {"name": "Brute Force SSH Sources", "created": "2025-09-05",
             "tags": ["brute-force", "ssh"]},
        ],
        "malware_count": 2,
        "malware_samples": [
            {"hash": "a1b2c3d4e5f6789012345678901234567890abcd",
             "av_name": "Trojan.GenericKD", "malware_name": "Cobalt Strike",
             "date": "2025-12-01"},
        ],
        "url_count": 1,
        "all_tags": ["c2", "cobalt-strike", "malware", "tor", "proxy", "apt", "brute-force"],
        "error": None,
    },
    "abuseipdb": {
        "source": "AbuseIPDB", "abuse_confidence_score": 89,
        "total_reports": 234, "num_distinct_users": 47,
        "last_reported_at": "2026-08-15T09:23:11+00:00",
        "is_public": True, "is_whitelisted": False,
        "isp": "Hetzner Online GmbH", "domain": "hetzner.com",
        "country_code": "DE", "usage_type": "Data Center/Web Hosting",
        "error": None, "status": "SUCCESS",
    },
    "vt": {
        "source": "VirusTotal", "malicious": 5, "suspicious": 2,
        "harmless": 58, "undetected": 7, "timeout": 0,
        "reputation": -45, "tags": ["tor", "malware"],
        "as_owner": "Hetzner Online GmbH", "asn": 24940,
        "country": "DE", "network": "185.220.96.0/19",
        "error": None, "status": "SUCCESS",
    },
    "shodan": {
        "source": "Shodan", "ports": [22, 80, 443, 8080],
        "os": "Linux", "org": "Hetzner Online GmbH",
        "vulns": ["CVE-2021-44228", "CVE-2023-23397", "CVE-2022-22965"],
        "error": None,
    },
    "threatfox": {
        "source": "ThreatFox", "ioc_count": 2,
        "iocs": [
            {"ioc": "185.220.101.34:443", "threat_type": "C2",
             "malware": "Cobalt Strike", "confidence": 90},
            {"ioc": "185.220.101.34:8080", "threat_type": "C2",
             "malware": "Cobalt Strike", "confidence": 85},
        ],
        "error": None,
    },
    "urlhaus": {"source": "URLhaus", "is_listed": False, "error": None},
    "recon": {
        "reverse_dns": {"ip": "185.220.101.34", "hostnames": ["tor-exit-node.example.com"], "has_rdns": True},
        "port_scan": {
            "ip": "185.220.101.34", "open_ports": [22, 80, 443, 8080],
            "service_banners": {22: "SSH-2.0-OpenSSH_8.9", 80: "nginx/1.18.0"},
            "scan_time": 3.2, "error": None,
        },
        "whois": {"registrar": "Hetzner Online GmbH", "creation_date": "2020-03-15"},
    },
}

output = generate_report(
    target="185.220.101.34",
    target_type="ip",
    risk_assessment=sample_data["risk_assessment"],
    ipinfo=sample_data["ipinfo"],
    otx=sample_data["otx"],
    abuseipdb=sample_data["abuseipdb"],
    vt=sample_data["vt"],
    shodan=sample_data["shodan"],
    threatfox=sample_data["threatfox"],
    urlhaus=sample_data["urlhaus"],
    recon=sample_data["recon"],
    output_path="Sample_ThreatLens_Report.docx",
    analyst="Threat Intel Analyst",
    classification="CONFIDENTIAL",
)

print(f"Sample report generated: {output}")
