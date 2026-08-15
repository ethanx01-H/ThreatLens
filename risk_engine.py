"""
Risk Scoring Engine
Multi-signal risk assessment for IP/Domain indicators.
Aggregates scores from all OSINT sources and produces a classification.
"""

from typing import Dict, List, Any, Tuple
from config import (
    WEIGHTS, RISK_THRESHOLDS, HIGH_RISK_PORTS,
    OTX_HIGH_TAGS, OTX_MEDIUM_TAGS, KNOWN_BAD_ASNS,
)


def calculate_ip_risk(
    ipinfo: dict = None,
    otx: dict = None,
    abuseipdb: dict = None,
    vt: dict = None,
    shodan: dict = None,
    threatfox: dict = None,
    urlhaus: dict = None,
    recon: dict = None,
    is_tor: bool = False,
) -> Dict[str, Any]:
    """
    Calculate composite risk score for an IP address.
    Returns score (0-100), classification, and breakdown of signals.
    """
    score = 0
    signals = []
    mitigations = []

    # ─── OTX Pulses ────────────────────────────────────────────
    if otx and not otx.get("error"):
        pulse_count = otx.get("pulse_count", 0)
        pulse_score = min(pulse_count, WEIGHTS["otx_pulse_cap"]) * WEIGHTS["otx_pulses"]
        if pulse_score > 0:
            score += pulse_score
            signals.append({
                "source": "OTX",
                "signal": f"{pulse_count} threat pulse(s) associated",
                "weight": pulse_score,
                "severity": "HIGH" if pulse_count >= 3 else "MEDIUM",
            })

        # Check for high-risk tags
        all_tags = set(t.lower() for t in otx.get("all_tags", []))
        high_tags = all_tags & OTX_HIGH_TAGS
        if high_tags:
            tag_score = len(high_tags) * 8
            score += tag_score
            signals.append({
                "source": "OTX",
                "signal": f"High-risk tags: {', '.join(sorted(high_tags))}",
                "weight": tag_score,
                "severity": "CRITICAL",
            })

        med_tags = all_tags & OTX_MEDIUM_TAGS
        if med_tags:
            tag_score = len(med_tags) * 4
            score += tag_score
            signals.append({
                "source": "OTX",
                "signal": f"Medium-risk tags: {', '.join(sorted(med_tags))}",
                "weight": tag_score,
                "severity": "MEDIUM",
            })

        # Malware associations
        malware_count = otx.get("malware_count", 0)
        if malware_count > 0:
            mal_score = min(malware_count, 5) * 10
            score += mal_score
            signals.append({
                "source": "OTX",
                "signal": f"{malware_count} malware sample(s) associated",
                "weight": mal_score,
                "severity": "CRITICAL",
            })

        # Malicious URLs
        url_count = otx.get("url_count", 0)
        if url_count > 0:
            url_score = min(url_count, 3) * 6
            score += url_score
            signals.append({
                "source": "OTX",
                "signal": f"{url_count} malicious URL(s) hosted",
                "weight": url_score,
                "severity": "HIGH",
            })

    # ─── AbuseIPDB ─────────────────────────────────────────────
    if abuseipdb and not abuseipdb.get("error"):
        confidence = abuseipdb.get("abuse_confidence_score", 0)
        if confidence > 0:
            ab_score = int(confidence * WEIGHTS["abuse_confidence"] / 100)
            score += ab_score
            total_reports = abuseipdb.get("total_reports", 0)
            signals.append({
                "source": "AbuseIPDB",
                "signal": f"Abuse confidence: {confidence}% ({total_reports} reports)",
                "weight": ab_score,
                "severity": "CRITICAL" if confidence >= 80 else "HIGH" if confidence >= 50 else "MEDIUM",
            })

        if abuseipdb.get("is_whitelisted"):
            mitigations.append("IP is whitelisted on AbuseIPDB")

    # ─── VirusTotal ────────────────────────────────────────────
    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious > 0:
            vt_score = min(malicious, WEIGHTS["vt_malicious_cap"]) * WEIGHTS["vt_malicious"]
            score += vt_score
            total_engines = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
            signals.append({
                "source": "VirusTotal",
                "signal": f"{malicious}/{total_engines} engines flagged malicious",
                "weight": vt_score,
                "severity": "CRITICAL" if malicious >= 5 else "HIGH" if malicious >= 2 else "MEDIUM",
            })
        if suspicious > 0:
            sus_score = min(suspicious, 3) * 5
            score += sus_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{suspicious} engine(s) flagged suspicious",
                "weight": sus_score,
                "severity": "MEDIUM",
            })

    # ─── Shodan ────────────────────────────────────────────────
    if shodan and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        if vulns:
            vuln_score = min(len(vulns), WEIGHTS["shodan_vuln_cap"]) * WEIGHTS["shodan_vulns"]
            score += vuln_score
            cve_str = ", ".join(vulns[:5])
            if len(vulns) > 5:
                cve_str += f" (+{len(vulns) - 5} more)"
            signals.append({
                "source": "Shodan",
                "signal": f"{len(vulns)} CVE(s): {cve_str}",
                "weight": vuln_score,
                "severity": "CRITICAL" if len(vulns) >= 5 else "HIGH" if len(vulns) >= 2 else "MEDIUM",
            })

    # ─── ThreatFox ─────────────────────────────────────────────
    if threatfox and not threatfox.get("error"):
        ioc_count = threatfox.get("ioc_count", 0)
        if ioc_count > 0:
            tf_score = min(ioc_count, 3) * WEIGHTS["threatfox_iocs"]
            score += tf_score
            malware_names = set()
            for ioc in threatfox.get("iocs", []):
                if ioc.get("malware"):
                    malware_names.add(ioc["malware"])
            mal_str = ", ".join(sorted(malware_names)[:5]) if malware_names else "unknown"
            signals.append({
                "source": "ThreatFox",
                "signal": f"{ioc_count} IOC(s) — malware: {mal_str}",
                "weight": tf_score,
                "severity": "CRITICAL" if ioc_count >= 3 else "HIGH",
            })

    # ─── URLhaus ───────────────────────────────────────────────
    if urlhaus and not urlhaus.get("error"):
        if urlhaus.get("is_listed"):
            uh_score = WEIGHTS["urlhaus_listed"]
            score += uh_score
            signals.append({
                "source": "URLhaus",
                "signal": f"Listed — {urlhaus.get('url_count', 0)} URL(s), threat: {urlhaus.get('threat', 'N/A')}",
                "weight": uh_score,
                "severity": "HIGH",
            })

    # ─── Port Scan Risk ────────────────────────────────────────
    if recon and recon.get("port_scan") and not recon["port_scan"].get("error"):
        open_ports = recon["port_scan"].get("open_ports", [])
        high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]
        if high_risk:
            port_score = min(len(high_risk), WEIGHTS["high_risk_ports"]) * WEIGHTS["open_ports_risk"]
            score += port_score
            port_desc = ", ".join(f"{p}({HIGH_RISK_PORTS[p]})" for p in high_risk[:5])
            signals.append({
                "source": "Port Scan",
                "signal": f"High-risk ports open: {port_desc}",
                "weight": port_score,
                "severity": "HIGH" if len(high_risk) >= 3 else "MEDIUM",
            })

    # ─── Reverse DNS ───────────────────────────────────────────
    if recon and recon.get("reverse_dns"):
        rdns = recon["reverse_dns"]
        if not rdns.get("has_rdns") and recon.get("port_scan", {}).get("open_ports"):
            rdns_score = WEIGHTS["no_reverse_dns"]
            score += rdns_score
            signals.append({
                "source": "Network",
                "signal": "No reverse DNS (PTR) record — active with open ports",
                "weight": rdns_score,
                "severity": "LOW",
            })

    # ─── ASN Check ─────────────────────────────────────────────
    if ipinfo and not ipinfo.get("error"):
        asn = ipinfo.get("asn", "")
        if asn in KNOWN_BAD_ASNS:
            asn_score = WEIGHTS["known_bad_asn"]
            score += asn_score
            signals.append({
                "source": "IPInfo",
                "signal": f"ASN {asn} ({ipinfo.get('isp', '')}) — known bulletproof hosting",
                "weight": asn_score,
                "severity": "MEDIUM",
            })

    # ─── TOR Exit Node ─────────────────────────────────────────
    if is_tor:
        tor_score = WEIGHTS["tor_exit_node"]
        score += tor_score
        signals.append({
            "source": "TOR",
            "signal": "Known TOR exit node",
            "weight": tor_score,
            "severity": "HIGH",
        })

    # ─── Cap at 100 ────────────────────────────────────────────
    score = min(score, 100)

    # ─── Classification ────────────────────────────────────────
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        classification = "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        classification = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    # ─── Recommended Actions ───────────────────────────────────
    actions = _get_recommended_actions(classification, signals)

    return {
        "score": score,
        "classification": classification,
        "signals": sorted(signals, key=lambda s: s["weight"], reverse=True),
        "mitigations": mitigations,
        "recommended_actions": actions,
        "signal_count": len(signals),
    }


def calculate_domain_risk(
    otx: dict = None,
    vt: dict = None,
    threatfox: dict = None,
    urlhaus: dict = None,
    recon: dict = None,
) -> Dict[str, Any]:
    """Calculate composite risk score for a domain."""
    score = 0
    signals = []
    mitigations = []

    # ─── OTX Pulses ────────────────────────────────────────────
    if otx and not otx.get("error"):
        pulse_count = otx.get("pulse_count", 0)
        if pulse_count > 0:
            pulse_score = min(pulse_count, WEIGHTS["otx_pulse_cap"]) * WEIGHTS["otx_pulses"]
            score += pulse_score
            signals.append({
                "source": "OTX",
                "signal": f"{pulse_count} threat pulse(s) associated",
                "weight": pulse_score,
                "severity": "HIGH" if pulse_count >= 3 else "MEDIUM",
            })

        all_tags = set(t.lower() for t in otx.get("all_tags", []))
        high_tags = all_tags & OTX_HIGH_TAGS
        if high_tags:
            tag_score = len(high_tags) * 8
            score += tag_score
            signals.append({
                "source": "OTX",
                "signal": f"High-risk tags: {', '.join(sorted(high_tags))}",
                "weight": tag_score,
                "severity": "CRITICAL",
            })

        malware_count = otx.get("malware_count", 0)
        if malware_count > 0:
            mal_score = min(malware_count, 5) * 10
            score += mal_score
            signals.append({
                "source": "OTX",
                "signal": f"{malware_count} malware sample(s) associated",
                "weight": mal_score,
                "severity": "CRITICAL",
            })

    # ─── VirusTotal ────────────────────────────────────────────
    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious > 0:
            vt_score = min(malicious, WEIGHTS["vt_malicious_cap"]) * WEIGHTS["vt_malicious"]
            score += vt_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{malicious} engine(s) flagged domain as malicious",
                "weight": vt_score,
                "severity": "CRITICAL" if malicious >= 5 else "HIGH",
            })
        if suspicious > 0:
            sus_score = min(suspicious, 3) * 5
            score += sus_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{suspicious} engine(s) flagged domain as suspicious",
                "weight": sus_score,
                "severity": "MEDIUM",
            })

    # ─── ThreatFox ─────────────────────────────────────────────
    if threatfox and not threatfox.get("error"):
        ioc_count = threatfox.get("ioc_count", 0)
        if ioc_count > 0:
            tf_score = min(ioc_count, 3) * WEIGHTS["threatfox_iocs"]
            score += tf_score
            signals.append({
                "source": "ThreatFox",
                "signal": f"{ioc_count} IOC association(s)",
                "weight": tf_score,
                "severity": "HIGH",
            })

    # ─── URLhaus ───────────────────────────────────────────────
    if urlhaus and not urlhaus.get("error"):
        if urlhaus.get("is_listed"):
            uh_score = WEIGHTS["urlhaus_listed"]
            score += uh_score
            signals.append({
                "source": "URLhaus",
                "signal": f"Listed on URLhaus — {urlhaus.get('url_count', 0)} malicious URL(s)",
                "weight": uh_score,
                "severity": "HIGH",
            })

    # ─── DNS / Network ─────────────────────────────────────────
    if recon and recon.get("dns"):
        dns = recon["dns"]
        if dns.get("error") or not dns.get("a_records"):
            if not dns.get("a_records"):
                signals.append({
                    "source": "DNS",
                    "signal": "No A records — domain may be parked or inactive",
                    "weight": 0,
                    "severity": "INFO",
                })

    if recon and recon.get("port_scan") and not recon["port_scan"].get("error"):
        open_ports = recon["port_scan"].get("open_ports", [])
        high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]
        if high_risk:
            port_score = min(len(high_risk), WEIGHTS["high_risk_ports"]) * WEIGHTS["open_ports_risk"]
            score += port_score
            port_desc = ", ".join(f"{p}({HIGH_RISK_PORTS[p]})" for p in high_risk[:5])
            signals.append({
                "source": "Port Scan",
                "signal": f"High-risk ports open: {port_desc}",
                "weight": port_score,
                "severity": "HIGH" if len(high_risk) >= 3 else "MEDIUM",
            })

    # ─── WHOIS Age Check ───────────────────────────────────────
    if recon and recon.get("whois") and not recon["whois"].get("error"):
        whois = recon["whois"]
        creation = whois.get("creation_date", "")
        if creation:
            try:
                from datetime import datetime
                created = datetime.strptime(creation[:10], "%Y-%m-%d")
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    score += 15
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered only {age_days} days ago — newly created",
                        "weight": 15,
                        "severity": "HIGH",
                    })
                elif age_days < 90:
                    score += 5
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered {age_days} days ago — relatively new",
                        "weight": 5,
                        "severity": "LOW",
                    })
            except (ValueError, TypeError):
                pass

    # ─── Cap and Classify ──────────────────────────────────────
    score = min(score, 100)

    if score >= RISK_THRESHOLDS["CRITICAL"]:
        classification = "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        classification = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    actions = _get_recommended_actions(classification, signals)

    return {
        "score": score,
        "classification": classification,
        "signals": sorted(signals, key=lambda s: s["weight"], reverse=True),
        "mitigations": mitigations,
        "recommended_actions": actions,
        "signal_count": len(signals),
    }


def _get_recommended_actions(classification: str, signals: list) -> List[str]:
    """Generate recommended actions based on risk classification."""
    actions = []

    has_c2 = any("c2" in s.get("signal", "").lower() for s in signals)
    has_malware = any("malware" in s.get("signal", "").lower() for s in signals)
    has_ports = any("port" in s.get("source", "").lower() for s in signals)
    has_brute = any("brute" in s.get("signal", "").lower() for s in signals)

    if classification == "CRITICAL":
        actions.append("IMMEDIATE: Block IP/domain at perimeter firewall and WAF")
        actions.append("IMMEDIATE: Search SIEM for all historical connections to this indicator")
        actions.append("IMMEDIATE: Isolate any hosts that communicated with this indicator")
        actions.append("ESCALATE: Notify SOC Manager and initiate incident response")
        if has_c2:
            actions.append("CRITICAL: Check for C2 beaconing patterns in network logs")
        if has_malware:
            actions.append("CRITICAL: Run endpoint scans on all connected hosts")
        actions.append("Create SIEM detection rule for ongoing monitoring")

    elif classification == "HIGH":
        actions.append("Block IP/domain at firewall (after business impact review)")
        actions.append("Search SIEM for connections in the last 30 days")
        actions.append("Flag for threat hunting — check lateral movement indicators")
        actions.append("Add to threat intelligence watchlist for monitoring")
        if has_brute:
            actions.append("Check for compromised credentials from brute force activity")

    elif classification == "MEDIUM":
        actions.append("Add to monitoring watchlist (SIEM alert rule)")
        actions.append("Review traffic patterns to/from this indicator")
        actions.append("Correlate with other IOCs from the same campaign/pulse")
        actions.append("Schedule follow-up review in 7 days")

    else:  # LOW
        actions.append("Log for reference — no immediate action required")
        actions.append("Include in periodic threat intelligence review")
        if has_ports:
            actions.append("Note open ports — may be legitimate service")

    return actions


def get_risk_badge(classification: str) -> str:
    """Return a text-based risk badge for terminal display."""
    badges = {
        "CRITICAL": "\033[97;41m CRITICAL \033[0m",
        "HIGH":     "\033[97;43m   HIGH   \033[0m",
        "MEDIUM":   "\033[30;43m  MEDIUM  \033[0m",
        "LOW":      "\033[97;42m   LOW    \033[0m",
    }
    return badges.get(classification, classification)


def get_risk_color_hex(classification: str) -> str:
    """Return hex color for DOCX report styling."""
    colors = {
        "CRITICAL": "E74C3C",
        "HIGH":     "E67E22",
        "MEDIUM":   "F1C40F",
        "LOW":      "27AE60",
    }
    return colors.get(classification, "95A5A6")
