"""
Risk Scoring Engine v2.0
Multi-signal risk assessment with tiered signal strength,
whitelist handling, and three-state source verification.

Signal Tiers:
  TIER 1 (STRONG):   Direct malicious verdict — VT detections, AbuseIPDB high,
                      OTX pulses with malicious tags, ThreatFox C2/malware IOCs
  TIER 2 (MODERATE): OTX pulses without strong tags, URLhaus listing, Shodan CVEs,
                      new domain age, high-risk open ports
  TIER 3 (WEAK):     OTX malware associations (passive), passive DNS links,
                      no reverse DNS, medium-risk tags

Three States per Source:
  MALICIOUS  — source confirms bad
  BENIGN     — source confirms clean
  NOT CHECKED — source failed, no key, or no data
"""

from typing import Dict, List, Any
from config import (
    WEIGHTS, RISK_THRESHOLDS, HIGH_RISK_PORTS,
    OTX_HIGH_TAGS, OTX_MEDIUM_TAGS, KNOWN_BAD_ASNS,
    KNOWN_GOOD_ASNS, KNOWN_GOOD_DOMAINS,
)


def _is_known_good(target: str, ipinfo: dict = None, recon: dict = None) -> tuple:
    """Check if target is a known-good domain/org. Returns (is_good, reason)."""
    target_lower = target.lower().strip(".")

    # Check known-good domain list
    for good_domain in KNOWN_GOOD_DOMAINS:
        if target_lower == good_domain or target_lower.endswith("." + good_domain):
            return True, f"Known legitimate domain ({good_domain})"

    # Check known-good ASN
    if ipinfo and not ipinfo.get("error"):
        asn = ipinfo.get("asn", "")
        org = ipinfo.get("isp", "").lower()
        if asn in KNOWN_GOOD_ASNS:
            return True, f"Known legitimate ASN ({asn} — {ipinfo.get('isp', '')})"

        # Check org name patterns
        good_orgs = ["google", "microsoft", "amazon", "cloudflare", "apple",
                     "facebook", "meta", "akamai", "fastly", "netflix"]
        for g in good_orgs:
            if g in org:
                return True, f"Known legitimate organization ({ipinfo.get('isp', '')})"

    return False, ""


def _get_source_status(source_data: dict) -> str:
    """Determine detailed source status using the status field from api_sources.

    Returns one of: SUCCESS, NOT_FOUND, NO_API_KEY, RATE_LIMITED,
    UNAUTHORIZED, FORBIDDEN, TIMEOUT, SERVER_ERROR, NETWORK_ERROR,
    INVALID_RESPONSE, NOT CHECKED
    """
    if source_data is None:
        return "NOT CHECKED"
    # Use the new status field if available
    status = source_data.get("status")
    if status and status != "SUCCESS":
        return status
    if source_data.get("error"):
        # Fallback: try to infer from error message
        err = source_data["error"].lower()
        if "no api key" in err or "no_api_key" in err:
            return "NO_API_KEY"
        if "rate" in err:
            return "RATE_LIMITED"
        if "timeout" in err:
            return "TIMEOUT"
        if "unauthorized" in err or "401" in err:
            return "UNAUTHORIZED"
        if "forbidden" in err or "403" in err:
            return "FORBIDDEN"
        return "NOT CHECKED"
    return "SUCCESS"


def _is_source_checked(status: str) -> bool:
    """Return True if the source actually returned useful data (not an error)."""
    return status == "SUCCESS" or status == "NOT_FOUND"


def _get_not_checked_sources(ipinfo=None, otx=None, abuseipdb=None, vt=None,
                              shodan=None, threatfox=None, urlhaus=None) -> List[str]:
    """Return list of sources that were NOT checked (had errors, not just empty)."""
    not_checked = []
    sources = {
        "VirusTotal": vt,
        "AbuseIPDB": abuseipdb,
        "Shodan": shodan,
        "ThreatFox": threatfox,
        "URLhaus": urlhaus,
        "OTX": otx,
        "IPInfo": ipinfo,
    }
    for name, data in sources.items():
        status = _get_source_status(data)
        if not _is_source_checked(status):
            not_checked.append(f"{name} ({status})")
    return not_checked


def _calculate_coverage(source_statuses: dict) -> tuple:
    """Calculate source coverage as (checked, total) and percentage.

    Returns (checked_count, total_count, percentage).
    """
    total = len(source_statuses)
    if total == 0:
        return 0, 0, 0.0
    checked = sum(1 for s in source_statuses.values() if _is_source_checked(s))
    return checked, total, round((checked / total) * 100, 1)


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
    Uses tiered signal strength and whitelist handling.
    """
    score = 0
    signals = []
    mitigations = []
    source_statuses = {}

    # ─── Check if known-good first ─────────────────────────────
    is_good, good_reason = _is_known_good("", ipinfo=ipinfo, recon=recon)

    # ─── Source Status Tracking ────────────────────────────────
    source_statuses["IPInfo"] = _get_source_status(ipinfo) if ipinfo else "NOT CHECKED"
    source_statuses["OTX"] = _get_source_status(otx)
    source_statuses["AbuseIPDB"] = _get_source_status(abuseipdb)
    source_statuses["VirusTotal"] = _get_source_status(vt)
    source_statuses["Shodan"] = _get_source_status(shodan)
    source_statuses["ThreatFox"] = _get_source_status(threatfox)
    source_statuses["URLhaus"] = _get_source_status(urlhaus)

    # ═══════════════════════════════════════════════════════════
    # TIER 1: STRONG SIGNALS (direct malicious verdict)
    # ═══════════════════════════════════════════════════════════

    # ─── VirusTotal Detections (TIER 1 — STRONG) ──────────────
    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious > 0:
            vt_score = min(malicious, 10) * 8  # 8 per engine, cap 10
            score += vt_score
            total = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
            signals.append({
                "source": "VirusTotal",
                "signal": f"{malicious}/{total} engines flagged malicious",
                "weight": vt_score,
                "severity": "CRITICAL" if malicious >= 8 else "HIGH" if malicious >= 3 else "MEDIUM",
                "tier": 1,
                "interpretation": "Strong — direct engine verdict",
            })
        if suspicious > 0 and malicious == 0:
            sus_score = min(suspicious, 5) * 3
            score += sus_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{suspicious} engine(s) flagged suspicious (no malicious)",
                "weight": sus_score,
                "severity": "MEDIUM",
                "tier": 2,
                "interpretation": "Moderate — suspicious but not confirmed",
            })

    # ─── AbuseIPDB (TIER 1 when high, TIER 2 when moderate) ──
    if abuseipdb and not abuseipdb.get("error"):
        confidence = abuseipdb.get("abuse_confidence_score", 0)
        total_reports = abuseipdb.get("total_reports", 0)

        if confidence >= 75:
            ab_score = 30
            score += ab_score
            signals.append({
                "source": "AbuseIPDB",
                "signal": f"Abuse confidence: {confidence}% ({total_reports} reports)",
                "weight": ab_score,
                "severity": "CRITICAL",
                "tier": 1,
                "interpretation": "Strong — high abuse confidence from multiple reporters",
            })
        elif confidence >= 40:
            ab_score = 15
            score += ab_score
            signals.append({
                "source": "AbuseIPDB",
                "signal": f"Abuse confidence: {confidence}% ({total_reports} reports)",
                "weight": ab_score,
                "severity": "HIGH",
                "tier": 2,
                "interpretation": "Moderate — some abuse reports",
            })
        elif confidence > 0:
            ab_score = 5
            score += ab_score
            signals.append({
                "source": "AbuseIPDB",
                "signal": f"Abuse confidence: {confidence}% ({total_reports} reports)",
                "weight": ab_score,
                "severity": "LOW",
                "tier": 3,
                "interpretation": "Weak — low confidence, few reports",
            })

        if abuseipdb.get("is_whitelisted"):
            mitigations.append("IP is whitelisted on AbuseIPDB")
            score = max(0, score - 15)

    # ─── ThreatFox IOCs (TIER 1 — direct C2/malware link) ─────
    if threatfox and not threatfox.get("error"):
        ioc_count = threatfox.get("ioc_count", 0)
        if ioc_count > 0:
            malware_names = set()
            for ioc in threatfox.get("iocs", []):
                if ioc.get("malware"):
                    malware_names.add(ioc["malware"])
            mal_str = ", ".join(sorted(malware_names)[:5]) if malware_names else "unknown"

            tf_score = min(ioc_count, 3) * 15
            score += tf_score
            signals.append({
                "source": "ThreatFox",
                "signal": f"{ioc_count} direct IOC(s) — malware: {mal_str}",
                "weight": tf_score,
                "severity": "CRITICAL" if ioc_count >= 3 else "HIGH",
                "tier": 1,
                "interpretation": "Strong — direct IOC association from abuse.ch",
            })

    # ─── URLhaus (TIER 1 — direct malicious URL hosting) ──────
    if urlhaus and not urlhaus.get("error"):
        if urlhaus.get("is_listed"):
            uh_score = 25
            score += uh_score
            signals.append({
                "source": "URLhaus",
                "signal": f"Listed — {urlhaus.get('url_count', 0)} URL(s), threat: {urlhaus.get('threat', 'N/A')}",
                "weight": uh_score,
                "severity": "HIGH",
                "tier": 1,
                "interpretation": "Strong — actively hosting malicious URLs",
            })

    # ═══════════════════════════════════════════════════════════
    # TIER 2: MODERATE SIGNALS
    # ═══════════════════════════════════════════════════════════

    # ─── OTX Pulses (TIER 2 — community threat intel) ──────────
    if otx and not otx.get("error"):
        pulse_count = otx.get("pulse_count", 0)
        if pulse_count > 0:
            # Check pulse tags for strength
            all_tags = set(t.lower() for t in otx.get("all_tags", []))
            high_tags = all_tags & OTX_HIGH_TAGS

            if high_tags:
                # Pulses with strong malicious tags = TIER 1
                tag_score = min(len(high_tags), 5) * 10
                score += tag_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{pulse_count} pulse(s) with high-risk tags: {', '.join(sorted(high_tags)[:5])}",
                    "weight": tag_score,
                    "severity": "CRITICAL" if len(high_tags) >= 3 else "HIGH",
                    "tier": 1,
                    "interpretation": "Strong — pulses directly classify as malicious",
                })
            else:
                # Pulses without strong tags = TIER 2
                pulse_score = min(pulse_count, 3) * 8
                score += pulse_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{pulse_count} threat pulse(s) associated (no high-risk tags)",
                    "weight": pulse_score,
                    "severity": "MEDIUM",
                    "tier": 2,
                    "interpretation": "Moderate — community mentions without direct malicious classification",
                })

            # Medium-risk tags
            med_tags = all_tags & OTX_MEDIUM_TAGS
            if med_tags:
                tag_score = min(len(med_tags), 3) * 3
                score += tag_score
                signals.append({
                    "source": "OTX",
                    "signal": f"Medium-risk tags: {', '.join(sorted(med_tags)[:5])}",
                    "weight": tag_score,
                    "severity": "MEDIUM",
                    "tier": 2,
                    "interpretation": "Moderate — associated with suspicious activity",
                })

    # ─── Shodan CVEs (TIER 2 — vulnerable but not malicious) ──
    if shodan and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        if vulns:
            vuln_score = min(len(vulns), 5) * 5
            score += vuln_score
            cve_str = ", ".join(vulns[:5])
            if len(vulns) > 5:
                cve_str += f" (+{len(vulns) - 5} more)"
            signals.append({
                "source": "Shodan",
                "signal": f"{len(vulns)} CVE(s): {cve_str}",
                "weight": vuln_score,
                "severity": "HIGH" if len(vulns) >= 5 else "MEDIUM",
                "tier": 2,
                "interpretation": "Moderate — vulnerable but not necessarily malicious",
            })

    # ─── Port Scan (TIER 2) ───────────────────────────────────
    if recon and recon.get("port_scan") and not recon["port_scan"].get("error"):
        open_ports = recon["port_scan"].get("open_ports", [])
        high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]
        if high_risk and not is_good:
            port_score = min(len(high_risk), 3) * 4
            score += port_score
            port_desc = ", ".join(f"{p}({HIGH_RISK_PORTS[p]})" for p in high_risk[:5])
            signals.append({
                "source": "Port Scan",
                "signal": f"High-risk ports open: {port_desc}",
                "weight": port_score,
                "severity": "HIGH" if len(high_risk) >= 3 else "MEDIUM",
                "tier": 2,
                "interpretation": "Moderate — high-risk services exposed",
            })

    # ─── WHOIS Age (TIER 2) ───────────────────────────────────
    if recon and recon.get("whois") and not recon["whois"].get("error"):
        whois = recon["whois"]
        creation = whois.get("creation_date", "")
        if creation:
            try:
                from datetime import datetime
                created = datetime.strptime(creation[:10], "%Y-%m-%d")
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    score += 12
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered only {age_days} days ago — newly created",
                        "weight": 12,
                        "severity": "HIGH",
                        "tier": 2,
                        "interpretation": "Moderate — newly registered domains are higher risk",
                    })
                elif age_days < 90:
                    score += 4
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered {age_days} days ago — relatively new",
                        "weight": 4,
                        "severity": "LOW",
                        "tier": 3,
                        "interpretation": "Weak — newer domain, slightly elevated risk",
                    })
            except (ValueError, TypeError):
                pass

    # ═══════════════════════════════════════════════════════════
    # TIER 3: WEAK / CONTEXTUAL SIGNALS
    # ═══════════════════════════════════════════════════════════

    # ─── OTX Malware Associations (TIER 3 — WEAK) ─────────────
    # These are passive associations, NOT direct malicious verdicts.
    # A domain like google.com can have malware associations because
    # malware communicates through it, not because it IS malware.
    if otx and not otx.get("error"):
        malware_count = otx.get("malware_count", 0)
        if malware_count > 0 and otx.get("pulse_count", 0) == 0:
            # Only count if no pulses (pulses already scored above)
            mal_score = min(malware_count, 5) * 2  # Max +10, was +50
            if is_good:
                mal_score = 0  # Suppress entirely for known-good domains
                signals.append({
                    "source": "OTX",
                    "signal": f"{malware_count} malware sample(s) associated (contextual only)",
                    "weight": 0,
                    "severity": "INFO",
                    "tier": 3,
                    "interpretation": "Contextual — passive association, not a direct verdict. "
                                      "Malware may communicate through this infrastructure without "
                                      "the infrastructure itself being malicious.",
                })
            else:
                score += mal_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{malware_count} malware sample(s) associated (passive)",
                    "weight": mal_score,
                    "severity": "MEDIUM",
                    "tier": 3,
                    "interpretation": "Weak — passive association. Samples may communicate through "
                                      "this IP/domain without it being the source of malware.",
                })

        # OTX URLs (TIER 3 — contextual)
        url_count = otx.get("url_count", 0)
        if url_count > 0:
            url_score = min(url_count, 3) * 3  # Was 6, now 3
            if is_good:
                url_score = 0
            if url_score > 0:
                score += url_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{url_count} malicious URL(s) historically observed",
                    "weight": url_score,
                    "severity": "MEDIUM",
                    "tier": 3,
                    "interpretation": "Weak — historical URL observation, may be incidental",
                })

    # ─── No Reverse DNS (TIER 3) ──────────────────────────────
    if recon and recon.get("reverse_dns"):
        rdns = recon["reverse_dns"]
        if not rdns.get("has_rdns") and recon.get("port_scan", {}).get("open_ports"):
            if not is_good:
                rdns_score = 3  # Was 5, now 3
                score += rdns_score
                signals.append({
                    "source": "Network",
                    "signal": "No reverse DNS (PTR) record — active with open ports",
                    "weight": rdns_score,
                    "severity": "LOW",
                    "tier": 3,
                    "interpretation": "Weak — no PTR record on an active host",
                })

    # ─── ASN Check (TIER 3 — contextual) ──────────────────────
    if ipinfo and not ipinfo.get("error"):
        asn = ipinfo.get("asn", "")
        if asn in KNOWN_BAD_ASNS and not is_good:
            asn_score = 6  # Was 10, now 6
            score += asn_score
            signals.append({
                "source": "IPInfo",
                "signal": f"ASN {asn} ({ipinfo.get('isp', '')}) — known bulletproof hosting",
                "weight": asn_score,
                "severity": "MEDIUM",
                "tier": 3,
                "interpretation": "Contextual — hosting provider associated with abuse (but hosts legitimate users too)",
            })

    # ─── TOR Exit Node (TIER 1 — strong) ──────────────────────
    if is_tor:
        tor_score = 20
        score += tor_score
        signals.append({
            "source": "TOR",
            "signal": "Known TOR exit node",
            "weight": tor_score,
            "severity": "HIGH",
            "tier": 1,
            "interpretation": "Strong — active TOR exit node",
        })

    # ═══════════════════════════════════════════════════════════
    # NEGATIVE SCORING: Whitelist / Known-Good adjustments
    # ═══════════════════════════════════════════════════════════

    if is_good:
        mitigations.append(f"Known-good indicator: {good_reason}")
        # Don't cap the score at 25. Instead, reduce only weak/contextual signals.
        # Strong direct malicious evidence (VT detections, ThreatFox IOC, URLhaus)
        # should still count even for known-good domains.
        # Zero out TIER 3 (weak/contextual) signals for known-good targets.
        weak_reduction = 0
        filtered_signals = []
        for sig in signals:
            if sig.get("tier", 3) == 3 and sig["weight"] > 0:
                weak_reduction += sig["weight"]
                # Keep the signal but with weight 0 (informational)
                sig_copy = dict(sig)
                sig_copy["weight"] = 0
                sig_copy["severity"] = "INFO"
                sig_copy["interpretation"] = (
                    "Suppressed — known-good indicator, weak contextual signal"
                )
                filtered_signals.append(sig_copy)
            else:
                filtered_signals.append(sig)
        signals = filtered_signals
        score = max(0, score - weak_reduction)
        if weak_reduction > 0:
            mitigations.append(
                f"Reduced {weak_reduction} points from weak/contextual signals "
                f"due to known-good status (strong evidence preserved)"
            )

    # ─── AbuseIPDB zero reports on known infrastructure ────────
    if abuseipdb and not abuseipdb.get("error"):
        if abuseipdb.get("abuse_confidence_score", 0) == 0 and abuseipdb.get("total_reports", 0) == 0:
            mitigations.append("AbuseIPDB: 0 reports, 0% confidence — no abuse reports")

    # ─── VirusTotal clean ──────────────────────────────────────
    if vt and not vt.get("error"):
        if vt.get("malicious", 0) == 0 and vt.get("suspicious", 0) == 0:
            total = vt.get("harmless", 0) + vt.get("undetected", 0)
            if total > 0:
                mitigations.append(f"VirusTotal: 0/{total} detections — clean")

    # ─── Floor at 0 ────────────────────────────────────────────
    score = max(0, score)
    score = min(score, 100)

    # ─── Coverage and Confidence ───────────────────────────────
    checked_count, total_count, coverage_pct = _calculate_coverage(source_statuses)

    # ─── Classification ────────────────────────────────────────
    # If most sources are NOT CHECKED, verdict should be UNKNOWN not LOW
    UNKNOWN_THRESHOLD = 40  # below this coverage %, verdict is UNKNOWN
    if coverage_pct < UNKNOWN_THRESHOLD and not signals:
        classification = "UNKNOWN"
    elif score >= RISK_THRESHOLDS["CRITICAL"]:
        classification = "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        classification = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    # ─── Not-checked sources ───────────────────────────────────
    not_checked = _get_not_checked_sources(
        ipinfo=ipinfo, otx=otx, abuseipdb=abuseipdb,
        vt=vt, shodan=shodan, threatfox=threatfox, urlhaus=urlhaus,
    )

    # ─── Recommended Actions ───────────────────────────────────
    actions = _get_recommended_actions(classification, signals, is_good)

    return {
        "score": score,
        "classification": classification,
        "signals": sorted(signals, key=lambda s: s["weight"], reverse=True),
        "mitigations": mitigations,
        "recommended_actions": actions,
        "signal_count": len(signals),
        "source_statuses": source_statuses,
        "not_checked_sources": not_checked,
        "is_known_good": is_good,
        "known_good_reason": good_reason,
        "coverage": {
            "checked": checked_count,
            "total": total_count,
            "percentage": coverage_pct,
        },
        "confidence": coverage_pct,  # confidence = coverage for now
    }


def calculate_domain_risk(
    domain: str = "",
    otx: dict = None,
    vt: dict = None,
    threatfox: dict = None,
    urlhaus: dict = None,
    recon: dict = None,
) -> Dict[str, Any]:
    """Calculate composite risk score for a domain with tiered signals."""
    score = 0
    signals = []
    mitigations = []
    source_statuses = {}

    # ─── Check if known-good first ─────────────────────────────
    is_good, good_reason = _is_known_good(domain)

    # ─── Source Status Tracking ────────────────────────────────
    source_statuses["OTX"] = _get_source_status(otx)
    source_statuses["VirusTotal"] = _get_source_status(vt)
    source_statuses["ThreatFox"] = _get_source_status(threatfox)
    source_statuses["URLhaus"] = _get_source_status(urlhaus)

    # ═══ TIER 1: STRONG ═══════════════════════════════════════

    if vt and not vt.get("error"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious > 0:
            vt_score = min(malicious, 10) * 8
            score += vt_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{malicious} engine(s) flagged domain as malicious",
                "weight": vt_score,
                "severity": "CRITICAL" if malicious >= 8 else "HIGH" if malicious >= 3 else "MEDIUM",
                "tier": 1,
                "interpretation": "Strong — direct engine verdict",
            })
        if suspicious > 0 and malicious == 0:
            sus_score = min(suspicious, 5) * 3
            score += sus_score
            signals.append({
                "source": "VirusTotal",
                "signal": f"{suspicious} engine(s) flagged domain as suspicious",
                "weight": sus_score,
                "severity": "MEDIUM",
                "tier": 2,
                "interpretation": "Moderate — suspicious but not confirmed",
            })

    if threatfox and not threatfox.get("error"):
        ioc_count = threatfox.get("ioc_count", 0)
        if ioc_count > 0:
            tf_score = min(ioc_count, 3) * 15
            score += tf_score
            signals.append({
                "source": "ThreatFox",
                "signal": f"{ioc_count} direct IOC association(s)",
                "weight": tf_score,
                "severity": "CRITICAL" if ioc_count >= 3 else "HIGH",
                "tier": 1,
                "interpretation": "Strong — direct IOC from abuse.ch",
            })

    if urlhaus and not urlhaus.get("error"):
        if urlhaus.get("is_listed"):
            uh_score = 25
            score += uh_score
            signals.append({
                "source": "URLhaus",
                "signal": f"Listed on URLhaus — {urlhaus.get('url_count', 0)} malicious URL(s)",
                "weight": uh_score,
                "severity": "HIGH",
                "tier": 1,
                "interpretation": "Strong — actively hosting malicious URLs",
            })

    # ═══ TIER 2: MODERATE ═════════════════════════════════════

    if otx and not otx.get("error"):
        pulse_count = otx.get("pulse_count", 0)
        if pulse_count > 0:
            all_tags = set(t.lower() for t in otx.get("all_tags", []))
            high_tags = all_tags & OTX_HIGH_TAGS
            if high_tags:
                tag_score = min(len(high_tags), 5) * 10
                score += tag_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{pulse_count} pulse(s) with high-risk tags: {', '.join(sorted(high_tags)[:5])}",
                    "weight": tag_score,
                    "severity": "CRITICAL" if len(high_tags) >= 3 else "HIGH",
                    "tier": 1,
                    "interpretation": "Strong — pulses directly classify as malicious",
                })
            else:
                pulse_score = min(pulse_count, 3) * 8
                score += pulse_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{pulse_count} threat pulse(s) associated (no high-risk tags)",
                    "weight": pulse_score,
                    "severity": "MEDIUM",
                    "tier": 2,
                    "interpretation": "Moderate — community mentions",
                })

    # Port scan
    if recon and recon.get("port_scan") and not recon["port_scan"].get("error"):
        open_ports = recon["port_scan"].get("open_ports", [])
        high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]
        if high_risk and not is_good:
            port_score = min(len(high_risk), 3) * 4
            score += port_score
            port_desc = ", ".join(f"{p}({HIGH_RISK_PORTS[p]})" for p in high_risk[:5])
            signals.append({
                "source": "Port Scan",
                "signal": f"High-risk ports open: {port_desc}",
                "weight": port_score,
                "severity": "HIGH" if len(high_risk) >= 3 else "MEDIUM",
                "tier": 2,
                "interpretation": "Moderate — high-risk services exposed",
            })

    # WHOIS age
    if recon and recon.get("whois") and not recon["whois"].get("error"):
        whois = recon["whois"]
        creation = whois.get("creation_date", "")
        if creation:
            try:
                from datetime import datetime
                created = datetime.strptime(creation[:10], "%Y-%m-%d")
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    score += 12
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered only {age_days} days ago — newly created",
                        "weight": 12,
                        "severity": "HIGH",
                        "tier": 2,
                        "interpretation": "Moderate — newly registered domain",
                    })
                elif age_days < 90:
                    score += 4
                    signals.append({
                        "source": "WHOIS",
                        "signal": f"Domain registered {age_days} days ago — relatively new",
                        "weight": 4,
                        "severity": "LOW",
                        "tier": 3,
                        "interpretation": "Weak — newer domain",
                    })
            except (ValueError, TypeError):
                pass

    # ═══ TIER 3: WEAK ═════════════════════════════════════════

    if otx and not otx.get("error"):
        malware_count = otx.get("malware_count", 0)
        if malware_count > 0 and otx.get("pulse_count", 0) == 0:
            mal_score = min(malware_count, 5) * 2  # Max +10, was +50
            if is_good:
                mal_score = 0
                signals.append({
                    "source": "OTX",
                    "signal": f"{malware_count} malware sample(s) associated (contextual only)",
                    "weight": 0,
                    "severity": "INFO",
                    "tier": 3,
                    "interpretation": "Contextual — passive association, not a direct verdict. "
                                      "Malware may communicate through this domain without it being malicious.",
                })
            else:
                score += mal_score
                signals.append({
                    "source": "OTX",
                    "signal": f"{malware_count} malware sample(s) associated (passive)",
                    "weight": mal_score,
                    "severity": "MEDIUM",
                    "tier": 3,
                    "interpretation": "Weak — passive association only",
                })

    # DNS check
    if recon and recon.get("dns"):
        dns = recon["dns"]
        if not dns.get("a_records"):
            signals.append({
                "source": "DNS",
                "signal": "No A records — domain may be parked or inactive",
                "weight": 0,
                "severity": "INFO",
                "tier": 3,
                "interpretation": "Contextual — no resolution",
            })

    # ═══ NEGATIVE SCORING ═════════════════════════════════════

    if is_good:
        mitigations.append(f"Known-good indicator: {good_reason}")
        # Don't cap score at 25 — reduce only weak/contextual signals
        weak_reduction = 0
        filtered_signals = []
        for sig in signals:
            if sig.get("tier", 3) == 3 and sig["weight"] > 0:
                weak_reduction += sig["weight"]
                sig_copy = dict(sig)
                sig_copy["weight"] = 0
                sig_copy["severity"] = "INFO"
                sig_copy["interpretation"] = (
                    "Suppressed — known-good indicator, weak contextual signal"
                )
                filtered_signals.append(sig_copy)
            else:
                filtered_signals.append(sig)
        signals = filtered_signals
        score = max(0, score - weak_reduction)
        if weak_reduction > 0:
            mitigations.append(
                f"Reduced {weak_reduction} points from weak/contextual signals "
                f"due to known-good status (strong evidence preserved)"
            )

    if vt and not vt.get("error"):
        if vt.get("malicious", 0) == 0 and vt.get("suspicious", 0) == 0:
            total = vt.get("harmless", 0) + vt.get("undetected", 0)
            if total > 0:
                mitigations.append(f"VirusTotal: 0/{total} detections — clean")

    score = max(0, score)
    score = min(score, 100)

    # ─── Coverage and Confidence ───────────────────────────────
    checked_count, total_count, coverage_pct = _calculate_coverage(source_statuses)

    # ─── Classification ────────────────────────────────────────
    UNKNOWN_THRESHOLD = 40
    if coverage_pct < UNKNOWN_THRESHOLD and not signals:
        classification = "UNKNOWN"
    elif score >= RISK_THRESHOLDS["CRITICAL"]:
        classification = "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        classification = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    not_checked = _get_not_checked_sources(otx=otx, vt=vt, threatfox=threatfox, urlhaus=urlhaus)
    actions = _get_recommended_actions(classification, signals, is_good)

    return {
        "score": score,
        "classification": classification,
        "signals": sorted(signals, key=lambda s: s["weight"], reverse=True),
        "mitigations": mitigations,
        "recommended_actions": actions,
        "signal_count": len(signals),
        "source_statuses": source_statuses,
        "not_checked_sources": not_checked,
        "is_known_good": is_good,
        "known_good_reason": good_reason,
        "coverage": {
            "checked": checked_count,
            "total": total_count,
            "percentage": coverage_pct,
        },
        "confidence": coverage_pct,
    }


def _get_recommended_actions(classification: str, signals: list, is_known_good: bool = False) -> List[str]:
    """Generate recommended actions based on risk classification."""
    actions = []

    if is_known_good:
        actions.append("No action required — known legitimate indicator")
        actions.append("Log for reference only")
        return actions

    has_c2 = any("c2" in s.get("signal", "").lower() for s in signals)
    has_malware = any("malware" in s.get("signal", "").lower() and s.get("tier", 3) <= 2
                      for s in signals)
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

    if classification == "UNKNOWN":
        actions.insert(0, "INSUFFICIENT DATA: Configure API keys for key sources")
        actions.append("Re-run analysis after configuring missing API keys")
        actions.append("Do not make blocking decisions based on UNKNOWN verdict")

    return actions


def get_risk_badge(classification: str) -> str:
    """Return a text-based risk badge for terminal display."""
    badges = {
        "CRITICAL": "\033[97;41m CRITICAL \033[0m",
        "HIGH":     "\033[97;43m   HIGH   \033[0m",
        "MEDIUM":   "\033[30;43m  MEDIUM  \033[0m",
        "LOW":      "\033[97;42m   LOW    \033[0m",
        "UNKNOWN":  "\033[30;100m UNKNOWN  \033[0m",
    }
    return badges.get(classification, classification)


def get_risk_color_hex(classification: str) -> str:
    """Return hex color for DOCX report styling."""
    colors = {
        "CRITICAL": "E74C3C",
        "HIGH":     "E67E22",
        "MEDIUM":   "F1C40F",
        "LOW":      "27AE60",
        "UNKNOWN":  "95A5A6",
    }
    return colors.get(classification, "95A5A6")
