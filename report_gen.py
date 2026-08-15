"""
Professional DOCX Report Generator
Generates management-level threat intelligence investigation reports
with color-coded tables, KPI dashboards, and actionable recommendations.
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Optional

import os as _os

try:
    from docx import Document
    from docx.shared import Pt, Cm, RGBColor, Inches, Emu
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

# Logo paths (relative to this file or exe bundle)
_BUNDLE_DIR = _os.path.dirname(_os.path.abspath(__file__))
_LOGO_512 = _os.path.join(_BUNDLE_DIR, "logo_512.png")
_WATERMARK = _os.path.join(_BUNDLE_DIR, "logo_watermark.png")


# ═══════════════════════════════════════════════════════════════════
# Styling Helpers
# ═══════════════════════════════════════════════════════════════════

def _set_cell_shading(cell, color_hex):
    """Apply background color to a table cell."""
    shading = OxmlElement('w:shd')
    shading.set(qn('w:fill'), color_hex)
    shading.set(qn('w:val'), 'clear')
    cell._tc.get_or_add_tcPr().append(shading)


def _ct(cell, text, bold=False, size=Pt(9), color=None, align=None):
    """Write styled text to a table cell."""
    cell.text = str(text)
    for p in cell.paragraphs:
        if align:
            p.alignment = align
        for r in p.runs:
            r.font.size = size
            r.bold = bold
            r.font.name = "Calibri"
            if color:
                r.font.color.rgb = color


def _add_watermark(doc):
    """Add a semi-transparent logo watermark behind page content."""
    if not _os.path.exists(_WATERMARK):
        return
    for section in doc.sections:
        header = section.header
        if not header.paragraphs:
            header.add_paragraph()
        p = header.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run()
        run.add_picture(_WATERMARK, width=Cm(6))
        # Set the picture to be behind text (watermark effect)
        # python-docx doesn't natively support z-index, so we use
        # the header approach which renders behind body content

def _add_header_logo(doc):
    """Add logo image to the first page header area."""
    if not _os.path.exists(_LOGO_512):
        return
    # Add as a small inline image at the top of the document
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    run.add_picture(_LOGO_512, width=Cm(4))
    return p

def _add_styled_paragraph(doc, text, style=None, bold=False, size=Pt(11),
                          color=None, alignment=None, space_after=Pt(6)):
    """Add a styled paragraph to the document."""
    p = doc.add_paragraph()
    if style:
        p.style = style
    if alignment:
        p.alignment = alignment
    p.paragraph_format.space_after = space_after
    run = p.add_run(text)
    run.font.size = size
    run.font.name = "Calibri"
    run.bold = bold
    if color:
        run.font.color.rgb = color
    return p


# ═══════════════════════════════════════════════════════════════════
# Risk Color Map
# ═══════════════════════════════════════════════════════════════════

SEV_COLORS = {
    "CRITICAL": ("E74C3C", True),   # Red bg, white text
    "HIGH":     ("E67E22", True),   # Orange bg, white text
    "MEDIUM":   ("F1C40F", False),  # Yellow bg, dark text
    "LOW":      ("27AE60", True),   # Green bg, white text
    "INFO":     ("3498DB", True),   # Blue bg, white text
}


# ═══════════════════════════════════════════════════════════════════
# Report Generator
# ═══════════════════════════════════════════════════════════════════

def generate_report(
    target: str,
    target_type: str,  # "ip" or "domain"
    risk_assessment: dict,
    ipinfo: dict = None,
    otx: dict = None,
    abuseipdb: dict = None,
    vt: dict = None,
    shodan: dict = None,
    threatfox: dict = None,
    urlhaus: dict = None,
    recon: dict = None,
    output_path: str = None,
    analyst: str = "Threat Intel Analyst",
    classification: str = "CONFIDENTIAL",
) -> str:
    """Generate a professional DOCX threat intelligence report."""

    if not HAS_DOCX:
        raise ImportError("python-docx not installed. Run: pip install python-docx")

    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{target.replace('.', '-').replace(':', '-')}"

    # ─── Cover Page ────────────────────────────────────────────
    for _ in range(4):
        doc.add_paragraph()

    _add_styled_paragraph(doc, "THREAT INTELLIGENCE REPORT",
                          bold=True, size=Pt(28), color=RGBColor(0, 0x33, 0x66),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    _add_styled_paragraph(doc, f"IP/Domain Reputation Analysis",
                          size=Pt(16), color=RGBColor(0x66, 0x66, 0x66),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    doc.add_paragraph()
    _add_styled_paragraph(doc, f"Target: {target}",
                          bold=True, size=Pt(14),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    # Risk badge on cover
    risk_cls = risk_assessment.get("classification", "LOW")
    risk_score = risk_assessment.get("score", 0)
    badge_color = {"CRITICAL": RGBColor(0xE7, 0x4C, 0x3C),
                   "HIGH": RGBColor(0xE6, 0x7E, 0x22),
                   "MEDIUM": RGBColor(0xF1, 0xC4, 0x0F),
                   "LOW": RGBColor(0x27, 0xAE, 0x60)}.get(risk_cls, RGBColor(0, 0, 0))
    _add_styled_paragraph(doc, f"Risk: {risk_cls} (Score: {risk_score}/100)",
                          bold=True, size=Pt(16), color=badge_color,
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    for _ in range(3):
        doc.add_paragraph()

    # Metadata table
    meta = [
        ("Report ID", report_id),
        ("Date", timestamp),
        ("Prepared By", analyst),
        ("Classification", classification),
        ("Type", f"IP Address Analysis" if target_type == "ip" else "Domain Analysis"),
        ("Version", "1.0"),
    ]
    meta_table = doc.add_table(rows=len(meta), cols=2, style='Light Shading Accent 1')
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, (k, v) in enumerate(meta):
        _ct(meta_table.rows[i].cells[0], k, bold=True, size=Pt(10))
        _ct(meta_table.rows[i].cells[1], v, size=Pt(10))

    doc.add_page_break()

    # ─── Table of Contents placeholder ─────────────────────────
    _add_styled_paragraph(doc, "Table of Contents", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))
    toc_items = [
        "1. Executive Summary",
        "2. Risk Assessment Dashboard",
        "3. Indicator Profile",
        "4. Threat Intelligence Findings",
        "5. Network Reconnaissance",
        "6. Signal Analysis",
        "7. IOC Table",
        "8. Recommended Actions",
        "9. Detection Rules",
        "10. Appendix — Raw Data Sources",
    ]
    for item in toc_items:
        _add_styled_paragraph(doc, item, size=Pt(11), space_after=Pt(3))

    doc.add_page_break()

    # ─── 1. Executive Summary ──────────────────────────────────
    _add_styled_paragraph(doc, "1. Executive Summary", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    # Build summary text
    signals = risk_assessment.get("signals", [])
    top_signals = signals[:3] if signals else []
    signal_text = "; ".join(s.get("signal", "") for s in top_signals) if top_signals else "No significant threats detected"

    summary_text = (
        f"This report presents the threat intelligence analysis of {target_type} "
        f"indicator \"{target}\". The investigation assessed multiple open-source "
        f"intelligence (OSINT) feeds including AlienVault OTX, AbuseIPDB, VirusTotal, "
        f"Shodan, ThreatFox, and URLhaus."
    )
    _add_styled_paragraph(doc, summary_text, size=Pt(11))

    summary2 = (
        f"Risk Assessment: The indicator received a composite risk score of "
        f"{risk_score}/100, classified as {risk_cls}. "
        f"Key findings: {signal_text}."
    )
    _add_styled_paragraph(doc, summary2, size=Pt(11), bold=True)

    # Summary KPI table
    kpi_data = [
        ("Risk Score", f"{risk_score}/100"),
        ("Classification", risk_cls),
        ("Signals Detected", str(risk_assessment.get("signal_count", 0))),
        ("OTX Pulses", str(otx.get("pulse_count", 0) if otx and not otx.get("error") else "N/A")),
        ("VT Detections", f"{vt.get('malicious', 0)}/{vt.get('malicious', 0) + vt.get('harmless', 0) + vt.get('undetected', 0)}" if vt and not vt.get("error") else "N/A"),
        ("Abuse Score", f"{abuseipdb.get('abuse_confidence_score', 0)}%" if abuseipdb and not abuseipdb.get("error") else "N/A"),
    ]
    kpi_table = doc.add_table(rows=len(kpi_data) + 1, cols=2, style='Light Shading Accent 1')
    kpi_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _ct(kpi_table.rows[0].cells[0], "Metric", bold=True, size=Pt(10), color=RGBColor(255, 255, 255))
    _ct(kpi_table.rows[0].cells[1], "Value", bold=True, size=Pt(10), color=RGBColor(255, 255, 255))
    _set_cell_shading(kpi_table.rows[0].cells[0], "003366")
    _set_cell_shading(kpi_table.rows[0].cells[1], "003366")
    for i, (metric, value) in enumerate(kpi_data):
        row = kpi_table.rows[i + 1]
        _ct(row.cells[0], metric, bold=True, size=Pt(10))
        _ct(row.cells[1], value, size=Pt(10))
        # Color code the classification row
        if metric == "Classification":
            hex_color, white_text = SEV_COLORS.get(value, ("95A5A6", True))
            _set_cell_shading(row.cells[1], hex_color)
            txt_color = RGBColor(255, 255, 255) if white_text else RGBColor(0, 0, 0)
            _ct(row.cells[1], value, bold=True, size=Pt(10), color=txt_color)

    doc.add_page_break()

    # ─── 2. Risk Assessment Dashboard ──────────────────────────
    _add_styled_paragraph(doc, "2. Risk Assessment Dashboard", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    # Signal summary table
    if signals:
        sig_table = doc.add_table(rows=len(signals) + 1, cols=4, style='Light Shading Accent 1')
        sig_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        headers = ["#", "Source", "Signal", "Severity"]
        for j, h in enumerate(headers):
            _ct(sig_table.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
            _set_cell_shading(sig_table.rows[0].cells[j], "003366")

        for i, sig in enumerate(signals):
            row = sig_table.rows[i + 1]
            _ct(row.cells[0], str(i + 1), size=Pt(9))
            _ct(row.cells[1], sig.get("source", ""), size=Pt(9))
            _ct(row.cells[2], sig.get("signal", ""), size=Pt(8))
            sev = sig.get("severity", "INFO")
            hex_color, white_text = SEV_COLORS.get(sev, ("95A5A6", True))
            _set_cell_shading(row.cells[3], hex_color)
            txt_color = RGBColor(255, 255, 255) if white_text else RGBColor(0, 0, 0)
            _ct(row.cells[3], sev, bold=True, size=Pt(9), color=txt_color)
    else:
        _add_styled_paragraph(doc, "No significant threat signals detected.", size=Pt(11))

    doc.add_page_break()

    # ─── 3. Indicator Profile ──────────────────────────────────
    _add_styled_paragraph(doc, "3. Indicator Profile", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    if target_type == "ip" and ipinfo and not ipinfo.get("error"):
        profile_data = [
            ("IP Address", target),
            ("Hostname", ipinfo.get("hostname", "N/A")),
            ("ASN", ipinfo.get("asn", "N/A")),
            ("ISP/Organization", ipinfo.get("isp", "N/A")),
            ("Country", ipinfo.get("country", "N/A")),
            ("City/Region", f"{ipinfo.get('city', '')}, {ipinfo.get('region', '')}".strip(", ")),
            ("Coordinates", ipinfo.get("loc", "N/A")),
            ("Cloud Provider", ipinfo.get("cloud_provider", "N/A") if ipinfo.get("is_cloud") else "Not detected"),
        ]
    elif target_type == "domain" and recon:
        dns = recon.get("dns", {})
        whois_data = recon.get("whois", {})
        profile_data = [
            ("Domain", target),
            ("A Records", ", ".join(dns.get("a_records", [])) or "N/A"),
            ("AAAA Records", ", ".join(dns.get("aaaa_records", [])) or "N/A"),
            ("MX Records", ", ".join(f"{m[0]} (pri {m[1]})" for m in dns.get("mx_records", [])) or "N/A"),
            ("NS Records", ", ".join(dns.get("ns_records", [])) or "N/A"),
            ("Registrar", whois_data.get("registrar", "N/A")),
            ("Creation Date", whois_data.get("creation_date", "N/A")),
            ("Expiration Date", whois_data.get("expiration_date", "N/A")),
        ]
    else:
        profile_data = [("Target", target), ("Profile Data", "Limited data available")]

    prof_table = doc.add_table(rows=len(profile_data), cols=2, style='Light Shading Accent 1')
    prof_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, (k, v) in enumerate(profile_data):
        _ct(prof_table.rows[i].cells[0], k, bold=True, size=Pt(10))
        _ct(prof_table.rows[i].cells[1], str(v), size=Pt(10))

    doc.add_paragraph()

    # ─── 4. Threat Intelligence Findings ───────────────────────
    _add_styled_paragraph(doc, "4. Threat Intelligence Findings", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    # OTX findings
    if otx and not otx.get("error"):
        _add_styled_paragraph(doc, "4.1 AlienVault OTX", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        _add_styled_paragraph(doc, f"Pulse Count: {otx.get('pulse_count', 0)} | "
                              f"Malware Samples: {otx.get('malware_count', 0)} | "
                              f"Malicious URLs: {otx.get('url_count', 0)}", size=Pt(10))

        if otx.get("pulses"):
            pulse_table = doc.add_table(rows=min(len(otx["pulses"]), 10) + 1, cols=4, style='Light Shading Accent 1')
            pulse_table.alignment = WD_TABLE_ALIGNMENT.CENTER
            for j, h in enumerate(["#", "Pulse Name", "Date", "Tags"]):
                _ct(pulse_table.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
                _set_cell_shading(pulse_table.rows[0].cells[j], "003366")
            for i, p in enumerate(otx["pulses"][:10]):
                row = pulse_table.rows[i + 1]
                _ct(row.cells[0], str(i + 1), size=Pt(8))
                _ct(row.cells[1], p.get("name", "")[:80], size=Pt(8))
                _ct(row.cells[2], p.get("created", ""), size=Pt(8))
                _ct(row.cells[3], ", ".join(p.get("tags", []))[:60], size=Pt(8))

        if otx.get("malware_samples"):
            doc.add_paragraph()
            _add_styled_paragraph(doc, "Associated Malware:", bold=True, size=Pt(11))
            for m in otx["malware_samples"][:5]:
                _add_styled_paragraph(doc, f"  - {m.get('malware_name', 'Unknown')} "
                                      f"(AV: {m.get('av_name', 'N/A')}, {m.get('date', '')})",
                                      size=Pt(9))

    # AbuseIPDB findings
    if abuseipdb and not abuseipdb.get("error"):
        _add_styled_paragraph(doc, "4.2 AbuseIPDB", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        ab_data = [
            ("Abuse Confidence Score", f"{abuseipdb.get('abuse_confidence_score', 0)}%"),
            ("Total Reports", str(abuseipdb.get("total_reports", 0))),
            ("Distinct Reporters", str(abuseipdb.get("num_distinct_users", 0))),
            ("Last Reported", abuseipdb.get("last_reported_at", "N/A") or "N/A"),
            ("Usage Type", abuseipdb.get("usage_type", "N/A")),
            ("ISP", abuseipdb.get("isp", "N/A")),
        ]
        ab_table = doc.add_table(rows=len(ab_data), cols=2, style='Light Shading Accent 1')
        ab_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, (k, v) in enumerate(ab_data):
            _ct(ab_table.rows[i].cells[0], k, bold=True, size=Pt(9))
            _ct(ab_table.rows[i].cells[1], str(v), size=Pt(9))

    # VirusTotal findings
    if vt and not vt.get("error"):
        _add_styled_paragraph(doc, "4.3 VirusTotal", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        clean = vt.get("harmless", 0)
        und = vt.get("undetected", 0)
        total = mal + sus + clean + und
        vt_info = [
            ("Detection Ratio", f"{mal}/{total} engines"),
            ("Malicious", str(mal)),
            ("Suspicious", str(sus)),
            ("Clean", str(clean)),
            ("Undetected", str(und)),
            ("Reputation Score", str(vt.get("reputation", "N/A"))),
        ]
        vt_table = doc.add_table(rows=len(vt_info), cols=2, style='Light Shading Accent 1')
        vt_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, (k, v) in enumerate(vt_info):
            _ct(vt_table.rows[i].cells[0], k, bold=True, size=Pt(9))
            _ct(vt_table.rows[i].cells[1], str(v), size=Pt(9))
            if k == "Detection Ratio" and mal > 0:
                hex_c, wt = ("E74C3C", True) if mal >= 5 else ("E67E22", True) if mal >= 2 else ("F1C40F", False)
                _set_cell_shading(vt_table.rows[i].cells[1], hex_c)
                tc = RGBColor(255, 255, 255) if wt else RGBColor(0, 0, 0)
                _ct(vt_table.rows[i].cells[1], str(v), bold=True, size=Pt(9), color=tc)

    # Shodan findings
    if shodan and not shodan.get("error"):
        _add_styled_paragraph(doc, "4.4 Shodan", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        shodan_info = [
            ("Open Ports", ", ".join(str(p) for p in shodan.get("ports", [])) or "None"),
            ("OS", shodan.get("os", "N/A") or "N/A"),
            ("Organization", shodan.get("org", "N/A")),
            ("Known CVEs", str(len(shodan.get("vulns", [])))),
        ]
        if shodan.get("vulns"):
            shodan_info.append(("CVE List", ", ".join(shodan["vulns"][:10])))
        sh_table = doc.add_table(rows=len(shodan_info), cols=2, style='Light Shading Accent 1')
        sh_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, (k, v) in enumerate(shodan_info):
            _ct(sh_table.rows[i].cells[0], k, bold=True, size=Pt(9))
            _ct(sh_table.rows[i].cells[1], str(v), size=Pt(9))

    # ThreatFox findings
    if threatfox and not threatfox.get("error") and threatfox.get("ioc_count", 0) > 0:
        _add_styled_paragraph(doc, "4.5 ThreatFox (abuse.ch)", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        _add_styled_paragraph(doc, f"IOC Associations: {threatfox.get('ioc_count', 0)}", size=Pt(10))
        for ioc in threatfox.get("iocs", [])[:5]:
            _add_styled_paragraph(doc, f"  - {ioc.get('malware', 'Unknown')} "
                                  f"(Type: {ioc.get('threat_type', 'N/A')}, "
                                  f"Confidence: {ioc.get('confidence', 0)}%)",
                                  size=Pt(9))

    # URLhaus findings
    if urlhaus and not urlhaus.get("error") and urlhaus.get("is_listed"):
        _add_styled_paragraph(doc, "4.6 URLhaus (abuse.ch)", bold=True, size=Pt(13),
                              color=RGBColor(0, 0x55, 0x99))
        _add_styled_paragraph(doc, f"LISTED — Threat: {urlhaus.get('threat', 'N/A')} | "
                              f"URLs: {urlhaus.get('url_count', 0)} "
                              f"(Online: {urlhaus.get('urls_online', 0)})",
                              size=Pt(10), bold=True)

    doc.add_page_break()

    # ─── 5. Network Reconnaissance ─────────────────────────────
    if recon:
        _add_styled_paragraph(doc, "5. Network Reconnaissance", bold=True, size=Pt(16),
                              color=RGBColor(0, 0x33, 0x66))

        # Port scan results
        port_scan = recon.get("port_scan", {})
        if port_scan and not port_scan.get("error"):
            _add_styled_paragraph(doc, "5.1 Port Scan Results", bold=True, size=Pt(13),
                                  color=RGBColor(0, 0x55, 0x99))
            open_ports = port_scan.get("open_ports", [])
            _add_styled_paragraph(doc, f"Open Ports: {len(open_ports)} | "
                                  f"Scan Time: {port_scan.get('scan_time', 0)}s",
                                  size=Pt(10))

            if open_ports:
                from config import HIGH_RISK_PORTS
                port_data = []
                for p in open_ports:
                    svc = HIGH_RISK_PORTS.get(p, "Unknown")
                    banner = port_scan.get("service_banners", {}).get(p, "")
                    risk = "HIGH" if p in HIGH_RISK_PORTS else "LOW"
                    port_data.append((str(p), svc, banner[:60] or "N/A", risk))

                port_table = doc.add_table(rows=len(port_data) + 1, cols=4, style='Light Shading Accent 1')
                port_table.alignment = WD_TABLE_ALIGNMENT.CENTER
                for j, h in enumerate(["Port", "Service", "Banner", "Risk"]):
                    _ct(port_table.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
                    _set_cell_shading(port_table.rows[0].cells[j], "003366")
                for i, (port, svc, banner, risk) in enumerate(port_data):
                    row = port_table.rows[i + 1]
                    _ct(row.cells[0], port, size=Pt(9))
                    _ct(row.cells[1], svc, size=Pt(9))
                    _ct(row.cells[2], banner, size=Pt(8))
                    hex_c, wt = SEV_COLORS.get(risk, ("95A5A6", True))
                    _set_cell_shading(row.cells[3], hex_c)
                    tc = RGBColor(255, 255, 255) if wt else RGBColor(0, 0, 0)
                    _ct(row.cells[3], risk, bold=True, size=Pt(9), color=tc)

        # Reverse DNS
        rdns = recon.get("reverse_dns", {})
        if rdns:
            _add_styled_paragraph(doc, "5.2 Reverse DNS", bold=True, size=Pt(13),
                                  color=RGBColor(0, 0x55, 0x99))
            hostnames = rdns.get("hostnames", [])
            _add_styled_paragraph(doc, f"PTR Records: {', '.join(hostnames) if hostnames else 'None'}",
                                  size=Pt(10))

        # HTTP Probe
        http = recon.get("http_probe")
        if http and not http.get("error"):
            _add_styled_paragraph(doc, "5.3 HTTP/HTTPS Probe", bold=True, size=Pt(13),
                                  color=RGBColor(0, 0x55, 0x99))
            http_info = [
                ("HTTP Status", str(http.get("http_status", "N/A"))),
                ("HTTPS Status", str(http.get("https_status", "N/A"))),
                ("Server", http.get("server_header", "N/A") or "N/A"),
                ("TLS Version", http.get("tls_version", "N/A") or "N/A"),
            ]
            http_table = doc.add_table(rows=len(http_info), cols=2, style='Light Shading Accent 1')
            http_table.alignment = WD_TABLE_ALIGNMENT.CENTER
            for i, (k, v) in enumerate(http_info):
                _ct(http_table.rows[i].cells[0], k, bold=True, size=Pt(9))
                _ct(http_table.rows[i].cells[1], str(v), size=Pt(9))

            # Security headers
            sec = http.get("security_headers", {})
            if sec:
                doc.add_paragraph()
                _add_styled_paragraph(doc, "Security Headers:", bold=True, size=Pt(10))
                for hdr, val in sec.items():
                    status = "PRESENT" if val != "MISSING" else "MISSING"
                    color = "27AE60" if val != "MISSING" else "E74C3C"
                    _add_styled_paragraph(doc, f"  {hdr}: {status}", size=Pt(9),
                                          color=RGBColor(0x27, 0xAE, 0x60) if val != "MISSING" else RGBColor(0xE7, 0x4C, 0x3C))

    doc.add_page_break()

    # ─── 6. IOC Table ──────────────────────────────────────────
    _add_styled_paragraph(doc, "6. IOC Table — Block/Monitor Actions", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    ioc_entries = []
    # Primary indicator
    action = "BLOCK" if risk_cls in ("CRITICAL", "HIGH") else "MONITOR"
    ioc_entries.append((target, target_type.upper(), risk_cls, action, "Primary indicator"))

    # Related IOCs from OTX malware
    if otx and otx.get("malware_samples"):
        for m in otx["malware_samples"][:3]:
            if m.get("hash"):
                ioc_entries.append((m["hash"][:16] + "...", "HASH", "HIGH", "BLOCK",
                                    f"Malware: {m.get('malware_name', 'Unknown')}"))

    # Related IOCs from ThreatFox
    if threatfox and threatfox.get("iocs"):
        for ioc in threatfox["iocs"][:3]:
            ioc_entries.append((ioc.get("ioc", "")[:40], ioc.get("ioc_type", ""),
                                "HIGH", "BLOCK", f"Malware: {ioc.get('malware', '')}"))

    if ioc_entries:
        ioc_table = doc.add_table(rows=len(ioc_entries) + 1, cols=5, style='Light Shading Accent 1')
        ioc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for j, h in enumerate(["Indicator", "Type", "Severity", "Action", "Notes"]):
            _ct(ioc_table.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
            _set_cell_shading(ioc_table.rows[0].cells[j], "003366")
        for i, (ind, itype, sev, act, notes) in enumerate(ioc_entries):
            row = ioc_table.rows[i + 1]
            _ct(row.cells[0], ind, size=Pt(8))
            _ct(row.cells[1], itype, size=Pt(8))
            hex_c, wt = SEV_COLORS.get(sev, ("95A5A6", True))
            _set_cell_shading(row.cells[2], hex_c)
            tc = RGBColor(255, 255, 255) if wt else RGBColor(0, 0, 0)
            _ct(row.cells[2], sev, bold=True, size=Pt(8), color=tc)
            # Action coloring
            act_color = "E74C3C" if act == "BLOCK" else "F39C12"
            _set_cell_shading(row.cells[3], act_color)
            _ct(row.cells[3], act, bold=True, size=Pt(8), color=RGBColor(255, 255, 255))
            _ct(row.cells[4], notes, size=Pt(8))

    doc.add_page_break()

    # ─── 7. Recommended Actions ────────────────────────────────
    _add_styled_paragraph(doc, "7. Recommended Actions", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    actions = risk_assessment.get("recommended_actions", [])
    if actions:
        action_table = doc.add_table(rows=len(actions) + 1, cols=2, style='Light Shading Accent 1')
        action_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _ct(action_table.rows[0].cells[0], "#", bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
        _ct(action_table.rows[0].cells[1], "Action", bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
        _set_cell_shading(action_table.rows[0].cells[0], "003366")
        _set_cell_shading(action_table.rows[0].cells[1], "003366")
        for i, act in enumerate(actions):
            row = action_table.rows[i + 1]
            _ct(row.cells[0], str(i + 1), size=Pt(9))
            _ct(row.cells[1], act, size=Pt(9))

    doc.add_page_break()

    # ─── 8. Detection Rules ────────────────────────────────────
    _add_styled_paragraph(doc, "8. Detection Rules (Sigma)", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    sigma_rule = f"""title: Traffic to/from {target}
id: {report_id.lower().replace('-', '')}
status: experimental
description: Detects network traffic to/from investigated indicator {target}
references:
    - This threat intelligence report ({report_id})
author: IP/Domain Rep Tool
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: firewall
detection:
    selection:
        DestinationIp|contains: '{target}' if target_type == 'ip' else ''
        DestinationHostname|contains: '{target}' if target_type == 'domain' else ''
    condition: selection
falsepositives:
    - Legitimate business traffic (review before blocking)
level: {risk_cls.lower()}
tags:
    - attack.command_and_control
    - attack.t1071"""

    _add_styled_paragraph(doc, "Sigma Rule (Firewall):", bold=True, size=Pt(11))
    _add_styled_paragraph(doc, sigma_rule, size=Pt(8), color=RGBColor(0x33, 0x33, 0x33))

    splunk_rule = f"""index=* (dest_ip="{target}" OR src_ip="{target}" OR dest="{target}")
| stats count by src_ip, dest_ip, dest, action, app
| sort -count"""

    _add_styled_paragraph(doc, "Splunk Query:", bold=True, size=Pt(11))
    _add_styled_paragraph(doc, splunk_rule, size=Pt(8), color=RGBColor(0x33, 0x33, 0x33))

    doc.add_paragraph()

    # Elastic SIEM EQL rule
    import json as _json
    if target_type == "ip":
        eql_rule = 'network where destination.ip == "' + target + '" or source.ip == "' + target + '"'
        kql_filter = 'source.ip: "' + target + '" OR destination.ip: "' + target + '"'
    else:
        eql_rule = 'network where dns.question.name == "' + target + '" or destination.domain == "' + target + '"'
        kql_filter = 'dns.question.name: "' + target + '" OR destination.domain: "' + target + '"'

    _add_styled_paragraph(doc, "Elastic SIEM (EQL Rule):", bold=True, size=Pt(11))
    _add_styled_paragraph(doc, eql_rule, size=Pt(8), color=RGBColor(0x33, 0x33, 0x33))

    doc.add_paragraph()
    _add_styled_paragraph(doc, "Elastic SIEM (KQL Filter):", bold=True, size=Pt(11))
    _add_styled_paragraph(doc, kql_filter, size=Pt(8), color=RGBColor(0x33, 0x33, 0x33))

    doc.add_paragraph()
    elastic_obj = {
        "name": "Traffic to/from " + target,
        "description": "Detects connections to investigated indicator " + target,
        "risk_score": risk_assessment.get("score", 0),
        "severity": risk_assessment.get("classification", "low").lower(),
        "type": "eql",
        "query": eql_rule,
        "interval": "5m",
        "from": "now-3600s",
        "enabled": True,
        "tags": ["threat-intel", "soc", "custom"],
        "threat": [{"framework": "MITRE ATT&CK", "tactic": {"id": "TA0011", "name": "Command and Control"}}]
    }
    _add_styled_paragraph(doc, "Elastic SIEM (JSON Rule Import):", bold=True, size=Pt(11))
    _add_styled_paragraph(doc, "POST /api/detection_engine/rules", size=Pt(8), color=RGBColor(0x33, 0x33, 0x33))
    _add_styled_paragraph(doc, _json.dumps(elastic_obj, indent=2), size=Pt(7), color=RGBColor(0x33, 0x33, 0x33))

    doc.add_page_break()

    # ─── 9. Appendix ───────────────────────────────────────────
    _add_styled_paragraph(doc, "9. Appendix — OSINT Sources", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    sources = [
        ("AlienVault OTX", "https://otx.alienvault.com/indicator/ip/" + target),
        ("AbuseIPDB", f"https://www.abuseipdb.com/check/{target}"),
        ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{target}" if target_type == "ip" else f"https://www.virustotal.com/gui/domain/{target}"),
        ("Shodan", f"https://www.shodan.io/host/{target}" if target_type == "ip" else f"https://www.shodan.io/search?query=hostname:{target}"),
        ("ThreatFox", "https://threatfox.abuse.ch/browse/"),
        ("URLhaus", "https://urlhaus.abuse.ch/browse/"),
        ("IPInfo", f"https://ipinfo.io/{target}"),
    ]

    src_table = doc.add_table(rows=len(sources) + 1, cols=2, style='Light Shading Accent 1')
    src_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    _ct(src_table.rows[0].cells[0], "Source", bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
    _ct(src_table.rows[0].cells[1], "URL", bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
    _set_cell_shading(src_table.rows[0].cells[0], "003366")
    _set_cell_shading(src_table.rows[0].cells[1], "003366")
    for i, (name, url) in enumerate(sources):
        row = src_table.rows[i + 1]
        _ct(row.cells[0], name, bold=True, size=Pt(9))
        _ct(row.cells[1], url, size=Pt(8))

    # ─── Footer ────────────────────────────────────────────────
    doc.add_paragraph()
    _add_styled_paragraph(doc, f"Report generated: {timestamp} | Classification: {classification}",
                          size=Pt(8), color=RGBColor(0x99, 0x99, 0x99),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_paragraph(doc, "This report was generated by the IP/Domain Reputation Tool v1.0",
                          size=Pt(8), color=RGBColor(0x99, 0x99, 0x99),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    # ─── Save ──────────────────────────────────────────────────
    if not output_path:
        safe_target = target.replace(":", "-").replace("/", "-").replace("\\", "-")
        output_path = f"TI_Report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

    try:
        doc.save(output_path)
    except PermissionError:
        output_path = output_path.replace(".docx", "_v2.docx")
        doc.save(output_path)

    return output_path


# ═══════════════════════════════════════════════════════════════════
# TXT Report Generator
# ═══════════════════════════════════════════════════════════════════

def generate_txt_report(
    target: str,
    target_type: str,
    risk_assessment: dict,
    ipinfo: dict = None,
    otx: dict = None,
    abuseipdb: dict = None,
    vt: dict = None,
    shodan: dict = None,
    threatfox: dict = None,
    urlhaus: dict = None,
    recon: dict = None,
    output_path: str = None,
    analyst: str = "Threat Intel Analyst",
    classification: str = "CONFIDENTIAL",
) -> str:
    """Generate a plain-text threat intelligence report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{target.replace('.', '-').replace(':', '-')}"
    risk = risk_assessment
    W = 72

    lines = []

    def ln(text=""):
        lines.append(text)

    def hdr(title):
        ln("=" * W)
        ln(f"  {title}")
        ln("=" * W)

    def sec(title):
        ln()
        ln(f"--- {title} {'─' * (W - len(title) - 6)}")
        ln()

    def kv(key, value):
        ln(f"  {key + ':':<24s} {value}")

    def bar(label, value, max_val=100, width=35):
        filled = int(width * value / max_val) if max_val > 0 else 0
        ln(f"  {label:<20s} {'█' * filled}{'░' * (width - filled)} {value}/{max_val}")

    # ─── Cover ─────────────────────────────────────────────────
    ln()
    ln("=" * W)
    ln("  THREAT INTELLIGENCE REPORT")
    ln(f"  IP/Domain Reputation Analysis")
    ln("=" * W)
    ln()
    ln(f"  Target:         {target}")
    ln(f"  Type:           {'IP Address' if target_type == 'ip' else 'Domain'}")
    ln(f"  Risk:           {risk.get('classification', 'N/A')} (Score: {risk.get('score', 0)}/100)")
    ln(f"  Report ID:      {report_id}")
    ln(f"  Date:           {timestamp}")
    ln(f"  Prepared By:    {analyst}")
    ln(f"  Classification: {classification}")
    ln()
    ln("=" * W)

    # ─── 1. Executive Summary ──────────────────────────────────
    sec("1. EXECUTIVE SUMMARY")

    signals = risk.get("signals", [])
    not_checked = risk.get("not_checked_sources", [])
    is_good = risk.get("is_known_good", False)

    if is_good:
        ln(f"  STATUS: KNOWN LEGITIMATE — {risk.get('known_good_reason', '')}")
        ln()

    kv("Risk Score", f"{risk.get('score', 0)}/100")
    kv("Classification", risk.get("classification", "N/A"))
    kv("Signals Detected", str(risk.get("signal_count", 0)))
    kv("Known-Good Status", "YES" if is_good else "No")

    if not_checked:
        ln()
        ln(f"  WARNING: The following sources were NOT checked:")
        ln(f"  {', '.join(not_checked)}")
        ln(f"  Assessment may be incomplete.")

    # ─── 2. Source Verification ────────────────────────────────
    sec("2. SOURCE VERIFICATION")
    source_statuses = risk.get("source_statuses", {})
    if source_statuses:
        for src, status in source_statuses.items():
            marker = "✓" if status == "CHECKED" else "✗"
            ln(f"  [{marker}] {src:<16s} {status}")
    else:
        # Fallback: infer from data
        for name, data in [("IPInfo", ipinfo), ("OTX", otx), ("AbuseIPDB", abuseipdb),
                           ("VirusTotal", vt), ("Shodan", shodan),
                           ("ThreatFox", threatfox), ("URLhaus", urlhaus)]:
            if data is None or data.get("error"):
                ln(f"  [✗] {name:<16s} NOT CHECKED")
            else:
                ln(f"  [✓] {name:<16s} CHECKED")

    # ─── 3. Indicator Profile ──────────────────────────────────
    sec("3. INDICATOR PROFILE")
    if target_type == "ip" and ipinfo and not ipinfo.get("error"):
        kv("IP Address", target)
        kv("Hostname", ipinfo.get("hostname", "N/A") or "N/A")
        kv("ASN", ipinfo.get("asn", "N/A"))
        kv("ISP/Organization", ipinfo.get("isp", "N/A"))
        kv("Country", ipinfo.get("country", "N/A"))
        kv("City/Region", f"{ipinfo.get('city', '')}, {ipinfo.get('region', '')}".strip(", "))
        if ipinfo.get("is_cloud"):
            kv("Cloud Provider", ipinfo.get("cloud_provider", ""))
    elif target_type == "domain" and recon:
        dns = recon.get("dns", {})
        whois_data = recon.get("whois", {})
        kv("Domain", target)
        kv("A Records", ", ".join(dns.get("a_records", [])) or "N/A")
        kv("AAAA Records", ", ".join(dns.get("aaaa_records", [])) or "N/A")
        kv("MX Records", ", ".join(f"{m[0]} (pri {m[1]})" for m in dns.get("mx_records", [])) or "N/A")
        kv("NS Records", ", ".join(dns.get("ns_records", [])) or "N/A")
        kv("Registrar", whois_data.get("registrar", "N/A"))
        kv("Creation Date", whois_data.get("creation_date", "N/A"))
        kv("Expiration Date", whois_data.get("expiration_date", "N/A"))
    else:
        kv("Target", target)

    # ─── 4. Risk Assessment ────────────────────────────────────
    sec("4. RISK ASSESSMENT")

    if signals:
        ln("  Score Breakdown:")
        for sig in signals[:10]:
            bar(sig["source"], sig["weight"])
        ln()

        ln("  Signal Details:")
        ln()
        for i, sig in enumerate(signals, 1):
            tier = sig.get("tier", "?")
            interp = sig.get("interpretation", "")
            ln(f"  {i:2d}. [{sig['severity']}] {sig['source']}: {sig['signal']}")
            ln(f"      Weight: +{sig['weight']}  Tier: {tier}")
            if interp:
                ln(f"      Interpretation: {interp}")
            ln()
    else:
        ln("  No significant threat signals detected.")

    # ─── 5. Mitigating Factors ─────────────────────────────────
    if risk.get("mitigations"):
        sec("5. MITIGATING FACTORS")
        for m in risk["mitigations"]:
            ln(f"  * {m}")

    # ─── 6. Threat Intelligence Findings ───────────────────────
    sec("6. THREAT INTELLIGENCE FINDINGS")

    # OTX
    if otx and not otx.get("error"):
        ln(f"  AlienVault OTX:")
        ln(f"    Pulse Count:      {otx.get('pulse_count', 0)}")
        ln(f"    Malware Samples:  {otx.get('malware_count', 0)}")
        ln(f"    Malicious URLs:   {otx.get('url_count', 0)}")
        if otx.get("pulses"):
            ln(f"    Top Pulses:")
            for p in otx["pulses"][:5]:
                ln(f"      - {p['name']} ({p.get('created', '')})")
                if p.get("tags"):
                    ln(f"        Tags: {', '.join(p['tags'][:5])}")
        if otx.get("malware_samples"):
            ln(f"    Associated Malware:")
            for m in otx["malware_samples"][:5]:
                ln(f"      - {m.get('malware_name', 'Unknown')} (AV: {m.get('av_name', 'N/A')})")
        ln()

    # AbuseIPDB
    if abuseipdb and not abuseipdb.get("error"):
        ln(f"  AbuseIPDB:")
        ln(f"    Abuse Confidence: {abuseipdb.get('abuse_confidence_score', 0)}%")
        ln(f"    Total Reports:    {abuseipdb.get('total_reports', 0)}")
        ln(f"    Distinct Users:   {abuseipdb.get('num_distinct_users', 0)}")
        ln(f"    Last Reported:    {abuseipdb.get('last_reported_at', 'N/A') or 'N/A'}")
        ln(f"    Usage Type:       {abuseipdb.get('usage_type', 'N/A')}")
        ln()
    elif abuseipdb and abuseipdb.get("error"):
        ln(f"  AbuseIPDB: NOT CHECKED — {abuseipdb.get('error', '')}")
        ln()

    # VirusTotal
    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        total = mal + sus + vt.get("harmless", 0) + vt.get("undetected", 0)
        ln(f"  VirusTotal:")
        ln(f"    Detection Ratio:  {mal}/{total} engines")
        ln(f"    Malicious:        {mal}")
        ln(f"    Suspicious:       {sus}")
        ln(f"    Clean:            {vt.get('harmless', 0)}")
        ln(f"    Reputation:       {vt.get('reputation', 'N/A')}")
        ln()
    elif vt and vt.get("error"):
        ln(f"  VirusTotal: NOT CHECKED — {vt.get('error', '')}")
        ln()

    # Shodan
    if shodan and not shodan.get("error"):
        ln(f"  Shodan:")
        ln(f"    Open Ports:       {', '.join(str(p) for p in shodan.get('ports', [])) or 'None'}")
        ln(f"    OS:               {shodan.get('os', 'N/A') or 'N/A'}")
        ln(f"    Organization:     {shodan.get('org', 'N/A')}")
        ln(f"    Known CVEs:       {len(shodan.get('vulns', []))}")
        if shodan.get("vulns"):
            ln(f"    CVE List:         {', '.join(shodan['vulns'][:10])}")
        ln()
    elif shodan and shodan.get("error"):
        ln(f"  Shodan: NOT CHECKED — {shodan.get('error', '')}")
        ln()

    # ThreatFox
    if threatfox and not threatfox.get("error") and threatfox.get("ioc_count", 0) > 0:
        ln(f"  ThreatFox:")
        ln(f"    IOC Associations: {threatfox.get('ioc_count', 0)}")
        for ioc in threatfox.get("iocs", [])[:5]:
            ln(f"    - {ioc.get('malware', 'Unknown')} (Type: {ioc.get('threat_type', 'N/A')}, "
               f"Confidence: {ioc.get('confidence', 0)}%)")
        ln()
    elif threatfox and threatfox.get("error"):
        ln(f"  ThreatFox: NOT CHECKED — {threatfox.get('error', '')}")
        ln()

    # URLhaus
    if urlhaus and not urlhaus.get("error") and urlhaus.get("is_listed"):
        ln(f"  URLhaus:")
        ln(f"    Status:           LISTED")
        ln(f"    Threat:           {urlhaus.get('threat', 'N/A')}")
        ln(f"    URLs:             {urlhaus.get('url_count', 0)} (Online: {urlhaus.get('urls_online', 0)})")
        ln()
    elif urlhaus and urlhaus.get("error"):
        ln(f"  URLhaus: NOT CHECKED — {urlhaus.get('error', '')}")
        ln()

    # ─── 7. Network Reconnaissance ─────────────────────────────
    if recon:
        sec("7. NETWORK RECONNAISSANCE")

        port_scan = recon.get("port_scan", {})
        if port_scan and port_scan.get("open_ports") and not port_scan.get("error"):
            from config import HIGH_RISK_PORTS
            ln(f"  Port Scan Results:")
            ln(f"    Open Ports: {len(port_scan.get('open_ports', []))}")
            ln(f"    Scan Time:  {port_scan.get('scan_time', 0)}s")
            ln()
            ln(f"    {'Port':<8s} {'Service':<16s} {'Risk':<8s} Banner")
            ln(f"    {'─' * 64}")
            for p in port_scan["open_ports"]:
                svc = HIGH_RISK_PORTS.get(p, "Unknown")
                risk_flag = "HIGH" if p in HIGH_RISK_PORTS else "LOW"
                banner = port_scan.get("service_banners", {}).get(p, "")[:40]
                ln(f"    {p:<8d} {svc:<16s} {risk_flag:<8s} {banner}")
            ln()

        rdns = recon.get("reverse_dns", {})
        if rdns:
            ln(f"  Reverse DNS:")
            ln(f"    PTR Records: {', '.join(rdns.get('hostnames', [])) or 'None'}")
            ln()

        http = recon.get("http_probe")
        if http and not http.get("error"):
            ln(f"  HTTP/HTTPS Probe:")
            ln(f"    HTTP Status:  {http.get('http_status', 'N/A')}")
            ln(f"    HTTPS Status: {http.get('https_status', 'N/A')}")
            ln(f"    Server:       {http.get('server_header', 'N/A') or 'N/A'}")
            ln(f"    TLS Version:  {http.get('tls_version', 'N/A') or 'N/A'}")
            sec_hdrs = http.get("security_headers", {})
            if sec_hdrs:
                ln(f"    Security Headers:")
                for h, v in sec_hdrs.items():
                    status = "PRESENT" if v != "MISSING" else "MISSING"
                    ln(f"      {h}: {status}")
            ln()

    # ─── 8. IOC Table ──────────────────────────────────────────
    sec("8. IOC TABLE — BLOCK/MONITOR ACTIONS")
    classification = risk.get("classification", "LOW")
    action = "BLOCK" if classification in ("CRITICAL", "HIGH") else "MONITOR"
    ln(f"  {'Indicator':<42s} {'Type':<8s} {'Severity':<10s} {'Action':<8s} Notes")
    ln(f"  {'─' * 80}")
    ln(f"  {target:<42s} {target_type.upper():<8s} {classification:<10s} {action:<8s} Primary indicator")

    if otx and otx.get("malware_samples"):
        for m in otx["malware_samples"][:3]:
            if m.get("hash"):
                ln(f"  {m['hash'][:40]:<42s} {'HASH':<8s} {'HIGH':<10s} {'BLOCK':<8s} {m.get('malware_name', '')[:25]}")

    if threatfox and threatfox.get("iocs"):
        for ioc in threatfox["iocs"][:3]:
            ln(f"  {ioc.get('ioc', '')[:40]:<42s} {ioc.get('ioc_type', ''):<8s} {'HIGH':<10s} {'BLOCK':<8s} {ioc.get('malware', '')[:25]}")
    ln()

    # ─── 9. Recommended Actions ────────────────────────────────
    sec("9. RECOMMENDED ACTIONS")
    actions = risk.get("recommended_actions", [])
    for i, act in enumerate(actions, 1):
        ln(f"  {i}. {act}")
    ln()

    # ─── 10. Detection Rules ───────────────────────────────────
    sec("10. DETECTION RULES")

    ln("  Sigma Rule (Firewall):")
    ln(f"  title: Traffic to/from {target}")
    ln(f"  logsource: category: firewall")
    ln(f"  detection:")
    if target_type == "ip":
        ln(f"    selection:")
        ln(f"      DestinationIp|contains: '{target}'")
    else:
        ln(f"    selection:")
        ln(f"      DestinationHostname|contains: '{target}'")
    ln(f"    condition: selection")
    ln(f"  level: {classification.lower()}")
    ln()

    ln("  Splunk Query:")
    ln(f"  index=* (dest_ip=\"{target}\" OR src_ip=\"{target}\" OR dest=\"{target}\")")
    ln(f"  | stats count by src_ip, dest_ip, dest, action, app")
    ln(f"  | sort -count")
    ln()

    ln("  Elastic SIEM (EQL):")
    ln(f"  // Kibana Security > Rules > Create Custom Rule")
    ln(f"  // Rule type: EQL")
    if target_type == "ip":
        ln(f"  network where destination.ip == \"{target}\" or source.ip == \"{target}\"")
    else:
        ln(f"  network where dns.question.name == \"{target}\"")
        ln(f"    or destination.domain == \"{target}\"")
    ln()
    ln("  Elastic SIEM (KQL filter for Detection Rule):")
    if target_type == "ip":
        ln(f"  source.ip: \"{target}\" OR destination.ip: \"{target}\"")
    else:
        ln(f"  dns.question.name: \"{target}\" OR destination.domain: \"{target}\"")
    ln()
    ln("  Elastic SIEM (JSON Rule Import — Kibana API):")
    ln(f'  POST /api/detection_engine/rules')
    ln(f'  {{')
    ln(f'    "name": "Traffic to/from {target}",')
    ln(f'    "description": "Detects connections to investigated indicator {target}",')
    ln(f'    "risk_score": {risk.get("score", 0)},')
    ln(f'    "severity": "{classification.lower()}",')
    if target_type == "ip":
        ln(f'    "type": "eql",')
        ln(f'    "query": "network where destination.ip == \\\"{target}\\\" or source.ip == \\\"{target}\\\"",')
    else:
        ln(f'    "type": "eql",')
        ln(f'    "query": "network where dns.question.name == \\\"{target}\\\" or destination.domain == \\\"{target}\\\"",')
    ln(f'    "risk_score_mapping": [],')
    ln(f'    "severity_mapping": [],')
    ln(f'    "interval": "5m",')
    ln(f'    "from": "now-3600s",')
    ln(f'    "enabled": true,')
    ln(f'    "tags": ["threat-intel", "soc", "custom"],')
    ln(f'    "threat": [{{"framework": "MITRE ATT&CK", "tactic": {{"id": "TA0011", "name": "Command and Control"}}}}]')
    ln(f'  }}')
    ln()

    # --- 11. Appendix ---
    sec("11. APPENDIX — OSINT SOURCES")
    sources = [
        ("AlienVault OTX", f"https://otx.alienvault.com/indicator/ip/{target}"),
        ("AbuseIPDB", f"https://www.abuseipdb.com/check/{target}"),
        ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{target}" if target_type == "ip" else f"https://www.virustotal.com/gui/domain/{target}"),
        ("Shodan", f"https://www.shodan.io/host/{target}" if target_type == "ip" else f"https://www.shodan.io/search?query=hostname:{target}"),
        ("ThreatFox", "https://threatfox.abuse.ch/browse/"),
        ("URLhaus", "https://urlhaus.abuse.ch/browse/"),
        ("IPInfo", f"https://ipinfo.io/{target}"),
    ]
    for name, url in sources:
        ln(f"  {name:<20s} {url}")
    ln()

    # ─── Footer ────────────────────────────────────────────────
    ln("=" * W)
    ln(f"  Report generated: {timestamp} | Classification: {classification}")
    ln(f"  IP/Domain Reputation Tool v1.0")
    ln("=" * W)

    # ─── Save ──────────────────────────────────────────────────
    if not output_path:
        safe_target = target.replace(":", "-").replace("/", "-").replace("\\", "-")
        output_path = f"TI_Report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


# ═══════════════════════════════════════════════════════════════════
# Bulk Report Generators
# ═══════════════════════════════════════════════════════════════════

def generate_bulk_txt_report(results_list: list, output_path: str) -> str:
    """Generate a combined TXT report for multiple targets."""
    from collections import Counter
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    W = 72
    lines = []

    def ln(text=""):
        lines.append(text)

    def sec(title):
        ln()
        ln(f"--- {title} {''.ljust(W - len(title) - 6, chr(0x2500))}")
        ln()

    # Cover
    ln("=" * W)
    ln("  BULK THREAT INTELLIGENCE REPORT")
    ln(f"  {len(results_list)} Target(s) Analyzed")
    ln("=" * W)
    ln(f"  Generated: {timestamp}")
    ln("=" * W)

    # Executive Summary
    sec("EXECUTIVE SUMMARY")
    ln(f"  {'#':<4s} {'Target':<35s} {'Type':<8s} {'Risk':<10s} {'Score':<8s} Status")
    ln(f"  {''.ljust(80, chr(0x2500))}")

    for i, r in enumerate(results_list, 1):
        risk = r.get("risk", {})
        cls = risk.get("classification", "N/A")
        score = risk.get("score", 0)
        is_good = risk.get("is_known_good", False)
        status = "KNOWN GOOD" if is_good else cls
        ln(f"  {i:<4d} {r.get('target', '?'):<35s} {r.get('target_type', '?'):<8s} {cls:<10s} {score:<8d} {status}")
    ln()

    cls_counts = Counter(r.get("risk", {}).get("classification", "N/A") for r in results_list)
    good_count = sum(1 for r in results_list if r.get("risk", {}).get("is_known_good"))
    ln(f"  Summary: {len(results_list)} total | "
       f"{cls_counts.get('CRITICAL', 0)} CRITICAL | "
       f"{cls_counts.get('HIGH', 0)} HIGH | "
       f"{cls_counts.get('MEDIUM', 0)} MEDIUM | "
       f"{cls_counts.get('LOW', 0)} LOW | "
       f"{good_count} known-good")

    # Per-Target Details
    for i, r in enumerate(results_list, 1):
        target = r.get("target", "?")
        risk = r.get("risk", {})
        cls = risk.get("classification", "N/A")
        score = risk.get("score", 0)

        sec(f"TARGET {i}: {target}")

        ln(f"  Type: {r.get('target_type', '?').upper()}  |  Risk: {cls} ({score}/100)  |  "
           f"Known-Good: {'YES' if risk.get('is_known_good') else 'No'}")
        ln()

        # Source verification
        source_statuses = risk.get("source_statuses", {})
        if source_statuses:
            ln("  Source Verification:")
            for src, status in source_statuses.items():
                marker = "+" if status == "CHECKED" else "x"
                ln(f"    [{marker}] {src:<16s} {status}")
            ln()

        # IP profile
        ipinfo = r.get("ipinfo")
        if ipinfo and not ipinfo.get("error"):
            ln(f"  ASN: {ipinfo.get('asn', 'N/A')}  |  ISP: {ipinfo.get('isp', 'N/A')}")
            ln(f"  Country: {ipinfo.get('country', 'N/A')}")
            ln()

        # Signals
        signals = risk.get("signals", [])
        if signals:
            ln("  Signals:")
            for sig in signals[:5]:
                tier = sig.get("tier", "?")
                ln(f"    [{sig['severity']}] {sig['source']}: {sig['signal']} (+{sig['weight']}) T{tier}")
                interp = sig.get("interpretation", "")
                if interp:
                    ln(f"      {interp}")
            ln()

        # Mitigations
        if risk.get("mitigations"):
            ln("  Mitigations:")
            for m in risk["mitigations"]:
                ln(f"    * {m}")
            ln()

        not_checked = risk.get("not_checked_sources", [])
        if not_checked:
            ln(f"  NOT CHECKED: {', '.join(not_checked)}")
            ln()

    # Combined IOC Table
    sec("COMBINED IOC TABLE")
    ln(f"  {'Indicator':<38s} {'Type':<8s} {'Risk':<10s} {'Action'}")
    ln(f"  {''.ljust(72, chr(0x2500))}")
    for r in results_list:
        target = r.get("target", "?")
        risk = r.get("risk", {})
        cls = risk.get("classification", "LOW")
        action = "BLOCK" if cls in ("CRITICAL", "HIGH") else "MONITOR"
        ln(f"  {target:<38s} {r.get('target_type', '?').upper():<8s} {cls:<10s} {action}")
    ln()

    # Footer
    ln("=" * W)
    ln(f"  Report generated: {timestamp}")
    ln(f"  IP/Domain Reputation Tool v1.0 - Bulk Report")
    ln("=" * W)

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def generate_bulk_docx_report(results_list: list, output_path: str) -> str:
    """Generate a combined DOCX report for multiple targets."""
    if not HAS_DOCX:
        raise ImportError("python-docx not installed")

    from collections import Counter

    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    _add_watermark(doc)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_colors = {"CRITICAL": ("E74C3C", True), "HIGH": ("E67E22", True),
                  "MEDIUM": ("F1C40F", False), "LOW": ("27AE60", True)}

    # Cover
    for _ in range(3):
        doc.add_paragraph()

    _add_styled_paragraph(doc, "BULK THREAT INTELLIGENCE REPORT",
                          bold=True, size=Pt(26), color=RGBColor(0, 0x33, 0x66),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_paragraph(doc, f"{len(results_list)} Target(s) Analyzed",
                          size=Pt(14), color=RGBColor(0x66, 0x66, 0x66),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()
    _add_styled_paragraph(doc, f"Generated: {timestamp}", size=Pt(11),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    # Summary
    doc.add_paragraph()
    cls_counts = Counter(r.get("risk", {}).get("classification", "N/A") for r in results_list)
    summary_data = [
        ("Total Targets", str(len(results_list))),
        ("CRITICAL", str(cls_counts.get("CRITICAL", 0))),
        ("HIGH", str(cls_counts.get("HIGH", 0))),
        ("MEDIUM", str(cls_counts.get("MEDIUM", 0))),
        ("LOW", str(cls_counts.get("LOW", 0))),
        ("Known-Good", str(sum(1 for r in results_list if r.get("risk", {}).get("is_known_good")))),
    ]
    st = doc.add_table(rows=len(summary_data), cols=2, style='Light Shading Accent 1')
    st.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, (k, v) in enumerate(summary_data):
        _ct(st.rows[i].cells[0], k, bold=True, size=Pt(10))
        _ct(st.rows[i].cells[1], v, size=Pt(10))

    doc.add_page_break()

    # Executive summary table
    _add_styled_paragraph(doc, "Executive Summary", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    t = doc.add_table(rows=len(results_list) + 1, cols=5, style='Light Shading Accent 1')
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(["#", "Target", "Type", "Risk", "Score"]):
        _ct(t.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
        _set_cell_shading(t.rows[0].cells[j], "003366")

    for i, r in enumerate(results_list):
        row = t.rows[i + 1]
        risk = r.get("risk", {})
        cls = risk.get("classification", "N/A")
        _ct(row.cells[0], str(i + 1), size=Pt(9))
        _ct(row.cells[1], r.get("target", "?")[:35], size=Pt(9))
        _ct(row.cells[2], r.get("target_type", "?").upper(), size=Pt(9))
        hex_c, wt = sev_colors.get(cls, ("95A5A6", True))
        _set_cell_shading(row.cells[3], hex_c)
        _ct(row.cells[3], cls, bold=True, size=Pt(9),
            color=RGBColor(255, 255, 255) if wt else RGBColor(0, 0, 0))
        _ct(row.cells[4], str(risk.get("score", 0)), size=Pt(9))

    doc.add_page_break()

    # Per-target details
    for i, r in enumerate(results_list, 1):
        target = r.get("target", "?")
        risk = r.get("risk", {})
        cls = risk.get("classification", "N/A")

        _add_styled_paragraph(doc, f"Target {i}: {target}",
                              bold=True, size=Pt(14), color=RGBColor(0, 0x33, 0x66))

        ipinfo = r.get("ipinfo")
        if ipinfo and not ipinfo.get("error"):
            profile = [
                ("Target", target), ("Type", r.get("target_type", "?").upper()),
                ("ASN", ipinfo.get("asn", "N/A")), ("ISP", ipinfo.get("isp", "N/A")),
                ("Country", ipinfo.get("country", "N/A")),
            ]
            pt = doc.add_table(rows=len(profile), cols=2, style='Light Shading Accent 1')
            pt.alignment = WD_TABLE_ALIGNMENT.CENTER
            for pi, (k, v) in enumerate(profile):
                _ct(pt.rows[pi].cells[0], k, bold=True, size=Pt(9))
                _ct(pt.rows[pi].cells[1], str(v), size=Pt(9))

        signals = risk.get("signals", [])
        if signals:
            doc.add_paragraph()
            _add_styled_paragraph(doc, "Signals:", bold=True, size=Pt(11))
            for sig in signals[:5]:
                tier = sig.get("tier", "?")
                interp = sig.get("interpretation", "")
                _add_styled_paragraph(doc,
                    f"[{sig['severity']}] {sig['source']}: {sig['signal']} (+{sig['weight']}) T{tier}",
                    size=Pt(9))
                if interp:
                    _add_styled_paragraph(doc, f"  {interp}", size=Pt(8),
                                          color=RGBColor(0x99, 0x99, 0x99))

        not_checked = risk.get("not_checked_sources", [])
        if not_checked:
            _add_styled_paragraph(doc, f"NOT CHECKED: {', '.join(not_checked)}",
                                  size=Pt(9), color=RGBColor(0xE6, 0x7E, 0x22))

        actions = risk.get("recommended_actions", [])
        if actions:
            doc.add_paragraph()
            _add_styled_paragraph(doc, "Recommended Actions:", bold=True, size=Pt(10))
            for ai, act in enumerate(actions[:3], 1):
                _add_styled_paragraph(doc, f"  {ai}. {act}", size=Pt(9))

        if i < len(results_list):
            doc.add_page_break()

    # Combined IOC Table
    doc.add_page_break()
    _add_styled_paragraph(doc, "Combined IOC Table", bold=True, size=Pt(16),
                          color=RGBColor(0, 0x33, 0x66))

    ioc_t = doc.add_table(rows=len(results_list) + 1, cols=4, style='Light Shading Accent 1')
    ioc_t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(["Target", "Type", "Risk", "Action"]):
        _ct(ioc_t.rows[0].cells[j], h, bold=True, size=Pt(9), color=RGBColor(255, 255, 255))
        _set_cell_shading(ioc_t.rows[0].cells[j], "003366")

    for i, r in enumerate(results_list):
        row = ioc_t.rows[i + 1]
        risk = r.get("risk", {})
        cls = risk.get("classification", "LOW")
        action = "BLOCK" if cls in ("CRITICAL", "HIGH") else "MONITOR"
        _ct(row.cells[0], r.get("target", "?")[:35], size=Pt(8))
        _ct(row.cells[1], r.get("target_type", "?").upper(), size=Pt(8))
        hex_c, wt = sev_colors.get(cls, ("95A5A6", True))
        _set_cell_shading(row.cells[2], hex_c)
        _ct(row.cells[2], cls, bold=True, size=Pt(8),
            color=RGBColor(255, 255, 255) if wt else RGBColor(0, 0, 0))
        act_c = "E74C3C" if action == "BLOCK" else "F39C12"
        _set_cell_shading(row.cells[3], act_c)
        _ct(row.cells[3], action, bold=True, size=Pt(8), color=RGBColor(255, 255, 255))

    doc.add_paragraph()
    _add_styled_paragraph(doc, f"Report generated: {timestamp} | IP/Domain Reputation Tool v1.0",
                          size=Pt(8), color=RGBColor(0x99, 0x99, 0x99),
                          alignment=WD_ALIGN_PARAGRAPH.CENTER)

    if not output_path:
        output_path = f"Bulk_Report_{len(results_list)}targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

    try:
        doc.save(output_path)
    except PermissionError:
        output_path = output_path.replace(".docx", "_v2.docx")
        doc.save(output_path)

    return output_path
