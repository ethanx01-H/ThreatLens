"""
DNS Reconnaissance & Network Probing Module
Handles DNS lookups, WHOIS, port scanning, and reverse DNS for IP/Domain investigation.
"""

import socket
import subprocess
import time
from typing import Dict, List, Any, Optional
from config import SCAN_PORTS, PORT_SCAN_TIMEOUT, DNS_TIMEOUT


# ═══════════════════════════════════════════════════════════════════
# DNS Resolution
# ═══════════════════════════════════════════════════════════════════

def resolve_dns(domain: str) -> Dict[str, Any]:
    """Full DNS resolution for a domain — A, AAAA, MX, NS, TXT, SOA, CNAME."""
    result = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "soa_record": None,
        "error": None,
    }

    try:
        import dns.resolver
        import dns.reversename

        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        # A records
        try:
            answers = resolver.resolve(domain, "A")
            result["a_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # AAAA records
        try:
            answers = resolver.resolve(domain, "AAAA")
            result["aaaa_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = resolver.resolve(domain, "MX")
            result["mx_records"] = [(str(r.exchange), r.preference) for r in answers]
        except Exception:
            pass

        # NS records
        try:
            answers = resolver.resolve(domain, "NS")
            result["ns_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # TXT records
        try:
            answers = resolver.resolve(domain, "TXT")
            result["txt_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # CNAME records
        try:
            answers = resolver.resolve(domain, "CNAME")
            result["cname_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # SOA record
        try:
            answers = resolver.resolve(domain, "SOA")
            for r in answers:
                result["soa_record"] = {
                    "mname": str(r.mname),
                    "rname": str(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum,
                }
                break
        except Exception:
            pass

    except ImportError:
        result["error"] = "dnspython not installed"
        # Fallback to socket
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            result["a_records"] = list(set(addr[4][0] for addr in ips))
        except socket.gaierror:
            result["error"] = "DNS resolution failed"
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════
# Reverse DNS
# ═══════════════════════════════════════════════════════════════════

def reverse_dns(ip: str) -> Dict[str, Any]:
    """Perform reverse DNS lookup for an IP."""
    result = {
        "ip": ip,
        "hostnames": [],
        "has_rdns": False,
        "error": None,
    }

    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result["hostnames"] = [hostname] + list(aliases)
        result["has_rdns"] = True
    except socket.herror:
        result["error"] = "No reverse DNS record"
    except socket.gaierror:
        result["error"] = "DNS lookup failed"
    except Exception as e:
        result["error"] = str(e)

    # Also try dig if available
    try:
        proc = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True, text=True, timeout=DNS_TIMEOUT,
        )
        dig_results = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        for h in dig_results:
            h = h.rstrip(".")
            if h not in result["hostnames"]:
                result["hostnames"].append(h)
        if dig_results:
            result["has_rdns"] = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return result


# ═══════════════════════════════════════════════════════════════════
# WHOIS Lookup
# ═══════════════════════════════════════════════════════════════════

def whois_lookup(target: str) -> Dict[str, Any]:
    """WHOIS lookup for IP or domain."""
    result = {
        "target": target,
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "name_servers": [],
        "registrant_org": "",
        "registrant_country": "",
        "whois_raw": "",
        "error": None,
    }

    try:
        import whois
        w = whois.whois(target)

        result["registrar"] = str(w.registrar or "")
        result["registrant_org"] = str(w.org or "")
        result["registrant_country"] = str(w.country or "")

        # Handle dates
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd:
            result["creation_date"] = str(cd)[:10]

        ed = w.expiration_date
        if isinstance(ed, list):
            ed = ed[0]
        if ed:
            result["expiration_date"] = str(ed)[:10]

        # Name servers
        ns = w.name_servers
        if isinstance(ns, str):
            result["name_servers"] = [ns]
        elif isinstance(ns, list):
            result["name_servers"] = [str(n).lower() for n in ns]

    except ImportError:
        result["error"] = "python-whois not installed"
    except Exception as e:
        result["error"] = f"WHOIS failed: {str(e)[:100]}"

    # Fallback: try system whois command
    if result["error"]:
        try:
            proc = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0 and proc.stdout:
                result["whois_raw"] = proc.stdout[:2000]
                result["error"] = None
                # Basic parsing
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line.lower().startswith("registrar:") and not result["registrar"]:
                        result["registrar"] = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("orgname:") and not result["registrant_org"]:
                        result["registrant_org"] = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("country:") and not result["registrant_country"]:
                        result["registrant_country"] = line.split(":", 1)[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return result


# ═══════════════════════════════════════════════════════════════════
# Port Scanning
# ═══════════════════════════════════════════════════════════════════

def port_scan(ip: str, ports: List[int] = None, timeout: float = PORT_SCAN_TIMEOUT) -> Dict[str, Any]:
    """TCP port scan using socket connect."""
    if ports is None:
        ports = SCAN_PORTS

    result = {
        "ip": ip,
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "service_banners": {},
        "scan_time": 0,
        "error": None,
    }

    start = time.time()

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((ip, port))
            if code == 0:
                result["open_ports"].append(port)
                # Try banner grab
                try:
                    sock.settimeout(1)
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        result["service_banners"][port] = banner[:200]
                except Exception:
                    pass
            else:
                result["closed_ports"].append(port)
            sock.close()
        except socket.timeout:
            result["filtered_ports"].append(port)
        except Exception:
            result["filtered_ports"].append(port)

    result["scan_time"] = round(time.time() - start, 2)
    return result


# ═══════════════════════════════════════════════════════════════════
# HTTP/HTTPS Probe
# ═══════════════════════════════════════════════════════════════════

def http_probe(target: str) -> Dict[str, Any]:
    """Probe HTTP/HTTPS for headers and TLS info."""
    import requests as req

    result = {
        "target": target,
        "http_status": None,
        "https_status": None,
        "server_header": "",
        "content_type": "",
        "security_headers": {},
        "tls_version": "",
        "tls_cert_issuer": "",
        "tls_cert_subject": "",
        "tls_cert_expires": "",
        "redirects": [],
        "error": None,
    }

    for scheme in ["https", "http"]:
        try:
            resp = req.get(
                f"{scheme}://{target}",
                timeout=5,
                allow_redirects=True,
                verify=False,
            )
            if scheme == "https":
                result["https_status"] = resp.status_code
            else:
                result["http_status"] = resp.status_code

            result["server_header"] = resp.headers.get("Server", "")
            result["content_type"] = resp.headers.get("Content-Type", "")

            # Security headers check
            sec_headers = [
                "X-Frame-Options", "X-Content-Type-Options",
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-XSS-Protection", "Referrer-Policy",
                "Permissions-Policy", "X-Permitted-Cross-Domain-Policies",
            ]
            for h in sec_headers:
                result["security_headers"][h] = resp.headers.get(h, "MISSING")

            # Redirect chain
            if resp.history:
                result["redirects"] = [r.url for r in resp.history]

            # TLS info from urllib3
            if scheme == "https":
                try:
                    import ssl
                    import urllib.parse
                    parsed = urllib.parse.urlparse(resp.url)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(socket.socket(), server_hostname=parsed.hostname) as s:
                        s.settimeout(3)
                        s.connect((parsed.hostname, 443))
                        cert = s.getpeercert(binary_form=False)
                        if cert:
                            result["tls_cert_subject"] = str(cert.get("subject", ""))
                            result["tls_cert_issuer"] = str(cert.get("issuer", ""))
                            result["tls_cert_expires"] = str(cert.get("notAfter", ""))
                            result["tls_version"] = s.version()
                except Exception:
                    pass

            break  # Got a response, don't try the other scheme
        except Exception:
            continue

    if result["http_status"] is None and result["https_status"] is None:
        result["error"] = "No HTTP/HTTPS response"

    return result


# ═══════════════════════════════════════════════════════════════════
# Comprehensive DNS+Network Recon for Domain
# ═══════════════════════════════════════════════════════════════════

def full_domain_recon(domain: str) -> Dict[str, Any]:
    """Complete network reconnaissance for a domain."""
    results = {
        "dns": resolve_dns(domain),
        "whois": whois_lookup(domain),
        "http_probe": http_probe(domain),
        "resolved_ips": [],
    }

    # Get resolved IPs for port scanning
    ips = results["dns"].get("a_records", [])
    results["resolved_ips"] = ips

    # Port scan first resolved IP
    if ips:
        results["port_scan"] = port_scan(ips[0])
        results["reverse_dns"] = reverse_dns(ips[0])
    else:
        results["port_scan"] = {"open_ports": [], "error": "No IPs resolved"}
        results["reverse_dns"] = {"hostnames": [], "error": "No IPs resolved"}

    return results


# ═══════════════════════════════════════════════════════════════════
# Comprehensive Network Recon for IP
# ═══════════════════════════════════════════════════════════════════

def full_ip_recon(ip: str) -> Dict[str, Any]:
    """Complete network reconnaissance for an IP address."""
    results = {
        "reverse_dns": reverse_dns(ip),
        "whois": whois_lookup(ip),
        "port_scan": port_scan(ip),
        "http_probe": None,
    }

    # Try HTTP probe if common web ports are open
    open_ports = results["port_scan"].get("open_ports", [])
    if 80 in open_ports or 443 in open_ports:
        results["http_probe"] = http_probe(ip)

    return results
