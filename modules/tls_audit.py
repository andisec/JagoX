#!/usr/bin/env python3
# tls_audit.py — TLS/SSL deep audit (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Fitur:
#   - Cek versi TLS yang didukung (1.0 / 1.1 / 1.2 / 1.3)
#   - Cert info (subject, issuer, SAN, expiry, sig alg)
#   - Weak cipher detection (RC4, DES, 3DES, NULL, EXPORT, anon, MD5)
#   - Forward secrecy check (ECDHE/DHE)
#   - ALPN (h2, http/1.1)
#   - OCSP stapling check
#   - HSTS via HTTP request
#   - Chain trust validation (self-signed detection)
#
# Public API (kompatibel dengan nmpx.py v1.0.0):
#   audit(host, port=443, timeout=5) -> dict {
#       host, port, supported_versions, cert, cipher, alpn, ocsp,
#       hsts, findings
#   }

import socket
import ssl
import datetime
import re
import urllib.request
import urllib.error

__version__ = "1.0.0"


# ============================================================
# KONSTANTA
# ============================================================
WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon",
    "ADH", "AECDH",
]


# ============================================================
# TLS VERSION CHECK
# ============================================================
def _try_version(host, port, version, timeout=5):
    """Coba konek dengan versi TLS spesifik. Return True kalau sukses."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


# ============================================================
# CERT + CIPHER INFO
# ============================================================
def _get_cert_info(host, port, timeout=5):
    """Ambil cert + cipher + ALPN + OCSP."""
    result = {
        "cert": None, "cipher": None, "alpn": None,
        "ocsp": False, "self_signed": False,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["cert"] = ssock.getpeercert()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = {
                        "name": cipher_info[0],
                        "protocol": cipher_info[1],
                        "bits": cipher_info[2],
                    }
                try:
                    result["alpn"] = ssock.selected_alpn_protocol()
                except Exception:
                    pass
                # OCSP stapling
                try:
                    result["ocsp"] = ssock.ocsp_response() is not None
                except Exception:
                    pass
                # Self-signed detection (issuer == subject)
                if result["cert"]:
                    subj = tuple(result["cert"].get("subject", ()))
                    iss = tuple(result["cert"].get("issuer", ()))
                    if subj and subj == iss:
                        result["self_signed"] = True
    except Exception:
        pass
    return result


def _parse_cert(cert):
    """Parse certificate dict jadi info berguna."""
    if not cert:
        return {}
    info = {
        "subject": "", "issuer": "", "san": [],
        "not_before": "", "not_after": "", "days_until_expiry": None,
    }
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                info["subject"] = v
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            if k == "commonName":
                info["issuer"] = v
            elif k == "organizationName" and not info["issuer"]:
                info["issuer"] = v
    for k, v in cert.get("subjectAltName", ()):
        if k == "DNS":
            info["san"].append(v)
    info["not_before"] = cert.get("notBefore", "")
    info["not_after"] = cert.get("notAfter", "")
    try:
        exp = datetime.datetime.strptime(
            info["not_after"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        info["days_until_expiry"] = (exp - now).days
    except Exception:
        pass
    return info


# ============================================================
# HSTS CHECK
# ============================================================
def _check_hsts(host, port=443, timeout=5):
    """Cek header HSTS via request."""
    try:
        url = (f"https://{host}/" if port == 443
                else f"https://{host}:{port}/")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0)"})
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=ctx) as r:
            return r.headers.get("Strict-Transport-Security", "")
    except Exception:
        return ""


# ============================================================
# MAIN AUDIT
# ============================================================
def audit(host, port=443, timeout=5):
    """
    Audit TLS pada host:port.

    Returns:
        dict {
            host, port,
            supported_versions: [str],
            cert: {subject, issuer, san, not_before, not_after,
                    days_until_expiry},
            cipher: {name, protocol, bits},
            alpn: str,
            ocsp: bool,
            hsts: str,
            self_signed: bool,
            findings: [ {type, severity, detail} ],
        }
    """
    findings = []

    # === 1. Versi TLS ===
    version_map = [
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ]
    supported = []
    for name, ver in version_map:
        try:
            if _try_version(host, port, ver, timeout):
                supported.append(name)
                if name in ("TLS 1.0", "TLS 1.1"):
                    findings.append({
                        "type": "weak_tls_version",
                        "severity": "HIGH",
                        "detail": (f"{name} didukung (deprecated, "
                                   f"rentan POODLE/BEAST)"),
                    })
        except Exception:
            continue

    if not supported:
        findings.append({
            "type": "connect_error",
            "severity": "INFO",
            "detail": f"Tidak bisa connect TLS ke {host}:{port}",
        })
        return {
            "host": host, "port": port,
            "supported_versions": [], "cert": {}, "cipher": None,
            "alpn": None, "ocsp": False, "hsts": "",
            "self_signed": False,
            "findings": findings,
        }

    # === 2. Cert + Cipher + ALPN ===
    conn_info = _get_cert_info(host, port, timeout)
    cert_info = _parse_cert(conn_info.get("cert"))
    cipher = conn_info.get("cipher")
    self_signed = conn_info.get("self_signed", False)

    # Cert expiry
    days = cert_info.get("days_until_expiry")
    if days is not None:
        if days < 0:
            findings.append({
                "type": "cert_expired",
                "severity": "CRITICAL",
                "detail": f"Sertifikat expired {abs(days)} hari lalu",
            })
        elif days < 30:
            findings.append({
                "type": "cert_expiring",
                "severity": "HIGH",
                "detail": f"Sertifikat kadaluarsa dalam {days} hari",
            })

    # Self-signed
    if self_signed:
        findings.append({
            "type": "self_signed_cert",
            "severity": "MEDIUM",
            "detail": "Sertifikat self-signed (issuer == subject)",
        })

    # Weak cipher
    if cipher:
        cname = cipher["name"]
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw in cname.upper():
                findings.append({
                    "type": "weak_cipher",
                    "severity": "HIGH",
                    "detail": f"Cipher lemah: {cname}",
                })
                break
        # Forward secrecy
        if not re.search(r"ECDHE|DHE", cname, re.IGNORECASE):
            findings.append({
                "type": "no_forward_secrecy",
                "severity": "MEDIUM",
                "detail": f"Cipher {cname} tanpa forward secrecy",
            })

    # === 3. ALPN / H2 ===
    alpn = conn_info.get("alpn")
    if alpn == "h2":
        findings.append({
            "type": "http2_supported",
            "severity": "INFO",
            "detail": "HTTP/2 (h2) didukung via ALPN",
        })

    # === 4. OCSP stapling ===
    if not conn_info.get("ocsp"):
        findings.append({
            "type": "no_ocsp_stapling",
            "severity": "LOW",
            "detail": "OCSP stapling tidak aktif",
        })

    # === 5. HSTS ===
    hsts = _check_hsts(host, port, timeout)
    if not hsts:
        findings.append({
            "type": "no_hsts",
            "severity": "MEDIUM",
            "detail": "Header Strict-Transport-Security tidak ada",
        })
    elif "max-age=0" in hsts.lower():
        findings.append({
            "type": "weak_hsts",
            "severity": "MEDIUM",
            "detail": f"HSTS max-age=0 (efektif nonaktif): {hsts[:60]}",
        })

    return {
        "host": host, "port": port,
        "supported_versions": supported,
        "cert": cert_info,
        "cipher": cipher,
        "alpn": alpn,
        "ocsp": conn_info.get("ocsp", False),
        "hsts": hsts,
        "self_signed": self_signed,
        "findings": findings,
    }


# ============================================================
# CLI
# ============================================================
def _cli():
    import argparse
    import sys
    import os

    try:
        from . import banner as _bn
    except ImportError:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import banner as _bn
        except ImportError:
            _bn = None
    if _bn is not None:
        try:
            from rich.console import Console
            _bn.print_banner(console=Console(), version=__version__,
                              subtitle="TLS Deep Audit — Pure Python")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX tls_audit — TLS/SSL deep audit")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("--version", action="version",
                        version=f"JagoX tls_audit v{__version__}")
    args = parser.parse_args()

    print(f"=== TLS Audit — {args.host}:{args.port} ===\n")
    r = audit(args.host, port=args.port, timeout=args.timeout)

    print(f"Versi TLS didukung : "
          f"{', '.join(r['supported_versions']) or 'N/A'}")
    if r.get("cipher"):
        print(f"Cipher aktif       : "
              f"{r['cipher']['name']} ({r['cipher']['bits']} bit)")
    if r.get("alpn"):
        print(f"ALPN               : {r['alpn']}")
    print(f"OCSP stapling      : {'Ya' if r.get('ocsp') else 'Tidak'}")
    print(f"Self-signed        : {'Ya' if r.get('self_signed') else 'Tidak'}")
    if r.get("hsts"):
        print(f"HSTS               : {r['hsts'][:60]}")

    cert = r.get("cert", {})
    if cert:
        print(f"\nCert Subject  : {cert.get('subject', 'N/A')}")
        print(f"Cert Issuer   : {cert.get('issuer', 'N/A')}")
        print(f"Cert Expiry   : {cert.get('not_after', 'N/A')} "
              f"({cert.get('days_until_expiry', '?')} hari lagi)")
        if cert.get("san"):
            print(f"Cert SAN      : {', '.join(cert['san'][:5])}")

    print(f"\n=== Findings ({len(r['findings'])}) ===")
    if not r["findings"]:
        print("[OK] Tidak ada temuan.")
        return
    for f in r["findings"]:
        print(f"[{f['severity']:<8}] {f['type']:<24} {f['detail']}")


if __name__ == "__main__":
    _cli()
