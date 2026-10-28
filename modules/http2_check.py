#!/usr/bin/env python3
# http2_check.py — HTTP/2 detection (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# CATATAN: Modul ini HANYA deteksi (read-only). TIDAK melakukan:
#   - Request smuggling (CL.TE, TE.CL, H2.CL)
#   - ALPN downgrade attack
#   - Frame manipulation yang bisa rusak server/proxy
#
# Fitur aman:
#   - ALPN negotiation check (h2 / http/1.1)
#   - HTTP/2 cleartext (h2c) via Upgrade header
#   - Server header detection
#   - HTTP/2 SETTINGS frame peek (read-only, 1 frame)
#   - Alt-Svc header detection
#
# Public API (kompatibel nmpx.py v1.0.0):
#   check(host, port=443, timeout=5) -> dict {
#       host, port, alpn, h2_over_tls, h2c_supported,
#       settings, server, alt_svc, findings
#   }

import socket
import ssl
import urllib.request
import urllib.error

__version__ = "1.0.0"


# ============================================================
# HELPERS
# ============================================================
def _make_ctx(alpn=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    return ctx


def _check_alpn(host, port=443, timeout=5):
    """Cek hasil negosiasi ALPN."""
    try:
        ctx = _make_ctx(alpn=["h2", "http/1.1"])
        with socket.create_connection((host, port),
                                        timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol()
    except Exception:
        return None


def _check_h2c(host, port=80, timeout=5):
    """Cek HTTP/2 cleartext via Upgrade header (read-only)."""
    try:
        req = urllib.request.Request(
            f"http://{host}:{port}/",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0 h2)",
                "Connection": "Upgrade, HTTP2-Settings",
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
            })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 101:
                return True
            upgrade = resp.headers.get("Upgrade", "").lower()
            return "h2c" in upgrade
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False


def _get_server_info(url, timeout=5):
    """Ambil Server + Alt-Svc header via HTTP request biasa."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0)"})
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_make_ctx()) as resp:
            return {
                "server": resp.headers.get("Server", ""),
                "alt_svc": resp.headers.get("Alt-Svc", ""),
                "status": resp.status,
                "proto": resp.version,  # 10=HTTP/1.0, 11=HTTP/1.1, 20=HTTP/2
            }
    except urllib.error.HTTPError as e:
        return {
            "server": e.headers.get("Server", "") if e.headers else "",
            "alt_svc": e.headers.get("Alt-Svc", "") if e.headers else "",
            "status": e.code,
            "proto": 0,
        }
    except Exception:
        return None


def _parse_settings_frame(host, port=443, timeout=5):
    """
    Baca HTTP/2 SETTINGS frame pertama (read-only, peek 1 frame).
    Return dict {frame_type, length, flags, stream_id, frame_name} atau None.
    """
    try:
        ctx = _make_ctx(alpn=["h2"])
        with socket.create_connection((host, port),
                                        timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                if ssock.selected_alpn_protocol() != "h2":
                    return None

                # Kirim HTTP/2 preface + empty SETTINGS
                preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
                ssock.sendall(preface + settings_frame)

                # Baca 9 byte header frame dari server
                header = ssock.recv(9)
                if len(header) < 9:
                    return None

                length = int.from_bytes(header[0:3], "big")
                frame_type = header[3]
                flags = header[4]
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF

                frame_names = {
                    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
                    4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING",
                    7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION",
                }
                return {
                    "frame_type": frame_type,
                    "length": length,
                    "flags": flags,
                    "stream_id": stream_id,
                    "frame_name": frame_names.get(frame_type,
                                                    f"UNKNOWN_{frame_type}"),
                }
    except Exception:
        return None


# ============================================================
# MAIN CHECK
# ============================================================
def check(host, port=443, timeout=5):
    """
    Cek HTTP/2 support + header analysis.

    Args:
        host:    target IP/hostname
        port:    port (default 443)
        timeout: timeout per koneksi

    Returns:
        dict {
            host, port,
            alpn: str,
            h2_over_tls: bool,
            h2c_supported: bool,
            settings: dict | None,
            server: str,
            alt_svc: str,
            findings: [ {type, severity, detail} ],
        }
    """
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}/"

    # 1. ALPN check
    alpn = _check_alpn(host, port, timeout)
    h2_over_tls = (alpn == "h2")

    # 2. h2c check
    h2c = _check_h2c(host, port=80, timeout=timeout)

    # 3. Server header
    info = _get_server_info(base_url, timeout=timeout)
    server_header = (info or {}).get("server", "")
    alt_svc = (info or {}).get("alt_svc", "")

    # 4. SETTINGS frame peek (kalau h2 over TLS)
    settings = None
    if h2_over_tls:
        settings = _parse_settings_frame(host, port, timeout)

    # === Findings ===
    if h2_over_tls:
        findings.append({
            "type": "h2_supported",
            "severity": "INFO",
            "detail": "HTTP/2 (h2) via ALPN — modern, baik",
        })
    else:
        findings.append({
            "type": "no_h2",
            "severity": "LOW",
            "detail": f"HTTP/2 tidak aktif (ALPN={alpn or 'none'})",
        })

    if h2c:
        findings.append({
            "type": "h2c_enabled",
            "severity": "MEDIUM",
            "detail": "HTTP/2 cleartext (h2c) aktif — tanpa TLS",
        })

    if server_header and any(c.isdigit() for c in server_header):
        findings.append({
            "type": "server_version_leak",
            "severity": "LOW",
            "detail": f"Server header: {server_header[:60]}",
        })

    if alt_svc:
        findings.append({
            "type": "alt_svc_present",
            "severity": "INFO",
            "detail": f"Alt-Svc: {alt_svc[:80]}",
        })

    if settings and settings.get("frame_type") == 4:
        findings.append({
            "type": "h2_settings_received",
            "severity": "INFO",
            "detail": (f"SETTINGS frame diterima "
                        f"({settings['length']} bytes)"),
        })

    return {
        "host": host,
        "port": port,
        "alpn": alpn,
        "h2_over_tls": h2_over_tls,
        "h2c_supported": h2c,
        "settings": settings,
        "server": server_header,
        "alt_svc": alt_svc,
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
                              subtitle="HTTP/2 Check — Read-Only")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX http2_check — safe HTTP/2 detection")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("--version", action="version",
                        version=f"JagoX http2_check v{__version__}")
    args = parser.parse_args()

    print(f"=== HTTP/2 Check — {args.host}:{args.port} ===\n")
    r = check(args.host, port=args.port, timeout=args.timeout)

    print(f"ALPN                 : {r['alpn'] or 'none'}")
    print(f"HTTP/2 over TLS      : {'Ya' if r['h2_over_tls'] else 'Tidak'}")
    print(f"HTTP/2 cleartext(h2c): "
          f"{'Ya' if r['h2c_supported'] else 'Tidak'}")
    print(f"Server header        : {r['server'][:60] or 'none'}")
    print(f"Alt-Svc              : {r['alt_svc'][:60] or 'none'}")
    if r["settings"]:
        print(f"First frame          : "
              f"{r['settings']['frame_name']} "
              f"({r['settings']['length']} bytes)")

    print(f"\n=== Findings ({len(r['findings'])}) ===")
    for f in r["findings"]:
        print(f"[{f['severity']:<8}] {f['type']:<24} {f['detail']}")


if __name__ == "__main__":
    _cli()
