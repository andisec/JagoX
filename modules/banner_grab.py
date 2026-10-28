#!/usr/bin/env python3
# banner_grab.py — Pure-Python banner grabber (JagoX v1.0.0)
# Part of JagoX framework
# MIT License
#
# Fitur:
#   - 25+ protokol probe otomatis
#   - TLS/SSL auto-wrap untuk port standar (443, 993, 995, 465, 636, 8443)
#   - Version extraction regex per-service
#   - Service detection dari banner non-standar
#   - Multi-line banner handling (HTTP header)
#   - Parallel scanning via ThreadPoolExecutor
#   - CLI standalone dengan banner dari modules/banner.py
#
# Public API (kompatibel dengan nmpx.py v1.0.0):
#   grab(host, port, timeout=3.0, use_tls=None, max_bytes=4096) -> dict
#   grab_many(targets, timeout=3.0, max_workers=20, on_result=None) -> dict
#   summarize(results) -> list of dict

import socket
import ssl
import re
import time
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"


# ============================================================
# PROBE PAYLOADS
# ============================================================
PROBES = {
    # HTTP / web
    80:    b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: JagoX/1.0\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: JagoX/1.0\r\n\r\n",
    8000:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: JagoX/1.0\r\n\r\n",
    8888:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: JagoX/1.0\r\n\r\n",
    3000:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    5000:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    9000:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    # Mail
    25:    b"EHLO jagoX.local\r\n",
    587:   b"EHLO jagoX.local\r\n",
    465:   b"EHLO jagoX.local\r\n",
    110:   b"USER test\r\n",
    995:   b"USER test\r\n",
    143:   b"a NOOP\r\n",
    993:   b"a NOOP\r\n",
    # File transfer
    21:    b"",
    # Remote shell
    22:    b"",
    23:    b"\r\n",
    # Database / cache
    3306:  b"",
    5432:  b"",
    6379:  b"PING\r\n",
    27017: b"",
    11211: b"version\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    # Remote desktop
    5900:  b"",
    5901:  b"",
    3389:  b"",
    # Directory
    389:   b"",
    636:   b"",
}


# ============================================================
# TLS PORTS
# ============================================================
TLS_PORTS = {
    443, 465, 636, 993, 995, 8443, 4443, 9443, 8883, 990, 992, 994,
    8006,  # Proxmox
    5671,  # AMQPs
}


# ============================================================
# HELPERS
# ============================================================
def _safe_decode(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


# ============================================================
# SERVICE PARSERS
# ============================================================
def parse_ssh(raw):
    m = re.match(r"SSH-([\d\.]+)-(\S+)", raw)
    if m:
        return {"product": m.group(2), "protocol": f"SSH {m.group(1)}"}
    return {}


def parse_ftp(raw):
    m = re.search(r"220[- ](?:\(([^)]+)\)|\s*([^\r\n]+))", raw)
    if m:
        return {"product": (m.group(1) or m.group(2)).strip()}
    return {}


def parse_http(raw):
    result = {}
    m = re.search(r"HTTP/([\d\.]+)\s+(\d+)", raw)
    if m:
        result["protocol"] = f"HTTP/{m.group(1)}"
        result["status"] = m.group(2)
    m = re.search(r"Server:\s*([^\r\n]+)", raw, re.IGNORECASE)
    if m:
        result["product"] = m.group(1).strip()
    m = re.search(r"X-Powered-By:\s*([^\r\n]+)", raw, re.IGNORECASE)
    if m:
        result["powered_by"] = m.group(1).strip()
    return result


def parse_smtp(raw):
    m = re.search(r"220[ -]([^\r\n]+)", raw)
    if m:
        return {"product": m.group(1).strip()[:100]}
    return {}


def parse_pop3(raw):
    m = re.search(r"\+OK[ ]*([^\r\n]*)", raw)
    if m:
        return {"product": m.group(1).strip()[:100]}
    return {}


def parse_imap(raw):
    m = re.search(r"\* OK[ ]*([^\r\n]*)", raw)
    if m:
        return {"product": m.group(1).strip()[:100]}
    return {}


def parse_mysql(raw):
    m = re.search(r"(\d+\.\d+\.\d+[^\x00-\x1f\r\n]*)", raw)
    if m:
        return {"product": f"MySQL {m.group(1)}"[:100]}
    return {}


def parse_redis(raw):
    if "PONG" in raw:
        return {"product": "Redis", "note": "no-auth"}
    m = re.search(r"-ERR[ ]+([^\r\n]+)", raw)
    if m:
        return {"product": f"Redis ({m.group(1)[:60]})"}
    return {}


def parse_memcached(raw):
    m = re.search(r"VERSION\s+(\S+)", raw)
    if m:
        return {"product": f"Memcached {m.group(1)}"}
    return {}


def parse_vnc(raw):
    m = re.search(r"RFB\s+(\d+\.\d+)", raw)
    if m:
        return {"product": f"VNC {m.group(1)}"}
    return {}


def parse_telnet(raw):
    clean = re.sub(r"[\x00-\x1f\x7f]", "", raw).strip()
    if clean:
        return {"product": clean[:100]}
    return {}


SERVICE_PARSERS = {
    "ssh":          parse_ssh,
    "ftp":          parse_ftp,
    "http":         parse_http,
    "https":        parse_http,
    "smtp":         parse_smtp,
    "pop3":         parse_pop3,
    "imap":         parse_imap,
    "mysql":        parse_mysql,
    "redis":        parse_redis,
    "memcached":    parse_memcached,
    "vnc":          parse_vnc,
    "elasticsearch": parse_http,
    "telnet":       parse_telnet,
}


# ============================================================
# SERVICE DETECTION
# ============================================================
BANNER_SIGNATURES = [
    (r"^SSH-",              "ssh"),
    (r"^220.*ESMTP",        "smtp"),
    (r"^220[- ]",           "ftp"),
    (r"^\+OK",              "pop3"),
    (r"^\* OK",             "imap"),
    (r"^HTTP/",             "http"),
    (r"^RFB\s+",            "vnc"),
    (r"^VERSION\s+",        "memcached"),
    (r"^\+PONG",            "redis"),
    (r"^-ERR",              "redis"),
    (r"mysql_native|\\d+\\.\\d+\\.\\d+.*MySQL", "mysql"),
]


def detect_service(raw, port):
    for pattern, svc in BANNER_SIGNATURES:
        if re.search(pattern, raw, re.IGNORECASE | re.MULTILINE):
            return svc
    port_map = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 465: "smtp", 587: "smtp",
        993: "imap", 995: "pop3", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 11211: "memcached", 5900: "vnc", 5901: "vnc",
        9200: "elasticsearch", 27017: "mongodb",
    }
    return port_map.get(int(port), "unknown")


# ============================================================
# CORE: GRAB SINGLE
# ============================================================
def grab(host, port, timeout=3.0, use_tls=None, max_bytes=4096):
    """
    Ambil banner dari host:port.

    Returns dict dengan keys:
        host, port, service, product, banner, raw, protocol,
        tls, error, elapsed_ms, extra
    """
    port = int(port)
    start = time.time()
    info = {
        "host": host,
        "port": port,
        "service": "unknown",
        "product": "",
        "banner": "",
        "raw": "",
        "protocol": "",
        "tls": False,
        "error": None,
        "elapsed_ms": 0,
        "extra": {},
    }

    if use_tls is None:
        use_tls = port in TLS_PORTS
    info["tls"] = use_tls

    conn = None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        conn = sock
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                conn = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError as e:
                info["error"] = f"tls_handshake: {e}"
                info["elapsed_ms"] = int((time.time() - start) * 1000)
                return info

        # Kirim probe
        probe = PROBES.get(port, b"\r\n")
        if probe:
            try:
                conn.sendall(probe)
            except Exception:
                pass

        # Baca respon
        chunks = []
        total = 0
        while total < max_bytes:
            try:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
            except socket.timeout:
                break
            except Exception:
                break

        raw_bytes = b"".join(chunks)
        raw_str = _safe_decode(raw_bytes)
        info["raw"] = raw_str[:2000]

        # Banner
        lines = [l.strip() for l in raw_str.splitlines() if l.strip()]
        info["banner"] = (lines[0] if lines else raw_str[:100])[:200]

        # Deteksi service
        svc = detect_service(raw_str, port)
        info["service"] = svc

        # Parse version
        parser = SERVICE_PARSERS.get(svc)
        if parser:
            try:
                parsed = parser(raw_str)
                if parsed:
                    info["product"] = parsed.get("product", "")
                    info["protocol"] = parsed.get("protocol", "")
                    for k, v in parsed.items():
                        if k not in ("product", "protocol"):
                            info["extra"][k] = v
            except Exception as e:
                info["extra"]["parse_error"] = str(e)

        # Ekstrak versi
        if info["product"]:
            vm = re.search(
                r"([\d]+\.[\d]+(?:\.[\d]+)?(?:[a-zA-Z]?\d*)?)",
                info["product"]
            )
            if vm:
                info["extra"]["version"] = vm.group(1)

    except socket.timeout:
        info["error"] = "timeout"
    except ConnectionRefusedError:
        info["error"] = "refused"
    except socket.gaierror as e:
        info["error"] = f"dns: {e}"
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    finally:
        info["elapsed_ms"] = int((time.time() - start) * 1000)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if sock is not None and sock is not conn:
            try:
                sock.close()
            except Exception:
                pass

    return info


# ============================================================
# PARALLEL GRAB
# ============================================================
def grab_many(targets, timeout=3.0, max_workers=20, on_result=None):
    """
    Grab banner dari banyak target paralel.

    Args:
        targets:     list of (host, port) tuples
        timeout:     per-target timeout
        max_workers: worker paralel
        on_result:   optional callback(info) tiap selesai

    Returns:
        dict: {host: [info1, info2, ...]}  (di-sort by port)
    """
    results = {}
    if not targets:
        return results

    with ThreadPoolExecutor(
            max_workers=min(max_workers, len(targets))) as ex:
        futures = {ex.submit(grab, h, p, timeout): (h, p)
                   for h, p in targets}
        for fut in as_completed(futures):
            h, p = futures[fut]
            try:
                info = fut.result()
            except Exception as e:
                info = {
                    "host": h, "port": int(p), "service": "unknown",
                    "product": "", "banner": "", "raw": "", "protocol": "",
                    "tls": False, "error": f"uncaught: {e}",
                    "elapsed_ms": 0, "extra": {},
                }
            results.setdefault(h, []).append(info)
            if on_result:
                try:
                    on_result(info)
                except Exception:
                    pass

    for h in results:
        results[h].sort(key=lambda x: x["port"])
    return results


# ============================================================
# SUMMARY
# ============================================================
def summarize(results):
    """
    Ringkas hasil grab_many jadi list of dict mudah dicetak.
    """
    rows = []
    for host, infos in results.items():
        for i in infos:
            rows.append({
                "host": host,
                "port": i["port"],
                "service": i["service"],
                "product": i["product"],
                "version": i["extra"].get("version", ""),
                "banner": i["banner"],
                "tls": i["tls"],
                "error": i["error"],
            })
    return rows


# ============================================================
# CLI ENTRY POINT
# ============================================================
def _print_startup_banner():
    """Cetak banner dari modules/banner.py — fallback kalau tak ada."""
    try:
        from . import banner as _bn
    except ImportError:
        try:
            sys.path.insert(
                0, os.path.dirname(os.path.abspath(__file__)))
            import banner as _bn
        except ImportError:
            _bn = None

    if _bn is not None and hasattr(_bn, "print_banner"):
        try:
            from rich.console import Console
            _bn.print_banner(
                console=Console(),
                version=__version__,
                subtitle="Banner Grab Module — Pure Python",
            )
            return
        except ImportError:
            _bn.print_banner()
            return

    # Fallback minimal
    print()
    print("  ====================================")
    print(f"   nmpX v{__version__} — Banner Grab")
    print("  ====================================")
    print()


def _cli():
    _print_startup_banner()

    parser = argparse.ArgumentParser(
        description="JagoX banner_grab — pure-Python banner grabber")
    parser.add_argument("target", help="IP/hostname")
    parser.add_argument(
        "-p", "--ports",
        default="21,22,25,80,443,3306,6379",
        help="Comma-separated ports (default: 21,22,25,80,443,3306,6379)",
    )
    parser.add_argument("-t", "--timeout", type=float, default=3.0)
    parser.add_argument("-w", "--workers", type=int, default=20)
    parser.add_argument(
        "--tls", choices=["auto", "on", "off"], default="auto",
        help="TLS mode: auto (by port), on (force), off (force plain)")
    parser.add_argument(
        "--version", action="version",
        version=f"JagoX banner_grab v{__version__}")
    args = parser.parse_args()

    ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    if not ports:
        print("[!] Tidak ada port valid.")
        sys.exit(1)

    # Override TLS mode
    global TLS_PORTS
    if args.tls == "on":
        TLS_PORTS = set(range(1, 65536))
    elif args.tls == "off":
        TLS_PORTS = set()

    print(f"=== Banner Grab — {args.target} ===")
    print(f"=== Ports: {','.join(str(p) for p in ports)} | "
          f"TLS: {args.tls} | Timeout: {args.timeout}s ===")
    print()

    targets = [(args.target, p) for p in ports]
    results = grab_many(
        targets, timeout=args.timeout, max_workers=args.workers)

    rows = summarize(results)
    if not rows:
        print("[!] Tidak ada hasil.")
        return

    header = (f"{'PORT':>6} {'TLS':<4} {'SERVICE':<14} "
              f"{'PRODUCT':<42} BANNER")
    print(header)
    print("-" * min(130, len(header) + 60))
    for row in rows:
        err = f" [ERR:{row['error']}]" if row["error"] else ""
        tls = "yes" if row["tls"] else "no"
        print(
            f"{row['port']:>6} {tls:<4} {row['service']:<14} "
            f"{(row['product'] or '—')[:40]:<42} "
            f"{row['banner'][:60]}{err}"
        )
    print()
    print(f"Total: {len(rows)} port diuji, "
          f"{sum(1 for r in rows if not r['error'])} sukses, "
          f"{sum(1 for r in rows if r['error'])} error")
    print()


if __name__ == "__main__":
    _cli()
