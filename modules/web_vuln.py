#!/usr/bin/env python3
# web_vuln.py — Comprehensive pure-Python web vulnerability scanner
# Part of JagoX framework — v1.0.0
# MIT License
#
# Fitur lengkap:
#   - Security headers audit (HSTS, CSP, X-Frame, X-Content-Type, dll)
#   - Server / X-Powered-By leak detection
#   - Cookie security flags (Secure, HttpOnly, SameSite)
#   - CORS misconfiguration detection
#   - HTTP methods audit (OPTIONS / Allow header)
#   - Exposed sensitive paths (.git, .env, admin, .htaccess, dll)
#   - Directory listing detection
#   - HTML comment disclosure (password, TODO, FIXME, version, dsb)
#   - Clickjacking detection (X-Frame-Options)
#   - Open redirect probe (via parameter)
#   - LFI / Path traversal probe (via parameter)
#   - HSTS / SSL basic check
#   - HTML meta / generator info disclosure
#
# Semua request HTTP murni via urllib stdlib. Zero external deps.
#
# Public API:
#   check_web(url, timeout=5, delay_ms=0, fast=False) -> list of findings
#   extract_param_links(body, base_url) -> list of URLs with query params
#
# Finding dict:
#   {
#       "type":     str,     # kategori temuan
#       "severity": str,     # CRITICAL / HIGH / MEDIUM / LOW / INFO
#       "detail":   str,     # penjelasan singkat
#       "evidence": str,     # opsional — cuplikan bukti
#   }

import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error


__version__ = "1.0.0"


# ============================================================
# KONFIGURASI PEMERIKSAAN
# ============================================================

# Header keamanan yang WAJIB ada (missing = temuan)
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "desc": "HSTS tidak diset — browser bisa fallback ke HTTP",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "X-Frame-Options tidak ada — rentan clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "desc": "X-Content-Type-Options tidak ada — MIME sniffing",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "desc": "CSP tidak ada — mitigasi XSS lebih lemah",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Referrer-Policy tidak ada — info referrer bocor",
    },
    "Permissions-Policy": {
        "severity": "INFO",
        "desc": "Permissions-Policy tidak ada — fitur browser kurang dibatasi",
    },
}

# Header server yang membocorkan info
LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"]

# Path sensitif yang umum bocor
SENSITIVE_PATHS = [
    # Format: (path, severity, deskripsi)
    ("/.git/config",       "CRITICAL", "Git repository bocor (.git/config)"),
    ("/.git/HEAD",         "CRITICAL", "Git HEAD bocor"),
    ("/.env",              "CRITICAL", "Environment file bocor (.env)"),
    ("/.env.local",        "CRITICAL", "Environment file bocor (.env.local)"),
    ("/.env.backup",       "CRITICAL", "Backup env bocor"),
    ("/.htaccess",         "HIGH",     ".htaccess bocor"),
    ("/.htpasswd",         "CRITICAL", ".htpasswd bocor"),
    ("/server-status",     "HIGH",     "Apache server-status terbuka"),
    ("/phpinfo.php",       "HIGH",     "phpinfo() terbuka"),
    ("/info.php",          "HIGH",     "info.php terbuka"),
    ("/test.php",          "MEDIUM",   "test.php terbuka"),
    ("/admin",             "MEDIUM",   "Panel admin terdeteksi"),
    ("/administrator",     "MEDIUM",   "Panel admin Joomla terdeteksi"),
    ("/wp-admin/",         "MEDIUM",   "WordPress admin terdeteksi"),
    ("/wp-config.php",     "CRITICAL", "WordPress config bocor"),
    ("/web.config",        "HIGH",     "IIS web.config bocor"),
    ("/backup.zip",        "CRITICAL", "Backup zip terdeteksi"),
    ("/backup.sql",        "CRITICAL", "Backup SQL terdeteksi"),
    ("/db.sql",            "CRITICAL", "Database dump terdeteksi"),
    ("/composer.json",     "MEDIUM",   "composer.json terbaca"),
    ("/package.json",      "LOW",      "package.json terbaca"),
    ("/Dockerfile",        "MEDIUM",   "Dockerfile terbaca"),
    ("/.dockerignore",     "LOW",      ".dockerignore terbaca"),
    ("/.DS_Store",         "LOW",      ".DS_Store bocor"),
    ("/crossdomain.xml",   "LOW",      "crossdomain.xml terdeteksi"),
    ("/sitemap.xml",       "INFO",     "sitemap.xml ada"),
    ("/robots.txt",        "INFO",     "robots.txt ada"),
]

# Pattern directory listing
DIR_LISTING_PATTERNS = [
    r"<title>Index of /",
    r"<h1>Index of /",
    r"\[To Parent Directory\]",
    r"<title>Directory listing for",
    r"<h1>Directory listing for",
]

# Pattern HTML comment yang membocorkan info
COMMENT_DISCLOSURE_PATTERNS = [
    (r"password\s*[:=]",        "HIGH",   "Kata 'password' di HTML comment"),
    (r"api[_-]?key\s*[:=]",     "HIGH",   "Kata 'api_key' di HTML comment"),
    (r"secret\s*[:=]",          "HIGH",   "Kata 'secret' di HTML comment"),
    (r"token\s*[:=]",           "HIGH",   "Kata 'token' di HTML comment"),
    (r"\bTODO\b",               "LOW",    "TODO di HTML comment"),
    (r"\bFIXME\b",              "LOW",    "FIXME di HTML comment"),
    (r"debug\s*=\s*true",       "MEDIUM", "Debug mode aktif (comment)"),
    (r"DB_[A-Z_]+\s*[:=]",      "HIGH",   "Variabel DB di comment"),
]

# HTTP methods yang dianggap berbahaya kalau diizinkan
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

# Payload open redirect (query param name → payload)
OPEN_REDIRECT_PARAMS = ["url", "next", "redirect", "return", "continue",
                        "dest", "destination", "redir", "returnUrl"]
OPEN_REDIRECT_PAYLOAD = "//evil.example.com/"

# Payload LFI / Path traversal
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
]
LFI_SUCCESS_PATTERN = re.compile(r"root:x?:\d*:\d*:|root:.*:0:0:")


# ============================================================
# LOW-LEVEL HTTP HELPERS
# ============================================================
def _make_ctx():
    """Buat SSL context yang menerima semua sertifikat (self-signed ok)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=5, delay_ms=0, method="GET", follow_redirects=True,
           extra_headers=None):
    """
    Fetch URL, return dict {status, headers, body, error, redirect_chain}.

    `follow_redirects=False` berguna untuk deteksi open redirect.
    """
    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; nmpX/0.5)",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, headers=headers, method=method)

    # urllib tidak punya opsi "follow_redirects=False" langsung,
    # tapi kita bisa pasang handler default yang menolak redirect
    handlers = []
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        handlers.append(NoRedirect())

    opener = urllib.request.build_opener(*handlers)
    result = {
        "status": 0,
        "headers": {},
        "body": "",
        "error": None,
        "redirect_chain": [],
        "url": url,
    }

    try:
        with opener.open(req, timeout=timeout) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["url"] = resp.geturl()
            try:
                body_bytes = resp.read(65536)  # batas 64KB
            except Exception:
                body_bytes = b""
            result["body"] = body_bytes.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        # HTTP error (4xx, 5xx) tetap kita anggap response valid
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
        except Exception:
            pass
        try:
            body_bytes = e.read(65536)
            result["body"] = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass
        result["error"] = None  # bukan network error
    except urllib.error.URLError as e:
        result["error"] = f"URLError: {e.reason}"
    except ssl.SSLError as e:
        result["error"] = f"SSLError: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ============================================================
# CHECKS — satu fungsi per pemeriksaan
# ============================================================
def _check_security_headers(headers):
    """Cek security headers yang hilang atau salah set."""
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}

    for header, cfg in SECURITY_HEADERS.items():
        if header.lower() not in lower:
            findings.append({
                "type": "missing_header",
                "severity": cfg["severity"],
                "detail": f"{header} tidak diset — {cfg['desc']}",
                "evidence": "",
            })

    # Cek HSTS khusus hanya jika scheme HTTPS
    hsts = lower.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.lower():
        findings.append({
            "type": "weak_hsts",
            "severity": "MEDIUM",
            "detail": "HSTS dengan max-age=0 (efektif nonaktif)",
            "evidence": hsts,
        })

    # Cek CSP yang lemah
    csp = lower.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp.lower():
        findings.append({
            "type": "weak_csp",
            "severity": "MEDIUM",
            "detail": "CSP mengandung 'unsafe-inline' (XSS lebih mudah)",
            "evidence": csp[:120],
        })
    if csp and "unsafe-eval" in csp.lower():
        findings.append({
            "type": "weak_csp",
            "severity": "MEDIUM",
            "detail": "CSP mengandung 'unsafe-eval'",
            "evidence": csp[:120],
        })

    return findings


def _check_server_leak(headers):
    """Deteksi header yang membocorkan info server."""
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    for h in LEAK_HEADERS:
        v = lower.get(h.lower())
        if v:
            findings.append({
                "type": "server_leak",
                "severity": "INFO",
                "detail": f"{h}: {v}",
                "evidence": v[:100],
            })
    return findings


def _check_cookies(headers):
    """Cek set-cookie dengan flag keamanan."""
    findings = []
    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            cookies.append(v)

    for cookie in cookies:
        c_lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        issues = []
        if "secure" not in c_lower:
            issues.append("tanpa Secure")
        if "httponly" not in c_lower:
            issues.append("tanpa HttpOnly")
        if "samesite" not in c_lower:
            issues.append("tanpa SameSite")
        if issues:
            findings.append({
                "type": "insecure_cookie",
                "severity": "MEDIUM" if "HttpOnly" in " ".join(issues) else "LOW",
                "detail": f"Cookie '{name}': {', '.join(issues)}",
                "evidence": cookie[:100],
            })
    return findings


def _check_cors(headers):
    """Deteksi CORS misconfiguration."""
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append({
            "type": "cors_misconfig",
            "severity": "HIGH",
            "detail": "CORS: ACAO=* dengan credentials=true (sangat berbahaya)",
            "evidence": f"ACAO={acao} ACAC={acac}",
        })
    elif acao == "*":
        findings.append({
            "type": "cors_wildcard",
            "severity": "LOW",
            "detail": "CORS: Access-Control-Allow-Origin=*",
            "evidence": f"ACAO={acao}",
        })
    return findings


def _check_http_methods(url, timeout, delay_ms):
    """Cek HTTP methods yang diizinkan via OPTIONS."""
    findings = []
    resp = _fetch(url, timeout=timeout, delay_ms=delay_ms, method="OPTIONS")
    if resp["error"]:
        return findings

    allow = ""
    for k, v in resp["headers"].items():
        if k.lower() in ("allow", "access-control-allow-methods"):
            allow = v
            break

    if allow:
        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous = [m for m in methods if m in DANGEROUS_METHODS]
        if dangerous:
            findings.append({
                "type": "dangerous_methods",
                "severity": "MEDIUM",
                "detail": f"HTTP methods berbahaya diizinkan: {', '.join(dangerous)}",
                "evidence": allow[:120],
            })

    # Cek TRACE method langsung
    trace_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms, method="TRACE")
    if trace_resp["status"] == 200 and "TRACE" in trace_resp["body"][:500]:
        findings.append({
            "type": "trace_enabled",
            "severity": "MEDIUM",
            "detail": "HTTP TRACE method aktif (XST risk)",
            "evidence": trace_resp["body"][:80],
        })

    return findings


def _check_sensitive_paths(base_url, timeout, delay_ms, fast=False):
    """Cek path sensitif yang terbuka."""
    findings = []
    # Mode fast: hanya cek paling kritis
    if fast:
        paths = [p for p in SENSITIVE_PATHS if p[1] == "CRITICAL"]
    else:
        paths = SENSITIVE_PATHS

    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, severity, desc in paths:
        url = base + path
        try:
            resp = _fetch(url, timeout=timeout, delay_ms=delay_ms,
                          follow_redirects=False)
        except Exception:
            continue

        if resp["error"]:
            continue

        # Status 200 + body non-kosong + bukan halaman error default
        if resp["status"] == 200 and len(resp["body"]) > 20:
            # Cek false positive untuk admin panel (kadang return 200 with login form)
            snippet = resp["body"][:200].lower()
            if path in ("/admin", "/administrator", "/wp-admin/") and \
               ("login" in snippet or "sign in" in snippet):
                # Masih menarik, tapi turunkan severity ke INFO
                findings.append({
                    "type": "admin_panel",
                    "severity": "INFO",
                    "detail": f"{desc} (login form terdeteksi)",
                    "evidence": url,
                })
                continue
            findings.append({
                "type": "exposed_path",
                "severity": severity,
                "detail": desc,
                "evidence": url,
            })

    return findings


def _check_directory_listing(body):
    """Deteksi directory listing dari isi body."""
    findings = []
    for pattern in DIR_LISTING_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "type": "directory_listing",
                "severity": "MEDIUM",
                "detail": "Directory listing aktif",
                "evidence": body[:100].replace("\n", " "),
            })
            break
    return findings


def _check_html_comments(body):
    """Cari HTML comment yang membocorkan info."""
    findings = []
    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    seen = set()
    for comment in comments[:50]:  # batasi
        for pattern, severity, desc in COMMENT_DISCLOSURE_PATTERNS:
            if re.search(pattern, comment, re.IGNORECASE):
                key = (pattern, desc)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type": "comment_disclosure",
                    "severity": severity,
                    "detail": desc,
                    "evidence": comment.strip()[:80],
                })
                break
    return findings


def _check_generator_meta(body):
    """Cek <meta name="generator"> untuk info teknologi."""
    findings = []
    m = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
        body, re.IGNORECASE
    )
    if m:
        findings.append({
            "type": "generator_leak",
            "severity": "INFO",
            "detail": f"Generator: {m.group(1)}",
            "evidence": m.group(0)[:100],
        })
    return findings


def _check_open_redirect(url, timeout, delay_ms):
    """Probe open redirect via parameter."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return findings

    # Coba tiap param yang namanya umum untuk redirect
    for param in qs.keys():
        if param.lower() not in [p.lower() for p in OPEN_REDIRECT_PARAMS]:
            continue
        test_qs = qs.copy()
        test_qs[param] = [OPEN_REDIRECT_PAYLOAD]
        test_url = parsed._replace(
            query=urllib.parse.urlencode(test_qs, doseq=True)
        ).geturl()

        try:
            resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms,
                          follow_redirects=False)
        except Exception:
            continue

        if resp["error"]:
            continue

        # Cek Location header
        loc = ""
        for k, v in resp["headers"].items():
            if k.lower() == "location":
                loc = v
                break

        if loc and ("evil.example.com" in loc or loc.startswith("//")):
            findings.append({
                "type": "open_redirect",
                "severity": "HIGH",
                "detail": f"Open redirect via parameter '{param}'",
                "evidence": f"Location: {loc[:100]}",
            })
            break  # satu temuan cukup

    return findings


def _check_lfi(url, timeout, delay_ms):
    """Probe LFI/path traversal via parameter."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return findings

    # Coba tiap param (batasi 3)
    for param in list(qs.keys())[:3]:
        for payload in LFI_PAYLOADS:
            test_qs = qs.copy()
            test_qs[param] = [payload]
            test_url = parsed._replace(
                query=urllib.parse.urlencode(test_qs, doseq=True)
            ).geturl()

            try:
                resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
            except Exception:
                continue

            if resp["error"]:
                continue

            if LFI_SUCCESS_PATTERN.search(resp["body"]):
                findings.append({
                    "type": "lfi",
                    "severity": "CRITICAL",
                    "detail": f"LFI terdeteksi di parameter '{param}'",
                    "evidence": f"payload={payload} — pola /etc/passwd cocok",
                })
                return findings  # satu temuan cukup

    return findings


# ============================================================
# MAIN ENTRY — check_web
# ============================================================
def check_web(url, timeout=5, delay_ms=0, fast=False):
    """
    Jalankan semua pemeriksaan web vulnerability pada URL.

    Args:
        url:       URL lengkap (misal https://example.com/)
        timeout:   timeout per request (detik)
        delay_ms:  delay antar request (ms) — dipakai di safe mode
        fast:      kalau True, skip pemeriksaan berat (LFI, open redirect,
                   sensitive paths lengkap) — hanya cek header & server

    Returns:
        list of finding dict:
            {"type": str, "severity": str, "detail": str, "evidence": str}
    """
    findings = []

    # Normalisasi URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}/"

    # === Fetch halaman utama ===
    main = _fetch(base_url, timeout=timeout, delay_ms=delay_ms)
    if main["error"]:
        # Coba HTTPS kalau HTTP gagal (atau sebaliknya)
        alt_scheme = "https" if parsed.scheme == "http" else "http"
        alt_url = f"{alt_scheme}://{parsed.netloc}/"
        main = _fetch(alt_url, timeout=timeout, delay_ms=delay_ms)
        if main["error"]:
            return [{
                "type": "connect_error",
                "severity": "INFO",
                "detail": f"Tidak bisa connect ke {base_url}: {main['error']}",
                "evidence": "",
            }]
        base_url = alt_url

    # === 1. Security headers ===
    findings.extend(_check_security_headers(main["headers"]))

    # === 2. Server leak ===
    findings.extend(_check_server_leak(main["headers"]))

    # === 3. Cookies ===
    findings.extend(_check_cookies(main["headers"]))

    # === 4. CORS ===
    findings.extend(_check_cors(main["headers"]))

    # === 5. HTML comments ===
    findings.extend(_check_html_comments(main["body"]))

    # === 6. Generator meta ===
    findings.extend(_check_generator_meta(main["body"]))

    # === 7. Directory listing ===
    findings.extend(_check_directory_listing(main["body"]))

    # Kalau fast mode, selesai sampai sini (sudah cukup informatif)
    if fast:
        return findings

    # === 8. HTTP methods ===
    findings.extend(_check_http_methods(base_url, timeout, delay_ms))

    # === 9. Sensitive paths ===
    findings.extend(_check_sensitive_paths(base_url, timeout, delay_ms,
                                           fast=fast))

    # === 10. Open redirect (hanya kalau ada query param) ===
    if parsed.query:
        findings.extend(_check_open_redirect(url, timeout, delay_ms))

    # === 11. LFI (hanya kalau ada query param) ===
    if parsed.query:
        findings.extend(_check_lfi(url, timeout, delay_ms))

    return findings


# ============================================================
# EXTRACT PARAM LINKS — untuk sqli.py / xss.py
# ============================================================
def extract_param_links(body, base_url):
    """
    Ambil semua link dengan query parameter dari HTML body.
    Hanya link yang sama-domain dengan base_url yang diambil.

    Args:
        body:      HTML body
        base_url:  URL halaman saat ini (untuk resolve relative link)

    Returns:
        list of URL dengan query parameter (maksimal 30)
    """
    if not body:
        return []

    base_parsed = urllib.parse.urlparse(base_url)
    found = set()

    # href="..."
    for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
        link = m.group(1).strip()
        if "?" not in link or "=" not in link:
            continue
        full = urllib.parse.urljoin(base_url, link)
        p = urllib.parse.urlparse(full)
        if p.netloc == base_parsed.netloc:
            found.add(full)
            if len(found) >= 30:
                break

    # action="..." (form)
    for m in re.finditer(r'action=["\']([^"\']+)["\']', body, re.IGNORECASE):
        link = m.group(1).strip()
        if "?" not in link or "=" not in link:
            continue
        full = urllib.parse.urljoin(base_url, link)
        p = urllib.parse.urlparse(full)
        if p.netloc == base_parsed.netloc:
            found.add(full)
            if len(found) >= 30:
                break

    return list(found)


# ============================================================
# CLI ENTRY POINT — test standalone
# ============================================================
def _cli():
    import argparse
    import sys
    import os

    # Startup banner
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
            _bn.print_banner(
                console=Console(),
                version=__version__,
                subtitle="Web Vulnerability Scanner — Pure Python",
            )
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX web_vuln — pure-Python web vulnerability scanner"
    )
    parser.add_argument("url", help="URL target (http:// atau https://)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0,
                        help="Delay antar request (ms)")
    parser.add_argument("--fast", action="store_true",
                        help="Mode cepat (hanya header + server check)")
    args = parser.parse_args()

    print(f"=== Web Vulnerability Scan — {args.url} ===\n")
    print("Memindai...\n")

    findings = check_web(
        args.url, timeout=args.timeout,
        delay_ms=args.delay, fast=args.fast
    )

    if not findings:
        print("[OK] Tidak ada temuan.")
        return

    # Kelompokkan per severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

    # Hitung per severity
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"Total temuan: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            print(f"  {sev:<10}: {counts[sev]}")
    print()

    # Cetak per temuan
    for f in findings:
        print(f"[{f['severity']:<8}] {f['type']:<20} {f['detail']}")
        if f.get("evidence"):
            print(f"            → {f['evidence']}")
    print()


if __name__ == "__main__":
    _cli()