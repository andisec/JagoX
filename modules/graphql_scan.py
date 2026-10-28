#!/usr/bin/env python3
# graphql_scan.py — GraphQL security scanner (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Fitur (semua read-only, tidak ada mutation):
#   - Deteksi endpoint GraphQL umum (/graphql, /graphiql, /api/graphql, dll)
#   - Introspection query (deteksi apakah introspection enabled)
#   - Schema dump (types, queries, mutations, subscriptions)
#   - Cek security headers
#   - Cek GET-based query (CSRF risk)
#   - Cek rate-limit header
#
# Public API (kompatibel nmpx.py v1.0.0):
#   scan(url, timeout=5, delay_ms=0, max_endpoints=5) -> dict {
#       url, endpoints_found, findings
#   }

import re
import ssl
import json
import time
import urllib.request
import urllib.parse
import urllib.error

__version__ = "1.0.0"


# ============================================================
# KONSTANTA
# ============================================================
ENDPOINTS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/api/v1/graphql", "/query", "/gql",
]

INTROSPECTION_QUERY = """
{__schema{queryType{name}mutationType{name}subscriptionType{name}
types{name kind fields{name type{name kind}}}}}
""".strip()

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Frame-Options",
]


# ============================================================
# HELPERS
# ============================================================
def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_json(url, payload, timeout=5, delay_ms=0):
    """POST JSON ke endpoint. Return dict."""
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0 gql)",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
    result = {"status": 0, "headers": {}, "body": "", "error": None,
              "elapsed": 0.0}
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_make_ctx()) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["body"] = resp.read(131072).decode("utf-8",
                                                        errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            result["body"] = e.read(131072).decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"[:80]
    finally:
        result["elapsed"] = time.time() - start
    return result


def _get_plain(url, timeout=5):
    """GET biasa. Return dict."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0 gql)"})
    result = {"status": 0, "headers": {}, "body": "", "error": None}
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_make_ctx()) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["body"] = resp.read(32768).decode("utf-8",
                                                       errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            result["body"] = e.read(32768).decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"[:80]
    return result


def _looks_like_graphql(body):
    """Heuristik apakah response terlihat seperti GraphQL."""
    if not body:
        return False
    body_lower = body[:1000].lower()
    markers = ["__schema", "__type", "\"data\"", "\"errors\"",
               "graphql", "querytype", "mutationtype"]
    return any(m in body_lower for m in markers)


def _parse_introspection(body):
    """Parse hasil introspection jadi ringkasan schema."""
    try:
        data = json.loads(body)
    except Exception:
        return None
    if "data" not in data or not isinstance(data["data"], dict):
        return None
    schema = data["data"].get("__schema")
    if not schema:
        return None
    return {
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
        "types_count": len(schema.get("types", [])),
        "types": [t.get("name") for t in schema.get("types", [])
                  if not t.get("name", "").startswith("__")][:50],
    }


# ============================================================
# MAIN SCAN
# ============================================================
def scan(url, timeout=5, delay_ms=0, max_endpoints=5):
    """
    Scan GraphQL endpoint di URL.

    Args:
        url:            URL target (misal https://example.com/)
        timeout:        timeout per request
        delay_ms:       delay antar request (safe mode)
        max_endpoints:  batas endpoint yang dicoba

    Returns:
        dict {
            "url": str,
            "endpoints_found": [ {path, url, introspection_enabled,
                                   schema, get_works, status} ],
            "findings": [ {type, severity, detail} ],
        }
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    findings = []
    endpoints_found = []

    # Cek security headers di homepage
    home = _get_plain(base + "/", timeout=timeout)
    missing_headers = []
    if home["status"] in (200, 301, 302, 401, 403):
        hdrs_lower = {k.lower() for k in home["headers"]}
        for h in SECURITY_HEADERS:
            if h.lower() not in hdrs_lower:
                missing_headers.append(h)
        if missing_headers:
            findings.append({
                "type": "missing_headers",
                "severity": "LOW",
                "detail": f"{', '.join(missing_headers)} tidak ada",
            })

    # Iterasi endpoint
    for path in ENDPOINTS[:max_endpoints]:
        ep_url = base + path

        # 1. POST introspection
        resp = _post_json(ep_url,
                           {"query": INTROSPECTION_QUERY},
                           timeout=timeout, delay_ms=delay_ms)
        if resp["error"]:
            continue

        is_gql = (resp["status"] != 404 and
                    (_looks_like_graphql(resp["body"]) or
                     resp["status"] in (400, 401, 403)))
        if not is_gql:
            continue

        # 2. Cek GET-based (CSRF risk)
        get_url = ep_url + "?query=" + urllib.parse.quote("{__typename}")
        get_resp = _get_plain(get_url, timeout=timeout)
        get_works = (
            get_resp["status"] in (200, 400)
            and ("errors" in get_resp["body"][:500].lower()
                 or "__typename" in get_resp["body"][:500])
        )

        # 3. Parse schema
        schema = _parse_introspection(resp["body"])
        introspection_enabled = schema is not None

        endpoint_info = {
            "path": path,
            "url": ep_url,
            "introspection_enabled": introspection_enabled,
            "schema": schema,
            "get_works": bool(get_works),
            "status": resp["status"],
        }
        endpoints_found.append(endpoint_info)

        # Findings
        if introspection_enabled:
            findings.append({
                "type": "introspection_enabled",
                "severity": "MEDIUM",
                "detail": (f"Introspection aktif di {path} "
                            f"({schema.get('types_count', 0)} types)"),
            })

        if get_works:
            findings.append({
                "type": "get_query_allowed",
                "severity": "LOW",
                "detail": f"GET query diizinkan di {path} (CSRF risk)",
            })

        # Rate limit header check
        rate_headers = ("x-ratelimit-limit", "ratelimit-limit",
                        "x-rate-limit")
        if not any(k.lower() in rate_headers for k in resp["headers"]):
            findings.append({
                "type": "no_rate_limit_header",
                "severity": "LOW",
                "detail": f"Tidak ada rate-limit header di {path}",
            })

    return {
        "url": base,
        "endpoints_found": endpoints_found,
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
                              subtitle="GraphQL Security Scan — Read-Only")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX graphql_scan — read-only GraphQL scanner")
    parser.add_argument("url")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("--max-endpoints", type=int, default=7)
    parser.add_argument("--version", action="version",
                        version=f"JagoX graphql_scan v{__version__}")
    args = parser.parse_args()

    print(f"=== GraphQL Scan — {args.url} ===\n")
    r = scan(args.url, timeout=args.timeout, delay_ms=args.delay,
             max_endpoints=args.max_endpoints)

    if not r["endpoints_found"]:
        print("[OK] Tidak ada endpoint GraphQL terdeteksi.")
        return

    print(f"Endpoint ditemukan: {len(r['endpoints_found'])}")
    for e in r["endpoints_found"]:
        print(f"\n  {e['url']}")
        print(f"    Status         : {e['status']}")
        print(f"    Introspection  : "
              f"{'ENABLED' if e['introspection_enabled'] else 'disabled'}")
        print(f"    GET query      : "
              f"{'allowed' if e['get_works'] else 'not allowed'}")
        if e["schema"]:
            print(f"    Query type     : {e['schema'].get('query_type', '-')}")
            if e["schema"].get("mutation_type"):
                print(f"    Mutation type  : "
                      f"{e['schema']['mutation_type']}")
            print(f"    Types          : {e['schema']['types_count']} total")

    print(f"\n=== Findings ({len(r['findings'])}) ===")
    if not r["findings"]:
        print("[OK] Tidak ada temuan.")
        return
    for f in r["findings"]:
        print(f"[{f['severity']:<8}] {f['type']:<24} {f['detail']}")


if __name__ == "__main__":
    _cli()
