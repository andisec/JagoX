#!/usr/bin/env python3
# subdomain.py — Pure-Python subdomain enumeration (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Fitur:
#   - 3 tier wordlist (120 / 350 / 500+ subdomain)
#   - DNS A/AAAA + CNAME chain
#   - Wildcard DNS detection (anti false positive)
#   - HTTP/HTTPS probe + title extraction
#   - CT logs via crt.sh (gratis)
#   - Subdomain takeover detection (27 pattern)
#   - Concurrent, safe mode ready
#   - Custom wordlist support
#   - Permutation generation dari CT logs
#
# Public API (kompatibel dengan nmpx.py v1.0.0):
#   scan(domain, tier=2, threads=20, timeout=3, delay_ms=0,
#        http_probe=True, use_ct_logs=True, on_found=None,
#        wordlist_file=None, permutate=True) -> dict

import re
import os
import ssl
import time
import json
import socket
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"


# ============================================================
# WORDLIST TIER 1 — 120 subdomain paling umum
# ============================================================
SUBDOMAINS_TIER1 = [
    # Web
    "www", "web", "web1", "web2", "app", "apps", "portal", "site",
    # Mail
    "mail", "email", "smtp", "pop", "pop3", "imap", "webmail",
    "mx", "mx1", "mx2",
    # API
    "api", "api1", "api2", "rest", "rpc", "graphql", "soap", "ws",
    # Admin
    "admin", "administrator", "panel", "dashboard", "manage",
    "manager", "console", "cpanel", "cp",
    # Auth
    "login", "sso", "auth", "oauth", "id", "account", "accounts",
    "signin", "signup",
    # Environment
    "dev", "dev1", "dev2", "test", "test1", "test2",
    "staging", "stage", "qa", "uat", "demo", "sandbox",
    "prod", "production", "live", "beta", "alpha",
    "preview", "pre",
    # CDN / static
    "cdn", "cdn1", "cdn2", "static", "assets", "img", "images",
    "css", "js", "media",
    # Files
    "file", "files", "download", "downloads", "upload", "uploads",
    # Database
    "db", "db1", "db2", "database", "mysql", "postgres",
    "redis", "mongo", "mongodb",
    # Cache / queue
    "cache", "memcached", "queue", "mq", "kafka", "rabbitmq",
    # Monitoring
    "monitor", "monitoring", "grafana", "kibana", "logs", "log",
    "status", "health", "metrics",
    # Services
    "vpn", "ftp", "sftp", "ssh", "git", "gitlab", "github",
    "jenkins", "ci", "cd",
    # Nameservers
    "ns1", "ns2", "ns3", "dns1", "dns2",
    # Content
    "forum", "blog", "wiki", "docs", "support", "help",
    "shop", "store", "cart", "news", "press",
]


# ============================================================
# WORDLIST TIER 2 — tambahan ~230 subdomain
# ============================================================
SUBDOMAINS_TIER2 = SUBDOMAINS_TIER1 + [
    "s3", "storage", "blob", "cloud", "aws", "azure", "gcp",
    "internal", "intranet", "extranet", "corp", "office",
    "backend", "back", "front", "lb", "load", "loadbalancer",
    "proxy", "reverse-proxy",
    "chat", "meet", "conference", "voip", "sip", "pbx",
    "calendar", "tasks", "notes", "photos", "gallery",
    "video", "tube", "stream", "music", "radio", "podcast",
    "orders", "order", "payment", "payments", "invoice",
    "billing", "subscribe",
    "people", "staff", "team", "employees", "hr",
    "directory", "contacts", "phone", "phonebook",
    "erp", "crm", "cms", "wms", "hrm", "scm", "bi", "analytics",
    "report", "reports",
    "waf", "firewall", "ids", "ips", "antivirus",
    "old", "legacy", "v1", "v2", "v3",
    "jakarta", "surabaya", "bandung", "medan", "singapore", "sg",
    "web3", "web4", "web5", "app1", "app2", "app3",
    "srv1", "srv2", "srv3", "node1", "node2", "node3",
    "host1", "host2", "host3", "mail1", "mail2", "mail3",
    "api3", "api4", "api5",
    "demo1", "demo2", "trial", "free", "premium",
    "public", "private", "external",
    "rss", "feed", "atom",
    "search", "find", "query",
    "ping", "pulse",
    "help-desk", "helpdesk", "ticket", "tickets",
    "confluence", "jira",
    "m", "mobile", "wap",
    "sso2", "auth2",
    "data", "dataset", "datasets",
    "assets1", "assets2", "img1", "img2", "js1", "css1",
    "form", "forms", "survey", "surveys",
]


# ============================================================
# WORDLIST TIER 3 — deep
# ============================================================
SUBDOMAINS_TIER3 = SUBDOMAINS_TIER2 + [
    *[f"www{i}" for i in range(3, 11)],
    *[f"mail{i}" for i in range(4, 11)],
    *[f"api{i}" for i in range(6, 16)],
    *[f"srv{i}" for i in range(4, 11)],
    *[f"node{i}" for i in range(4, 11)],
    *[f"host{i}" for i in range(4, 11)],
    *[f"web{i}" for i in range(6, 16)],
    *[f"app{i}" for i in range(4, 11)],
    "kafka", "zookeeper", "consul", "vault", "etcd",
    "kubernetes", "k8s", "docker", "registry", "harbor",
    "nexus", "artifactory", "maven", "npm",
    "ldap", "ad", "dc", "dc1", "dc2",
    "radius", "tacacs",
    "proxy1", "proxy2", "proxy3",
    "cache1", "cache2", "cache3",
    "db3", "db-master", "db-slave",
    "mysql1", "mysql2", "pg", "pg1", "pg2",
    "mongo1", "mongo2", "redis1", "redis2",
    "es1", "es2", "elastic1", "elastic2",
    "us", "us1", "us2", "eu", "eu1", "eu2",
    "uk", "de", "fr", "jp", "kr", "au",
    "oauth2", "openid", "saml", "wsfed", "kerberos",
    "ticketing", "crm2", "salesforce",
    "slack", "teams", "zoom", "webex",
    "hub", "zendesk", "freshdesk", "intercom",
    "developers", "dev-portal", "api-docs",
    "misc", "other", "temp", "tmp", "old1", "old2",
    "test-api", "test-app", "api-test",
    "staging-api", "dev-api", "prod-api",
    "internal-api", "external-api",
]


# ============================================================
# TAKEOVER PATTERNS
# ============================================================
TAKEOVER_PATTERNS = [
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.herokuapp\.com$", "Heroku"),
    (r"\.s3\.amazonaws\.com$", "AWS S3"),
    (r"\.s3-[a-z0-9-]+\.amazonaws\.com$", "AWS S3"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.elasticbeanstalk\.com$", "AWS Elastic Beanstalk"),
    (r"\.azurewebsites\.net$", "Azure Web Apps"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager"),
    (r"\.cloudapp\.azure\.com$", "Azure CloudApp"),
    (r"\.azure-api\.net$", "Azure API Management"),
    (r"\.fastly\.net$", "Fastly"),
    (r"\.netlify\.app$", "Netlify"),
    (r"\.surge\.sh$", "Surge.sh"),
    (r"\.readthedocs\.io$", "ReadTheDocs"),
    (r"\.ghost\.io$", "Ghost.io"),
    (r"\.myshopify\.com$", "Shopify"),
    (r"\.zendesk\.com$", "Zendesk"),
    (r"\.statuspage\.io$", "StatusPage.io"),
    (r"\.pantheonsite\.io$", "Pantheon"),
    (r"\.wpengine\.com$", "WP Engine"),
    (r"\.bitbucket\.io$", "Bitbucket"),
    (r"\.gitlab\.io$", "GitLab Pages"),
    (r"\.cargo\.collective$", "Cargo Collective"),
    (r"\.unbounce\.com$", "Unbounce"),
    (r"\.bounceexchange\.com$", "BounceX"),
    (r"\.tumblr\.com$", "Tumblr"),
    (r"\.wordpress\.com$", "WordPress.com"),
    (r"\.smugmug\.com$", "SmugMug"),
]


# ============================================================
# HELPERS
# ============================================================
def _resolve(hostname, timeout=3):
    """Resolve hostname → {ips, canonical, aliases, error}."""
    result = {"ips": [], "canonical": "", "aliases": [], "error": None}
    try:
        socket.setdefaulttimeout(timeout)
        info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips = set()
        for fam, _, _, _, addr in info:
            ips.add(addr[0])
        result["ips"] = sorted(ips)
    except socket.gaierror as e:
        result["error"] = str(e)[:80]
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}"[:80]
        return result
    try:
        socket.setdefaulttimeout(timeout)
        canonical, aliases, _ = socket.gethostbyname_ex(hostname)
        result["canonical"] = canonical
        result["aliases"] = aliases
    except Exception:
        pass
    return result


def _cname_chain(hostname, timeout=3):
    """Bangun chain CNAME (max 5 hop)."""
    chain = [hostname]
    current = hostname
    for _ in range(5):
        try:
            socket.setdefaulttimeout(timeout)
            canonical, _, _ = socket.gethostbyname_ex(current)
            if canonical and canonical != current and canonical not in chain:
                chain.append(canonical)
                current = canonical
            else:
                break
        except Exception:
            break
    return chain


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe_http(hostname, timeout=3, delay_ms=0):
    """Probe HTTP/HTTPS, return {http: {...}, https: {...}}."""
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    result = {"http": None, "https": None}
    for scheme in ("http", "https"):
        url = f"{scheme}://{hostname}/"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0)"})
            with urllib.request.urlopen(req, timeout=timeout,
                                         context=_make_ctx()) as resp:
                body = resp.read(16384).decode("utf-8", errors="replace")
                title = ""
                m = re.search(r"<title[^>]*>([^<]+)</title>", body,
                              re.IGNORECASE)
                if m:
                    title = m.group(1).strip()[:80]
                server = ""
                for k, v in resp.headers.items():
                    if k.lower() == "server":
                        server = v[:60]
                        break
                result[scheme] = {"status": resp.status, "title": title,
                                    "server": server, "size": len(body)}
                break
        except urllib.error.HTTPError as e:
            server = ""
            try:
                for k, v in e.headers.items():
                    if k.lower() == "server":
                        server = v[:60]
                        break
            except Exception:
                pass
            result[scheme] = {"status": e.code, "title": "",
                                "server": server, "size": 0}
        except Exception:
            pass
    return result


def _check_takeover(canonical, http_info):
    """Deteksi takeover. Return dict atau None."""
    if not canonical:
        return None
    for pattern, service in TAKEOVER_PATTERNS:
        if re.search(pattern, canonical, re.IGNORECASE):
            http = http_info.get("http") or http_info.get("https")
            if http:
                status = http.get("status", 0)
                title = (http.get("title") or "").lower()
                if status == 404:
                    return {"service": service, "severity": "HIGH",
                            "evidence": f"CNAME ke {canonical}, HTTP 404"}
                for marker in ("not found", "no such app",
                                "there isn't a github pages site here",
                                "no longer available", "page not found"):
                    if marker in title:
                        return {"service": service, "severity": "HIGH",
                                "evidence": f"CNAME ke {canonical}, {marker}"}
            return {"service": service, "severity": "MEDIUM",
                    "evidence": f"CNAME ke {canonical} (bisa takeover)"}
    return None


def _detect_wildcard(domain, timeout=3):
    """Deteksi wildcard DNS."""
    probes = [
        f"thisdoesnotexist-{int(time.time())}-xyz123.{domain}",
        f"random-{int(time.time())}-abc789.{domain}",
        f"jagox-test-{int(time.time())}.{domain}",
    ]
    wildcard_ips = set()
    wildcard_cname = set()
    for probe in probes:
        result = _resolve(probe, timeout=timeout)
        if result["ips"]:
            wildcard_ips.update(result["ips"])
        if result["canonical"] and result["canonical"] != probe:
            wildcard_cname.add(result["canonical"])
    if wildcard_ips or wildcard_cname:
        return {"ips": sorted(wildcard_ips), "cname": sorted(wildcard_cname)}
    return None


def _query_crt_sh(domain, timeout=15):
    """Query CT logs via crt.sh."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; JagoX/1.0)"})
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_make_ctx()) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return []
    subs = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith("." + domain):
                subs.add(name)
    return sorted(subs)


def _load_custom_wordlist(path):
    """Load custom wordlist (1 per baris, # comment diabaikan)."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f
                     if l.strip() and not l.strip().startswith("#")]
        return lines
    except Exception:
        return None


def _generate_permutations(subdomains, limit=50):
    """Generate permutasi dari subdomain yang ketemu."""
    prefixes = ["dev", "test", "staging", "api", "prod", "old", "new"]
    suffixes = ["dev", "test", "staging", "api", "prod", "old", "new",
                 "backup", "1", "2", "3", "bak"]
    perms = set()
    for sub in subdomains[:30]:
        base = sub.split(".")[0] if "." in sub else sub
        base = base.strip("-").lower()
        if not base or len(base) > 20:
            continue
        for p in prefixes[:4]:
            if p != base:
                perms.add(f"{p}-{base}")
                perms.add(f"{base}-{p}")
        for s in suffixes[:4]:
            if s != base:
                perms.add(f"{base}-{s}")
                perms.add(f"{base}{s}")
    return list(perms)[:limit]


def _test_subdomain(sub, domain, timeout, delay_ms, wildcard,
                     http_probe):
    """Test satu subdomain."""
    full = f"{sub}.{domain}"
    res = _resolve(full, timeout=timeout)
    if res["error"] or not res["ips"]:
        return None
    if wildcard:
        wild_ips = set(wildcard.get("ips", []))
        if wild_ips and set(res["ips"]) == wild_ips:
            return None
    chain = _cname_chain(full, timeout=timeout)
    canonical = chain[-1] if len(chain) > 1 else res["canonical"]
    http_info = {}
    if http_probe:
        http_info = _probe_http(full, timeout=timeout, delay_ms=delay_ms)
    takeover = _check_takeover(canonical, http_info)
    return {
        "subdomain": full,
        "ip": res["ips"][0] if res["ips"] else "",
        "ips_all": res["ips"],
        "cname_chain": chain if len(chain) > 1 else [],
        "canonical": canonical if canonical != full else "",
        "http": http_info.get("http"),
        "https": http_info.get("https"),
        "takeover": takeover,
    }


# ============================================================
# MAIN SCAN
# ============================================================
def scan(domain, tier=2, threads=20, timeout=3, delay_ms=0,
         http_probe=True, use_ct_logs=True, on_found=None,
         wordlist_file=None, permutate=True):
    """
    Enumerate subdomain untuk domain.

    Args:
        domain:       domain utama (misal example.com)
        tier:         1 (quick), 2 (standard), 3 (deep)
        threads:      worker paralel
        timeout:      timeout DNS/HTTP per request
        delay_ms:     delay antar request (ms) — safe mode
        http_probe:   probe HTTP/HTTPS tiap subdomain
        use_ct_logs:  query crt.sh
        on_found:     callback(dict)
        wordlist_file: path custom wordlist (opsional)
        permutate:    generate permutasi dari CT logs

    Returns:
        dict {domain, found, wildcard, ct_count, stats}
    """
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    start = time.time()

    # Wordlist dasar
    if tier <= 1:
        words = list(SUBDOMAINS_TIER1)
    elif tier == 2:
        words = list(SUBDOMAINS_TIER2)
    else:
        words = list(SUBDOMAINS_TIER3)

    # Custom wordlist
    custom = _load_custom_wordlist(wordlist_file)
    if custom:
        words = words + custom

    # CT logs
    ct_subs = []
    ct_prefixes = []
    if use_ct_logs:
        ct_subs = _query_crt_sh(domain, timeout=15)
        ct_subs = [s for s in ct_subs
                   if s.count(".") == domain.count(".") + 1]
        for s in ct_subs:
            prefix = s[:-len(domain) - 1]
            if prefix and "." not in prefix:
                ct_prefixes.append(prefix)
        words = words + ct_prefixes

    # Permutasi
    if permutate and ct_prefixes:
        try:
            perms = _generate_permutations(ct_prefixes, limit=50)
            words = words + perms
        except Exception:
            pass

    # Dedupe
    seen = set()
    uniq_words = []
    for w in words:
        w = w.strip().lower()
        if w and w not in seen:
            seen.add(w)
            uniq_words.append(w)

    # Wildcard detection
    wildcard = _detect_wildcard(domain, timeout=timeout)

    # Parallel scan
    found = []
    errors = 0
    with ThreadPoolExecutor(
            max_workers=max(1, min(threads, len(uniq_words)))) as ex:
        futures = {
            ex.submit(_test_subdomain, w, domain, timeout, delay_ms,
                       wildcard, http_probe): w
            for w in uniq_words
        }
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                errors += 1
                continue
            if res:
                found.append(res)
                if on_found:
                    try:
                        on_found(res)
                    except Exception:
                        pass

    # Sort: takeover dulu
    def _priority(item):
        if item.get("takeover"):
            return (0, item["subdomain"])
        return (1, item["subdomain"])
    found.sort(key=_priority)

    return {
        "domain": domain,
        "found": found,
        "wildcard": wildcard,
        "ct_count": len(ct_subs),
        "stats": {
            "tested": len(uniq_words),
            "found": len(found),
            "errors": errors,
            "elapsed": time.time() - start,
            "tier": tier,
        },
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
                              subtitle="Subdomain Enumeration — Pure Python")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX subdomain — pure-Python subdomain enumeration")
    parser.add_argument("domain")
    parser.add_argument("-t", "--tier", type=int, choices=[1, 2, 3],
                        default=2)
    parser.add_argument("-w", "--threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("--no-http", action="store_true")
    parser.add_argument("--no-ct", action="store_true")
    parser.add_argument("--wordlist", help="Path custom wordlist")
    parser.add_argument("--version", action="version",
                        version=f"JagoX subdomain v{__version__}")
    args = parser.parse_args()

    print(f"=== Subdomain Enum — {args.domain} ===")
    print(f"=== Tier: {args.tier} | Threads: {args.threads} ===\n")

    result = scan(args.domain, tier=args.tier, threads=args.threads,
                   timeout=args.timeout, delay_ms=args.delay,
                   http_probe=not args.no_http,
                   use_ct_logs=not args.no_ct,
                   wordlist_file=args.wordlist)

    if result["wildcard"]:
        print(f"[!] Wildcard DNS: {result['wildcard']}")
        print("[!] Beberapa hasil mungkin false positive.\n")

    print(f"Total diuji: {result['stats']['tested']}")
    print(f"Ditemukan  : {result['stats']['found']}")
    print(f"CT entries : {result.get('ct_count', 0)}")
    print(f"Waktu      : {result['stats']['elapsed']:.1f}s\n")

    for f in result["found"]:
        http_status = ""
        if f.get("http"):
            http_status = f" [HTTP {f['http']['status']}]"
        elif f.get("https"):
            http_status = f" [HTTPS {f['https']['status']}]"
        takeover = ""
        if f.get("takeover"):
            takeover = f" ⚠ TAKEOVER ({f['takeover']['service']})"
        print(f"{f['subdomain']:<40} {f['ip']:<16}"
              f"{http_status}{takeover}")


if __name__ == "__main__":
    _cli()
