#!/usr/bin/env python3
# dir_brute.py — Pure-Python directory & file bruteforcer
# Part of JagoX framework — v1.0.0
# MIT License
#
# Fitur:
#   - 3 tier wordlist (120 / 300 / 500+ path)
#   - 20+ extension file (.php, .bak, .old, .zip, .sql, dll)
#   - Wildcard & soft-404 detection (anti false positive)
#   - Concurrent scanning
#   - Title extraction, redirect detection
#   - Status filter (200, 204, 301, 302, 401, 403, 405, 500)
#   - User-Agent rotation
#
# Public API:
#   scan(base_url, tier=2, threads=20, timeout=5, delay_ms=0,
#        extensions=True, on_found=None) -> dict

import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"

PATHS_TIER1 = [
    "admin", "admin/", "admin.php", "admin.html", "admin/login",
    "admin/login.php", "administrator", "administrator/", "login",
    "login.php", "login.html", "dashboard", "dashboard.php", "panel",
    "panel/", "panel.php", "manage", "manager", "console", "cpanel",
    "wp-admin", "wp-admin/", "wp-login.php",
    ".env", ".env.local", ".env.backup", ".git/", ".git/config",
    ".git/HEAD", ".htaccess", ".htpasswd", ".DS_Store", "Dockerfile",
    "web.config", "config.php", "config.inc.php", "config.js",
    "configuration.php", "settings.php", "appsettings.json",
    "database.php", "db.php", "connection.php",
    "phpinfo.php", "info.php", "test.php", "test.html",
    "server-status", "server-info", "robots.txt", "sitemap.xml",
    "readme.md", "README.md", "package.json", "composer.json",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "index.php.bak", "index.php.old", "index.php~",
    "api", "api/", "api/v1", "api/v2", "rest", "rest/",
    "graphql", "graphql/", "swagger", "swagger.json", "openapi.json",
    "index.php", "index.html", "home", "main.php",
    "upload", "uploads", "files/", "download/", "images/", "img/",
    "css/", "js/", "static/", "assets/", "includes/", "inc/", "lib/",
    "vendor/", "tmp/", "cache/", "logs/", "log/", "data/",
    "user", "users", "account", "accounts", "profile", "register",
    "signup", "logout", "auth", "auth/",
    "wp-content", "wp-includes", "wp-json", "adminer.php",
    "phpmyadmin", "phpmyadmin/",
]

PATHS_TIER2 = PATHS_TIER1 + [
    "admin/index.php", "admin/main.php", "admin/dashboard",
    "admin/settings", "admin/users", "admin/backup", "admin/logs",
    "wp-config.php.bak", "wp-config.php.old", "config.php.bak",
    "config.php.old", "site-backup.zip", "db-backup.sql",
    "access.log", "error.log", "debug.log", "error_log", "app.log",
    ".aws/credentials", ".ssh/id_rsa", "id_rsa",
    "credentials.json", "secrets.json", "credentials.txt",
    ".git-credentials", ".netrc", ".npmrc",
    "rpc", "rpc.php", "jsonrpc", "wsdl", "services",
    "api/health", "health", "healthz", "health-check", "ping",
    "version", "info", "status.php",
    "server.php", "artisan", "node_modules/", "dist/", "build/",
    "public/", "web/", "www/",
    ".editorconfig", ".eslintrc", "tsconfig.json",
    "webpack.config.js", "vite.config.js",
    "help", "support", "contact", "about", "test/", "demo", "demo/",
    "dev", "dev/", "staging/", "beta/", "alpha/",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/mappings", "actuator/beans",
    "api/users", "api/auth", "api/login", "api/token", "api/admin",
    "api/config", "api/status", "api/swagger.json",
    "v1", "v1/", "v2", "v2/", "v3", "v3/",
    "readme.txt", "readme.html", "INSTALL", "CHANGELOG", "LICENSE.txt",
    "swagger-ui.html", "swagger-ui/", "api-docs", "docs", "docs/",
]

PATHS_TIER3 = PATHS_TIER2 + [
    "wp-admin/admin.php", "wp-admin/setup-config.php",
    "wp-admin/install.php", "wp-content/uploads/", "wp-content/debug.log",
    "sites/default/settings.php",
    "settings.gradle", "build.gradle", "pom.xml",
    "manage.py", "settings.py", "wsgi.py",
    "config.json", "config.yml", "config.yaml",
    "kubernetes/", "helm/", "deployment.yaml",
    ".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile",
    ".travis.yml", "nginx.conf", "apache2.conf", "httpd.conf",
    "php.ini", "my.cnf",
    "actuator/threaddump", "actuator/heapdump", "actuator/shutdown",
    "backup-2023.zip", "backup-2024.zip", "backup-2025.zip",
    "sql-dump.sql", "mysqldump.sql", "db.tar.gz",
]

EXTENSIONS_TIER2 = [".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
                     ".txt", ".xml", ".json", ".bak"]

EXTENSIONS_TIER3 = EXTENSIONS_TIER2 + [".conf", ".config", ".ini",
                                        ".yml", ".yaml", ".log", ".sql",
                                        ".zip", ".tar.gz", ".tgz", ".old",
                                        ".orig", ".save", ".swp", ".tmp",
                                        ".backup", ".inc", ".env", ".dist"]

FOUND_STATUS = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]


def _ua():
    return USER_AGENTS[int(time.time()) % len(USER_AGENTS)]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=5, delay_ms=0):
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    headers = {"User-Agent": _ua(), "Accept": "*/*"}
    req = urllib.request.Request(url, headers=headers)
    result = {"status": 0, "headers": {}, "body": "",
              "error": None, "redirect": None, "size": 0}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(NoRedirect())

    try:
        with opener.open(req, timeout=timeout, context=_make_ctx()) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            body = resp.read(32768)
            result["body"] = body.decode("utf-8", errors="replace")
            result["size"] = len(body)
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            body = e.read(32768)
            result["body"] = body.decode("utf-8", errors="replace")
            result["size"] = len(body)
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"{type(e).__name__}"[:80]

    if result["status"] in (301, 302, 303, 307, 308):
        for k, v in result["headers"].items():
            if k.lower() == "location":
                result["redirect"] = v
                break
    return result


def _extract_title(body):
    if not body:
        return ""
    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    return m.group(1).strip()[:80] if m else ""


def _detect_wildcard(base_url, timeout, delay_ms):
    probes = [f"/thisPathDoesNotExist_{int(time.time())}x",
              f"/random_{int(time.time())}abc",
              "/xyz-not-real-999"]
    results = []
    for p in probes:
        url = base_url.rstrip("/") + p
        r = _fetch(url, timeout=timeout, delay_ms=delay_ms)
        if not r["error"]:
            results.append({"status": r["status"], "size": r["size"],
                             "body": r["body"][:400].lower()})

    if not results:
        return None

    if all(r["status"] == 200 for r in results):
        sizes = [r["size"] for r in results]
        if len(set(sizes)) == 1 and sizes[0] > 0:
            return {"type": "wildcard_200", "size": sizes[0]}
        for marker in ("not found", "404", "page not found", "does not exist"):
            if marker in results[0]["body"]:
                return {"type": "soft_404", "marker": marker,
                        "size": sizes[0] if sizes else 0}
    return None


def _build_paths(tier, include_ext):
    if tier <= 1:
        base, exts = PATHS_TIER1, []
    elif tier == 2:
        base, exts = PATHS_TIER2, EXTENSIONS_TIER2 if include_ext else []
    else:
        base, exts = PATHS_TIER3, EXTENSIONS_TIER3 if include_ext else []

    paths = list(base)
    if include_ext and exts:
        for p in base[:100]:
            if "." in p.rsplit("/", 1)[-1]:
                continue
            p_clean = p.rstrip("/")
            for e in exts:
                paths.append(p_clean + e)

    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _test_path(base_url, path, timeout, delay_ms, wildcard):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    r = _fetch(url, timeout=timeout, delay_ms=delay_ms)

    if r["error"] or r["status"] not in FOUND_STATUS:
        return None

    if wildcard:
        wtype = wildcard.get("type")
        if wtype == "wildcard_200" and r["status"] == 200:
            wsize = wildcard.get("size", 0)
            if wsize > 0 and abs(r["size"] - wsize) / max(wsize, 1) < 0.05:
                return None
        if wtype == "soft_404" and r["status"] == 200:
            marker = wildcard.get("marker", "")
            if marker and marker in r["body"][:400].lower():
                return None

    return {
        "path": path,
        "url": url,
        "status": r["status"],
        "size": r["size"],
        "title": _extract_title(r["body"]),
        "redirect": r.get("redirect"),
    }


def scan(base_url, tier=2, threads=20, timeout=5, delay_ms=0,
         extensions=True, on_found=None):
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
    if not base_url.endswith("/"):
        base_url = base_url + "/"

    start = time.time()
    wildcard = _detect_wildcard(base_url, timeout, delay_ms)
    paths = _build_paths(tier, extensions)

    findings = []
    errors = 0

    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(paths)))) as ex:
        futures = {ex.submit(_test_path, base_url, p, timeout, delay_ms,
                              wildcard): p for p in paths}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                errors += 1
                continue
            if res:
                findings.append(res)
                if on_found:
                    try:
                        on_found(res)
                    except Exception:
                        pass

    priority = {200: 0, 204: 1, 301: 2, 302: 3, 401: 4, 403: 5, 405: 6, 500: 7}
    findings.sort(key=lambda f: (priority.get(f["status"], 99), f["path"]))

    return {
        "url": base_url,
        "findings": findings,
        "wildcard": wildcard,
        "stats": {
            "tested": len(paths), "found": len(findings),
            "errors": errors, "elapsed": time.time() - start, "tier": tier,
        },
    }


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
                              subtitle="Directory Bruteforcer — Pure Python")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX dir_brute — pure-Python directory bruteforcer")
    parser.add_argument("url")
    parser.add_argument("-t", "--tier", type=int, choices=[1, 2, 3], default=2)
    parser.add_argument("-w", "--threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("--no-ext", action="store_true")
    args = parser.parse_args()

    print(f"=== Dir Brute — {args.url} ===")
    print(f"=== Tier: {args.tier} | Threads: {args.threads} ===\n")

    result = scan(args.url, tier=args.tier, threads=args.threads,
                   timeout=args.timeout, delay_ms=args.delay,
                   extensions=not args.no_ext)

    if result["wildcard"]:
        print(f"[!] Wildcard: {result['wildcard']['type']}\n")

    print(f"Total diuji: {result['stats']['tested']}")
    print(f"Ditemukan  : {result['stats']['found']}")
    print(f"Waktu      : {result['stats']['elapsed']:.1f}s\n")

    for f in result["findings"]:
        redirect = f" → {f['redirect']}" if f["redirect"] else ""
        title = f" [{f['title']}]" if f["title"] else ""
        print(f"[{f['status']:>3}] {f['path']:<40} {f['size']:>6}B{title}{redirect}")


if __name__ == "__main__":
    _cli()
