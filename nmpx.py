#!/usr/bin/env python3
# nmpx.py — JagoX full pipeline orchestrator v1.0.0 (CONSOLIDATED)
# Part of JagoX framework
# MIT License
#
# Konsolidasi semua fitur dari v0.5.1 → v1.0.0:
#   - Defensive fallback untuk semua modul
#   - Progress bar hijau
#   - Scan profiles + follow-up NSE
#   - Multi-target + concurrent + host discovery
#   - Auto CVE + OSINT + diff + auto-filter
#   - Banner grab + web vuln + sqli + xss
#   - Dir brute + subdomain
#   - TUI mode (--tui) + watchdog (--watch N)
#   - Blind SQLi (--blind-sqli)
#   - HTTP fuzz (--fuzz) + port-knock (--port-knock + --sequence)
#   - Search (--search QUERY atau prompt otomatis)
#   - TLS audit (--tls-audit)
#   - GraphQL (--graphql) + HTTP/2 (--http2)
#   - Plugin system (auto-load, --no-plugins untuk disable)
#
# Watchdog mode: simpan target + profile dari iterasi pertama,
# lalu scan ulang tiap N detik tanpa prompt ulang.
#
# Open Source — MIT License

import sys
import os
import re
import time
import socket
import shutil
import configparser
import ipaddress
import subprocess
import traceback
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# RICH — fallback ke print biasa kalau tidak terinstall
# ============================================================
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    )
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("[!] 'rich' tidak terinstall. Jalankan: pip install rich")
    print("[!] Jalan tanpa rich — output tidak berwarna/tabel.\n")

    class Console:
        def print(self, *a, **kw):
            text = " ".join(str(x) for x in a)
            text = re.sub(r"\[/?[a-zA-Z0-9 _#=]+\]", "", text)
            print(text)

        def input(self, prompt=""):
            prompt = re.sub(r"\[/?[a-zA-Z0-9 _#=]+\]", "", prompt)
            return input(prompt)

    class Table:
        def __init__(self, **kw):
            self.rows = []
            self.title = kw.get("title", "")

        def add_column(self, *a, **kw):
            pass

        def add_row(self, *a, **kw):
            self.rows.append(a)

        def __str__(self):
            out = [f"\n=== {self.title} ==="]
            for r in self.rows:
                out.append(" | ".join(str(x) for x in r))
            return "\n".join(out)

    class Panel:
        def __init__(self, text, **kw):
            self.text = text

        def __str__(self):
            return str(self.text)

        @staticmethod
        def fit(text, **kw):
            return Panel(text)

    class Progress:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def add_task(self, *a, **kw):
            return 0

        def update(self, *a, **kw):
            pass

    class _Box:
        ROUNDED = HEAVY_HEAD = DOUBLE = SIMPLE = ""

    box = _Box()
    SpinnerColumn = BarColumn = TextColumn = TimeElapsedColumn = lambda *a, **kw: None


# ============================================================
# IMPORT MODUL JAGOX — defensive (fallback ke None)
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

console = Console()


# --- Banner ---
try:
    from modules import banner as bn
    if bn is None or not hasattr(bn, "print_banner"):
        raise ImportError("banner module tidak punya print_banner")
    HAS_BANNER = True
except Exception as e:
    HAS_BANNER = False
    _BANNER_ERR = str(e)

    class _FallbackBanner:
        @staticmethod
        def print_banner(console=None, version="1.0.0", subtitle=None):
            sub = subtitle or "Automatic Nmap · Web Vuln · SQLi · XSS · OSINT"
            msg = f"nmpX v{version} — Part of JagoX Framework\n{sub}"
            if console is not None:
                try:
                    console.print(f"[bold green]{msg}[/bold green]")
                    console.print()
                except Exception:
                    print(msg + "\n")
            else:
                print(msg + "\n")

    bn = _FallbackBanner()


# --- Banner grab ---
try:
    from modules import banner_grab
    HAS_BANNER_GRAB = banner_grab is not None
except Exception as e:
    HAS_BANNER_GRAB = False
    _BG_ERR = str(e)
    banner_grab = None


# --- Web vuln ---
try:
    from modules import web_vuln
    HAS_WEB_VULN = web_vuln is not None
except Exception:
    web_vuln = None
    HAS_WEB_VULN = False


# --- SQLi ---
try:
    from modules import sqli
    HAS_SQLI = sqli is not None
except Exception:
    sqli = None
    HAS_SQLI = False


# --- XSS ---
try:
    from modules import xss
    HAS_XSS = xss is not None
except Exception:
    xss = None
    HAS_XSS = False


# --- Dir brute ---
try:
    from modules import dir_brute
    HAS_DIR_BRUTE = dir_brute is not None
except Exception:
    dir_brute = None
    HAS_DIR_BRUTE = False


# --- Subdomain ---
try:
    from modules import subdomain
    HAS_SUBDOMAIN = subdomain is not None
except Exception:
    subdomain = None
    HAS_SUBDOMAIN = False


# --- TUI ---
try:
    from modules import tui
    HAS_TUI = tui is not None
except Exception:
    tui = None
    HAS_TUI = False


# --- HTTP fuzz ---
try:
    from modules import http_fuzz
    HAS_HTTP_FUZZ = http_fuzz is not None
except Exception:
    http_fuzz = None
    HAS_HTTP_FUZZ = False


# --- Port knock ---
try:
    from modules import port_knock
    HAS_PORT_KNOCK = port_knock is not None
except Exception:
    port_knock = None
    HAS_PORT_KNOCK = False


# --- Search ---
try:
    from modules import search as search_mod
    HAS_SEARCH = search_mod is not None
except Exception:
    search_mod = None
    HAS_SEARCH = False


# --- TLS audit ---
try:
    from modules import tls_audit
    HAS_TLS_AUDIT = tls_audit is not None
except Exception:
    tls_audit = None
    HAS_TLS_AUDIT = False


# --- Plugins ---
try:
    from modules import plugins as plugin_sys
    HAS_PLUGINS = plugin_sys is not None
except Exception:
    plugin_sys = None
    HAS_PLUGINS = False


# --- GraphQL ---
try:
    from modules import graphql_scan
    HAS_GRAPHQL = graphql_scan is not None
except Exception:
    graphql_scan = None
    HAS_GRAPHQL = False


# --- HTTP/2 ---
try:
    from modules import http2_check
    HAS_HTTP2_CHECK = http2_check is not None
except Exception:
    http2_check = None
    HAS_HTTP2_CHECK = False


# --- Eksternal opsional ---
try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    whois_lib = None
    HAS_WHOIS = False

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    geoip2 = None
    HAS_GEOIP = False

GEOIP_DB_PATH = "/usr/share/GeoIP/GeoLite2-City.mmdb"


# ============================================================
# CONFIG LOADER
# ============================================================
DEFAULT_CONFIG = {
    "general": {
        "cvss_threshold": "4.0",
        "max_workers": "10",
        "safe_mode": "false",
        "enable_banner_grab": "true",
        "enable_web_vuln": "true",
        "enable_sqli": "true",
        "enable_xss": "true",
        "enable_dir_brute": "true",
        "enable_subdomain": "true",
        "enable_graphql": "true",
        "enable_http2": "true",
        "enable_watchdog": "false",
    },
    "scan": {"default_profile": "1", "timing_template": "T4"},
    "ratelimit": {"delay_ms": "500", "max_concurrent_safe": "3"},
    "output": {"show_banner": "true", "show_module_status": "true"},
    "advanced": {
        "scan_timeout": "900",
        "banner_timeout": "3.0",
        "banner_workers": "10",
        "max_hosts_warning": "1024",
        "dir_brute_tier": "2",
        "subdomain_tier": "2",
        "watch_interval": "300",
    },
    "wordlist": {"dir_brute_custom": "", "subdomain_custom": ""},
    "tui": {"enabled": "false"},
    "fuzz": {"enable_http_fuzz": "false", "fuzz_modes": "param,header,path"},
    "portknock": {"enable_port_knock": "false", "target_port": "22",
                  "custom_sequence": ""},
    "search": {"prompt_after_scan": "true"},
    "dump": {"enable_dump": "false", "max_rows": "10", "max_char": "50",
             "timeout_minutes": "30"},
}


def load_config(quiet=False):
    """Load .nmpxrc — defensive, fallback ke default kalau corrupt."""
    cfg_path = os.path.join(BASE_DIR, ".nmpxrc")
    cfg = configparser.ConfigParser()
    for section, vals in DEFAULT_CONFIG.items():
        cfg[section] = vals

    if os.path.exists(cfg_path):
        try:
            cfg.read(cfg_path, encoding="utf-8")
            if not quiet:
                console.print(f"[dim]✔ Config dimuat dari {cfg_path}[/dim]")
        except (configparser.Error, UnicodeDecodeError, OSError) as e:
            console.print(f"[yellow]⚠ Config error ({type(e).__name__}): "
                          f"{e}[/yellow]")
            console.print("[yellow]→ Pakai default, lanjut...[/yellow]")
            cfg = configparser.ConfigParser()
            for section, vals in DEFAULT_CONFIG.items():
                cfg[section] = vals
    else:
        if not quiet:
            console.print("[dim]ℹ .nmpxrc tidak ditemukan, pakai default.[/dim]")

    # Validasi — tambah key yang hilang
    for section, vals in DEFAULT_CONFIG.items():
        if not cfg.has_section(section):
            cfg.add_section(section)
        for key, val in vals.items():
            if not cfg.has_option(section, key):
                cfg.set(section, key, val)

    return cfg


def _safe_cfg(cfg, section, key, type_fn, default):
    try:
        if type_fn is bool:
            return cfg.getboolean(section, key, fallback=default)
        if type_fn is int:
            return cfg.getint(section, key, fallback=default)
        if type_fn is float:
            return cfg.getfloat(section, key, fallback=default)
        return cfg.get(section, key, fallback=default)
    except Exception:
        return default


# ============================================================
# CONSTANTS
# ============================================================
RISK_MAP = {
    "21": ("CRITICAL", "bold red"), "23": ("CRITICAL", "bold red"),
    "512": ("CRITICAL", "bold red"), "513": ("CRITICAL", "bold red"),
    "514": ("CRITICAL", "bold red"), "445": ("CRITICAL", "bold red"),
    "3389": ("CRITICAL", "bold red"), "5900": ("CRITICAL", "bold red"),
    "5901": ("CRITICAL", "bold red"),
    "25": ("HIGH", "red"), "110": ("HIGH", "red"), "135": ("HIGH", "red"),
    "139": ("HIGH", "red"), "143": ("HIGH", "red"), "161": ("HIGH", "red"),
    "993": ("HIGH", "red"), "995": ("HIGH", "red"), "2049": ("HIGH", "red"),
    "2375": ("HIGH", "red"),
    "22": ("MEDIUM", "yellow"), "1433": ("MEDIUM", "yellow"),
    "3306": ("MEDIUM", "yellow"), "5432": ("MEDIUM", "yellow"),
    "6379": ("MEDIUM", "yellow"), "9200": ("MEDIUM", "yellow"),
    "11211": ("MEDIUM", "yellow"), "27017": ("MEDIUM", "yellow"),
    "80": ("LOW", "green"), "443": ("LOW", "green"),
    "8080": ("LOW", "green"), "8443": ("LOW", "green"),
}


def get_risk(port):
    return RISK_MAP.get(str(port), ("INFO", "dim"))


PROFILES = {
    "1": {"name": "Quick", "desc": "Top 100 port TCP + versi",
          "args": ["-T4", "-F", "-sV", "-Pn"], "needs_root": False},
    "2": {"name": "Full TCP", "desc": "Semua 65535 port TCP",
          "args": ["-T4", "-p-", "-sV", "-Pn"], "needs_root": False},
    "3": {"name": "Stealth", "desc": "SYN lambat + fragmentasi",
          "args": ["-sS", "-T2", "-f", "-Pn", "-F"], "needs_root": True},
    "4": {"name": "UDP Top 100", "desc": "100 port UDP",
          "args": ["-sU", "--top-ports", "100", "-T4", "-Pn"],
          "needs_root": True},
    "5": {"name": "Vuln Scan", "desc": "Vulners NSE",
          "args": ["-T4", "-sV", "--script", "vulners",
                   "-Pn", "--top-ports", "1000"], "needs_root": False},
    "6": {"name": "Aggressive", "desc": "OS + versi + script default",
          "args": ["-A", "-T4", "-Pn"], "needs_root": True},
}

FOLLOWUP_MAP = {
    "http":  {"ports": ["80", "443", "8080", "8443", "8000", "8888"],
              "scripts": "http-title,http-headers"},
    "ssh":   {"ports": ["22"], "scripts": "ssh-hostkey,ssh-auth-methods"},
    "smb":   {"ports": ["139", "445"],
              "scripts": "smb-os-discovery,smb-enum-shares"},
    "ftp":   {"ports": ["21"], "scripts": "ftp-anon"},
    "mysql": {"ports": ["3306"], "scripts": "mysql-info"},
    "redis": {"ports": ["6379"], "scripts": "redis-info"},
    "ssl":   {"ports": ["443", "8443"], "scripts": "ssl-cert"},
}

PREVIOUS_SCAN = {}
CVSS_THRESHOLD = 4.0


# ============================================================
# HELPERS
# ============================================================
def check_nmap():
    if shutil.which("nmap") is None:
        console.print("[bold red]✘ Nmap tidak ditemukan di sistem.[/bold red]")
        console.print("[yellow]→ Install: sudo apt install nmap / "
                      "brew install nmap[/yellow]")
        sys.exit(1)


def is_root():
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def select_profile(cfg):
    console.print("\n[bold cyan]═══ Pilih Scan Profile ═══[/bold cyan]\n")
    for key, prof in PROFILES.items():
        rt = " [dim](butuh root)[/dim]" if prof["needs_root"] else ""
        console.print(
            f"  [bold yellow][{key}][/bold yellow] {prof['name']:<13}"
            f" [dim]{prof['desc']}[/dim]{rt}"
        )
    default = _safe_cfg(cfg, "scan", "default_profile", str, "1")
    if default not in PROFILES:
        default = "1"
    console.print()
    try:
        choice = console.input(
            f"[bold]Pilih profile [1-6, default {default}]: [/bold]"
        ).strip() or default
    except (EOFError, KeyboardInterrupt):
        choice = default
    if choice not in PROFILES:
        choice = "1"
    prof = PROFILES[choice]
    console.print(f"[green]✔ Mode:[/green] [bold]{prof['name']}[/bold]")
    if prof["needs_root"] and not is_root():
        console.print(
            f"[yellow]⚠ Profile '{prof['name']}' disarankan root.[/yellow]")
    return prof["args"], prof["name"]


# ============================================================
# TARGET PARSING
# ============================================================
def expand_range(part):
    if "-" not in part:
        return [part]
    start, end = part.rsplit("-", 1)
    try:
        start_ip = ipaddress.ip_address(start)
        if end.isdigit():
            prefix = ".".join(start.split(".")[:-1])
            end_ip = ipaddress.ip_address(f"{prefix}.{end}")
        else:
            end_ip = ipaddress.ip_address(end)
        cnt = int(end_ip) - int(start_ip) + 1
        if cnt <= 0 or cnt > 65536:
            return [part]
        return [str(ipaddress.ip_address(int(start_ip) + i))
                for i in range(cnt)]
    except Exception:
        return [part]


def parse_targets(text):
    targets = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                targets.extend([str(ip) for ip in net.hosts()])
                continue
            except ValueError:
                pass
        if "-" in part:
            targets.extend(expand_range(part))
            continue
        targets.append(part)
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def is_domain(t):
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$", t))


# ============================================================
# NMAP RUNNER
# ============================================================
def run_nmap(target, args, extra=None, quiet=False, timeout=900):
    cmd = ["nmap"] + list(args) + (extra or []) + ["-oX", "-", target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout)
        if r.stdout.strip():
            return r.stdout
        if not quiet:
            console.print(f"[red]✘ {target}: {r.stderr.strip()[:120]}[/red]")
        return None
    except subprocess.TimeoutExpired:
        if not quiet:
            console.print(f"[red]✘ {target}: timeout ({timeout}s)[/red]")
        return None
    except FileNotFoundError:
        if not quiet:
            console.print("[red]✘ nmap binary hilang![/red]")
        return None
    except Exception as e:
        if not quiet:
            console.print(f"[red]✘ {target}: {type(e).__name__}: {e}[/red]")
        return None


def host_discovery(targets):
    if len(targets) <= 1:
        return targets
    alive = []
    try:
        for i in range(0, len(targets), 100):
            chunk = targets[i:i + 100]
            cmd = ["nmap", "-sn", "-T4"] + chunk + ["-oX", "-"]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=300)
                if r.stdout:
                    root = ET.fromstring(r.stdout)
                    for h in root.findall("host"):
                        st = h.find("status")
                        if st is not None and st.get("state") == "up":
                            for a in h.findall("address"):
                                if a.get("addrtype") == "ipv4":
                                    alive.append(a.get("addr"))
            except ET.ParseError:
                continue
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Host discovery dibatalkan.[/yellow]")
        return alive if alive else targets
    return alive


def parse_xml(xml):
    data = {"hosts": []}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return data
    except Exception:
        return data

    for host in root.findall("host"):
        try:
            h = {"ip": "N/A", "hostname": "N/A", "status": "N/A",
                 "mac": "N/A", "vendor": "N/A",
                 "os": [], "ports": [], "scripts": [], "vulns": []}
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    h["ip"] = a.get("addr")
                elif a.get("addrtype") == "mac":
                    h["mac"] = a.get("addr")
                    h["vendor"] = a.get("vendor", "Unknown")
            hn = host.find("./hostnames/hostname")
            if hn is not None:
                h["hostname"] = hn.get("name", "N/A")
            st = host.find("status")
            if st is not None:
                h["status"] = st.get("state", "N/A")
            osm = host.find("os")
            if osm is not None:
                for m in osm.findall("osmatch"):
                    h["os"].append({"name": m.get("name", "?"),
                                    "accuracy": m.get("accuracy", "0")})
            pts = host.find("ports")
            if pts is not None:
                for p in pts.findall("port"):
                    se = p.find("state")
                    sv = p.find("service")
                    pnum = p.get("portid", "?")
                    h["ports"].append({
                        "port": pnum,
                        "protocol": p.get("protocol", "?"),
                        "state": se.get("state", "?") if se is not None else "?",
                        "service": sv.get("name", "?") if sv is not None else "?",
                        "product": sv.get("product", "") if sv is not None else "",
                        "version": sv.get("version", "") if sv is not None else "",
                    })
                    for sc in p.findall("script"):
                        sid = sc.get("id", "")
                        out = sc.get("output", "").strip()
                        if sid == "vulners":
                            for table in sc.findall("table"):
                                cpe_key = table.get("key", "unknown")
                                for inner in table.findall("table"):
                                    cve_id, cvss = "", ""
                                    for el in inner.findall("elem"):
                                        k = el.get("key", "")
                                        if k == "id":
                                            cve_id = el.text or ""
                                        elif k == "cvss":
                                            cvss = el.text or ""
                                    if cve_id:
                                        try:
                                            cv = float(cvss) if cvss else 0.0
                                        except ValueError:
                                            cv = 0.0
                                        if cv >= CVSS_THRESHOLD:
                                            h["vulns"].append({
                                                "cpe": cpe_key,
                                                "id": cve_id,
                                                "cvss": cv,
                                            })
                        elif out:
                            h["scripts"].append({
                                "port": pnum, "id": sid,
                                "output": out.split("\n")[0][:100]
                            })
            data["hosts"].append(h)
        except Exception:
            continue
    return data


# ============================================================
# PROGRESS HELPER
# ============================================================
def _green_bar(width=40):
    return BarColumn(
        bar_width=width,
        complete_style="green",
        finished_style="bold green",
    )


# ============================================================
# SCAN
# ============================================================
def scan_hosts_parallel(hosts, args, prof_name, max_workers):
    results = {}
    if not hosts:
        return results
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            _green_bar(40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(hosts)} host...", total=len(hosts))
            with ThreadPoolExecutor(
                    max_workers=min(max_workers, len(hosts))) as ex:
                futures = {ex.submit(run_nmap, h, args, None, True): h
                           for h in hosts}
                for fut in as_completed(futures):
                    host = futures[fut]
                    try:
                        xml = fut.result()
                        if xml:
                            p = parse_xml(xml)
                            if p["hosts"]:
                                results[host] = p
                    except Exception:
                        pass
                    try:
                        progress.update(task, advance=1)
                    except Exception:
                        pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan dibatalkan.[/yellow]")
    return results


def run_banner_grab(results):
    if not HAS_BANNER_GRAB or banner_grab is None:
        return {}
    targets = []
    for data in results.values():
        for h in data["hosts"]:
            for p in h["ports"]:
                if p["state"] == "open":
                    try:
                        targets.append((h["ip"], int(p["port"])))
                    except (ValueError, TypeError):
                        continue
    if not targets:
        return {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Banner grab {len(targets)} port..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(targets))

            def _cb(_info):
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass

            banners = banner_grab.grab_many(
                targets, timeout=3.0, max_workers=10, on_result=_cb)
        return banners
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Banner grab dibatalkan.[/yellow]")
        return {}
    except Exception as e:
        console.print(f"[yellow]⚠ Banner grab error: {e}[/yellow]")
        return {}


def render_banners(banners):
    if not banners:
        return
    console.print("\n[bold green]═══════ Banner Grab ═══════[/bold green]\n")
    for ip, items in banners.items():
        try:
            t = Table(title=f"🏷  Banner — {ip}", box=box.ROUNDED,
                      title_style="bold cyan", header_style="bold magenta")
            t.add_column("Port", justify="center", style="cyan", width=7)
            t.add_column("TLS", justify="center", width=4)
            t.add_column("Service", style="yellow", width=12)
            t.add_column("Product", style="white")
            t.add_column("Version", style="green", width=12)
            t.add_column("Banner", style="dim")
            for it in items:
                tls_tag = "[green]yes[/green]" if it.get("tls") else "—"
                err = (f" [red]({it.get('error')})[/red]"
                       if it.get("error") else "")
                extra = it.get("extra", {}) or {}
                t.add_row(
                    str(it.get("port", "?")), tls_tag,
                    str(it.get("service", "?")),
                    it.get("product") or "—",
                    extra.get("version", "—"),
                    (str(it.get("banner", ""))[:60] or "—") + err,
                )
            console.print(t)
        except Exception:
            continue


def run_auto_vuln_scan(results, existing_args):
    try:
        if any("vulners" in a for a in existing_args):
            return {}
        targets = []
        for ip, data in results.items():
            for h in data["hosts"]:
                opens = [p["port"] for p in h["ports"]
                         if p["state"] == "open"]
                if opens:
                    targets.append((ip, opens))
        if not targets:
            return {}
        out = {}
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Auto Vuln Scan — {len(targets)} host..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(targets))
            with ThreadPoolExecutor(
                    max_workers=min(10, len(targets))) as ex:
                futures = {}
                for ip, ports in targets:
                    args = ["-T4", "-Pn", "-sV", "--script", "vulners",
                            "-p", ",".join(ports)]
                    futures[ex.submit(run_nmap, ip, args, None, True)] = ip
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        xml = fut.result()
                        if xml:
                            p = parse_xml(xml)
                            if p["hosts"]:
                                out[ip] = p
                    except Exception:
                        pass
                    try:
                        progress.update(task, advance=1)
                    except Exception:
                        pass
        return out
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Vuln scan dibatalkan.[/yellow]")
        return {}
    except Exception as e:
        console.print(f"[yellow]⚠ Vuln scan error: {e}[/yellow]")
        return {}


def render_vulns(vuln_data):
    if not vuln_data:
        return
    for ip, data in vuln_data.items():
        try:
            for h in data["hosts"]:
                if not h["vulns"]:
                    continue
                t = Table(title=f"🔥 CVE — {ip}", box=box.HEAVY_HEAD,
                          title_style="bold red",
                          header_style="bold magenta")
                t.add_column("CPE", style="cyan")
                t.add_column("CVE", style="bold yellow")
                t.add_column("CVSS", justify="center", style="bold red")
                for v in h["vulns"]:
                    short = (v["cpe"].split(":")[3]
                             if ":" in v["cpe"] else v["cpe"])
                    t.add_row(short, v["id"], f"{v['cvss']:.1f}")
                console.print(t)
        except Exception:
            continue


# ============================================================
# OSINT
# ============================================================
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def whois_lookup(domain):
    if not HAS_WHOIS or whois_lib is None:
        return None
    try:
        w = whois_lib.whois(domain)
        return {
            "registrar": str(w.get("registrar", "—"))[:60],
            "creation": str(w.get("creation_date", "—"))[:10],
            "expiry": str(w.get("expiration_date", "—"))[:10],
        }
    except Exception:
        return None


def geoip_lookup(ip):
    if not HAS_GEOIP or geoip2 is None or not os.path.exists(GEOIP_DB_PATH):
        return "—"
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as r:
            resp = r.city(ip)
            return f"{resp.country.name or '—'} / {resp.city.name or '—'}"
    except Exception:
        return "—"


def render_osint(results):
    try:
        console.print("\n[bold green]═══════ OSINT Recon ═══════[/bold green]\n")
        for host_key in results:
            for h in results[host_key]["hosts"]:
                ip = h["ip"]
                try:
                    t = Table(box=box.SIMPLE, show_header=False)
                    t.add_column("Field", style="bold yellow", width=18)
                    t.add_column("Value", style="white")
                    t.add_row("IP", ip)
                    t.add_row("Reverse DNS", reverse_dns(ip))
                    if h["hostname"] != "N/A" and "." in h["hostname"]:
                        w = whois_lookup(h["hostname"])
                        if w:
                            t.add_row("Whois Registrar", w["registrar"])
                            t.add_row("Whois Created", w["creation"])
                            t.add_row("Whois Expiry", w["expiry"])
                    t.add_row("GeoIP", geoip_lookup(ip))
                    console.print(t)
                except Exception:
                    continue
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ OSINT dibatalkan.[/yellow]")


# ============================================================
# DIFF
# ============================================================
def build_snapshot(results):
    snap = {}
    try:
        for data in results.values():
            for h in data["hosts"]:
                snap[h["ip"]] = {}
                for p in h["ports"]:
                    if p["state"] == "open":
                        snap[h["ip"]][p["port"]] = {
                            "service": p["service"],
                            "version": f"{p['product']} {p['version']}".strip(),
                        }
    except Exception:
        pass
    return snap


def diff_snapshots(prev, curr):
    diff = {"new_ports": [], "closed_ports": [], "changed": []}
    try:
        for ip, ports in curr.items():
            pp = prev.get(ip, {})
            for port, info in ports.items():
                if port not in pp:
                    diff["new_ports"].append((ip, port, info))
                elif (info["service"] != pp[port]["service"] or
                      info["version"] != pp[port]["version"]):
                    diff["changed"].append((ip, port, pp[port], info))
        for ip, ports in prev.items():
            cp = curr.get(ip, {})
            for port, info in ports.items():
                if port not in cp:
                    diff["closed_ports"].append((ip, port, info))
    except Exception:
        pass
    return diff


def render_diff(diff):
    try:
        if not any(diff.values()):
            console.print(
                "\n[green]✔ Tidak ada perubahan dibanding scan sebelumnya.[/green]")
            return
        console.print(
            "\n[bold yellow]═══════ Scan Diff ═══════[/bold yellow]")
        if diff["new_ports"]:
            t = Table(title="🟢 Port BARU", box=box.ROUNDED,
                      header_style="bold green")
            t.add_column("Host", style="cyan")
            t.add_column("Port")
            t.add_column("Service", style="yellow")
            for ip, port, info in diff["new_ports"]:
                t.add_row(ip, port, info["service"])
            console.print(t)
        if diff["closed_ports"]:
            t = Table(title="🔴 Port TERTUTUP", box=box.ROUNDED,
                      header_style="bold red")
            t.add_column("Host", style="cyan")
            t.add_column("Port")
            for ip, port, info in diff["closed_ports"]:
                t.add_row(ip, port)
            console.print(t)
        if diff["changed"]:
            t = Table(title="🟡 Service BERUBAH", box=box.ROUNDED,
                      header_style="bold yellow")
            t.add_column("Host", style="cyan")
            t.add_column("Port")
            t.add_column("Sebelum")
            t.add_column("Sekarang")
            for ip, port, old, new in diff["changed"]:
                t.add_row(ip, port,
                          f"{old['service']} {old['version']}",
                          f"{new['service']} {new['version']}")
            console.print(t)
    except Exception:
        pass


# ============================================================
# WEB PIPELINE
# ============================================================
def build_web_urls(results):
    web_ports = {"80": "http", "443": "https", "8080": "http",
                 "8443": "https", "8000": "http", "8888": "http"}
    urls = []
    for data in results.values():
        for h in data["hosts"]:
            for p in h["ports"]:
                if p["state"] == "open" and p["port"] in web_ports:
                    urls.append(
                        f"{web_ports[p['port']]}://{h['ip']}:{p['port']}/")
    return urls


def run_web_vuln(urls, delay_ms):
    if not HAS_WEB_VULN or web_vuln is None or not urls:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Web vuln check {len(urls)} URL..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(urls))
            for u in urls:
                try:
                    f = web_vuln.check_web(u, delay_ms=delay_ms)
                    if f:
                        out[u] = f
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Web vuln dibatalkan.[/yellow]")
    return out


def render_web_vuln(wv):
    if not wv:
        return
    try:
        console.print(
            "\n[bold green]═══════ Web Vulnerability Scan ═══════[/bold green]")
        for url, findings in wv.items():
            t = Table(title=f"🌐 {url}", box=box.HEAVY_HEAD,
                      header_style="bold magenta")
            t.add_column("Type", style="yellow")
            t.add_column("Severity", justify="center")
            t.add_column("Detail", style="white")
            for f in findings:
                sev = f.get("severity", "INFO")
                c = {"CRITICAL": "bold red", "HIGH": "bold red",
                     "MEDIUM": "yellow", "LOW": "green",
                     "INFO": "dim"}.get(sev, "white")
                t.add_row(
                    str(f.get("type", "?")),
                    f"[{c}]{sev}[/{c}]",
                    str(f.get("detail", "")),
                )
            console.print(t)
    except Exception:
        pass


def run_sqli_xss(urls, delay_ms, enable_sqli, enable_xss, blind_sqli=False):
    sqli_r, xss_r = {}, {}
    if not urls:
        return sqli_r, xss_r

    # Kumpulkan URL dengan parameter
    param_urls = set()
    if HAS_WEB_VULN and web_vuln is not None:
        try:
            import urllib.request as _ureq
            import ssl as _ssl
            for base in urls:
                try:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    req = _ureq.Request(
                        base, headers={"User-Agent": "nmpX/1.0"})
                    with _ureq.urlopen(
                            req, timeout=5, context=ctx) as r:
                        body = r.read(8192).decode("utf-8", errors="replace")
                        if hasattr(web_vuln, "extract_param_links"):
                            for link in web_vuln.extract_param_links(
                                    body, base):
                                param_urls.add(link)
                except Exception:
                    pass
        except Exception:
            pass

    for base in urls:
        for q in ("?id=1", "?q=test", "?search=test"):
            param_urls.add(base.rstrip("/") + "/" + q)

    param_urls = list(param_urls)[:15]
    if not param_urls:
        return sqli_r, xss_r

    # SQLi
    if enable_sqli and HAS_SQLI and sqli is not None:
        modes = ["error", "boolean", "time"]
        if blind_sqli:
            modes.append("blind")
            console.print(
                "[yellow]🔍 Blind SQLi extraction aktif (lebih lambat)[/yellow]")
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]SQLi test..."),
                _green_bar(30),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("", total=len(param_urls))
                for u in param_urls:
                    try:
                        f = sqli.scan(
                            u, delay_ms=delay_ms, modes=modes,
                            blind_dump_data=blind_sqli)
                        if f:
                            sqli_r[u] = f
                    except Exception:
                        pass
                    try:
                        progress.update(task, advance=1)
                    except Exception:
                        pass
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ SQLi dibatalkan.[/yellow]")

    # XSS
    if enable_xss and HAS_XSS and xss is not None:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]XSS test..."),
                _green_bar(30),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("", total=len(param_urls))
                for u in param_urls:
                    try:
                        f = xss.scan(u, delay_ms=delay_ms)
                        if f:
                            xss_r[u] = f
                    except Exception:
                        pass
                    try:
                        progress.update(task, advance=1)
                    except Exception:
                        pass
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ XSS dibatalkan.[/yellow]")

    return sqli_r, xss_r


def render_sqli(sqli_res):
    if not sqli_res:
        return
    try:
        console.print(
            "\n[bold red]═══════ SQL Injection (terdeteksi) ═══════[/bold red]")
        t = Table(box=box.HEAVY_HEAD, header_style="bold red")
        t.add_column("URL", style="cyan")
        t.add_column("Param", style="yellow")
        t.add_column("Payload", style="white")
        t.add_column("Evidence", style="red")
        for u, findings in sqli_res.items():
            for f in findings:
                t.add_row(
                    str(f.get("url", ""))[:60],
                    str(f.get("param", "")),
                    str(f.get("payload", ""))[:40],
                    str(f.get("evidence", ""))[:60],
                )
        console.print(t)
    except Exception:
        pass


def render_xss(xss_res):
    if not xss_res:
        return
    try:
        console.print(
            "\n[bold red]═══════ Reflected XSS (terdeteksi) ═══════[/bold red]")
        t = Table(box=box.HEAVY_HEAD, header_style="bold red")
        t.add_column("URL", style="cyan")
        t.add_column("Param", style="yellow")
        t.add_column("Payload", style="white")
        t.add_column("Context", style="dim")
        for u, findings in xss_res.items():
            for f in findings:
                t.add_row(
                    str(f.get("url", ""))[:60],
                    str(f.get("param", "")),
                    str(f.get("payload", ""))[:40],
                    str(f.get("context", "-")),
                )
        console.print(t)
    except Exception:
        pass


# ============================================================
# DIR BRUTE
# ============================================================
def run_dir_brute(urls, delay_ms, tier=2):
    if not HAS_DIR_BRUTE or dir_brute is None or not urls:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Dir bruteforce {len(urls)} URL (tier {tier})..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(urls))
            for u in urls:
                try:
                    r = dir_brute.scan(
                        u, tier=tier, threads=20, timeout=5,
                        delay_ms=delay_ms if delay_ms else 0,
                        extensions=True,
                    )
                    if r and r["findings"]:
                        out[u] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Dir brute dibatalkan.[/yellow]")
    return out


def render_dir_brute(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ Directory Bruteforce ═══════[/bold green]")
        for url, res in data.items():
            findings = res.get("findings", [])
            if not findings:
                continue
            t = Table(title=f"📁 {url} — {len(findings)} ditemukan",
                      box=box.HEAVY_HEAD, header_style="bold magenta")
            t.add_column("Status", justify="center", width=6)
            t.add_column("Path", style="cyan")
            t.add_column("Size", justify="right", style="dim")
            t.add_column("Title", style="yellow")
            t.add_column("Redirect", style="dim")
            for f in findings[:30]:
                t.add_row(
                    str(f.get("status", "?")),
                    f.get("path", "")[:45],
                    f"{f.get('size', 0)}B",
                    (f.get("title") or "")[:25],
                    (f.get("redirect") or "")[:35],
                )
            if len(findings) > 30:
                t.add_row("...", f"+{len(findings) - 30} lagi", "", "", "")
            console.print(t)
            if res.get("wildcard"):
                console.print(
                    f"[yellow]⚠ Wildcard: "
                    f"{res['wildcard'].get('type', '?')}[/yellow]")
    except Exception:
        pass


# ============================================================
# SUBDOMAIN
# ============================================================
def run_subdomain_enum(domains, delay_ms, tier=2):
    if not HAS_SUBDOMAIN or subdomain is None or not domains:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Subdomain enum {len(domains)} domain "
                       f"(tier {tier})..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(domains))
            for d in domains:
                try:
                    r = subdomain.scan(
                        d, tier=tier, threads=20, timeout=3,
                        delay_ms=delay_ms if delay_ms else 0,
                        http_probe=True, use_ct_logs=True,
                    )
                    if r and r["found"]:
                        out[d] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Subdomain enum dibatalkan.[/yellow]")
    return out


def render_subdomain(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ Subdomain Enumeration ═══════[/bold green]")
        for domain, res in data.items():
            found = res.get("found", [])
            if not found:
                continue
            t = Table(
                title=f"🌐 {domain} — {len(found)} subdomain",
                box=box.HEAVY_HEAD, header_style="bold magenta")
            t.add_column("Subdomain", style="cyan")
            t.add_column("IP", style="white")
            t.add_column("HTTP", justify="center", width=6)
            t.add_column("Title", style="yellow")
            t.add_column("Risk", justify="center")
            for f in found[:30]:
                http_code = ""
                if f.get("http"):
                    http_code = str(f["http"].get("status", ""))
                elif f.get("https"):
                    http_code = str(f["https"].get("status", ""))
                title = ""
                if f.get("http"):
                    title = f["http"].get("title", "")
                elif f.get("https"):
                    title = f["https"].get("title", "")
                risk = "—"
                if f.get("takeover"):
                    risk = (f"[bold red]⚠ "
                            f"{f['takeover']['service']}[/bold red]")
                t.add_row(
                    f["subdomain"][:40],
                    f["ip"],
                    http_code,
                    (title or "")[:25],
                    risk,
                )
            if len(found) > 30:
                t.add_row(f"...+{len(found) - 30} lagi", "", "", "", "")
            console.print(t)
    except Exception:
        pass


# ============================================================
# HTTP FUZZ
# ============================================================
def run_http_fuzz(urls, delay_ms):
    if not HAS_HTTP_FUZZ or http_fuzz is None or not urls:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]HTTP fuzz {len(urls)} URL..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(urls))
            for u in urls:
                try:
                    r = http_fuzz.fuzz_params(
                        u, timeout=5,
                        delay_ms=delay_ms if delay_ms else 0,
                        modes=("param", "header", "path"))
                    if r and r["findings"]:
                        out[u] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ HTTP fuzz dibatalkan.[/yellow]")
    return out


def render_http_fuzz(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ HTTP Fuzzer ═══════[/bold green]")
        for url, res in data.items():
            findings = res.get("findings", [])
            if not findings:
                continue
            t = Table(title=f"🎯 {url} — {len(findings)} anomali",
                      box=box.HEAVY_HEAD, header_style="bold magenta")
            t.add_column("Severity", justify="center", width=10)
            t.add_column("Category", style="yellow", width=12)
            t.add_column("Param", style="cyan")
            t.add_column("Payload", style="white")
            t.add_column("Evidence", style="dim")
            sev_color = {"CRITICAL": "bold red", "HIGH": "red",
                         "MEDIUM": "yellow", "LOW": "green"}
            for f in findings[:25]:
                c = sev_color.get(f["severity"], "white")
                t.add_row(
                    f"[{c}]{f['severity']}[/{c}]",
                    f["category"], f["param"],
                    f["payload"][:30], f["evidence"][:40])
            if len(findings) > 25:
                t.add_row("...", f"+{len(findings) - 25} lagi", "", "", "")
            console.print(t)
    except Exception:
        pass


# ============================================================
# PORT KNOCK
# ============================================================
def run_port_knock(targets, target_port=22, custom_sequence=None):
    if not HAS_PORT_KNOCK or port_knock is None or not targets:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Port-knock check {len(targets)} host..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(targets))
            for t in targets[:3]:
                try:
                    if custom_sequence:
                        r = port_knock.detect_with_custom(
                            t, custom_sequence, target_port=target_port)
                    else:
                        r = port_knock.detect(t, target_port=target_port)
                    if r:
                        out[t] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Port-knock dibatalkan.[/yellow]")
    return out


def render_port_knock(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ Port-Knock Detection ═══════[/bold green]")
        for host, res in data.items():
            t = Table(
                title=f"🚪 {host} (target port {res.get('target_port', 22)})",
                box=box.ROUNDED, header_style="bold magenta")
            t.add_column("Sequence", style="cyan")
            t.add_column("Ports", style="white")
            t.add_column("Before", justify="center")
            t.add_column("After", justify="center")
            t.add_column("Detected", justify="center")
            for r in res.get("results", []):
                det = ("[bold green]✅ YES[/bold green]"
                       if r["detected"] else "[dim]❌[/dim]")
                t.add_row(r["sequence"],
                          "→".join(str(p) for p in r["ports"]),
                          r["before"], r["after"], det)
            console.print(t)
            if res.get("detected"):
                console.print(
                    "[bold red]⚠ PORT-KNOCK TERDETEKSI![/bold red]")
    except Exception:
        pass


# ============================================================
# TLS AUDIT
# ============================================================
def run_tls_audit(results):
    if not HAS_TLS_AUDIT or tls_audit is None:
        return {}
    targets = []
    for data in results.values():
        for h in data["hosts"]:
            for p in h["ports"]:
                if p["state"] == "open" and p["port"] in (
                        "443", "8443", "993", "995", "465", "636"):
                    try:
                        targets.append((h["ip"], int(p["port"])))
                    except (ValueError, TypeError):
                        continue
    if not targets:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]TLS audit {len(targets)} endpoint..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(targets))
            for ip, port in targets:
                try:
                    r = tls_audit.audit(ip, port=port, timeout=5)
                    if r and r.get("findings"):
                        out[f"{ip}:{port}"] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ TLS audit dibatalkan.[/yellow]")
    return out


def render_tls_audit(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ TLS Deep Audit ═══════[/bold green]")
        for endpoint, r in data.items():
            t = Table(title=f"🔒 {endpoint}",
                      box=box.ROUNDED, header_style="bold magenta")
            t.add_column("Field", style="bold yellow", width=18)
            t.add_column("Value", style="white")
            t.add_row("TLS Versions",
                      ", ".join(r.get("supported_versions", [])) or "N/A")
            if r.get("cipher"):
                t.add_row(
                    "Cipher",
                    f"{r['cipher']['name']} ({r['cipher']['bits']} bit)")
            if r.get("alpn"):
                t.add_row("ALPN", r["alpn"])
            t.add_row("OCSP", "Yes" if r.get("ocsp") else "No")
            cert = r.get("cert", {})
            if cert.get("subject"):
                t.add_row("Cert Subject", cert["subject"][:50])
            if cert.get("issuer"):
                t.add_row("Cert Issuer", cert["issuer"][:50])
            days = cert.get("days_until_expiry")
            if days is not None:
                color = ("bold red" if days < 0 else
                         "yellow" if days < 30 else "green")
                t.add_row("Days until expiry",
                          f"[{color}]{days}[/{color}]")
            console.print(t)

            if r.get("findings"):
                ft = Table(title="Findings", box=box.SIMPLE,
                           header_style="bold red")
                ft.add_column("Severity", width=10)
                ft.add_column("Type", style="yellow")
                ft.add_column("Detail", style="white")
                sev_color = {"CRITICAL": "bold red", "HIGH": "red",
                             "MEDIUM": "yellow", "LOW": "green",
                             "INFO": "dim"}
                for f in r["findings"]:
                    c = sev_color.get(f["severity"], "white")
                    ft.add_row(f"[{c}]{f['severity']}[/{c}]",
                               f["type"], f["detail"][:80])
                console.print(ft)
    except Exception:
        pass


# ============================================================
# GRAPHQL
# ============================================================
def run_graphql_scan(web_urls, delay_ms):
    if not HAS_GRAPHQL or graphql_scan is None or not web_urls:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]GraphQL scan {len(web_urls)} URL..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(web_urls))
            for u in web_urls:
                try:
                    r = graphql_scan.scan(
                        u, timeout=5,
                        delay_ms=delay_ms if delay_ms else 0)
                    if r and r.get("endpoints_found"):
                        out[u] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ GraphQL scan dibatalkan.[/yellow]")
    return out


def render_graphql(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ GraphQL Scan ═══════[/bold green]")
        for base_url, r in data.items():
            endpoints = r.get("endpoints_found", [])
            if not endpoints:
                continue
            t = Table(
                title=f"🔷 {base_url} — {len(endpoints)} endpoint",
                box=box.HEAVY_HEAD, header_style="bold magenta")
            t.add_column("Path", style="cyan")
            t.add_column("Status", justify="center")
            t.add_column("Introspection", justify="center")
            t.add_column("GET", justify="center")
            t.add_column("Types", justify="right")
            for e in endpoints:
                intro = ("[yellow]ENABLED[/yellow]"
                         if e["introspection_enabled"]
                         else "[dim]disabled[/dim]")
                get_ok = ("[yellow]yes[/yellow]"
                          if e["get_works"] else "[dim]no[/dim]")
                types_count = (str(e["schema"]["types_count"])
                               if e["schema"] else "—")
                t.add_row(e["path"], str(e["status"]), intro, get_ok,
                          types_count)
            console.print(t)
            if r.get("findings"):
                ft = Table(title="Findings", box=box.SIMPLE,
                           header_style="bold red")
                ft.add_column("Severity", width=10)
                ft.add_column("Type", style="yellow")
                ft.add_column("Detail", style="white")
                sev_color = {"CRITICAL": "bold red", "HIGH": "red",
                             "MEDIUM": "yellow", "LOW": "green",
                             "INFO": "dim"}
                for f in r["findings"]:
                    color = sev_color.get(f["severity"], "white")
                    ft.add_row(f"[{color}]{f['severity']}[/{color}]",
                               f["type"], f["detail"][:80])
                console.print(ft)
    except Exception:
        pass


# ============================================================
# HTTP/2
# ============================================================
def run_http2_check(results):
    if not HAS_HTTP2_CHECK or http2_check is None:
        return {}
    targets = []
    for data in results.values():
        for h in data["hosts"]:
            for p in h["ports"]:
                if p["state"] == "open" and p["port"] in (
                        "443", "8443", "80", "8080"):
                    try:
                        targets.append((h["ip"], int(p["port"])))
                    except (ValueError, TypeError):
                        continue
    if not targets:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]HTTP/2 check {len(targets)} endpoint..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(targets))
            for ip, port in targets:
                try:
                    r = http2_check.check(ip, port=port, timeout=5)
                    if r:
                        out[f"{ip}:{port}"] = r
                except Exception:
                    pass
                try:
                    progress.update(task, advance=1)
                except Exception:
                    pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ HTTP/2 check dibatalkan.[/yellow]")
    return out


def render_http2(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ HTTP/2 Detection ═══════[/bold green]")
        for endpoint, r in data.items():
            h2_tag = ("[green]✓ h2[/green]" if r["h2_over_tls"]
                      else "[dim]✗ h2[/dim]")
            h2c_tag = ("[yellow]h2c[/yellow]" if r["h2c_supported"]
                       else "[dim]—[/dim]")
            console.print(
                f"\n[cyan]{endpoint}[/cyan]  "
                f"ALPN={r['alpn'] or 'none'}  "
                f"{h2_tag}  {h2c_tag}  "
                f"Server={r['server'][:40] or '—'}")
    except Exception:
        pass


# ============================================================
# FILTER + RENDER HOST
# ============================================================
def auto_filter(results, vuln_data):
    out = {}
    try:
        for host_key, data in results.items():
            new_data = {"hosts": []}
            for h in data["hosts"]:
                interesting = []
                for p in h["ports"]:
                    if p["state"] != "open":
                        continue
                    risk = get_risk(p["port"])[0]
                    if risk in ("CRITICAL", "HIGH"):
                        interesting.append(p)
                if interesting:
                    nh = h.copy()
                    nh["ports"] = interesting
                    new_data["hosts"].append(nh)
            if new_data["hosts"]:
                out[host_key] = new_data
    except Exception:
        return results
    return out


def render_overview(results):
    try:
        t = Table(title=f"📋 Overview — {len(results)} host",
                  box=box.HEAVY_HEAD, header_style="bold magenta")
        t.add_column("#", justify="right", width=4)
        t.add_column("IP", style="cyan")
        t.add_column("Hostname")
        t.add_column("Open", justify="center", style="green")
        t.add_column("Critical", justify="center", style="bold red")
        t.add_column("Status", justify="center")
        for i, (_, data) in enumerate(results.items(), 1):
            for h in data["hosts"]:
                opens = [p for p in h["ports"] if p["state"] == "open"]
                crit = sum(1 for p in opens
                           if get_risk(p["port"])[0] == "CRITICAL")
                t.add_row(str(i), h["ip"], h["hostname"], str(len(opens)),
                          f"[bold red]{crit}[/bold red]" if crit else "0",
                          f"[green]{h['status']}[/green]")
        console.print()
        console.print(t)
    except Exception:
        pass


def render_host(h, prof_name):
    try:
        info = Table(title=f"🖥  {h['ip']} — {prof_name}",
                     box=box.ROUNDED, title_style="bold cyan",
                     header_style="bold magenta")
        info.add_column("Field", style="bold yellow", width=15)
        info.add_column("Value", style="white")
        info.add_row("IP", h["ip"])
        info.add_row("Hostname", h["hostname"])
        info.add_row("Status", h["status"])
        info.add_row("MAC", h["mac"])
        info.add_row("Vendor", h["vendor"])
        console.print()
        console.print(info)

        opens = [p for p in h["ports"] if p["state"] == "open"]
        pt = Table(title=f"🔓 Port Terbuka ({len(opens)})",
                   box=box.HEAVY_HEAD, header_style="bold magenta")
        pt.add_column("Port", style="bold cyan", justify="center")
        pt.add_column("Proto", justify="center")
        pt.add_column("Service", style="yellow")
        pt.add_column("Version", style="white")
        pt.add_column("Risk", justify="center")
        for p in opens:
            risk, color = get_risk(p["port"])
            ver = (" ".join(filter(None, [p["product"], p["version"]]))
                   or "—")
            pt.add_row(p["port"], p["protocol"], p["service"], ver,
                       f"[{color}]{risk}[/{color}]")
        if not opens:
            pt.add_row("—", "—", "no open ports", "—", "—")
        console.print(pt)
    except Exception:
        pass


# ============================================================
# FOLLOW-UP
# ============================================================
def build_followup_plan(results):
    plan = {}
    try:
        for data in results.values():
            for h in data["hosts"]:
                opens = {p["port"] for p in h["ports"]
                         if p["state"] == "open"}
                ports, scripts = set(), set()
                for cfg in FOLLOWUP_MAP.values():
                    matched = opens & set(cfg["ports"])
                    if matched:
                        ports.update(matched)
                        scripts.update(cfg["scripts"].split(","))
                if ports and scripts:
                    try:
                        sorted_ports = sorted(ports, key=int)
                    except (ValueError, TypeError):
                        sorted_ports = sorted(ports)
                    plan[h["ip"]] = {
                        "ports": sorted_ports,
                        "scripts": ",".join(sorted(scripts)),
                    }
    except Exception:
        pass
    return plan


def run_followup(plan):
    if not plan:
        return {}
    out = {}
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[magenta]Follow-up {len(plan)} host..."),
            _green_bar(40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(plan))
            with ThreadPoolExecutor(
                    max_workers=min(10, len(plan))) as ex:
                futures = {}
                for ip, cfg in plan.items():
                    args = ["-T4", "-Pn", "-p", ",".join(cfg["ports"]),
                            "--script", cfg["scripts"], "-sV"]
                    futures[ex.submit(run_nmap, ip, args, None, True)] = ip
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        xml = fut.result()
                        if xml:
                            out[ip] = parse_xml(xml)
                    except Exception:
                        pass
                    try:
                        progress.update(task, advance=1)
                    except Exception:
                        pass
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Follow-up dibatalkan.[/yellow]")
    return out


def render_followup(data):
    if not data:
        return
    try:
        console.print(
            "\n[bold green]═══════ Auto Follow-up ═══════[/bold green]")
        for ip, d in data.items():
            for h in d["hosts"]:
                if not h["scripts"]:
                    continue
                t = Table(title=f"📜 NSE — {ip}", box=box.ROUNDED,
                          header_style="bold blue")
                t.add_column("Port", style="cyan", width=8)
                t.add_column("Script", style="yellow")
                t.add_column("Output", style="white")
                for s in h["scripts"]:
                    t.add_row(s.get("port", "—"), s["id"], s["output"])
                console.print(t)
    except Exception:
        pass


# ============================================================
# SUMMARY + MODULE STATUS
# ============================================================
def render_summary(results, prof_name, elapsed, discovered, extras):
    try:
        total_hosts = sum(len(d["hosts"]) for d in results.values())
        total_open = 0
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                  "LOW": 0, "INFO": 0}
        for d in results.values():
            for h in d["hosts"]:
                for p in h["ports"]:
                    if p["state"] == "open":
                        total_open += 1
                        counts[get_risk(p["port"])[0]] += 1

        t = Table(title="📊 Summary Statistics", box=box.DOUBLE,
                  title_style="bold magenta", header_style="bold yellow")
        t.add_column("Metric", style="bold yellow", width=26)
        t.add_column("Value", style="white")
        t.add_row("Profile", prof_name)
        t.add_row("Targets Input", str(discovered["input"]))
        t.add_row("Alive Hosts", str(discovered["alive"]))
        t.add_row("Hosts Scanned", str(total_hosts))
        t.add_row("Open Ports",
                  f"[bold green]{total_open}[/bold green]")
        t.add_row("Critical", f"[bold red]{counts['CRITICAL']}[/bold red]")
        t.add_row("High", f"[red]{counts['HIGH']}[/red]")
        t.add_row("Medium", f"[yellow]{counts['MEDIUM']}[/yellow]")
        t.add_row("Low", f"[green]{counts['LOW']}[/green]")
        t.add_row("Banners", str(extras.get("banners", 0)))
        t.add_row("Subdomains", str(extras.get("subdomains", 0)))
        t.add_row("Web URLs", str(extras.get("web_urls", 0)))
        t.add_row("Dir Found", str(extras.get("dir_found", 0)))
        t.add_row("SQLi Found", str(extras.get("sqli", 0)))
        t.add_row("XSS Found", str(extras.get("xss", 0)))
        t.add_row("Safe Mode",
                  "[green]ON[/green]" if extras.get("safe_mode")
                  else "[dim]OFF[/dim]")
        t.add_row("Waktu", f"{elapsed:.2f} detik")
        console.print()
        console.print(t)
    except Exception:
        pass


def render_module_status():
    try:
        parts = []
        for name, has in [
            ("banner", HAS_BANNER),
            ("banner_grab", HAS_BANNER_GRAB),
            ("web_vuln", HAS_WEB_VULN),
            ("sqli", HAS_SQLI),
            ("xss", HAS_XSS),
            ("dir_brute", HAS_DIR_BRUTE),
            ("subdomain", HAS_SUBDOMAIN),
            ("tls_audit", HAS_TLS_AUDIT),
            ("http_fuzz", HAS_HTTP_FUZZ),
            ("graphql", HAS_GRAPHQL),
            ("http2", HAS_HTTP2_CHECK),
            ("port_knock", HAS_PORT_KNOCK),
            ("search", HAS_SEARCH),
            ("plugins", HAS_PLUGINS),
            ("tui", HAS_TUI),
        ]:
            parts.append(f"[green]{name}[/green]" if has
                         else f"[dim]{name}[/dim]")
        console.print("[dim]Modul aktif:[/dim] " + " ".join(parts))
    except Exception:
        pass


# ============================================================
# SEARCH + PLUGINS
# ============================================================
def collect_all_findings(results, vuln_data, wv, sq, xs, dir_data,
                          sub_data, banners, fuzz_data, tls_data=None,
                          graphql_data=None, http2_data=None,
                          port_knock_data=None):
    """Kumpulkan semua findings jadi list flat untuk search & plugins."""
    findings = []

    def _add(source, host, port, service, risk, text):
        findings.append({
            "source": source, "host": host, "port": port,
            "service": service, "risk": risk, "text": text,
        })

    # Port scan
    try:
        for host, data in results.items():
            for h in data["hosts"]:
                for p in h["ports"]:
                    if p["state"] == "open":
                        risk = get_risk(p["port"])[0]
                        ver = f"{p['product']} {p['version']}".strip()
                        _add("port", h["ip"], p["port"], p["service"],
                             risk, f"{p['service']} {ver}")
    except Exception:
        pass

    # CVE
    try:
        for ip, data in (vuln_data or {}).items():
            for h in data["hosts"]:
                for v in h["vulns"]:
                    _add("cve", ip, "", "", "HIGH",
                         f"{v['id']} (CVSS {v['cvss']}) di {v['cpe']}")
    except Exception:
        pass

    # Web vuln
    try:
        for url, items in (wv or {}).items():
            try:
                host = urllib.parse.urlparse(url).netloc or url[:40]
            except Exception:
                host = url[:40]
            for f in items:
                _add("web_vuln", host, "", "",
                     f.get("severity", "INFO"),
                     f"{f.get('type', '')}: {f.get('detail', '')}")
    except Exception:
        pass

    # SQLi
    try:
        for url, items in (sq or {}).items():
            for f in items:
                _add("sqli", url, f.get("param", ""), "",
                     f.get("severity", "INFO"),
                     f"{f.get('type', '')} param={f.get('param', '')} "
                     f"{f.get('evidence', '')}")
    except Exception:
        pass

    # XSS
    try:
        for url, items in (xs or {}).items():
            for f in items:
                _add("xss", url, f.get("param", ""), "",
                     f.get("severity", "INFO"),
                     f"{f.get('type', '')} {f.get('context', '')}")
    except Exception:
        pass

    # Dir brute
    try:
        for url, res in (dir_data or {}).items():
            for f in res.get("findings", []):
                _add("dir", url, "", "", "MEDIUM",
                     f"{f.get('status', '')} {f.get('path', '')}")
    except Exception:
        pass

    # Subdomain
    try:
        for domain, res in (sub_data or {}).items():
            for f in res.get("found", []):
                risk = ("CRITICAL" if f.get("takeover") else "INFO")
                takeover = (f.get("takeover", {}).get("service", "")
                            if f.get("takeover") else "")
                _add("sub", f["subdomain"], "", "", risk,
                     f"IP {f.get('ip', '')} "
                     f"{('TAKEOVER ' + takeover) if takeover else ''}")
    except Exception:
        pass

    # HTTP fuzz
    try:
        for url, res in (fuzz_data or {}).items():
            for f in res.get("findings", []):
                _add("fuzz", url, f.get("param", ""), "",
                     f.get("severity", "INFO"),
                     f"{f.get('category', '')} {f.get('evidence', '')}")
    except Exception:
        pass

    # TLS
    try:
        for endpoint, r in (tls_data or {}).items():
            for f in r.get("findings", []):
                _add("tls", endpoint, "", "",
                     f.get("severity", "INFO"),
                     f"{f.get('type', '')} {f.get('detail', '')}")
    except Exception:
        pass

    # GraphQL
    try:
        for url, r in (graphql_data or {}).items():
            try:
                host = urllib.parse.urlparse(url).netloc or url[:40]
            except Exception:
                host = url[:40]
            for f in r.get("findings", []):
                _add("graphql", host, "", "",
                     f.get("severity", "INFO"),
                     f"{f.get('type', '')} {f.get('detail', '')}")
    except Exception:
        pass

    return findings


def do_search_loop(findings, initial_query=None):
    """Interactive search atau single query."""
    if not HAS_SEARCH or search_mod is None:
        return
    if not findings:
        return

    console.print(
        f"\n[bold green]🔍 {len(findings)} findings terkumpul[/bold green]")

    if initial_query:
        results = search_mod.search_findings(findings, initial_query)
        console.print(f"[dim]Query: {initial_query}[/dim]")
        search_mod.render_results(
            console, results, title=f"Query: {initial_query}")
        return

    # Interactive prompt
    console.print(
        "\n[dim]Ketik query (contoh: risk:CRITICAL, service:ssh, "
        "CVE-2021). Enter untuk skip, 'help' untuk bantuan, "
        "'quit' untuk keluar.[/dim]")
    try:
        while True:
            try:
                q = console.input("[bold cyan]🔍 > [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not q or q.lower() in ("quit", "exit", "q"):
                break
            if q.lower() == "help":
                search_mod.interactive(console)
                continue
            results = search_mod.search_findings(findings, q)
            search_mod.render_results(console, results,
                                        title=f"Query: {q}")
    except KeyboardInterrupt:
        pass


# ============================================================
# ARGV PARSER
# ============================================================
def parse_argv():
    """Parse CLI args minimal. Semua opsional."""
    opts = {
        "tui": False, "watch": 0, "compact": False, "blind": False,
        "fuzz": False, "port_knock": False, "dump": False,
        "search": None, "sequence": None,
        "tls_audit": False, "no_plugins": False,
        "graphql": False, "http2": False,
    }
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--tui", "-T"):
            opts["tui"] = True
        elif a in ("--compact", "-c"):
            opts["compact"] = True
        elif a == "--blind-sqli":
            opts["blind"] = True
        elif a == "--fuzz":
            opts["fuzz"] = True
        elif a == "--port-knock":
            opts["port_knock"] = True
        elif a == "--dump":
            opts["dump"] = True
        elif a == "--tls-audit":
            opts["tls_audit"] = True
        elif a == "--no-plugins":
            opts["no_plugins"] = True
        elif a == "--graphql":
            opts["graphql"] = True
        elif a == "--http2":
            opts["http2"] = True
        elif a.startswith("--search="):
            opts["search"] = a.split("=", 1)[1]
        elif a == "--search":
            i += 1
            if i < len(argv):
                opts["search"] = argv[i]
        elif a.startswith("--sequence="):
            opts["sequence"] = a.split("=", 1)[1]
        elif a == "--sequence":
            i += 1
            if i < len(argv):
                opts["sequence"] = argv[i]
        elif a.startswith("--watch"):
            if "=" in a:
                try:
                    opts["watch"] = int(a.split("=")[1])
                except ValueError:
                    pass
            else:
                i += 1
                if i < len(argv):
                    try:
                        opts["watch"] = int(argv[i])
                    except ValueError:
                        pass
        i += 1
    return opts


# ============================================================
# RUN ONE ITERATION
# ============================================================
def _run_once(opts, iteration=1, cached_inputs=None):
    """
    Satu iterasi pipeline. Return dict cache untuk watchdog:
        {"targets": [...], "profile": str, "safe_mode": bool}
    Raise SystemExit(1) kalau fatal error.
    """
    global PREVIOUS_SCAN, CVSS_THRESHOLD

    # === 1. Plugin manager ===
    plugin_mgr = None
    try:
        if HAS_PLUGINS and not opts.get("no_plugins"):
            plugin_mgr = plugin_sys.load_plugins()
            if len(plugin_mgr) > 0:
                console.print(
                    f"[dim]🔌 {len(plugin_mgr)} plugin ter-load[/dim]")
                plugin_mgr.fire("start", {"opts": opts,
                                            "iteration": iteration})
    except Exception as e:
        console.print(f"[yellow]⚠ Plugin loader error: {e}[/yellow]")

    # === 2. Config ===
    cfg = load_config(quiet=(iteration > 1))

    # === 3. Banner (hanya iterasi 1) ===
    show_banner = _safe_cfg(cfg, "output", "show_banner", bool, True)
    if iteration == 1 and show_banner:
        try:
            bn.print_banner(
                console=console,
                version="1.0.0",
                subtitle="Automatic Nmap · Web Vuln · SQLi · XSS · OSINT · "
                         "Fuzz · TLS · GraphQL · HTTP/2",
            )
        except Exception as e:
            console.print(f"[yellow]⚠ Banner error: {e}[/yellow]")

    if not HAS_BANNER:
        console.print(
            f"[yellow]⚠ modules/banner.py gagal di-load: "
            f"{_BANNER_ERR}[/yellow]")

    if iteration > 1:
        ts = time.strftime("%H:%M:%S")
        console.print(
            f"\n[bold cyan]═══ Watchdog Iterasi {iteration} — {ts} "
            f"═══[/bold cyan]\n")

    # === 4. Module status ===
    render_module_status()

    # === 5. Cek nmap ===
    check_nmap()

    # === 6. Load konfigurasi ===
    safe_mode = _safe_cfg(cfg, "general", "safe_mode", bool, False)
    max_workers = _safe_cfg(cfg, "general", "max_workers", int, 10)
    CVSS_THRESHOLD = _safe_cfg(cfg, "general", "cvss_threshold",
                                float, 4.0)
    enable_banner = (_safe_cfg(cfg, "general", "enable_banner_grab",
                                bool, True) and HAS_BANNER_GRAB)
    enable_web = (_safe_cfg(cfg, "general", "enable_web_vuln",
                             bool, True) and HAS_WEB_VULN)
    enable_sqli = (_safe_cfg(cfg, "general", "enable_sqli", bool, True)
                   and HAS_SQLI)
    enable_xss = (_safe_cfg(cfg, "general", "enable_xss", bool, True)
                  and HAS_XSS)
    enable_dir_brute = (_safe_cfg(cfg, "general", "enable_dir_brute",
                                   bool, True) and HAS_DIR_BRUTE)
    enable_subdomain = (_safe_cfg(cfg, "general", "enable_subdomain",
                                   bool, True) and HAS_SUBDOMAIN)
    delay_ms = _safe_cfg(cfg, "ratelimit", "delay_ms", int, 500)
    max_safe = _safe_cfg(cfg, "ratelimit", "max_concurrent_safe", int, 3)
    dir_tier = _safe_cfg(cfg, "advanced", "dir_brute_tier", int, 2)
    sub_tier = _safe_cfg(cfg, "advanced", "subdomain_tier", int, 2)
    max_warn = _safe_cfg(cfg, "advanced", "max_hosts_warning", int, 1024)

    # Clamp
    if max_workers < 1:
        max_workers = 1
    if max_workers > 100:
        max_workers = 100

    # === 7. Input target (TUI / cached / manual) ===
    forced_profile = None
    forced_safe = None

    if cached_inputs:
        # Watchdog iterasi 2+ — pakai cache
        target_input = cached_inputs["target"]
        forced_profile = cached_inputs["profile"]
        if cached_inputs.get("safe_mode") is not None:
            safe_mode = cached_inputs["safe_mode"]
        console.print(
            f"[dim]♻ Menggunakan target cached:[/dim] "
            f"[cyan]{target_input}[/cyan]")
    elif opts.get("tui") and HAS_TUI and tui is not None:
        # TUI mode
        try:
            tui_inputs = tui.collect_inputs(console=console)
        except Exception as e:
            console.print(f"[yellow]⚠ TUI error: {e}[/yellow]")
            tui_inputs = {"error": "tui failed"}
        if tui_inputs.get("error"):
            console.print(
                f"[yellow]⚠ TUI: {tui_inputs['error']}[/yellow]")
            sys.exit(0)
        target_input = tui_inputs["target"]
        forced_profile = tui_inputs["profile"]
        forced_safe = tui_inputs["safe_mode"]
        console.print(
            f"[green]✔ TUI:[/green] target=[cyan]{target_input}[/cyan] "
            f"profile=[yellow]{forced_profile}[/yellow] "
            f"safe={'ON' if forced_safe else 'OFF'}")
    else:
        # Manual
        try:
            target_input = console.input(
                "\n[bold cyan]input:target/ip → [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]⚠ Input dibatalkan.[/yellow]")
            sys.exit(0)

    if not target_input:
        console.print("[red]✘ Target kosong. Keluar.[/red]")
        sys.exit(1)

    # Override safe_mode dari TUI
    if forced_safe is not None:
        safe_mode = forced_safe

    if safe_mode:
        console.print(
            f"[bold yellow]⚙ SAFE MODE ON[/bold yellow] "
            f"[dim](workers={max_safe}, delay={delay_ms}ms)[/dim]")
        max_workers = max(1, min(max_safe, 50))

    # === 8. Parse targets ===
    try:
        targets = parse_targets(target_input)
    except Exception as e:
        console.print(f"[red]✘ Gagal parse target: {e}[/red]")
        sys.exit(1)

    if not targets:
        console.print("[red]✘ Tidak ada target valid.[/red]")
        sys.exit(1)

    console.print(f"[dim]→ {len(targets)} target ter-resolve.[/dim]")

    if len(targets) > max_warn and not cached_inputs:
        try:
            ans = console.input(
                f"[yellow]⚠ {len(targets)} host (> {max_warn}). "
                f"Lanjut? (y/N): [/yellow]").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y", "yes"):
            console.print("[dim]Dibatalkan.[/dim]")
            sys.exit(0)

    # === 9. Profil ===
    if forced_profile and forced_profile in PROFILES:
        prof = PROFILES[forced_profile]
        args = prof["args"]
        prof_name = prof["name"]
        console.print(f"[green]✔ Mode:[/green] [bold]{prof_name}[/bold]")
    else:
        try:
            args, prof_name = select_profile(cfg)
        except Exception as e:
            console.print(f"[red]✘ Gagal pilih profile: {e}[/red]")
            sys.exit(1)

    if safe_mode:
        try:
            args = [("-T2" if a.startswith("-T") else a) for a in args]
        except Exception:
            pass

    # === 10. Start timer + cache dict ===
    start = time.perf_counter()

    cache = {
        "target": target_input,
        "profile": forced_profile or [
            k for k, v in PROFILES.items() if v["name"] == prof_name
        ][0] if prof_name in [v["name"] for v in PROFILES.values()] else "1",
        "safe_mode": safe_mode,
    }

    # === 11. Host discovery ===
    if len(targets) > 1:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Host discovery..."),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                progress.add_task("", total=None)
                scan_targets = host_discovery(targets)
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Discovery dibatalkan.[/yellow]")
            scan_targets = targets
        except Exception as e:
            console.print(f"[yellow]⚠ Discovery error: {e}[/yellow]")
            scan_targets = targets
        if not scan_targets:
            console.print("[bold red]✘ Tidak ada host hidup.[/bold red]")
            sys.exit(1)
        console.print(
            f"[green]✔ {len(scan_targets)} host hidup.[/green]\n")
    else:
        scan_targets = targets

    # === 12. Scan parallel ===
    try:
        results = scan_hosts_parallel(
            scan_targets, args, prof_name, max_workers)
    except Exception as e:
        console.print(f"[red]✘ Scan error: {e}[/red]")
        traceback.print_exc()
        sys.exit(1)

    if not results:
        console.print("[bold red]✘ Scan gagal / tidak ada hasil.[/bold red]")
        sys.exit(1)
    console.print(
        f"[bold green]✔ Scan selesai: {len(results)} host.[/bold green]")

    extras = {"safe_mode": safe_mode}

    # === 13. Plugin: on_host_result ===
    if plugin_mgr:
        try:
            for host_key, data in results.items():
                for h in data["hosts"]:
                    plugin_mgr.fire("host_result", h)
        except Exception:
            pass

    # === 14. Banner grab ===
    banners = {}
    if enable_banner:
        try:
            banners = run_banner_grab(results)
            extras["banners"] = sum(len(v) for v in banners.values())
            if banners:
                console.print("[green]✔ Banner grab selesai.[/green]")
                render_banners(banners)
        except Exception as e:
            console.print(f"[yellow]⚠ Banner grab error: {e}[/yellow]")

    # === 15. CVE scan ===
    vuln_data = {}
    try:
        vuln_data = run_auto_vuln_scan(results, args)
        if vuln_data:
            render_vulns(vuln_data)
    except Exception as e:
        console.print(f"[yellow]⚠ Vuln scan error: {e}[/yellow]")

    # === 16. OSINT ===
    try:
        render_osint(results)
    except Exception as e:
        console.print(f"[yellow]⚠ OSINT error: {e}[/yellow]")

    # === 17. Diff ===
    try:
        curr_snap = build_snapshot(results)
        if PREVIOUS_SCAN:
            render_diff(diff_snapshots(PREVIOUS_SCAN, curr_snap))
        else:
            console.print(
                "\n[dim]Scan pertama — baseline disimpan di memori.[/dim]")
        PREVIOUS_SCAN = curr_snap
    except Exception as e:
        console.print(f"[yellow]⚠ Diff error: {e}[/yellow]")

    # === 18. Auto-filter + render overview + per-host ===
    try:
        filtered = auto_filter(results, vuln_data)
        if len(filtered) > 1:
            render_overview(filtered)
        for host in scan_targets:
            if host in results:
                for h in results[host]["hosts"]:
                    render_host(h, prof_name)
    except Exception as e:
        console.print(f"[yellow]⚠ Render error: {e}[/yellow]")

    # === 19. Follow-up NSE ===
    try:
        plan = ({} if "-sU" in args
                else build_followup_plan(results))
        if plan:
            console.print(
                f"[bold yellow]⚡ Follow-up {len(plan)} host..."
                f"[/bold yellow]")
            render_followup(run_followup(plan))
    except Exception as e:
        console.print(f"[yellow]⚠ Follow-up error: {e}[/yellow]")

    # === 20. Subdomain enum ===
    sub_data = {}
    try:
        if enable_subdomain:
            domains = [t for t in targets if is_domain(t)]
            if domains:
                sub_data = run_subdomain_enum(
                    domains, delay_ms if safe_mode else 0,
                    tier=sub_tier)
                if sub_data:
                    render_subdomain(sub_data)
                    extras["subdomains"] = sum(
                        len(v.get("found", []))
                        for v in sub_data.values())
                else:
                    extras["subdomains"] = 0
            else:
                console.print(
                    "[dim]Subdomain enum di-skip (target bukan domain)."
                    "[/dim]")
                extras["subdomains"] = 0
        else:
            extras["subdomains"] = 0
    except Exception as e:
        console.print(f"[yellow]⚠ Subdomain error: {e}[/yellow]")
        extras["subdomains"] = 0

    # === 21. Port-knock (opt-in) ===
    port_knock_data = {}
    try:
        if opts.get("port_knock") and HAS_PORT_KNOCK:
            custom_seq = None
            if opts.get("sequence"):
                try:
                    custom_seq = [int(x.strip())
                                  for x in opts["sequence"].split(",")]
                except ValueError:
                    pass
            port_knock_data = run_port_knock(
                list(results.keys()), target_port=22,
                custom_sequence=custom_seq)
            if port_knock_data:
                render_port_knock(port_knock_data)
    except Exception as e:
        console.print(f"[yellow]⚠ Port-knock error: {e}[/yellow]")

    # === 22. Web vuln + SQLi + XSS ===
    web_urls = []
    wv, sq, xs = {}, {}, {}
    try:
        web_urls = build_web_urls(results)
        extras["web_urls"] = len(web_urls)

        if enable_web and web_urls:
            wv = run_web_vuln(
                web_urls, delay_ms if safe_mode else 0)
            render_web_vuln(wv)

        if (enable_sqli or enable_xss) and web_urls:
            sq, xs = run_sqli_xss(
                web_urls, delay_ms if safe_mode else 0,
                enable_sqli, enable_xss,
                blind_sqli=opts.get("blind", False))
            extras["sqli"] = sum(len(v) for v in sq.values())
            extras["xss"] = sum(len(v) for v in xs.values())
            render_sqli(sq)
            render_xss(xs)
        else:
            extras["sqli"] = 0
            extras["xss"] = 0
    except Exception as e:
        console.print(f"[yellow]⚠ Web test error: {e}[/yellow]")
        extras.setdefault("sqli", 0)
        extras.setdefault("xss", 0)

    # === 23. Dir brute ===
    dir_data = {}
    try:
        if enable_dir_brute and web_urls:
            dir_data = run_dir_brute(
                web_urls, delay_ms if safe_mode else 0, tier=dir_tier)
            if dir_data:
                render_dir_brute(dir_data)
                extras["dir_found"] = sum(
                    len(v.get("findings", []))
                    for v in dir_data.values())
            else:
                extras["dir_found"] = 0
        else:
            extras["dir_found"] = 0
    except Exception as e:
        console.print(f"[yellow]⚠ Dir brute error: {e}[/yellow]")
        extras["dir_found"] = 0

    # === 24. GraphQL (opt-in) ===
    graphql_data = {}
    try:
        if opts.get("graphql") and HAS_GRAPHQL and web_urls:
            graphql_data = run_graphql_scan(
                web_urls, delay_ms if safe_mode else 0)
            if graphql_data:
                render_graphql(graphql_data)
    except Exception as e:
        console.print(f"[yellow]⚠ GraphQL scan error: {e}[/yellow]")

    # === 25. HTTP/2 check (opt-in) ===
    http2_data = {}
    try:
        if opts.get("http2") and HAS_HTTP2_CHECK:
            http2_data = run_http2_check(results)
            if http2_data:
                render_http2(http2_data)
    except Exception as e:
        console.print(f"[yellow]⚠ HTTP/2 check error: {e}[/yellow]")

    # === 26. TLS audit (opt-in) ===
    tls_data = {}
    try:
        if opts.get("tls_audit") and HAS_TLS_AUDIT:
            tls_data = run_tls_audit(results)
            if tls_data:
                render_tls_audit(tls_data)
    except Exception as e:
        console.print(f"[yellow]⚠ TLS audit error: {e}[/yellow]")

    # === 27. Summary ===
    try:
        elapsed = time.perf_counter() - start
        render_summary(
            results, prof_name, elapsed,
            {"input": len(targets), "alive": len(scan_targets)},
            extras)
    except Exception as e:
        console.print(f"[yellow]⚠ Summary error: {e}[/yellow]")

    # === 28. Search + Plugin on_finding / on_end ===
    try:
        if HAS_SEARCH:
            all_findings = collect_all_findings(
                results, vuln_data, wv, sq, xs, dir_data, sub_data,
                banners, {}, tls_data, graphql_data, http2_data,
                port_knock_data)

            # Plugin: fire per finding
            if plugin_mgr:
                try:
                    for f in all_findings:
                        plugin_mgr.fire("finding", f)
                    plugin_mgr.fire("end", {
                        "findings": len(all_findings),
                        "hosts": len(results),
                        "iteration": iteration,
                    })
                except Exception:
                    pass

            # Search: --search flag, atau prompt kalau bukan watchdog 2+
            if opts.get("search"):
                do_search_loop(all_findings,
                               initial_query=opts["search"])
            else:
                prompt_search = _safe_cfg(
                    cfg, "search", "prompt_after_scan", bool, True)
                is_watch_iter = (iteration > 1)
                if prompt_search and not is_watch_iter:
                    do_search_loop(all_findings)
    except Exception as e:
        console.print(f"[yellow]⚠ Search/plugin error: {e}[/yellow]")

    # Footer
    try:
        console.print(Panel(
            "[dim]JagoX v1.0.0 — Open Source | "
            "Gunakan hanya pada sistem yang Anda miliki izin.[/dim]",
            border_style="dim"))
    except Exception:
        pass

    return cache


# ============================================================
# MAIN
# ============================================================
def main():
    opts = parse_argv()

    if opts.get("watch", 0) > 0:
        # === WATCHDOG MODE ===
        console.print(
            f"[bold yellow]👁️  WATCHDOG MODE — scan ulang tiap "
            f"{opts['watch']} detik[/bold yellow]")
        console.print("[dim]Target + profile dari iterasi pertama "
                      "akan di-cache. Ctrl+C untuk stop.[/dim]\n")

        cached = None
        iteration = 1
        try:
            while True:
                try:
                    cached = _run_once(opts, iteration, cached)
                except SystemExit:
                    # Error di iterasi ini, lanjut iterasi berikutnya
                    pass
                except Exception as e:
                    console.print(
                        f"[red]✘ Watchdog iterasi {iteration} error: "
                        f"{e}[/red]")

                iteration += 1
                console.print(
                    f"\n[dim]💤 Tidur {opts['watch']} detik... "
                    f"(Ctrl+C untuk stop)[/dim]")
                try:
                    time.sleep(opts["watch"])
                except KeyboardInterrupt:
                    raise
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Watchdog dihentikan.[/yellow]")
            sys.exit(0)
    else:
        # === SINGLE RUN ===
        try:
            _run_once(opts, iteration=1, cached_inputs=None)
        except SystemExit:
            raise
        except Exception as e:
            console.print(f"\n[bold red]✘ Fatal error: {e}[/bold red]")
            console.print("[yellow]Traceback:[/yellow]")
            try:
                traceback.print_exc()
            except Exception:
                pass
            sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Dihentikan oleh user.[/yellow]")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"\n[bold red]✘ Fatal error: {e}[/bold red]")
        console.print("[yellow]Traceback:[/yellow]")
        try:
            traceback.print_exc()
        except Exception:
            pass
        sys.exit(1)