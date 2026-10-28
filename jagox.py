#!/usr/bin/env python3
# jagox.py — Unified CLI untuk semua modul JagoX
# Part of JagoX framework — v1.0.0
# MIT License
#
# Pemakaian:
#   jagox scan <target>          — full pipeline (nmpx)
#   jagox dir <url>              — directory bruteforce
#   jagox sub <domain>           — subdomain enumeration
#   jagox sqli <url>             — SQL injection
#   jagox xss <url>              — XSS detection
#   jagox web <url>              — web vulnerability
#   jagox tls <host>             — TLS deep audit
#   jagox fuzz <url>             — HTTP fuzzer
#   jagox graphql <url>          — GraphQL scanner
#   jagox http2 <host>           — HTTP/2 detection
#   jagox banner-grab <host>     — banner grab
#   jagox port-knock <host>      — port-knock detection
#
# Utility:
#   jagox modules                — list modul aktif
#   jagox version                — versi
#   jagox help                   — bantuan
#
# Tanpa argumen → tampilkan bantuan.

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

__version__ = "1.0.0"


# ============================================================
# COMMAND REGISTRY
# ============================================================
# Format: nama_command -> (module_name, entry_function, description)
# - "nmpx" (tanpa prefix modules.) = jalankan nmpx.py
# - "modules.X" = import modul X, panggil fungsi entry
COMMANDS = {
    # Full pipeline
    "scan":        ("nmpx",                 "_main_entry",  "Full pipeline (nmap + all modules)"),

    # Recon
    "dir":         ("modules.dir_brute",    "_cli",         "Directory bruteforce"),
    "sub":         ("modules.subdomain",    "_cli",         "Subdomain enumeration"),
    "banner-grab": ("modules.banner_grab",  "_cli",         "Banner grabber"),
    "port-knock":  ("modules.port_knock",   "_cli",         "Port-knock detection"),

    # Vulnerability
    "sqli":        ("modules.sqli",         "_cli",         "SQL injection detector + blind + dump"),
    "xss":         ("modules.xss",          "_cli",         "Reflected XSS detector"),
    "web":         ("modules.web_vuln",     "_cli",         "Web vulnerability scanner"),
    "fuzz":        ("modules.http_fuzz",    "_cli",         "HTTP fuzzer"),

    # Modern protocol
    "tls":         ("modules.tls_audit",    "_cli",         "TLS deep audit"),
    "graphql":     ("modules.graphql_scan", "_cli",         "GraphQL scanner (read-only)"),
    "http2":       ("modules.http2_check",  "_cli",         "HTTP/2 detection (read-only)"),
}


# ============================================================
# HELP TEXT
# ============================================================
HELP_TEXT = """
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551              JagoX v1.0.0 \u2014 Unified CLI                        \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d

Pemakaian: jagox <command> [args...]

SCAN
\u2500\u2500\u2500\u2500
  scan <target>       Full pipeline (nmap + banner + CVE + OSINT +
                      web vuln + sqli + xss + dir brute + subdomain)
                      Flags: --tui --watch N --fuzz --tls-audit
                             --graphql --http2 --search QUERY
                             --blind-sqli --port-knock --no-plugins

RECON
\u2500\u2500\u2500\u2500\u2500
  dir <url>           Directory bruteforce          [-t 1|2|3] [-w N]
  sub <domain>        Subdomain enumeration         [-t 1|2|3] [--no-ct]
  banner-grab <host>  Banner grabber                [-p 22,80,443]
  port-knock <host>   Port-knock detection          [-p TARGET]

VULNERABILITY
\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  sqli <url>          SQL injection                 [-m modes] [--blind]
                                                    [--dump-db|--dump-tables]
  xss <url>           XSS detection                 [--no-verify]
  web <url>           Web vulnerability (headers)   [--fast]
  fuzz <url>          HTTP fuzzer                   [--modes ...]

MODERN PROTOCOL
\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  tls <host>          TLS deep audit                [-p PORT]
  graphql <url>       GraphQL scanner (read-only)
  http2 <host>        HTTP/2 detection (read-only)  [-p PORT]

UTILITY
\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  modules             List modul aktif
  version             Tampilkan versi
  help                Tampilkan bantuan ini

CONTOH
\u2500\u2500\u2500\u2500\u2500\u2500
  jagox scan example.com
  jagox scan example.com --tls-audit --graphql --http2
  jagox scan 192.168.1.0/24 --watch 300
  jagox tls example.com -p 443
  jagox dir http://example.com -t 2
  jagox sqli "http://example.com/page?id=1" -m error,time
  jagox sub example.com -t 2 --no-ct
  jagox modules

\u26a0 Gunakan hanya pada sistem yang Anda miliki izin tertulis.
"""


# ============================================================
# HELPERS
# ============================================================
def show_help():
    print(HELP_TEXT)


def show_version():
    print(f"JagoX v{__version__}")
    print("Part of JagoX Framework — MIT License")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Path:   {BASE_DIR}")

    # Coba print versi modul
    try:
        from modules import __version__ as mod_ver
        print(f"Modules: v{mod_ver}")
    except Exception:
        pass


def show_modules():
    """Tampilkan status semua modul."""
    try:
        from modules import print_status, __version__ as mv
        print(f"JagoX modules v{mv}\n")
        try:
            from rich.console import Console
            print_status(console=Console())
        except ImportError:
            print_status()
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()


def _run_nmpx(argv):
    """Jalankan nmpx.py dengan sys.argv yang sesuai."""
    old_argv = sys.argv
    try:
        sys.argv = ["nmpx.py"] + list(argv)
        # Import nmpx dan panggil main()
        import nmpx
        nmpx.main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"[!] nmpx error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        sys.argv = old_argv


def _run_module(module_name, cli_fn_name, argv):
    """Jalankan modul dengan sys.argv yang sesuai."""
    import importlib

    old_argv = sys.argv
    try:
        sys.argv = [module_name.split(".")[-1]] + list(argv)
        mod = importlib.import_module(module_name)
        fn = getattr(mod, cli_fn_name, None)
        if fn is None:
            print(
                f"[!] Modul '{module_name}' tidak punya fungsi "
                f"'{cli_fn_name}'",
                file=sys.stderr
            )
            return 1
        fn()
        return 0
    except SystemExit as e:
        # Propagate exit code dari modul
        raise
    except ImportError as e:
        print(
            f"[!] Modul '{module_name}' tidak tersedia: {e}",
            file=sys.stderr
        )
        return 1
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"[!] Error di '{module_name}': {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        sys.argv = old_argv


# ============================================================
# MAIN DISPATCHER
# ============================================================
def main():
    if len(sys.argv) < 2:
        show_help()
        return 0

    cmd = sys.argv[1].lower()
    rest = sys.argv[2:]

    # === Utility commands ===
    if cmd in ("help", "-h", "--help"):
        show_help()
        return 0

    if cmd in ("version", "-v", "--version"):
        show_version()
        return 0

    if cmd in ("modules", "mod"):
        show_modules()
        return 0

    # === Dispatch ke modul ===
    if cmd in COMMANDS:
        module_name, entry_fn, _desc = COMMANDS[cmd]

        if module_name == "nmpx":
            _run_nmpx(rest)
        else:
            return _run_module(module_name, entry_fn, rest)
        return 0

    # === Unknown command ===
    print(f"[!] Command tidak dikenal: '{cmd}'", file=sys.stderr)
    print(f"    Ketik 'jagox help' untuk bantuan.", file=sys.stderr)

    # Suggestion berdasarkan prefix
    similar = [k for k in COMMANDS if k.startswith(cmd[:2])]
    if similar:
        print(f"    Mungkin maksud Anda: {', '.join(similar)}",
              file=sys.stderr)

    return 1


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan oleh user.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
