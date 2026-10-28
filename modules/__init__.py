#!/usr/bin/env python3
# modules/__init__.py — JagoX internal modules package
# v1.0.0 — Final release
# MIT License
#
# File ini berfungsi sebagai package initializer JagoX.
# Modul yang sudah ada akan otomatis terdeteksi.
# Modul yang belum dibuat TIDAK akan membuat import error — hanya
# ditandai sebagai "not available".
#
# Public API:
#   __version__             : str    — versi package
#   available_modules()     : list   — nama modul yang tersedia
#   missing_modules()       : list   — nama modul yang belum ada
#   module_status()         : dict   — status lengkap per modul
#   print_status(console)   : None   — cetak status ke terminal
#
# 16 modul yang diekspos (kalau ada):
#   Required (2):
#     banner          — ASCII art banner nmpX
#     banner_grab     — Pure-Python banner grabber
#   Optional (14):
#     web_vuln        — Web vulnerability scanner
#     sqli            — SQL injection + blind + dump
#     xss             — Reflected XSS detector
#     dir_brute       — Directory bruteforcer
#     subdomain       — Subdomain enumeration
#     tls_audit       — TLS/SSL deep audit
#     http_fuzz       — HTTP fuzzer
#     graphql_scan    — GraphQL scanner (safe)
#     http2_check     — HTTP/2 detection (safe)
#     port_knock      — Port-knock detection
#     search          — Full-text search findings
#     plugins         — Plugin system
#     tui             — TUI mode (prompt_toolkit)

import importlib
import warnings

__version__ = "1.0.0"
__author__ = "JagoX Project"
__license__ = "MIT"
__release_date__ = "2026"

# ============================================================
# DAFTAR MODUL YANG DIHARAPKAN ADA
# Format: nama_modul -> (deskripsi singkat, wajib?)
# ============================================================
_EXPECTED_MODULES = {
    # --- Wajib ---
    "banner":       ("ASCII art banner nmpX",            True),
    "banner_grab":  ("Pure-Python banner grabber",       True),

    # --- Scan core ---
    "web_vuln":     ("Web vulnerability scanner",        False),
    "sqli":         ("SQL injection + blind + dump",     False),
    "xss":          ("Reflected XSS detector",           False),

    # --- Recon ---
    "dir_brute":    ("Directory bruteforcer",            False),
    "subdomain":    ("Subdomain enumeration",            False),
    "tls_audit":    ("TLS/SSL deep audit",               False),

    # --- Advanced ---
    "http_fuzz":    ("HTTP fuzzer",                      False),
    "graphql_scan": ("GraphQL scanner (safe)",           False),
    "http2_check":  ("HTTP/2 detection (safe)",          False),
    "port_knock":   ("Port-knock detection",             False),

    # --- Utility ---
    "search":       ("Full-text search findings",        False),
    "plugins":      ("Plugin system",                    False),
    "tui":          ("TUI mode (prompt_toolkit)",        False),
}


# ============================================================
# LAZY IMPORT — cache hasil import
# ============================================================
_LOADED = {}
_FAILED = {}


def _try_import(name):
    """
    Coba import modul `modules.<name>`.
    Return module object kalau sukses, None kalau gagal.
    Error disimpan di _FAILED untuk diagnosa.
    """
    if name in _LOADED:
        return _LOADED[name]
    if name in _FAILED:
        return None

    try:
        mod = importlib.import_module(f".{name}", package=__name__)
        _LOADED[name] = mod
        return mod
    except ImportError as e:
        _FAILED[name] = f"ImportError: {e}"
        return None
    except SyntaxError as e:
        _FAILED[name] = f"SyntaxError: {e}"
        return None
    except Exception as e:
        _FAILED[name] = f"{type(e).__name__}: {e}"
        return None


# ============================================================
# LOAD SEMUA MODUL (eager load untuk modul wajib, lazy untuk opsional)
# ============================================================
banner       = _try_import("banner")
banner_grab  = _try_import("banner_grab")
web_vuln     = _try_import("web_vuln")
sqli         = _try_import("sqli")
xss          = _try_import("xss")
dir_brute    = _try_import("dir_brute")
subdomain    = _try_import("subdomain")
tls_audit    = _try_import("tls_audit")
http_fuzz    = _try_import("http_fuzz")
graphql_scan = _try_import("graphql_scan")
http2_check  = _try_import("http2_check")
port_knock   = _try_import("port_knock")
search       = _try_import("search")
plugins      = _try_import("plugins")
tui          = _try_import("tui")


# ============================================================
# FAIL-LOUD untuk modul WAJIB
# ============================================================
_missing_required = []
for _name, (_desc, _required) in _EXPECTED_MODULES.items():
    if _required and _try_import(_name) is None:
        _missing_required.append(_name)

if _missing_required:
    _msg = (
        f"JagoX modules: modul WAJIB gagal di-load: "
        f"{', '.join(_missing_required)}. "
        f"Detail error: " +
        "; ".join(
            f"{n} → {_FAILED.get(n, '?')}" for n in _missing_required
        )
    )
    warnings.warn(_msg, RuntimeWarning, stacklevel=2)


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def available_modules():
    """Return list nama modul yang bisa di-import."""
    return [n for n in _EXPECTED_MODULES if _try_import(n) is not None]


def missing_modules():
    """Return list nama modul yang belum tersedia (file belum ada / error)."""
    return [n for n in _EXPECTED_MODULES if _try_import(n) is None]


def module_status():
    """
    Return dict status lengkap per modul.

    Returns:
        dict: {
            "banner": {
                "available": True,
                "required": True,
                "desc": "ASCII art banner nmpX",
                "error": None,
                "version": "1.0.0",
            },
            ...
        }
    """
    status = {}
    for name, (desc, required) in _EXPECTED_MODULES.items():
        mod = _try_import(name)
        status[name] = {
            "available": mod is not None,
            "required": required,
            "desc": desc,
            "error": _FAILED.get(name),
            "version": getattr(mod, "__version__", "—") if mod else None,
        }
    return status


def print_status(console=None):
    """
    Cetak status modul ke terminal.
    Kalau `console` (rich.Console) diberikan, pakai tabel rich;
    kalau tidak, fallback ke print biasa.
    """
    st = module_status()

    if console is not None:
        try:
            from rich.table import Table
            from rich import box
            t = Table(
                title=f"📦 Modul JagoX v{__version__}",
                box=box.ROUNDED,
                title_style="bold cyan",
                header_style="bold magenta",
            )
            t.add_column("Modul", style="yellow", width=14)
            t.add_column("Status", justify="center", width=12)
            t.add_column("Versi", justify="center", width=8)
            t.add_column("Deskripsi", style="white")

            for name, info in st.items():
                if info["available"]:
                    status = "[green]✔ aktif[/green]"
                elif info["required"]:
                    status = "[red]✘ hilang[/red]"
                else:
                    status = "[dim]— belum[/dim]"

                ver = info["version"] or "—"
                desc = info["desc"]
                # Tandai modul wajib
                if info["required"]:
                    desc = f"{desc} [dim](wajib)[/dim]"

                t.add_row(name, status, str(ver), desc)

            console.print(t)

            # Ringkasan
            total = len(st)
            active = len(available_modules())
            missing = total - active
            summary = (
                f"[green]✔ {active}[/green] aktif / "
                f"{total} total"
            )
            if missing > 0:
                summary += f" · [dim]{missing} belum tersedia[/dim]"
            console.print(f"\n{summary}")
            return
        except ImportError:
            pass
        except Exception as e:
            console.print(f"[yellow]⚠ print_status error: {e}[/yellow]")

    # Fallback plain print
    print(f"\n=== Modul JagoX v{__version__} ===")
    for name, info in st.items():
        if info["available"]:
            mark = "[OK]"
        elif info["required"]:
            mark = "[!!]"
        else:
            mark = "[--]"
        req = " *wajib*" if info["required"] else ""
        err = f" ({info['error']})" if info["error"] else ""
        print(f"  {mark} {name:<14} — {info['desc']}{req}{err}")
    print(f"\n{len(available_modules())} / {len(st)} modul aktif")


def reload_all():
    """Force reload semua modul (berguna untuk development)."""
    global _LOADED, _FAILED
    _LOADED = {}
    _FAILED = {}
    importlib.invalidate_caches()

    # Re-assign global vars
    g = globals()
    for name in _EXPECTED_MODULES:
        g[name] = _try_import(name)

    return available_modules()


# ============================================================
# __all__ — ekspos semua modul yang ada + helpers
# ============================================================
__all__ = ["__version__"] + available_modules() + [
    "available_modules", "missing_modules", "module_status",
    "print_status", "reload_all",
]


# ============================================================
# __getattr__ — lazy attribute access (PEP 562)
# ============================================================
def __getattr__(name):
    """Lazy access untuk modul yang belum di-load."""
    if name in _EXPECTED_MODULES:
        mod = _try_import(name)
        if mod is not None:
            return mod
        raise AttributeError(
            f"module 'modules' has no attribute '{name}' "
            f"(file belum dibuat atau error: {_FAILED.get(name, '?')})"
        )
    raise AttributeError(f"module 'modules' has no attribute '{name}'")


# ============================================================
# CLI test — python3 -m modules
# ============================================================
if __name__ == "__main__":
    try:
        from rich.console import Console
        _c = Console()
        _c.print(
            f"[bold cyan]JagoX modules package v{__version__}[/bold cyan]"
        )
        _c.print(
            "[dim]Part of JagoX Framework — MIT License[/dim]\n"
        )
        print_status(console=_c)
    except ImportError:
        print(f"JagoX modules package v{__version__}")
        print_status()
