#!/usr/bin/env python3
# tui.py — TUI mode (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Kalau prompt_toolkit terinstall: menu interaktif arrow-key.
# Kalau tidak terinstall: fallback ke input() biasa.
#
# Public API (kompatibel nmpx.py v1.0.0):
#   collect_inputs(console=None) -> dict {
#       target, profile, safe_mode, error
#   }
#   HAS_PT: bool (True kalau prompt_toolkit tersedia)

__version__ = "1.0.0"

try:
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.shortcuts import (
        radiolist_dialog, yes_no_dialog, message_dialog,
    )
    from prompt_toolkit.styles import Style
    HAS_PT = True
except ImportError:
    HAS_PT = False


# ============================================================
# PROFILE LIST
# ============================================================
PROFILES = [
    ("1", "Quick         — Top 100 port TCP + versi (cepat)"),
    ("2", "Full TCP      — Semua 65535 port (lama)"),
    ("3", "Stealth       — SYN lambat + fragmentasi (butuh root)"),
    ("4", "UDP Top 100   — 100 port UDP (butuh root)"),
    ("5", "Vuln Scan     — NSE vulners"),
    ("6", "Aggressive    — OS + versi + script (butuh root)"),
]


# ============================================================
# TUI STYLE
# ============================================================
_TUI_STYLE = None
if HAS_PT:
    try:
        _TUI_STYLE = Style.from_dict({
            "dialog": "bg:#1a1b26",
            "dialog frame.label": "bg:#7aa2f7 #1a1b26 bold",
            "dialog.body": "bg:#1a1b26 #c0caf5",
            "dialog shadow": "bg:#000000",
            "button": "bg:#7aa2f7 #1a1b26",
            "button.focused": "bg:#bb9af7 #1a1b26 bold",
            "text-area": "bg:#1a1b26 #c0caf5",
        })
    except Exception:
        _TUI_STYLE = None


# ============================================================
# FALLBACK INPUT (kalau prompt_toolkit tidak ada)
# ============================================================
def _fallback_input(console):
    """Fallback interaktif kalau prompt_toolkit tidak tersedia."""
    if console is None:
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            class _C:
                def input(self, p=""):
                    import re
                    return input(re.sub(r"\[/?[a-zA-Z0-9 _#=]+\]", "", p))
                def print(self, *a, **kw):
                    import re
                    print(re.sub(r"\[/?[a-zA-Z0-9 _#=]+\]", "",
                                  " ".join(str(x) for x in a)))
            console = _C()

    try:
        target = console.input(
            "[bold cyan]input:target/ip → [/bold cyan]").strip()
    except (EOFError, KeyboardInterrupt):
        return {"error": "cancelled"}
    if not target:
        return {"error": "empty"}

    console.print("\n[bold cyan]═══ Pilih Scan Profile ═══[/bold cyan]")
    for key, desc in PROFILES:
        console.print(f"  [bold yellow][{key}][/bold yellow] {desc}")

    try:
        profile = console.input(
            "[bold]Pilih profile [1-6, default 1]: [/bold]").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return {"error": "cancelled"}
    if profile not in [k for k, _ in PROFILES]:
        profile = "1"

    try:
        safe = console.input("[bold]Safe mode? (y/N): [/bold]").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return {"error": "cancelled"}

    return {
        "target": target,
        "profile": profile,
        "safe_mode": safe in ("y", "yes"),
        "error": None,
    }


# ============================================================
# MAIN ENTRY
# ============================================================
def collect_inputs(console=None):
    """
    Kumpulkan input (target, profile, safe_mode).

    Args:
        console: rich.Console instance (optional)

    Returns:
        dict {
            "target": str,
            "profile": str (1-6),
            "safe_mode": bool,
            "error": str | None  (None = sukses)
        }
    """
    # Fallback kalau tidak ada prompt_toolkit
    if not HAS_PT:
        return _fallback_input(console)

    # === TUI mode (prompt_toolkit) ===
    # Step 1: input target
    try:
        target = pt_prompt(
            " input:target/ip → ",
            bottom_toolbar="JagoX TUI · Ctrl+C untuk cancel · Enter untuk lanjut",
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return {"error": "cancelled"}

    if not target:
        return {"error": "empty"}

    # Step 2: pilih profile
    try:
        profile = radiolist_dialog(
            title="JagoX TUI — Scan Profile",
            text=f"Target: {target}\n\nPilih scan profile:",
            values=[(k, d) for k, d in PROFILES],
            default="1",
            style=_TUI_STYLE,
        ).run()
    except (KeyboardInterrupt, EOFError):
        return {"error": "cancelled"}

    if profile is None:
        return {"error": "cancelled"}

    # Step 3: safe mode?
    try:
        safe = yes_no_dialog(
            title="JagoX TUI — Safe Mode",
            text=(f"Profile: {profile}\n\nAktifkan safe mode?\n"
                  "(rate-limit, timing lambat — untuk production)"),
            style=_TUI_STYLE,
        ).run()
    except (KeyboardInterrupt, EOFError):
        return {"error": "cancelled"}

    if safe is None:
        return {"error": "cancelled"}

    # Step 4: konfirmasi
    try:
        confirm = yes_no_dialog(
            title="JagoX TUI — Konfirmasi",
            text=(f"Target: {target}\n"
                  f"Profile: {profile}\n"
                  f"Safe mode: {'ON' if safe else 'OFF'}\n\n"
                  f"Mulai scanning?"),
            style=_TUI_STYLE,
        ).run()
    except (KeyboardInterrupt, EOFError):
        return {"error": "cancelled"}

    if not confirm:
        return {"error": "cancelled"}

    return {
        "target": target,
        "profile": profile,
        "safe_mode": bool(safe),
        "error": None,
    }


def show_welcome():
    """Tampilkan welcome screen (kalau prompt_toolkit tersedia)."""
    if not HAS_PT:
        return
    try:
        message_dialog(
            title="JagoX TUI v1.0.0",
            text=("Selamat datang di JagoX!\n\n"
                  "Mode TUI aktif (prompt_toolkit).\n"
                  "Gunakan arrow keys untuk navigasi, Enter untuk pilih.\n"
                  "Ctrl+C untuk cancel kapan saja."),
            style=_TUI_STYLE,
        ).run()
    except (KeyboardInterrupt, EOFError):
        pass


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
                              subtitle="TUI Mode — JagoX")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX tui — TUI mode test")
    parser.add_argument("--welcome", action="store_true",
                        help="Tampilkan welcome dialog")
    parser.add_argument("--version", action="version",
                        version=f"JagoX tui v{__version__}")
    args = parser.parse_args()

    print(f"prompt_toolkit: {'tersedia ✓' if HAS_PT else 'TIDAK tersedia'}")
    if not HAS_PT:
        print("\n[i] Untuk mengaktifkan TUI mode, install:")
        print("    pip install prompt_toolkit")
        print("\n[!] Fallback ke input() biasa akan dipakai.\n")
    else:
        print()

    if args.welcome and HAS_PT:
        show_welcome()

    # Demo collect_inputs
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    result = collect_inputs(console=console)

    print("\n=== Hasil collect_inputs ===")
    for k, v in result.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    _cli()
