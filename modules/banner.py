#!/usr/bin/env python3
# banner.py — ASCII art banner nmpX / JagoX
# Part of JagoX framework — v1.0.0
# MIT License
#
# PENTING: file murni ASCII. Karakter blok dibangun via chr() —
# TIDAK bisa korup lewat copy-paste, editor apapun, atau terminal.

__version__ = "1.0.0"

_B = chr(0x2588)   # FULL BLOCK
_L = chr(0x2592)   # MEDIUM SHADE
_DOT = chr(0x00b7) # MIDDLE DOT

NMPX_BANNER = "\n" + "\n".join([
    " " * 38 + _B * 5 + " " + _B * 5,
    " " * 37 + _L * 2 + _B * 3 + " " + _L * 2 + _B * 3 + " ",
    " " + _B * 8 + " " * 3 + _B * 13 + " " * 3 + _B * 8 + " " * 2
    + _L * 2 + _B * 3 + " " + _B * 3 + " " * 2,
    _L * 2 + _B * 3 + _L * 2 + _B * 3 + " "
    + _L * 2 + _B * 3 + _L * 2 + _B * 3 + _L * 2 + _B * 3 + " "
    + _L * 2 + _B * 3 + _L * 2 + _B * 3 + " " * 2
    + _L * 2 + _B * 5 + " " * 3,
    " " + _L + _B * 3 + " " + _L + _B * 3 + " " * 2
    + _L + _B * 3 + " " + _L + _B * 3 + " " + _L + _B * 3 + " " * 2
    + _L + _B * 3 + " " + _L + _B * 3 + " " * 3
    + _B * 3 + _L + _B * 3 + " " * 2,
    " " + _L + _B * 3 + " " + _L + _B * 3 + " " * 2
    + _L + _B * 3 + " " + _L + _B * 3 + " " + _L + _B * 3 + " " * 2
    + _L + _B * 3 + " " + _L + _B * 3 + " " * 2
    + _B * 3 + " " + _L * 2 + _B * 3 + " ",
    " " + _B * 4 + " " + _B * 5 + " "
    + _B * 5 + _L + _B * 3 + " "
    + _B * 5 + " " + _L + _B * 7 + " " * 2
    + _B * 5 + " " + _B * 5,
    _L * 4 + " " + _L * 5 + " " + _L * 5 + " "
    + _L * 3 + " " + _L * 5 + " " * 2
    + _L + _B * 3 + _L * 3 + " " * 2
    + _L * 5 + " " + _L * 5 + " ",
    " " * 28 + _L + _B * 3,
    " " * 28 + _B * 5,
    " " * 27 + _L * 5,
]) + "\n"


def get_banner():
    return NMPX_BANNER


def print_banner(console=None, version=None, subtitle=None):
    ver = version or __version__
    info = f"  nmpX v{ver}  {_DOT}  Part of JagoX Framework"
    sub = subtitle or ("Automatic Nmap · Web Vuln · SQLi · XSS · "
                        "OSINT · Fuzz · TLS · GraphQL")
    if console is not None:
        try:
            console.print(NMPX_BANNER, style="bold green",
                          markup=False, highlight=False, end="")
            console.print(f"[bold cyan]{info}[/bold cyan]", highlight=False)
            console.print(f"[dim italic]{sub}[/dim italic]", highlight=False)
            console.print()
            return
        except Exception:
            pass
    print(NMPX_BANNER)
    print(info)
    print(sub)
    print()


def print_mini_banner(console=None, version=None):
    ver = version or __version__
    box = (chr(0x2554) + chr(0x2550) * 55 + chr(0x2557))
    box_bottom = (chr(0x255a) + chr(0x2550) * 55 + chr(0x255d))
    v = chr(0x2551)
    text = (f"\n  {box}\n"
            f"  {v}  nmpX v{ver}  {_DOT}  JagoX Framework{' ' * 27}{v}\n"
            f"  {box_bottom}\n")
    if console is not None:
        try:
            console.print(text, style="bold green",
                          markup=False, highlight=False)
            return
        except Exception:
            pass
    print(text)


if __name__ == "__main__":
    try:
        from rich.console import Console
        _c = Console()
        print_banner(console=_c)
        print_mini_banner(console=_c)
    except ImportError:
        print_banner()
        print_mini_banner()
