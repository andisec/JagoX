#!/usr/bin/env python3
# modules/__main__.py — entry point untuk `python3 -m modules`
# Part of JagoX framework — MIT License

from . import __version__, print_status


def main():
    try:
        from rich.console import Console
        _c = Console()
        _c.print(f"[bold cyan]JagoX modules package v{__version__}[/bold cyan]")
        _c.print("[dim]Part of JagoX Framework — MIT License[/dim]\n")
        print_status(console=_c)
    except ImportError:
        print(f"JagoX modules package v{__version__}")
        print_status()


if __name__ == "__main__":
    main()
