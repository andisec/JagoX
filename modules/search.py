#!/usr/bin/env python3
# search.py — Full-text search & filter findings (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Query syntax:
#   ssh                            → free text (case-insensitive)
#   risk:CRITICAL                  → filter by risk
#   service:ssh                    → filter by service
#   port:22                        → filter by port
#   source:port                    → filter by source
#   host:192.168.*                 → wildcard
#   risk:CRITICAL AND service:ssh  → kombinasi AND
#   risk:CRITICAL OR risk:HIGH     → kombinasi OR
#   CVE-2021                       → free text (cari CVE)
#   regex:^ssh.*                   → regex match
#
# Public API (kompatibel nmpx.py v1.0.0):
#   search_findings(findings, query) -> list
#   render_results(console, results, title="Search Results")
#   interactive(console=None)
#   SearchIndex() — class untuk incremental add

import re

__version__ = "1.0.0"


# ============================================================
# SEARCH INDEX
# ============================================================
class SearchIndex:
    """
    In-memory search index untuk findings.

    Finding dict standar:
        {
            "source": "port" | "cve" | "web_vuln" | "sqli" | "xss" |
                       "dir" | "sub" | "fuzz" | "tls" | "graphql",
            "host": "1.2.3.4",
            "port": "22",
            "service": "ssh",
            "risk": "CRITICAL",
            "text": "SSH exposed OpenSSH_8.2",
        }
    """

    def __init__(self):
        self.findings = []

    def add(self, finding):
        """Tambah satu finding. Normalisasi field standar."""
        if not isinstance(finding, dict):
            return
        normalized = {
            "source": str(finding.get("source", "unknown")),
            "host": str(finding.get("host", "")),
            "port": str(finding.get("port", "")),
            "service": str(finding.get("service", "")),
            "risk": str(finding.get("risk", "")).upper(),
            "text": str(finding.get("text", "")),
            "_raw": finding,
        }
        self.findings.append(normalized)

    def extend(self, findings):
        """Tambah banyak finding."""
        for f in findings:
            self.add(f)

    def __len__(self):
        return len(self.findings)

    def _match_term(self, finding, term):
        """Match satu term (bisa field:value, wildcard, regex, atau free text)."""
        term_lower = term.lower()

        # Regex mode
        if term_lower.startswith("regex:"):
            pattern = term[len("regex:"):]
            try:
                haystack = " ".join([
                    finding["text"], finding["host"],
                    finding["service"], finding["port"],
                    finding["risk"], finding["source"],
                ])
                return bool(re.search(pattern, haystack, re.IGNORECASE))
            except re.error:
                return False

        # Field query (field:value)
        if ":" in term:
            field, value = term.split(":", 1)
            field = field.lower().strip()
            value = value.strip()

            if field in finding and field != "_raw":
                fv = str(finding[field])
                # Wildcard support
                if "*" in value:
                    pattern = "^" + re.escape(value).replace("\\*", ".*") + "$"
                    return bool(re.match(pattern, fv, re.IGNORECASE))
                return fv.lower() == value.lower()

            # Field tidak dikenal → treat as free text
            return value.lower() in finding["text"].lower()

        # Free text (cari di semua field)
        haystack = " ".join([
            finding["text"], finding["host"], finding["service"],
            finding["port"], finding["risk"], finding["source"],
        ]).lower()
        return term_lower in haystack

    def _match_query(self, finding, query):
        """Match query dengan AND / OR support (OR lower precedence)."""
        if not query.strip():
            return True

        # Split by OR dulu (lowest precedence)
        or_parts = re.split(r"\s+OR\s+", query, flags=re.IGNORECASE)

        for or_part in or_parts:
            # Split by AND
            and_terms = re.split(r"\s+AND\s+", or_part, flags=re.IGNORECASE)
            and_terms = [t.strip() for t in and_terms if t.strip()]
            if not and_terms:
                continue

            # Semua term harus match (AND)
            if all(self._match_term(finding, t) for t in and_terms):
                return True

        return False

    def search(self, query):
        """Return list finding yang match query."""
        return [f for f in self.findings if self._match_query(f, query)]


# ============================================================
# PUBLIC API
# ============================================================
def search_findings(findings, query):
    """
    Search dalam list of finding dict.

    Args:
        findings: list of dict {source, host, port, service, risk, text}
        query:    string query (support AND/OR/field:value/wildcard/regex)

    Returns:
        list of finding yang match
    """
    idx = SearchIndex()
    idx.extend(findings)
    return idx.search(query)


def render_results(console, results, title="Search Results"):
    """
    Render hasil search ke rich table.

    Args:
        console:  rich.Console instance
        results:  list of finding (dari search_findings)
        title:    judul tabel
    """
    if not results:
        try:
            console.print("[yellow]Tidak ada hasil untuk pencarian.[/yellow]")
        except Exception:
            print("Tidak ada hasil.")
        return

    try:
        from rich.table import Table
        from rich import box

        t = Table(
            title=f"🔍 {title} ({len(results)} findings)",
            box=box.HEAVY_HEAD,
            header_style="bold magenta",
        )
        t.add_column("Risk", justify="center", width=10)
        t.add_column("Source", style="cyan", width=10)
        t.add_column("Host", style="white")
        t.add_column("Port", justify="center", width=6)
        t.add_column("Service", style="yellow", width=10)
        t.add_column("Detail", style="dim")

        sev_color = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "green",
            "INFO": "dim",
        }

        # Tampilkan max 50
        for f in results[:50]:
            risk = f.get("risk", "INFO") or "INFO"
            color = sev_color.get(risk, "white")
            t.add_row(
                f"[{color}]{risk}[/{color}]",
                f.get("source", "")[:10],
                f.get("host", "")[:30],
                f.get("port", "")[:5],
                f.get("service", "")[:10],
                f.get("text", "")[:60],
            )

        if len(results) > 50:
            t.add_row("...", f"+{len(results) - 50} lagi", "", "", "", "")

        console.print(t)
    except ImportError:
        # Fallback plain
        for f in results[:50]:
            print(f"[{f.get('risk', 'INFO'):<8}] {f.get('source', ''):<10} "
                  f"{f.get('host', ''):<20} {f.get('service', ''):<10} "
                  f"{f.get('text', '')[:60]}")
        if len(results) > 50:
            print(f"... +{len(results) - 50} lagi")


def interactive(console=None):
    """Tampilkan bantuan query syntax."""
    if console is None:
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            console = None

    help_text = """
[bold cyan]🔍 Search Query Syntax[/bold cyan]

[bold yellow]Free text:[/bold yellow]
  ssh                          → cari "ssh" di semua field
  CVE-2021                     → cari CVE

[bold yellow]Field filter:[/bold yellow]
  risk:CRITICAL                → filter risk
  service:ssh                  → filter service
  port:22                      → filter port
  source:sqli                  → filter sumber finding
  host:192.168.1.1             → filter host

[bold yellow]Wildcard:[/bold yellow]
  host:192.168.*               → host dengan prefix 192.168.

[bold yellow]Kombinasi:[/bold yellow]
  risk:CRITICAL AND service:ssh → AND
  risk:HIGH OR risk:CRITICAL    → OR
  ssh AND port:22               → free text + field

[bold yellow]Regex:[/bold yellow]
  regex:^CVE-202[0-9]           → regex match

[bold yellow]Tips:[/bold yellow]
  • Case-insensitive
  • Ketik [cyan]quit[/cyan] / [cyan]exit[/cyan] / kosong untuk keluar
  • Ketik [cyan]help[/cyan] untuk tampilkan ini lagi
"""

    if console is not None:
        try:
            from rich.panel import Panel
            console.print(Panel(help_text, title="Search Help",
                                  border_style="cyan"))
            return
        except Exception:
            pass

    # Plain fallback
    plain = re.sub(r"\[/?[a-zA-Z0-9 _#=]+\]", "", help_text)
    print(plain)


# ============================================================
# CLI
# ============================================================
def _cli():
    import argparse
    import sys
    import os
    import json

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
                              subtitle="Full-text Search — JagoX")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX search — full-text search untuk findings")
    parser.add_argument("query", nargs="?", help="Query string")
    parser.add_argument("--json", help="File JSON dengan findings (opsional)")
    parser.add_argument("--version", action="version",
                        version=f"JagoX search v{__version__}")
    args = parser.parse_args()

    # Load findings
    findings = []
    if args.json and os.path.exists(args.json):
        try:
            with open(args.json, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict) and "findings" in data:
                    findings = data["findings"]
            print(f"[i] Loaded {len(findings)} findings dari {args.json}")
        except Exception as e:
            print(f"[!] Gagal load JSON: {e}")
            return
    else:
        # Sample findings untuk demo
        print("[i] Tidak ada --json, pakai sample findings untuk demo\n")
        findings = [
            {"source": "port", "host": "192.168.1.1", "port": "22",
             "service": "ssh", "risk": "MEDIUM",
             "text": "OpenSSH 8.2"},
            {"source": "port", "host": "192.168.1.1", "port": "80",
             "service": "http", "risk": "LOW",
             "text": "Apache 2.4.7"},
            {"source": "cve", "host": "192.168.1.1", "port": "22",
             "service": "ssh", "risk": "HIGH",
             "text": "CVE-2021-41617 (CVSS 7.0) di openssh"},
            {"source": "sqli", "host": "192.168.1.2", "port": "",
             "service": "", "risk": "CRITICAL",
             "text": "error_based param=id MySQL syntax error"},
            {"source": "sub", "host": "admin.example.com", "port": "",
             "service": "", "risk": "CRITICAL",
             "text": "IP 1.2.3.4 TAKEOVER GitHub Pages"},
        ]
        print(f"Sample: {len(findings)} findings\n")

    # Kalau tidak ada query, interactive mode
    if not args.query:
        interactive()
        print("\n[i] Jalankan: python3 -m modules.search '<query>'\n")
        return

    # Search
    results = search_findings(findings, args.query)
    print(f"\nQuery: '{args.query}'")
    print(f"Matched: {len(results)} / {len(findings)}\n")

    try:
        from rich.console import Console
        console = Console()
        render_results(console, results, title=f"Query: {args.query}")
    except ImportError:
        for r in results:
            print(f"[{r.get('risk', 'INFO'):<8}] {r.get('source', ''):<10} "
                  f"{r.get('host', ''):<20} {r.get('text', '')[:60]}")


if __name__ == "__main__":
    _cli()
