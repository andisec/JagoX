#!/usr/bin/env python3
# sample_logger.py — contoh plugin JagoX
# Part of JagoX framework — MIT License
#
# Plugin ini log semua finding CRITICAL/HIGH ke stderr.
# Berguna untuk integrasi dengan sistem logging eksternal
# atau cuma untuk lihat quick summary di stderr.
#
# Cara kerja:
#   1. Copy file ini ke modules/plugins/sample_logger.py
#   2. Pipeline nmpx.py otomatis load dan fire
#   3. Tidak perlu konfigurasi tambahan
#
# Event handlers yang dipakai:
#   - on_start       : log awal
#   - on_host_result : log tiap host selesai scan
#   - on_finding     : log finding CRITICAL/HIGH
#   - on_end         : log summary

import sys

__version__ = "1.0.0"


def _log(msg):
    """Print ke stderr supaya tidak ganggu stdout."""
    try:
        print(f"[plugin:logger] {msg}", file=sys.stderr)
    except Exception:
        pass


def on_start(context):
    _log("Scan dimulai")


def on_host_result(host_data):
    """host_data = dict dari nmap parse_xml."""
    try:
        ip = host_data.get("ip", "?")
        ports = host_data.get("ports", [])
        n_open = sum(1 for p in ports if p.get("state") == "open")
        vulns = host_data.get("vulns", [])
        if n_open > 0 or vulns:
            _log(f"Host {ip}: {n_open} port terbuka"
                  + (f", {len(vulns)} CVE" if vulns else ""))
    except Exception:
        pass


def on_finding(f):
    """f = {source, host, port, service, risk, text}."""
    try:
        risk = f.get("risk", "").upper()
        if risk in ("CRITICAL", "HIGH"):
            _log(f"⚠ {risk}: {f.get('source', '?')} "
                  f"{f.get('host', '')} {f.get('port', '')} — "
                  f"{f.get('text', '')[:80]}")
    except Exception:
        pass


def on_end(summary):
    """summary = {findings, hosts, iteration}."""
    try:
        n = summary.get("findings", 0)
        h = summary.get("hosts", 0)
        it = summary.get("iteration", 1)
        _log(f"Scan selesai iter {it}: {n} findings, {h} host")
    except Exception:
        pass
