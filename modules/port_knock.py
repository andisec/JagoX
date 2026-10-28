#!/usr/bin/env python3
# port_knock.py — Port-knock detection (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Deteksi apakah target menggunakan port-knocking untuk menyembunyikan
# service (biasanya SSH di port 22).
#
# Cara kerja:
#   1. Cek status target port SEBELUM (harus closed/filtered)
#   2. Kirim TCP connect ke tiap port di sequence (dengan delay kecil)
#   3. Cek status target port SESUDAH (harus open kalau port-knock berhasil)
#
# Catatan: Port-knock adalah teknik obscure — banyak false negative
# kalau firewall pakai sequence yang tidak umum. Modul ini coba
# 7 sequence default + bisa custom.
#
# Public API (kompatibel nmpx.py v1.0.0):
#   detect(host, target_port=22, sequences=None, timeout=2.0, delay=0.2)
#   detect_with_custom(host, sequence, target_port=22, timeout=2.0, delay=0.2)

import socket
import time

__version__ = "1.0.0"


# ============================================================
# DEFAULT SEQUENCES — 7 paling umum
# ============================================================
DEFAULT_SEQUENCES = [
    {"name": "classic", "ports": [7000, 8000, 9000], "target": 22},
    {"name": "numeric", "ports": [1000, 2000, 3000], "target": 22},
    {"name": "repeated", "ports": [1111, 2222, 3333], "target": 22},
    {"name": "simple", "ports": [1, 2, 3], "target": 22},
    {"name": "increment1000", "ports": [3000, 4000, 5000], "target": 22},
    {"name": "cool_ports", "ports": [13, 37, 30000], "target": 22},
    {"name": "reverse_triple", "ports": [22, 80, 443], "target": 22},
]


# ============================================================
# HELPERS
# ============================================================
def _port_state(host, port, timeout=2.0):
    """
    Cek status port via TCP connect.

    Returns:
        "open"      — connect() sukses (SYN/ACK diterima)
        "closed"    — RST diterima (ECONNREFUSED)
        "filtered"  — timeout atau host unreachable
        "error"     — exception lain
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return "open"
        # ECONNREFUSED (Linux=111, macOS=61, Windows=10061)
        if result in (61, 111, 10061):
            return "closed"
        return "filtered"
    except socket.timeout:
        return "filtered"
    except Exception:
        return "error"


def _knock(host, ports, delay=0.2, timeout=1.0):
    """Kirim TCP connect ke serangkaian port (dengan delay antar knock)."""
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect_ex((host, int(p)))
            sock.close()
        except Exception:
            pass
        if delay > 0:
            time.sleep(delay)


# ============================================================
# MAIN DETECT
# ============================================================
def detect(host, target_port=22, sequences=None, timeout=2.0, delay=0.2):
    """
    Deteksi port-knocking dengan multiple sequences.

    Args:
        host:         target IP/hostname
        target_port:  port yang mungkin disembunyikan (default 22)
        sequences:    list of dict {name, ports} — None = pakai default
        timeout:      timeout connect
        delay:        delay antar knock (detik)

    Returns:
        dict {
            host, target_port, initial_state,
            results: [ {sequence, ports, before, after, detected, note} ],
            detected: bool,
        }
    """
    if sequences is None:
        sequences = DEFAULT_SEQUENCES

    initial = _port_state(host, target_port, timeout=timeout)
    results = []
    detected_any = False

    for seq in sequences:
        # Reset state: tunggu sebentar antar sequence
        time.sleep(0.3)

        # Cek state sebelum knock
        before = _port_state(host, target_port, timeout=timeout)

        # Kalau sudah open dari awal — bukan port-knock, tapi catat
        if before == "open":
            results.append({
                "sequence": seq["name"],
                "ports": seq["ports"],
                "before": before,
                "after": before,
                "detected": False,
                "note": "port sudah open dari awal (bukan port-knock)",
            })
            continue

        # Kirim knock
        _knock(host, seq["ports"], delay=delay, timeout=1.0)

        # Cek state sesudah knock
        after = _port_state(host, target_port, timeout=timeout)

        is_detected = (before in ("closed", "filtered") and after == "open")

        results.append({
            "sequence": seq["name"],
            "ports": seq["ports"],
            "before": before,
            "after": after,
            "detected": is_detected,
            "note": None,
        })

        if is_detected:
            detected_any = True

    return {
        "host": host,
        "target_port": target_port,
        "initial_state": initial,
        "results": results,
        "detected": detected_any,
    }


def detect_with_custom(host, sequence, target_port=22, timeout=2.0,
                        delay=0.2):
    """Test satu sequence custom."""
    return detect(
        host, target_port=target_port,
        sequences=[{"name": "custom", "ports": list(sequence)}],
        timeout=timeout, delay=delay,
    )


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
                              subtitle="Port-Knock Detection — Pure Python")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX port_knock — port-knock detection")
    parser.add_argument("host")
    parser.add_argument("-p", "--target-port", type=int, default=22)
    parser.add_argument("-t", "--timeout", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Delay antar knock (detik, default 0.2)")
    parser.add_argument("--sequence",
                        help="Comma-separated custom: 7000,8000,9000")
    parser.add_argument("--version", action="version",
                        version=f"JagoX port_knock v{__version__}")
    args = parser.parse_args()

    print(f"=== Port-Knock Detection — {args.host} ===")
    print(f"=== Target port: {args.target_port} | "
          f"Delay: {args.delay}s ===\n")

    if args.sequence:
        try:
            seq = [int(x.strip()) for x in args.sequence.split(",")]
        except ValueError:
            print("[!] Sequence tidak valid (harus angka dipisah koma).")
            return
        print(f"Sequence custom: {'→'.join(str(p) for p in seq)}\n")
        result = detect_with_custom(args.host, seq,
                                     target_port=args.target_port,
                                     timeout=args.timeout,
                                     delay=args.delay)
    else:
        result = detect(args.host, target_port=args.target_port,
                         timeout=args.timeout, delay=args.delay)

    print(f"Initial state port {args.target_port}: "
          f"{result['initial_state']}\n")

    for r in result["results"]:
        mark = "✓" if r["detected"] else "✗"
        ports_str = "→".join(str(p) for p in r["ports"])
        print(f"  [{mark}] {r['sequence']:<15} {ports_str:<25} "
              f"before={r['before']:<8} after={r['after']:<8}")
        if r["note"]:
            print(f"      note: {r['note']}")

    print()
    if result["detected"]:
        print("⚠ PORT-KNOCK DETECTED!")
    else:
        print("[OK] Tidak ada port-knock terdeteksi.")


if __name__ == "__main__":
    _cli()
