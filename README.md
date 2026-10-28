# JagoX v1.0.0

<div align="center">

    ░█████                                  ░██    ░██ 
      ░██                                    ░██  ░██  
      ░██   ░██████    ░████████  ░███████    ░██░██   
      ░██        ░██  ░██    ░██ ░██    ░██    ░███    
░██   ░██   ░███████  ░██    ░██ ░██    ░██   ░██░██   
░██   ░██  ░██   ░██  ░██   ░███ ░██    ░██  ░██  ░██  
 ░██████    ░█████░██  ░█████░██  ░███████  ░██    ░██ 
                             ░██                       
                       ░███████                        
                                                       

**Automatic Security Scanner Framework**

*Pure Python stdlib · 15 modules · MIT License*

**Version:** `1.0.0` · **Platform:** Linux / macOS / WSL

</div>

---

## 🎯 Apa itu JagoX?

JagoX adalah framework security scanner yang membungkus Nmap dengan
orkestrasi cerdas dan **15 modul internal** — semua pure Python stdlib,
zero external dependencies (kecuali Nmap + `rich`).

Cukup ketik `jagox scan <target>`, dan JagoX otomatis menjalankan:

    nmap scan → banner grab → CVE scan → OSINT → subdomain enum
      → web vuln → SQLi → XSS → dir brute → graphql → http2
        → TLS audit → port-knock → search → summary

---

## ⚡ Quick Start

**1. Install Nmap** (wajib):

    sudo apt install nmap      # Debian/Ubuntu/Kali
    brew install nmap          # macOS

**2. Install Python dependencies**:

    pip install rich

**3. Jalankan**:

    cd JagoX
    sudo python3 jagox.py scan example.com

Atau install via pip:

    pip install -e .
    jagox scan example.com

---

## 🚀 Commands

Full pipeline:

    jagox scan <target>

Modul individual:

    jagox dir <url>              # Directory bruteforce
    jagox sub <domain>           # Subdomain enumeration
    jagox sqli <url>             # SQL injection
    jagox xss <url>              # XSS detection
    jagox web <url>              # Web vulnerability
    jagox tls <host>             # TLS deep audit
    jagox fuzz <url>             # HTTP fuzzer
    jagox graphql <url>          # GraphQL scanner
    jagox http2 <host>           # HTTP/2 detection
    jagox banner-grab <host>     # Banner grabber
    jagox port-knock <host>      # Port-knock detection

Utility:

    jagox modules                # List modul aktif
    jagox version                # Versi
    jagox help                   # Bantuan

### Scan Flags (opt-in)

    jagox scan example.com --tui              # TUI mode
    jagox scan example.com --watch 300        # Watchdog tiap 5 menit
    jagox scan example.com --fuzz             # HTTP fuzzer
    jagox scan example.com --tls-audit        # TLS deep audit
    jagox scan example.com --graphql          # GraphQL scanner
    jagox scan example.com --http2            # HTTP/2 detection
    jagox scan example.com --port-knock       # Port-knock detection
    jagox scan example.com --blind-sqli       # Blind SQLi extraction
    jagox scan example.com --search QUERY     # Search findings
    jagox scan example.com --no-plugins       # Disable plugins

---

## 📦 15 Modules

| # | Modul | Fungsi |
|---|-------|--------|
| 1 | `banner` | ASCII art banner |
| 2 | `banner_grab` | Banner grabber 25+ protokol |
| 3 | `web_vuln` | Web vulnerability (13 checks) |
| 4 | `sqli` | SQL injection + blind + dump |
| 5 | `xss` | Reflected XSS + DOM heuristic |
| 6 | `dir_brute` | Directory bruteforce (3 tier) |
| 7 | `subdomain` | Subdomain enum + takeover detect |
| 8 | `tls_audit` | TLS/SSL deep audit |
| 9 | `http_fuzz` | HTTP fuzzer (12 kategori payload) |
| 10 | `graphql_scan` | GraphQL scanner (read-only) |
| 11 | `http2_check` | HTTP/2 detection (safe) |
| 12 | `port_knock` | Port-knock detection |
| 13 | `search` | Full-text search findings |
| 14 | `plugins` | Plugin system (5 events) |
| 15 | `tui` | TUI mode (prompt_toolkit) |

---

## ⚙️ Config `.nmpxrc`

Format INI, di folder root. Default config sudah ada.

    [general]
    cvss_threshold = 4.0
    max_workers = 10
    safe_mode = false
    enable_banner_grab = true
    enable_web_vuln = true
    enable_sqli = true
    enable_xss = true
    enable_dir_brute = true
    enable_subdomain = true
    enable_graphql = true
    enable_http2 = true

    [scan]
    default_profile = 1

    [ratelimit]
    delay_ms = 500
    max_concurrent_safe = 3

    [output]
    show_banner = true
    show_module_status = true

    [advanced]
    scan_timeout = 900
    banner_timeout = 3.0
    max_hosts_warning = 1024
    dir_brute_tier = 2
    subdomain_tier = 2
    watch_interval = 300

**Preset production:**

    [general]
    max_workers = 5
    safe_mode = true

    [ratelimit]
    delay_ms = 1000
    max_concurrent_safe = 2

---

## 🔌 Plugin System

Buat file `.py` di `plugins/`:

    # plugins/my_plugin.py
    
    def on_finding(f):
        """Dipanggil tiap finding."""
        if f.get("risk") == "CRITICAL":
            print(f"[!] {f.get('host')} — {f.get('text', '')[:80]}")
    
    def on_end(summary):
        """Dipanggil di akhir pipeline."""
        print(f"Selesai: {summary.get('findings', 0)} findings")

**5 events:** `on_start`, `on_target`, `on_host_result`, `on_finding`, `on_end`

Auto-load. Disable: `--no-plugins`.

---

## 🏗️ Struktur Project

    JagoX/
    ├── jagox.py                ← Unified CLI
    ├── nmpx.py                 ← Full pipeline orchestrator
    ├── setup.py + pyproject.toml
    ├── README.md
    ├── CHANGELOG.md
    ├── LICENSE (MIT)
    ├── .nmpxrc                 ← Config
    ├── plugins/                ← Plugin auto-load
    │   ├── __init__.py
    │   └── sample_logger.py
    └── modules/
        ├── __init__.py
        ├── __main__.py
        ├── banner.py
        ├── banner_grab.py
        ├── web_vuln.py
        ├── sqli.py
        ├── xss.py
        ├── dir_brute.py
        ├── subdomain.py
        ├── tls_audit.py
        ├── http_fuzz.py
        ├── graphql_scan.py
        ├── http2_check.py
        ├── port_knock.py
        ├── search.py
        ├── plugins.py
        └── tui.py

---

## ⚠️ Ethics & Legal

**Gunakan dengan tanggung jawab penuh.**

### ✅ Boleh
- Scan sistem milik sendiri
- Scan dengan **izin tertulis** dari pemilik
- CTF, lab, bug bounty (dalam scope)
- Training, edukasi

### ❌ Dilarang
- Scan tanpa izin — **ilegal** di hampir semua negara
- Eksploitasi tanpa otorisasi
- Data exfiltration (`--dump`)
- Mengganggu layanan publik

### 📜 Hukum

| Negara | UU |
|---|---|
| Indonesia | UU ITE No. 11/2008 & 19/2016 (Pasal 30) |
| USA | CFAA |
| UK | Computer Misuse Act 1990 |
| EU | Directive 2013/40/EU |

**Penulis tidak bertanggung jawab atas penyalahgunaan.**

### 🚫 Yang TIDAK ada di JagoX (by design)

- ❌ HTTP request smuggling (CL.TE/TE.CL/H2)
- ❌ WAF bypass payload generation
- ❌ CVE exploit PoC
- ❌ Auth bypass automation
- ❌ Rate-limit bypass

Ini **scanner**, bukan **attack framework**.

---

## 🐛 Troubleshooting

**`nmap not found`**

    sudo apt install nmap

**`ModuleNotFoundError: No module named 'rich'`**

    pip install rich

**`prompt_toolkit` error**

    pip install prompt_toolkit

**Modul tidak terdeteksi**

    python3 -m modules
    # Harus: 15 aktif / 15 total

**Scan lambat**

- Turunkan profile ke `1 (Quick)`
- Full TCP: edit `nmpx.py`, tambah `--min-rate 1000` di `PROFILES["2"]`

---

## 📜 License

MIT License — lihat file [LICENSE](LICENSE)

---

## 🙏 Kredit

- **[Nmap](https://nmap.org)** — Gordon Lyon (Fyodor)
- **[Rich](https://github.com/Textualize/rich)** — Will McGugan
- **[crt.sh](https://crt.sh)** — Certificate Transparency
- **Komunitas Security Open Source**

---

<div align="center">

**JagoX v1.0.0** · Made with ❤️ for security community

**⚡ Stay ethical. Hack responsibly. ⚡**

</div>
