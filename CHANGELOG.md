# Changelog

Semua perubahan penting pada JagoX didokumentasikan di file ini.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [1.0.0] — 2026 — Final Release

### Added

**Fitur Baru:**
- `graphql_scan` — GraphQL security scanner (read-only): endpoint discovery,
  introspection check, GET-based query (CSRF risk), schema dump
- `http2_check` — HTTP/2 detection (safe): ALPN, h2c, SETTINGS frame peek,
  server/alt-svc header analysis
- `jagox.py` — Unified CLI untuk semua 12 command modul
- Packaging: `setup.py` + `pyproject.toml` untuk `pip install jagox`
- Console scripts: `jagox` dan `nmpx` sebagai command global

**Flag nmpx.py:**
- `--tls-audit`, `--graphql`, `--http2`, `--no-plugins`
- (sebelumnya: `--tui`, `--watch`, `--fuzz`, `--port-knock`,
  `--blind-sqli`, `--search`, `--sequence`)

**Polish:**
- `banner.py` — gunakan Unicode escape (`\u2588`/`\u2592`) → anti-korupsi
- `__init__.py` — 15 modul terdaftar, `reload_all()`, summary status
- Version bump semua modul ke 1.0.0

### Changed
- Banner subtitle → include Fuzz · TLS · GraphQL
- README lengkap semua fitur v1.0.0
- `.nmpxrc` — section lengkap: fuzz, portknock, search, dump, tui, wordlist

### Skipped (deliberate — ethical by design)
- ❌ HTTP request smuggling (CL.TE, TE.CL, H2 smuggling)
- ❌ WAF bypass payload generation
- ❌ CVE exploit PoC
- ❌ Auth bypass automation
- ❌ Rate-limit bypass

Alasan: itu **attack tool**, bukan scanner.
Alternatif aman yang disediakan:
- ✅ `http2_check` — deteksi HTTP/2 (bukan smuggling)
- ✅ WAF fingerprint — identifikasi WAF di `sqli.py`/`xss.py`

---

## [0.9.0]

### Added
- `tls_audit` — TLS/SSL deep audit (versi, cert, cipher, OCSP, HSTS)
- `plugins` — Plugin system dengan 5 events (start, target, host_result,
  finding, end)
- Contoh plugin `sample_logger.py`
- Flag `--tls-audit`, `--no-plugins`

---

## [0.8.0]

### Added
- `http_fuzz` — HTTP fuzzer dengan 12 kategori payload
- `port_knock` — Port-knock detection (7 sequence default + custom)
- `search` — Full-text search findings (`risk:CRITICAL AND service:ssh`)
- `sqli` dump extension: `--dump-db`, `--dump-tables`, `--dump-columns`,
  `--dump-rows` (blind extraction)
- Flag `--fuzz`, `--port-knock`, `--search QUERY`, `--sequence`

---

## [0.7.0]

### Added
- TUI mode (`prompt_toolkit` optional)
- Blind SQLi binary search (`blind_extract`, `blind_dump`)
- Watchdog mode (`--watch N` — scan ulang tiap N detik)
- Custom wordlist untuk `dir_brute` + `subdomain`
- Flag `--tui`, `--watch`, `--blind-sqli`

---

## [0.6.0]

### Added
- `dir_brute` — Directory bruteforcer (3 tier, 20+ extension)
- `subdomain` — Subdomain enumeration (CNAME chain, takeover detection,
  CT logs via crt.sh)
- Progress bar hijau

---

## [0.5.0]

### Added
- Framework `JagoX` dengan struktur `modules/`
- Modul `banner`, `banner_grab`, `web_vuln`, `sqli`, `xss`
- `nmpx.py` modular orchestrator
- `.nmpxrc` config file
- Graceful import dengan fallback

---

## [0.4.0]

### Added
- Auto CVE scan (NSE vulners)
- OSINT recon (Reverse DNS, Whois, GeoIP)
- Watchdog/diff scanning
- Auto-filter (CRITICAL/HIGH + CVE)

---

## [0.3.0]

### Added
- Multi-target (CIDR, range, comma)
- Concurrent port scan (ThreadPoolExecutor)
- Host discovery (ping sweep)
- Summary statistics panel

---

## [0.2.0]

### Added
- 6 scan profiles (Quick, Full TCP, Stealth, UDP, Vuln, Aggressive)
- Auto follow-up NSE scripts
- Risk color coding (CRITICAL/HIGH/MEDIUM/LOW)
- Port-level script parsing

---

## [0.1.0]

### Added
- Interactive input
- 4 tabel output (Info Host, Port Terbuka, Port Tertutup, NSE)
- Dependency check (nmap, rich)
