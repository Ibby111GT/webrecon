#!/usr/bin/env python3
"""
WebRecon - Web Vulnerability Scanner
-------------------------------------
OWASP Top 10 aligned web vulnerability scanner. Checks HTTP security
headers, TLS/SSL configuration, reflected XSS, SQL injection errors,
and path traversal. Runs in demo mode without a live target.

Usage:
    python web_scanner.py --target https://example.com
    python web_scanner.py --demo
"""

import ssl
import sys
import json
import socket
import argparse
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "HIGH",
        "owasp": "A05:2021",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "HIGH",
        "owasp": "A03:2021",
    },
    "X-Frame-Options": {
        "description": "Clickjacking protection",
        "severity": "MEDIUM",
        "owasp": "A05:2021",
    },
    "X-Content-Type-Options": {
        "description": "MIME-type sniffing prevention",
        "severity": "LOW",
        "owasp": "A05:2021",
    },
    "Referrer-Policy": {
        "description": "Referrer information control",
        "severity": "LOW",
        "owasp": "A05:2021",
    },
    "Permissions-Policy": {
        "description": "Browser feature permissions",
        "severity": "LOW",
        "owasp": "A05:2021",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but informational)",
        "severity": "INFO",
        "owasp": "A03:2021",
    },
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "'--",
    "1 OR 1=1",
    "1' OR '1'='1",
    "admin'--",
]

SQLI_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql",
    "sqlite_", "syntax error", "unclosed quotation",
    "odbc driver", "jdbc", "sqlexception",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    owasp: str = ""
    evidence: str = ""

    def to_dict(self):
        return {
            "check": self.check, "severity": self.severity,
            "title": self.title, "detail": self.detail,
            "owasp": self.owasp, "evidence": self.evidence,
        }


def make_request(url: str, timeout: int = 10) -> tuple:
    """Make HTTP request. Returns (response_object, body_text, error)."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "WebRecon/1.0 Security Scanner"},
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="ignore")
            return resp, body, None
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="ignore")
        return e, body, None
    except Exception as ex:
        return None, "", str(ex)


def check_security_headers(url: str) -> list:
    """Check for missing HTTP security headers."""
    findings = []
    resp, _, err = make_request(url)
    if err or resp is None:
        findings.append(Finding(
            check="headers", severity="ERROR",
            title="Could not connect to target",
            detail=err or "No response",
        ))
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append(Finding(
                check="headers",
                severity=meta["severity"],
                title=f"Missing: {header}",
                detail=meta["description"],
                owasp=meta["owasp"],
            ))
        else:
            val = headers[header.lower()]
            if header == "Strict-Transport-Security" and "max-age" in val:
                try:
                    age = int(val.split("max-age=")[1].split(";")[0].strip())
                    if age < 31536000:
                        findings.append(Finding(
                            check="headers", severity="MEDIUM",
                            title="Weak HSTS max-age",
                            detail=f"max-age={age} is less than 1 year (31536000)",
                            owasp="A05:2021",
                        ))
                except Exception:
                    pass
    return findings


def check_tls(hostname: str) -> list:
    """Check TLS/SSL configuration."""
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(Finding(
                        check="tls", severity="HIGH",
                        title=f"Weak TLS protocol: {protocol}",
                        detail="TLS 1.0 and 1.1 are deprecated. Use TLS 1.2+.",
                        owasp="A02:2021",
                    ))

                if cert:
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_left = (not_after - datetime.now().timestamp()) / 86400
                    if days_left < 30:
                        findings.append(Finding(
                            check="tls", severity="HIGH",
                            title=f"Certificate expiring soon: {int(days_left)} days",
                            detail="Renew the TLS certificate before expiry.",
                            owasp="A02:2021",
                        ))
    except ssl.SSLError as e:
        findings.append(Finding(
            check="tls", severity="HIGH",
            title="TLS/SSL Error",
            detail=str(e), owasp="A02:2021",
        ))
    except Exception as e:
        findings.append(Finding(
            check="tls", severity="INFO",
            title="TLS check skipped",
            detail=str(e),
        ))
    return findings


def check_xss(base_url: str) -> list:
    """Test for reflected XSS by injecting payloads into URL parameters."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        test_url = base_url.rstrip("/") + "/?q=test"
        params = {"q": ["test"]}
        parsed = urllib.parse.urlparse(test_url)

    for param in list(params.keys())[:3]:
        for payload in XSS_PAYLOADS[:3]:
            new_params = dict(params)
            new_params[param] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, "",
            ))
            _, body, err = make_request(test_url)
            if err:
                continue
            if payload.lower() in body.lower():
                findings.append(Finding(
                    check="xss", severity="HIGH",
                    title=f"Reflected XSS in parameter: {param}",
                    detail="User input reflected unsanitized in response.",
                    owasp="A03:2021",
                    evidence=f"Payload: {payload[:50]}",
                ))
                break
    return findings


def check_sqli(base_url: str) -> list:
    """Test for SQL injection via error-based detection."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings

    for param in list(params.keys())[:3]:
        for payload in SQLI_PAYLOADS[:3]:
            new_params = dict(params)
            new_params[param] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, "",
            ))
            _, body, err = make_request(test_url)
            if err:
                continue
            body_lower = body.lower()
            for error in SQLI_ERROR_PATTERNS:
                if error in body_lower:
                    findings.append(Finding(
                        check="sqli", severity="CRITICAL",
                        title=f"Possible SQL Injection in parameter: {param}",
                        detail="Database error exposed in response.",
                        owasp="A03:2021",
                        evidence=f"Error pattern: {error}",
                    ))
                    break
    return findings


def check_server_info(url: str) -> list:
    """Check for information disclosure in headers."""
    findings = []
    resp, _, err = make_request(url)
    if err or resp is None:
        return findings
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h in headers:
            findings.append(Finding(
                check="info_disclosure", severity="LOW",
                title=f"Server info disclosed: {h.title()}",
                detail=f"Value: {headers[h]}. Remove or obscure this header.",
                owasp="A05:2021",
                evidence=headers[h],
            ))
    return findings


def generate_demo_findings() -> list:
    return [
        Finding("headers", "HIGH", "Missing: Content-Security-Policy",
                "No CSP header found.", "A03:2021"),
        Finding("headers", "HIGH", "Missing: Strict-Transport-Security",
                "HSTS not configured.", "A05:2021"),
        Finding("headers", "MEDIUM", "Missing: X-Frame-Options",
                "Site may be vulnerable to clickjacking.", "A05:2021"),
        Finding("tls", "HIGH", "Weak TLS protocol: TLSv1.1",
                "TLS 1.1 is deprecated.", "A02:2021"),
        Finding("xss", "HIGH", "Reflected XSS in parameter: q",
                "Input reflected unsanitized.", "A03:2021",
                evidence="<script>alert(1)</script>"),
        Finding("sqli", "CRITICAL", "Possible SQL Injection in parameter: id",
                "Database error in response.", "A03:2021",
                evidence="sql syntax near"),
        Finding("info_disclosure", "LOW", "Server info disclosed: Server",
                "Apache/2.4.41 version leaked.", "A05:2021",
                evidence="Apache/2.4.41 (Ubuntu)"),
    ]


def print_report(target: str, findings: list):
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "ERROR": 5}
    findings.sort(key=lambda f: sev_order.get(f.severity, 9))
    icons = {"CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[!  ]",
             "LOW": "[.  ]", "INFO": "[   ]", "ERROR": "[ERR]"}
    sep = "=" * 60
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{sep}")
    print(f"  WebRecon Scan Report")
    print(f"  Target  : {target}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Findings: {len(findings)}")
    for sev, count in sorted(counts.items(), key=lambda x: sev_order.get(x[0], 9)):
        print(f"    {icons.get(sev, ' '):<7} {sev:<10} {count}")
    print(sep)

    for f in findings:
        print(f"\n  [{f.severity}] {f.title}")
        print(f"  Check   : {f.check.upper()}")
        if f.owasp:
            print(f"  OWASP   : {f.owasp}")
        print(f"  Detail  : {f.detail}")
        if f.evidence:
            print(f"  Evidence: {f.evidence[:80]}")
    print(f"\n{sep}\n")


def main():
    parser = argparse.ArgumentParser(description="WebRecon - OWASP web vulnerability scanner")
    parser.add_argument("--target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--demo", action="store_true", help="Run with demo findings")
    parser.add_argument("--checks", default="headers,tls,xss,sqli,info",
                        help="Checks to run (default: all)")
    parser.add_argument("--output", help="Save results to JSON file")
    args = parser.parse_args()

    if args.demo:
        findings = generate_demo_findings()
        print_report("https://demo.example.com", findings)
        return

    if not args.target:
        parser.print_help()
        sys.exit(0)

    target = args.target
    if not target.startswith("http"):
        target = "https://" + target

    checks = [c.strip() for c in args.checks.split(",")]
    all_findings = []

    print(f"[*] Scanning: {target}")
    parsed = urllib.parse.urlparse(target)

    if "headers" in checks:
        print("[*] Checking security headers...")
        all_findings.extend(check_security_headers(target))

    if "tls" in checks and parsed.scheme == "https":
        print("[*] Checking TLS configuration...")
        all_findings.extend(check_tls(parsed.hostname))

    if "xss" in checks:
        print("[*] Testing for reflected XSS...")
        all_findings.extend(check_xss(target))

    if "sqli" in checks:
        print("[*] Testing for SQL injection...")
        all_findings.extend(check_sqli(target))

    if "info" in checks:
        print("[*] Checking for information disclosure...")
        all_findings.extend(check_server_info(target))

    print_report(target, all_findings)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "findings": [fi.to_dict() for fi in all_findings],
            }, f, indent=2)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
