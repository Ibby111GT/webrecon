# WebRecon — Web Vulnerability Scanner

An OWASP Top 10 aligned web vulnerability scanner that audits HTTP security headers,
TLS configuration, reflected XSS, SQL injection, and information disclosure.
Built with Python's standard library — no external dependencies.

## Features

- HTTP security header validation (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
- SSL/TLS configuration auditing (protocol versions, certificate expiry)
- Reflected XSS detection via parameter fuzzing (5 payloads)
- SQL injection error-based detection
- Server information disclosure detection
- OWASP Top 10 finding classification
- Risk-sorted findings report (CRITICAL → INFO)
- JSON export for ticketing and SIEM ingestion
- Demo mode with realistic pre-loaded findings

## Usage

```bash
# Demo mode (no live target needed)
python web_scanner.py --demo

# Scan a target URL
python web_scanner.py --target https://example.com

# Run specific checks only
python web_scanner.py --target https://example.com --checks headers,tls

# Export to JSON
python web_scanner.py --target https://example.com --output report.json
```

## Checks Performed

| Check | Description | OWASP |
|-------|-------------|-------|
| headers | 7 security header validations | A05:2021 |
| tls | Protocol version + cert expiry | A02:2021 |
| xss | Reflected XSS via payload fuzzing | A03:2021 |
| sqli | SQL error-based injection detection | A03:2021 |
| info | Server header information disclosure | A05:2021 |

## Security Headers Checked

- `Content-Security-Policy` (HIGH)
- `Strict-Transport-Security` (HIGH)
- `X-Frame-Options` (MEDIUM)
- `X-Content-Type-Options` (LOW)
- `Referrer-Policy` (LOW)
- `Permissions-Policy` (LOW)
- `X-XSS-Protection` (INFO)

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)

## Ethical Use

Only scan web applications you own or have **explicit written authorization** to test.
Unauthorized scanning may violate the CFAA, GDPR, or other applicable laws.
This tool is for authorized security assessments only.
