#!/usr/bin/env python3
"""
web_scanner.py -- WebRecon CLI entry point.

Runs header, TLS, and active checks against one or more targets
and prints a coloured summary (or JSON) to stdout.

Usage:
    python web_scanner.py --target https://example.com
    python web_scanner.py --file targets.txt --json
    python web_scanner.py --target https://example.com --no-active
"""

import argparse
import sys
from urllib.parse import urlparse

from checks.headers import run as check_headers
from checks.tls     import run as check_tls
from checks.active  import run as check_active
from models         import ScanResult
from utils          import normalise_url, load_targets, print_scan_result


def scan(url: str, skip_active: bool = False) -> ScanResult:
    result = ScanResult(target=url)
    parsed = urlparse(url)

    result.headers = check_headers(url)

    if parsed.scheme == "https":
        host = parsed.hostname or ""
        port = parsed.port or 443
        result.tls = check_tls(host, port)

    if not skip_active:
        result.active = check_active(url)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WebRecon -- web security header, TLS, and path scanner",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--target", metavar="URL",  help="Single URL to scan")
    src.add_argument("--file",   metavar="PATH", help="File with one URL per line")
    parser.add_argument("--no-active", dest="skip_active", action="store_true",
                        help="Skip active path probing")
    parser.add_argument("--json", dest="use_json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    if args.target:
        targets = [normalise_url(args.target)]
    else:
        try:
            targets = [normalise_url(u) for u in load_targets(args.file)]
        except FileNotFoundError:
            print(f"error: {args.file} not found", file=sys.stderr)
            sys.exit(1)

    if not targets:
        print("No targets found.", file=sys.stderr)
        sys.exit(1)

    for url in targets:
        result = scan(url, skip_active=args.skip_active)
        print_scan_result(result, use_json=args.use_json)


if __name__ == "__main__":
    main()
