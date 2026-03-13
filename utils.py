"""
utils.py -- Shared helpers for webrecon.
"""

import json
import sys
from typing import List
from urllib.parse import urlparse


_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"

_SEV_COLOUR = {
    "HIGH":   _RED,
    "MEDIUM": _YELLOW,
    "LOW":    _CYAN,
    "OK":     _GREEN,
}


def normalise_url(raw: str) -> str:
    """Ensure the URL has a scheme; default to https."""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    return parsed.geturl()


def load_targets(path: str) -> List[str]:
    """Read one URL per line from a file, skipping blanks and comments."""
    with open(path) as fh:
        return [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]


def print_scan_result(result, use_json: bool = False) -> None:
    from models import ScanResult  # local import to avoid circular
    if use_json:
        out = {
            "target":   result.target,
            "severity": result.severity,
        }
        if result.headers:
            out["headers"] = {
                "score":   result.headers.score,
                "missing": result.headers.missing,
                "leaking": list(result.headers.leaking.keys()),
            }
        if result.tls:
            out["tls"] = {
                "valid":     result.tls.valid,
                "expires":   result.tls.expires,
                "days_left": result.tls.days_left,
                "warnings":  result.tls.warnings,
            }
        if result.active:
            out["active"] = {"exposed": result.active.exposed_paths}
        print(json.dumps(out))
        return

    sev = result.severity
    c   = _SEV_COLOUR.get(sev, "")
    print(f"{_BOLD}{result.target}{_RESET}  [{c}{sev}{_RESET}]")
    if result.headers:
        score = result.headers.score
        print(f"  Headers  : score {score}/100")
        if result.headers.missing:
            print(f"    missing  : {', '.join(result.headers.missing)}")
        if result.headers.leaking:
            print(f"    leaking  : {', '.join(result.headers.leaking.keys())}")
    if result.tls:
        status = "OK" if result.tls.valid else "INVALID"
        print(f"  TLS      : {status}  expires {result.tls.expires}  ({result.tls.days_left}d)")
        for w in result.tls.warnings:
            print(f"    warning  : {w}")
    if result.active and result.active.exposed_paths:
        print(f"  Exposed  :")
        for p in result.active.exposed_paths:
            print(f"    {p}")
    print()
