"""
checks/active.py -- Active probes: open redirects, common sensitive paths.
"""

import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urljoin


# Paths commonly exposed by misconfigured servers
_SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/wp-config.php",
    "/config.php",
    "/admin/",
    "/phpmyadmin/",
    "/.htaccess",
    "/server-status",
    "/api/v1/",
    "/swagger.json",
    "/openapi.json",
    "/actuator/",
    "/debug/",
]


@dataclass
class ActiveResult:
    base_url:       str
    exposed_paths:  List[str]              = field(default_factory=list)
    redirect_issues: List[Tuple[str, str]] = field(default_factory=list)
    errors:         List[str]              = field(default_factory=list)


def _probe_path(base: str, path: str, timeout: int) -> bool:
    """Return True if the path exists (HTTP 200)."""
    url = urljoin(base, path)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "webrecon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False
    except Exception:  # noqa: BLE001
        return False


def run(url: str, timeout: int = 8) -> ActiveResult:
    """Probe for exposed sensitive paths."""
    result = ActiveResult(base_url=url)
    for path in _SENSITIVE_PATHS:
        try:
            if _probe_path(url, path, timeout):
                result.exposed_paths.append(urljoin(url, path))
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{path}: {exc}")
    return result
