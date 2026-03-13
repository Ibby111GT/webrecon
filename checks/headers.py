"""
checks/headers.py -- Inspect HTTP security headers.
"""

import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List


# Headers that should be present on a well-hardened site
_REQUIRED = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that reveal server internals and should ideally be absent
_LEAKY = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


@dataclass
class HeaderResult:
    url:      str
    present:  Dict[str, str]       = field(default_factory=dict)
    missing:  List[str]            = field(default_factory=list)
    leaking:  Dict[str, str]       = field(default_factory=dict)
    errors:   List[str]            = field(default_factory=list)

    @property
    def score(self) -> int:
        """Simple 0-100 score: starts at 100, -10 per missing required header."""
        return max(0, 100 - len(self.missing) * 10)


def run(url: str, timeout: int = 10) -> HeaderResult:
    """Fetch the URL and inspect its HTTP response headers."""
    result = HeaderResult(url=url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "webrecon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            for h in _REQUIRED:
                val = hdrs.get(h.lower())
                if val:
                    result.present[h] = val
                else:
                    result.missing.append(h)
            for h in _LEAKY:
                val = hdrs.get(h.lower())
                if val:
                    result.leaking[h] = val
    except urllib.error.URLError as exc:
        result.errors.append(str(exc))
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"unexpected: {exc}")
    return result
