"""
checks/ -- individual web-security check modules.

Each module exposes a run(url, timeout) function that returns a CheckResult.
"""

from .headers import run as check_headers
from .tls     import run as check_tls
from .active  import run as check_active

__all__ = [
    "check_headers",
    "check_tls",
    "check_active",
]
