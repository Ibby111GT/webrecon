"""
models.py -- Shared result types for webrecon.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from checks.headers import HeaderResult
from checks.tls     import TLSResult
from checks.active  import ActiveResult


@dataclass
class ScanResult:
    """Aggregated result for a single target URL."""
    target:   str
    headers:  Optional[HeaderResult] = None
    tls:      Optional[TLSResult]    = None
    active:   Optional[ActiveResult] = None
    errors:   List[str]              = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        if self.headers and (self.headers.missing or self.headers.leaking):
            return True
        if self.tls and (not self.tls.valid or self.tls.warnings):
            return True
        if self.active and self.active.exposed_paths:
            return True
        return False

    @property
    def severity(self) -> str:
        """High / Medium / Low / OK based on findings."""
        if not self.has_issues:
            return "OK"
        issues = 0
        if self.headers:
            issues += len(self.headers.missing)
        if self.tls and not self.tls.valid:
            issues += 3
        if self.active:
            issues += len(self.active.exposed_paths) * 2
        if issues >= 6:
            return "HIGH"
        if issues >= 3:
            return "MEDIUM"
        return "LOW"
