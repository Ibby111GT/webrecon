"""
checks/tls.py -- Inspect TLS certificate metadata for a host.
"""

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class TLSResult:
    host:          str
    port:          int             = 443
    valid:         bool            = False
    subject:       Optional[str]   = None
    issuer:        Optional[str]   = None
    expires:       Optional[str]   = None
    days_left:     Optional[int]   = None
    protocol:      Optional[str]   = None
    cipher:        Optional[str]   = None
    san:           List[str]       = field(default_factory=list)
    warnings:      List[str]       = field(default_factory=list)
    errors:        List[str]       = field(default_factory=list)


def _fmt_dn(dn_tuples) -> str:
    return ", ".join(f"{k}={v}" for rdn in dn_tuples for k, v in rdn)


def run(host: str, port: int = 443, timeout: int = 10) -> TLSResult:
    """Connect to host:port and pull TLS certificate details."""
    result = TLSResult(host=host, port=port)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result.valid    = True
                result.protocol = ssock.version()
                result.cipher   = ssock.cipher()[0]
                result.subject  = _fmt_dn(cert.get("subject", []))
                result.issuer   = _fmt_dn(cert.get("issuer", []))
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    result.expires   = exp.strftime("%Y-%m-%d")
                    result.days_left = (exp - datetime.now(timezone.utc)).days
                    if result.days_left < 30:
                        result.warnings.append(
                            f"certificate expires in {result.days_left} days"
                        )
                sans = cert.get("subjectAltName", [])
                result.san = [v for _, v in sans]
    except ssl.SSLCertVerificationError as exc:
        result.errors.append(f"cert verification failed: {exc}")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.errors.append(str(exc))
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"unexpected: {exc}")
    return result
