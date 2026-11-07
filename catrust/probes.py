"""Handshake probes: physically prove whether a client rejects the revoked cert.

Contract (implemented by Person A):
- ProbeResult dataclass with: client, url, success, verify_error, detail, crl_checked
- run_probe(client, url, cafile=None, crl_pem=None, timeout=5) -> ProbeResult
  client in {"requests", "requests-crl", "curl", "openssl-crl"}
- probe_all(url, cafile=None, crl_pem=None) -> list[ProbeResult]
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    client: str                 # "requests" | "requests-crl" | "curl" | "openssl-crl"
    url: str
    success: bool               # True = handshake ACCEPTED the cert (attack works)
    verify_error: str = ""      # TLS verify error if rejected
    detail: str = ""
    crl_checked: bool = False
    elapsed_ms: int = 0


def run_probe(client: str, url: str, cafile: str | None = None,
              crl_pem: str | None = None, timeout: float = 5.0) -> ProbeResult:
    """Run one handshake probe. Implemented by Person A."""
    raise NotImplementedError


def probe_all(url: str, cafile: str | None = None, crl_pem: str | None = None) -> list[ProbeResult]:
    """Run the full probe matrix against url."""
    return [
        run_probe("requests", url, cafile=cafile, crl_pem=None),
        run_probe("requests-crl", url, cafile=cafile, crl_pem=crl_pem),
        run_probe("curl", url, cafile=cafile),
        run_probe("openssl-crl", url, cafile=cafile, crl_pem=crl_pem),
    ]
