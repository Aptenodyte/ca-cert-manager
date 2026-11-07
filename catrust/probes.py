"""Handshake probes: physically prove whether a client rejects the revoked cert.

Clients:
  requests      — plain requests.get(verify=cafile): NO revocation checking (default)
  requests-crl  — TLS with VERIFY_CRL_CHECK_LEAF + CRL loaded: rejects revoked cert
  curl          — curl --cacert <cafile>: NO revocation checking (default)
  openssl-crl   — openssl s_client -crl_check -CRLfile <crl>: rejects revoked cert
"""
from __future__ import annotations

import http.client
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProbeResult:
    client: str                 # "requests" | "requests-crl" | "curl" | "openssl-crl"
    url: str
    success: bool               # True = handshake ACCEPTED the cert (attack works)
    verify_error: str = ""      # TLS verify error if rejected
    detail: str = ""
    crl_checked: bool = False
    elapsed_ms: int = 0


def _host_port(url: str) -> tuple[str, int, str]:
    from urllib.parse import urlparse
    u = urlparse(url)
    return u.hostname or "127.0.0.1", u.port or 443, u.path or "/"


def _requests_probe(url: str, cafile: str | None, crl_pem: str | None) -> ProbeResult:
    import requests
    t0 = time.perf_counter()
    try:
        r = requests.get(url, verify=cafile or True, timeout=5)
        return ProbeResult("requests", url, success=True,
                           detail=f"HTTP {r.status_code}", elapsed_ms=int((time.perf_counter()-t0)*1000))
    except requests.exceptions.SSLError as e:
        return ProbeResult("requests", url, success=False, verify_error=str(e).split("\n")[0],
                           elapsed_ms=int((time.perf_counter()-t0)*1000))
    except Exception as e:
        return ProbeResult("requests", url, success=False, verify_error=f"{type(e).__name__}: {e}",
                           elapsed_ms=int((time.perf_counter()-t0)*1000))


def _requests_crl_probe(url: str, cafile: str | None, crl_pem: str | None) -> ProbeResult:
    """TLS with CRL checking enabled (VERIFY_CRL_CHECK_LEAF + CRL in the store)."""
    t0 = time.perf_counter()
    host, port, path = _host_port(url)
    try:
        ctx = ssl.create_default_context(cafile=cafile)
        if crl_pem:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(crl_pem)
                crlfile = f.name
            ctx.load_verify_locations(cafile=crlfile)  # OpenSSL loads CRLs from PEM too
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return ProbeResult("requests-crl", url, success=True, detail=f"HTTP {resp.status}",
                           crl_checked=True, elapsed_ms=int((time.perf_counter()-t0)*1000))
    except ssl.SSLCertVerificationError as e:
        return ProbeResult("requests-crl", url, success=False, verify_error=str(e),
                           crl_checked=True, elapsed_ms=int((time.perf_counter()-t0)*1000))
    except Exception as e:
        return ProbeResult("requests-crl", url, success=False,
                           verify_error=f"{type(e).__name__}: {e}", crl_checked=True,
                           elapsed_ms=int((time.perf_counter()-t0)*1000))


def _curl_probe(url: str, cafile: str | None, crl_pem: str | None) -> ProbeResult:
    t0 = time.perf_counter()
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}"]
    if cafile:
        cmd += ["--cacert", cafile]
    cmd += [url]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    ms = int((time.perf_counter()-t0)*1000)
    if r.returncode == 0:
        return ProbeResult("curl", url, success=True, detail=f"HTTP {r.stdout.strip()}", elapsed_ms=ms)
    return ProbeResult("curl", url, success=False,
                       verify_error=(r.stderr.strip().splitlines() or ["curl error"])[-1], elapsed_ms=ms)


def _openssl_crl_probe(url: str, cafile: str | None, crl_pem: str | None) -> ProbeResult:
    t0 = time.perf_counter()
    host, port, _ = _host_port(url)
    # this OpenSSL build has no -CRLfile: CRLs are loaded from the -CAfile PEM bundle
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        if cafile:
            f.write(Path(cafile).read_text())
        if crl_pem:
            f.write(crl_pem)
        bundle = f.name
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-CAfile", bundle,
           "-crl_check", "-brief"]
    r = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=10)
    ms = int((time.perf_counter()-t0)*1000)
    out = r.stdout + r.stderr
    err_line = next((l.strip() for l in out.splitlines()
                     if "verify error" in l.lower() or "verification error" in l.lower()), "")
    if "Verification: OK" in out and not err_line:
        return ProbeResult("openssl-crl", url, success=True, detail="Verification: OK",
                           crl_checked=True, elapsed_ms=ms)
    return ProbeResult("openssl-crl", url, success=False,
                       verify_error=err_line or out.strip().splitlines()[-1],
                       crl_checked=True, elapsed_ms=ms)


def run_probe(client: str, url: str, cafile: str | None = None,
              crl_pem: str | None = None, timeout: float = 5.0) -> ProbeResult:
    if client == "requests":
        return _requests_probe(url, cafile, None)
    if client == "requests-crl":
        return _requests_crl_probe(url, cafile, crl_pem)
    if client == "curl":
        return _curl_probe(url, cafile, None)
    if client == "openssl-crl":
        return _openssl_crl_probe(url, cafile, crl_pem)
    raise ValueError(f"unknown client: {client}")


def probe_all(url: str, cafile: str | None = None, crl_pem: str | None = None) -> list[ProbeResult]:
    """Run the full probe matrix against url."""
    return [
        run_probe("requests", url, cafile=cafile),
        run_probe("requests-crl", url, cafile=cafile, crl_pem=crl_pem),
        run_probe("curl", url, cafile=cafile),
        run_probe("openssl-crl", url, cafile=cafile, crl_pem=crl_pem),
    ]
