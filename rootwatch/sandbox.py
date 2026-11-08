"""Sandbox setup: copy the machine's REAL trust stores into the sandbox (read-only
on the real ones), build the mock PKI, and plant the compromised root on top —
so the dashboard shows the real ~150 roots plus the eMudhra one.
Person A owns this file.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from cryptography import x509

from . import pki as pki_mod
from .stores import _bundle, sandbox_root
from .stores.base import KNOWN_BAD_FPS

REAL_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",     # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",        # RHEL/Fedora
    "/etc/ssl/cert.pem",                       # Alpine/macOS-ish
]


def _real_system_bundle() -> str:
    for c in REAL_BUNDLE_CANDIDATES:
        p = Path(c)
        if p.exists() and p.stat().st_size > 1000:
            return p.read_text()
    # fallback: concatenate the hashed cert dir
    d = Path("/etc/ssl/certs")
    if d.exists():
        return "".join(f.read_text() for f in sorted(d.glob("*.pem")) if f.is_file() and not f.is_symlink())
    return ""


def _real_certifi_bundle() -> str:
    try:
        import certifi
        return Path(certifi.where()).read_text()
    except Exception:
        return ""


def _real_firefox_roots() -> list[dict]:
    """Export trusted roots from real Firefox NSS profiles via certutil, if present."""
    base = Path.home() / ".mozilla" / "firefox"
    if not (base.exists() and shutil.which("certutil")):
        return []
    out = []
    for prof in sorted(p for p in base.iterdir() if p.is_dir() and (p / "cert9.db").exists()):
        r = subprocess.run(["certutil", "-L", "-d", f"sql:{prof}"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if not line.strip() or line.startswith("Certificate Nickname"):
                continue
            nick = line.split()[0]
            if not line.rstrip().endswith(("CT,C,C", "C,C,C", "CT,C,C")):
                pass  # include all listed; trust flags vary
            e = subprocess.run(["certutil", "-L", "-d", f"sql:{prof}", "-n", nick, "-a"],
                               capture_output=True, text=True)
            if "BEGIN CERTIFICATE" not in e.stdout:
                continue
            try:
                cert = x509.load_pem_x509_certificate(e.stdout.encode())
            except Exception:
                continue
            info = _bundle.root_info(cert)
            out.append({"subject": info.subject, "fingerprint": info.fingerprint,
                        "spki_hash": info.spki_hash, "not_after": info.not_after,
                        "sig_alg": info.sig_alg, "flags": info.flags,
                        "source": f"firefox:{prof.name}"})
    return out


def _certs_json_from_pem(pem: str) -> list[dict]:
    out = []
    for c in _bundle.load_certs(_pem_bytes(pem)):
        info = _bundle.root_info(c)
        out.append({"subject": info.subject, "fingerprint": info.fingerprint,
                    "spki_hash": info.spki_hash, "not_after": info.not_after,
                    "sig_alg": info.sig_alg, "flags": info.flags, "source": "bundle"})
    return out


def setup_sandbox(root: Path | None = None, use_real: bool = True) -> Path:
    """Create the sandbox tree: pki/ + every store seeded from the machine's REAL
    trust stores (copied, never modified) plus the compromised eMudhra root.
    Returns the sandbox root."""
    root = Path(root) if root else sandbox_root()
    pki_dir = root / "pki"
    p = pki_mod.build_pki(pki_dir)
    pki_mod.revoke_leaf(p, pki_dir)

    KNOWN_BAD_FPS.add(p.root_fingerprint)
    (root / "known_bad.json").write_text(json.dumps([p.root_fingerprint]))

    compromised_pem = p.root_cert_pem + p.inter_cert_pem
    real_sys = _real_system_bundle() if use_real else ""
    real_certifi = _real_certifi_bundle() if use_real else ""
    if use_real and not real_sys and not real_certifi:
        raise RuntimeError(
            "no real trust stores found on this machine (looked for "
            f"{', '.join(REAL_BUNDLE_CANDIDATES)} and certifi's cacert.pem) — "
            "refusing to seed the sandbox with synthetic decoy roots")

    def bundle_pem(real: str) -> str:
        return real + compromised_pem

    # system bundle (+ hashed dir)
    sys_bundle = root / "etc" / "ssl" / "ca-bundle.crt"
    _bundle.write_bundle(sys_bundle, _bundle.load_certs(_pem_bytes(bundle_pem(real_sys))))
    sys_dir = root / "etc" / "ssl" / "certs"
    sys_dir.mkdir(parents=True, exist_ok=True)
    for c in _bundle.load_certs(sys_bundle):
        (sys_dir / f"{_bundle.root_info(c).fingerprint[:8]}.pem").write_text(_bundle.cert_to_pem(c))

    # certifi + curl bundles
    _bundle.write_bundle(root / "certifi" / "cacert.pem",
                         _bundle.load_certs(_pem_bytes(bundle_pem(real_certifi or real_sys))))
    _bundle.write_bundle(root / "curl" / "ca-bundle.crt",
                         _bundle.load_certs(_pem_bytes(bundle_pem(real_sys))))

    # firefox: real NSS export if possible, else system bundle as the mirror source
    ff_roots = _real_firefox_roots()
    if not ff_roots:
        ff_roots = _certs_json_from_pem(bundle_pem(real_sys))
    else:
        for c in _bundle.load_certs(_pem_bytes(compromised_pem)):
            info = _bundle.root_info(c)
            ff_roots.append({"subject": info.subject, "fingerprint": info.fingerprint,
                             "spki_hash": info.spki_hash, "not_after": info.not_after,
                             "sig_alg": info.sig_alg, "flags": info.flags, "source": "planted"})
    prof = root / "mozilla" / "firefox" / "demo.default-release"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "certs.json").write_text(json.dumps(ff_roots, indent=2))
    (prof / "onecrl.json").write_text("[]")

    # chrome: system roots (Chrome uses them on Linux) + empty synthetic CRLSet
    chrome = root / "chrome"
    chrome.mkdir(parents=True, exist_ok=True)
    chrome_roots = _certs_json_from_pem(bundle_pem(real_sys))
    (chrome / "trusted_roots.json").write_text(json.dumps(chrome_roots, indent=2))
    from .stores.chrome import build_crlset
    (chrome / "crlset.bin").write_bytes(build_crlset([]))

    (root / "blocklist.json").write_text("[]")
    (root / "scenario.runtime.json").write_text(json.dumps({
        "name": "emudhra-2026",
        "compromised_root_fingerprint": p.root_fingerprint,
        "revoked_serial": p.leaf_serial,
        "compromised_spki_hashes": [p.root_spki_hash, p.inter_spki_hash],
        "leaf_spki_hash": p.leaf_spki_hash,
        "revoked_subject_cn": "localhost",
        "crl_pem": p.crl_pem,
        "root_cert_pem": p.root_cert_pem,
        "seeded_from_real_stores": bool(real_sys or real_certifi),
    }, indent=2))
    return root


def _pem_bytes(s: str) -> Path:
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    f.write(s)
    f.close()
    return Path(f.name)
