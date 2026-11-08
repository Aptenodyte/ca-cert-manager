"""Shared helpers for PEM-bundle trust stores (system / certifi / curl). Person A."""
from __future__ import annotations

import datetime
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .base import KNOWN_BAD_FPS, RootInfo

PEM_CERT_RE = None  # split handled by cryptography loader below


def _known_bad_from_disk() -> set[str]:
    """Known-bad root fingerprints persisted in the sandbox (survives across processes)."""
    import json
    try:
        from .base import sandbox_root
        f = sandbox_root() / "known_bad.json"
        return set(json.loads(f.read_text())) if f.exists() else set()
    except Exception:
        return set()


def load_certs(path: Path) -> list[x509.Certificate]:
    """Load all certificates from a PEM bundle file (or all *.pem/*.crt in a dir)."""
    path = Path(path)
    if not path.exists():
        return []
    if path.is_dir():
        certs = []
        for f in sorted(path.iterdir()):
            if f.suffix in (".pem", ".crt", ".cer"):
                certs += load_certs(f)
        return certs
    data = path.read_bytes()
    certs = []
    for block in data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in block:
            pem = block + b"-----END CERTIFICATE-----\n"
            try:
                certs.append(x509.load_pem_x509_certificate(pem))
            except Exception:
                pass
    return certs


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def root_info(cert: x509.Certificate, extra_bad_fps: set[str] | None = None) -> RootInfo:
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    from ..pki import spki_hash
    flags = []
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_after_utc < now:
        flags.append("expired")
    if "sha1" in cert.signature_hash_algorithm.name.lower():
        flags.append("sha1")
    bad = set(KNOWN_BAD_FPS) | (extra_bad_fps or set()) | _known_bad_from_disk()
    if fp in bad:
        flags.append("known-bad")
    return RootInfo(
        subject=cert.subject.rfc4514_string(),
        fingerprint=fp,
        spki_hash=spki_hash(cert),
        not_after=cert.not_valid_after_utc.date().isoformat(),
        sig_alg=cert.signature_algorithm_oid._name or cert.signature_hash_algorithm.name,
        flags=flags,
    )


def write_bundle(path: Path, certs: list[x509.Certificate]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(cert_to_pem(c) for c in certs))


def remove_matching(certs: list[x509.Certificate], scenario, mode) -> tuple[list[x509.Certificate], list[str]]:
    """Return (kept certs, action log lines) after applying the remediation mode."""
    from .base import RemediationMode
    kept, actions = [], []
    bad_spkis = set(getattr(scenario, "compromised_spki_hashes", []) or [])
    bad_fp = getattr(scenario, "compromised_root_fingerprint", "")
    for c in certs:
        info = root_info(c)
        if mode == RemediationMode.ROOT and (info.fingerprint == bad_fp or info.spki_hash in bad_spkis):
            actions.append(f"removed root/chain {info.subject} (fp {info.fingerprint[:16]}…)")
            continue
        if mode == RemediationMode.SPKI and info.spki_hash in bad_spkis:
            actions.append(f"blocked SPKI {info.spki_hash[:16]}… ({info.subject})")
            continue
        kept.append(c)
    if not actions:
        actions.append("nothing matched — store already clean")
    return kept, actions
