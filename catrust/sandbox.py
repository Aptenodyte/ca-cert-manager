"""Sandbox setup: build the mock PKI and populate every store with the
compromised root (plus decoy roots), so the dashboard has something to find.
Person A owns this file.
"""
from __future__ import annotations

import json
from pathlib import Path

from cryptography import x509

from . import pki as pki_mod
from .stores import _bundle, sandbox_root
from .stores.base import KNOWN_BAD_FPS


def _decoy_root_pem(cn: str) -> str:
    """A throwaway legitimate-looking root for realism."""
    import datetime
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return _bundle.cert_to_pem(cert)


def setup_sandbox(root: Path | None = None) -> Path:
    """Create the sandbox tree: pki/ (root+inter+leaf+CRL), all stores seeded with
    the compromised root + decoys. Returns the sandbox root."""
    root = Path(root) if root else sandbox_root()
    pki_dir = root / "pki"
    p = pki_mod.build_pki(pki_dir)
    pki_mod.revoke_leaf(p, pki_dir)

    # mark the compromised root as known-bad (persisted so other processes see it too)
    KNOWN_BAD_FPS.add(p.root_fingerprint)
    (root / "known_bad.json").write_text(json.dumps([p.root_fingerprint]))

    decoys = [_decoy_root_pem("DigiDemo Root CA"), _decoy_root_pem("Example Trust Root 2026")]
    compromised_pem = p.root_cert_pem + p.inter_cert_pem

    # system bundle (+ hashed dir)
    sys_bundle = root / "etc" / "ssl" / "ca-bundle.crt"
    sys_dir = root / "etc" / "ssl" / "certs"
    _bundle.write_bundle(sys_bundle, _bundle.load_certs(_pem_bytes(compromised_pem + "".join(decoys))))
    sys_dir.mkdir(parents=True, exist_ok=True)
    for c in _bundle.load_certs(sys_bundle):
        info = _bundle.root_info(c)
        (sys_dir / f"{info.fingerprint[:8]}.pem").write_text(_bundle.cert_to_pem(c))

    # certifi + curl bundles
    _bundle.write_bundle(root / "certifi" / "cacert.pem",
                         _bundle.load_certs(_pem_bytes(compromised_pem + "".join(decoys))))
    _bundle.write_bundle(root / "curl" / "ca-bundle.crt",
                         _bundle.load_certs(_pem_bytes(compromised_pem + "".join(decoys))))

    # firefox profile: certs.json + empty onecrl.json
    prof = root / "mozilla" / "firefox" / "demo.default-release"
    prof.mkdir(parents=True, exist_ok=True)
    certs = []
    for c in _bundle.load_certs(_pem_bytes(compromised_pem + "".join(decoys))):
        info = _bundle.root_info(c)
        certs.append({"subject": info.subject, "fingerprint": info.fingerprint,
                      "spki_hash": info.spki_hash, "not_after": info.not_after,
                      "sig_alg": info.sig_alg, "flags": info.flags})
    (prof / "certs.json").write_text(json.dumps(certs, indent=2))
    (prof / "onecrl.json").write_text("[]")

    # chrome: trusted_roots.json + empty crlset.bin
    chrome = root / "chrome"
    chrome.mkdir(parents=True, exist_ok=True)
    (chrome / "trusted_roots.json").write_text(json.dumps(certs, indent=2))
    (chrome / "crlset.bin").write_bytes(__import__("catrust.stores.chrome", fromlist=["build_crlset"]).build_crlset([]))

    # runtime blocklist state (empty until Update CRL)
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
    }, indent=2))
    return root


def _pem_bytes(s: str) -> Path:
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    f.write(s)
    f.close()
    return Path(f.name)
