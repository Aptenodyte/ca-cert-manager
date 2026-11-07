"""Mock PKI for the attack scenario (Person A implements).

Generates: root CA -> intermediate CA -> leaf cert for localhost, then REVOKES the
leaf and emits a CRL. Produces everything the server and stores need.

Contract:
- build_pki(outdir: Path) -> PKI
- PKI dataclass fields: root_cert_pem, root_key_pem, inter_cert_pem, inter_key_pem,
  leaf_cert_pem, leaf_key_pem, chain_pem (leaf+inter), crl_pem,
  root_fingerprint (sha256 hex of root DER), leaf_serial (hex)
- revoke_leaf(pki: PKI, outdir: Path) -> str  (regenerates CRL, returns crl_pem)
- load_scenario_pki(scenario_dir: Path) -> PKI  (reload from disk)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PKI:
    root_cert_pem: str = ""
    root_key_pem: str = ""
    inter_cert_pem: str = ""
    inter_key_pem: str = ""
    leaf_cert_pem: str = ""
    leaf_key_pem: str = ""
    chain_pem: str = ""
    crl_pem: str = ""
    root_fingerprint: str = ""
    leaf_serial: str = ""


def build_pki(outdir: Path, cn_root: str = "eMudhra Demo Root CA") -> PKI:
    """Create root+intermediate+leaf(localhost), write all PEMs under outdir."""
    raise NotImplementedError


def revoke_leaf(pki: PKI, outdir: Path) -> str:
    """Mark the leaf revoked on the intermediate and return the new CRL PEM."""
    raise NotImplementedError


def load_pki(pki_dir: Path) -> PKI:
    """Reload a PKI previously written by build_pki."""
    raise NotImplementedError
