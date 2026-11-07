"""Shared contract for all trust stores. Both workstreams build against this.

A TrustStore is one fragmented place where CA roots are trusted on a machine:
system bundle, Firefox NSS (OneCRL semantics), Chrome CRLSet, certifi (requests),
curl's bundle, etc.

All paths resolve under CATRUST_ROOT (sandbox) unless real=True.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


def sandbox_root() -> Path:
    """Root of the sandbox. Every store path lives under here unless real mode."""
    return Path(os.environ.get("CATRUST_ROOT", Path.cwd() / ".sandbox")).resolve()


# Known-bad root fingerprints (sha256 of DER) — stand-in for OneCRL / CRLSet entries.
# eMudhra-style incidents get added here (or via a scenario) by the tool.
KNOWN_BAD_FPS: set[str] = set()


@dataclass
class RootInfo:
    """One trusted root CA as seen inside a store."""
    subject: str                    # CN / DN
    fingerprint: str                # sha256 hex of cert DER
    spki_hash: str                  # sha256 hex of SubjectPublicKeyInfo
    not_after: str                  # ISO date
    sig_alg: str                    # e.g. sha256WithRSAEncryption
    flags: list[str] = field(default_factory=list)  # "expired", "sha1", "known-bad", ...


@dataclass
class StoreAssessment:
    """System-wide posture of one trust store (the DEFAULT dashboard view)."""
    store_id: str
    display_name: str
    icon: str
    total_roots: int = 0
    roots: list[RootInfo] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)  # human-readable flags


@dataclass
class BlocklistEntry:
    """One untrusted cert/root at the APPLICATION level, fed by CRLs / OneCRL / CRLSet.

    Shown in the dashboard's blocklist panel. `serial` = revoked leaf serial (hex),
    `spki_hash` = blocked key hash (sha256 hex, OneCRL-style), `source` = where the
    revocation came from ("CRL", "OneCRL", "CRLSet", ...).
    """
    serial: str = ""
    spki_hash: str = ""
    subject: str = ""
    issuer: str = ""
    revoked_at: str = ""
    source: str = "CRL"
    reason: str = ""


@dataclass
class Scenario:
    """A compromised-CA incident scenario (e.g. eMudhra)."""
    name: str                       # e.g. "emudhra-2026"
    compromised_root_fingerprint: str   # sha256 hex of the root DER
    revoked_serial: str             # hex serial of the revoked leaf cert
    revoked_subject_cn: str         # e.g. "localhost"
    narrative: str = ""
    root_cert_pem: str = ""         # PEM of compromised root (populated at runtime)
    crl_pem: str = ""               # PEM CRL issued by the intermediate (runtime)
    # SPKI (SubjectPublicKeyInfo) sha256 hex hashes of the COMPROMISED KEYS
    # (root and/or intermediate). Surgical distrust targets these, not the CA name.
    compromised_spki_hashes: list[str] = field(default_factory=list)
    leaf_spki_hash: str = ""        # sha256 hex of the leaf's SPKI


class RemediationMode(str, Enum):
    """How aggressively to distrust.
    spki  = surgical: block the compromised keys' SPKI hashes only (OneCRL-style);
            other certs from that CA and future key rotations keep working.
    root  = nuclear: remove/distrust the entire root CA (Mozilla's eMudhra move);
            everything the CA ever signed stops verifying.
    """
    SPKI = "spki"
    ROOT = "root"


@dataclass
class Finding:
    """One reason a store is considered compromised."""
    store_id: str
    kind: str                       # "root_trusted" | "serial_in_crlset" | "root_in_bundle"
    detail: str                     # human-readable, shown in the web UI
    fingerprint: str = ""


@dataclass
class RemediationResult:
    store_id: str
    success: bool
    actions: list[str] = field(default_factory=list)   # log lines, shown in the web UI
    error: str = ""


class TrustStore(ABC):
    """Interface every trust store implements."""

    id: str = "abstract"
    display_name: str = "Abstract store"
    icon: str = "🗄️"

    def __init__(self, real: bool = False):
        self.real = real

    @abstractmethod
    def store_path(self) -> Path:
        """Directory/file this store manages (sandbox-resolved unless real)."""

    @abstractmethod
    def assess(self) -> StoreAssessment:
        """System-wide posture: enumerate every trusted root in this store.

        This is the DEFAULT dashboard view — not tied to any incident. Flags roots
        that are expired, sha1-signed, or on the known-bad list (see KNOWN_BAD_FPS).
        """

    @abstractmethod
    def audit(self, scenario: Scenario) -> list[Finding]:
        """Return findings if this store trusts the compromised root / revoked serial."""

    @abstractmethod
    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        """Distrust the compromised keys (spki mode) or the whole root (root mode).

        spki: block the SPKI hashes in scenario.compromised_spki_hashes where the
              store format supports it (Firefox OneCRL, Chrome CRLSet); for bundle
              stores (system/certifi/curl) remove only certs whose SPKI matches.
        root: remove the root from the store entirely.
        """

    @abstractmethod
    def cafile(self) -> Path | None:
        """CA bundle file to use for TLS verification against this store, if any."""
