"""Orchestration across stores. Contract used by both CLI (A) and web UI (B)."""
from __future__ import annotations

from .stores.base import (
    BlocklistEntry,
    Finding,
    RemediationMode,
    RemediationResult,
    Scenario,
    StoreAssessment,
    TrustStore,
)


def assess_all(stores: list[TrustStore]) -> dict[str, StoreAssessment]:
    """DEFAULT view: system-wide posture of every trust store (not incident-scoped).

    Returns {store_id: StoreAssessment} with every trusted root enumerated and
    flagged (expired / sha1 / known-bad). Used by GET /api/stores.
    """
    raise NotImplementedError


def collect_blocklist(crl_pems: list[str] | None = None,
                      extra_spki_hashes: list[str] | None = None) -> list[BlocklistEntry]:
    """Application-level untrusted list, fed by CRLs (parse revoked serials) plus any
    explicit SPKI hashes (OneCRL/CRLSet style). Used by GET /api/blocklist.
    """
    raise NotImplementedError


def update_crl(crl_pem: str | None = None, url: str | None = None) -> list[BlocklistEntry]:
    """'Update CRL' button backend: fetch/parse a CRL (PEM string or URL) and merge its
    revoked entries into the application-level blocklist. Returns the new full list.
    """
    raise NotImplementedError


def affected_stores(stores: list[TrustStore], blocklist: list[BlocklistEntry]) -> set[str]:
    """Store ids whose assessed roots/SPKIs intersect the blocklist."""
    raise NotImplementedError


def audit_all(stores: list[TrustStore], scenario: Scenario) -> dict[str, list[Finding]]:
    """Audit every store; returns {store_id: findings}. Empty list = clean."""
    raise NotImplementedError


def remediate_selected(stores: list[TrustStore], store_ids: list[str],
                       scenario: Scenario,
                       mode: RemediationMode = RemediationMode.SPKI) -> dict[str, RemediationResult]:
    """Remediate the given stores (all at once) in the given mode (spki=default, root)."""
    raise NotImplementedError


def load_scenario(path: str) -> Scenario:
    """Load a scenario YAML (fingerprint, serial, narrative) and attach runtime PEMs."""
    raise NotImplementedError
