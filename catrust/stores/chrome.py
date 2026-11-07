"""Chrome CRLSet store (Person A).

Chrome's CRLSet is a binary blob (length-prefixed blocks). We implement a minimal
parser to check whether the revoked serial is present, and remediate by writing an
updated set / enterprise-policy block. Sandbox keeps a local crlset.bin mirror.
"""
from __future__ import annotations

from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class ChromeStore(TrustStore):
    id = "chrome"
    display_name = "Chrome (CRLSet)"
    icon = "🧭"

    def store_path(self) -> Path:
        if self.real:
            return Path.home() / ".config" / "google-chrome"
        return sandbox_root() / "chrome"

    def crlset_path(self) -> Path:
        return self.store_path() / "crlset.bin"

    def assess(self) -> StoreAssessment:
        raise NotImplementedError

    def audit(self, scenario: Scenario) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        raise NotImplementedError

    def cafile(self) -> Path | None:
        return None


def parse_crlset(data: bytes) -> list[int]:
    """Minimal CRLSet parser: return list of revoked serial numbers (ints)."""
    raise NotImplementedError
