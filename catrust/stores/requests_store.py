"""certifi bundle as used by Python requests (Person A)."""
from __future__ import annotations

from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class RequestsStore(TrustStore):
    id = "requests"
    display_name = "Python requests (certifi bundle)"
    icon = "🐍"

    def store_path(self) -> Path:
        if self.real:
            import certifi
            return Path(certifi.where()).parent
        return sandbox_root() / "certifi"

    def assess(self) -> StoreAssessment:
        raise NotImplementedError

    def audit(self, scenario: Scenario) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        raise NotImplementedError

    def cafile(self) -> Path | None:
        if self.real:
            import certifi
            return Path(certifi.where())
        return sandbox_root() / "certifi" / "cacert.pem"
