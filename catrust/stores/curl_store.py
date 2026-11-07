"""curl's CA bundle (Person A). In sandbox mode curl is pointed at our bundle via --cacert."""
from __future__ import annotations

from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class CurlStore(TrustStore):
    id = "curl"
    display_name = "curl (CA bundle)"
    icon = "🌐"

    def store_path(self) -> Path:
        if self.real:
            return Path("/etc/ssl/certs")
        return sandbox_root() / "curl"

    def assess(self) -> StoreAssessment:
        raise NotImplementedError

    def audit(self, scenario: Scenario) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        raise NotImplementedError

    def cafile(self) -> Path | None:
        if self.real:
            return None
        return sandbox_root() / "curl" / "ca-bundle.crt"
