"""System CA bundle store (Person A). Sandboxed dir mimics /etc/ssl/certs."""
from __future__ import annotations

from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class SystemStore(TrustStore):
    id = "system"
    display_name = "System CA bundle (/etc/ssl/certs)"
    icon = "🖥️"

    def store_path(self) -> Path:
        if self.real:
            return Path("/etc/ssl/certs")
        return sandbox_root() / "etc" / "ssl" / "certs"

    def assess(self) -> StoreAssessment:
        raise NotImplementedError

    def audit(self, scenario: Scenario) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        raise NotImplementedError

    def cafile(self) -> Path | None:
        # Sandbox: concatenated bundle; real: system default
        if self.real:
            return None
        return sandbox_root() / "etc" / "ssl" / "ca-bundle.crt"
