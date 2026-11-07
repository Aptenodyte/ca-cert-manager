"""Firefox NSS store + OneCRL semantics (Person A).

Sandbox: a fake profile dir with cert9.db managed via certutil (if available) or a
PEM/JSON mirror when certutil is absent. Real: ~/.mozilla/firefox/*/cert9.db.
OneCRL is Mozilla's remotely-updated blocklist; we model distrust entries in a local
onecrl.json mirror and (when real) note the submission path.
"""
from __future__ import annotations

from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class FirefoxStore(TrustStore):
    id = "firefox"
    display_name = "Firefox (NSS cert9.db / OneCRL)"
    icon = "🦊"

    def store_path(self) -> Path:
        if self.real:
            return Path.home() / ".mozilla" / "firefox"
        return sandbox_root() / "mozilla" / "firefox"

    def assess(self) -> StoreAssessment:
        raise NotImplementedError

    def audit(self, scenario: Scenario) -> list[Finding]:
        raise NotImplementedError

    def remediate(self, scenario: Scenario, mode: "RemediationMode" = RemediationMode.SPKI) -> RemediationResult:
        raise NotImplementedError

    def cafile(self) -> Path | None:
        return None  # NSS is a DB, not a bundle; probes use extracted PEM
