"""curl's CA bundle. Sandbox: $CATRUST_ROOT/curl/ca-bundle.crt (probes pass --cacert)."""
from __future__ import annotations

from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class CurlStore(TrustStore):
    id = "curl"
    display_name = "curl (CA bundle)"
    icon = "🌐"

    def bundle_path(self) -> Path:
        if self.real:
            return Path("/etc/ssl/certs/ca-certificates.crt")
        return sandbox_root() / "curl" / "ca-bundle.crt"

    def store_path(self) -> Path:
        return self.bundle_path().parent

    def _certs(self):
        return _bundle.load_certs(self.bundle_path())

    def assess(self) -> StoreAssessment:
        roots = [_bundle.root_info(c) for c in self._certs()]
        findings = [f"{r.subject} [{','.join(r.flags)}]" for r in roots if r.flags]
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        out = []
        for c in self._certs():
            info = _bundle.root_info(c)
            if info.fingerprint == scenario.compromised_root_fingerprint or \
               info.spki_hash in (scenario.compromised_spki_hashes or []):
                out.append(Finding(self.id, "root_in_bundle",
                                   f"compromised CA in curl bundle: {info.subject}", info.fingerprint))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        kept, actions = _bundle.remove_matching(self._certs(), scenario, mode)
        _bundle.write_bundle(self.bundle_path(), kept)
        return RemediationResult(self.id, success=True, actions=[f"mode={mode.value}"] + actions)

    def cafile(self) -> Path | None:
        if self.real:
            return None
        return self.bundle_path()
