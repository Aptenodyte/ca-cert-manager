"""certifi bundle as used by Python requests. Sandbox: $ROOTWATCH_ROOT/certifi/cacert.pem."""
from __future__ import annotations

from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class RequestsStore(TrustStore):
    id = "requests"
    display_name = "Python requests (certifi bundle)"
    icon = "🐍"

    def bundle_path(self) -> Path:
        if self.real:
            import certifi
            return Path(certifi.where())
        return sandbox_root() / "certifi" / "cacert.pem"

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
                                   f"compromised CA in certifi bundle: {info.subject}", info.fingerprint))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        certs = self._certs()
        kept, actions = _bundle.remove_matching(certs, scenario, mode)
        _bundle.write_bundle(self.bundle_path(), kept)
        actions = [f"store file: {self.bundle_path()} (roots {len(certs)} -> {len(kept)})",
                   _bundle.mode_header(mode)] + actions
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        return self.bundle_path()
