"""System CA bundle store. Sandbox: $ROOTWATCH_ROOT/etc/ssl/certs (+ ca-bundle.crt)."""
from __future__ import annotations

from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root


class SystemStore(TrustStore):
    id = "system"
    display_name = "System CA bundle (/etc/ssl/certs)"
    icon = "🖥️"

    def store_path(self) -> Path:
        if self.real:
            return Path("/etc/ssl/certs")
        return sandbox_root() / "etc" / "ssl" / "certs"

    def bundle_path(self) -> Path:
        if self.real:
            return Path("/etc/ssl/certs/ca-certificates.crt")
        return sandbox_root() / "etc" / "ssl" / "ca-bundle.crt"

    def _certs(self):
        return _bundle.load_certs(self.bundle_path())

    def assess(self) -> StoreAssessment:
        certs = self._certs()
        roots = [_bundle.root_info(c) for c in certs]
        findings = [f"{r.subject} [{','.join(r.flags)}]" for r in roots if r.flags]
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        out = []
        for c in self._certs():
            info = _bundle.root_info(c)
            if info.fingerprint == scenario.compromised_root_fingerprint:
                out.append(Finding(self.id, "root_trusted",
                                   f"compromised root present: {info.subject}", info.fingerprint))
            if info.spki_hash in (scenario.compromised_spki_hashes or []):
                out.append(Finding(self.id, "spki_trusted",
                                   f"compromised SPKI present: {info.subject}", info.fingerprint))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        certs = self._certs()
        kept, actions = _bundle.remove_matching(certs, scenario, mode)
        _bundle.write_bundle(self.bundle_path(), kept)
        # keep the hashed dir in sync (sandbox)
        d = self.store_path()
        if not self.real and d.exists():
            for f in d.iterdir():
                if f.suffix in (".pem", ".crt"):
                    try:
                        c = _bundle.load_certs(f)[0]
                        if c not in kept:
                            f.unlink()
                    except Exception:
                        pass
            kept_set = {_bundle.cert_to_pem(c) for c in kept}
            for c in kept:
                fp = _bundle.root_info(c).fingerprint[:8]
                (d / f"{fp}.pem").write_text(_bundle.cert_to_pem(c))
        actions = [f"store file: {self.bundle_path()} (roots {len(certs)} -> {len(kept)}), "
                   f"hashed dir {self.store_path()} synced",
                   _bundle.mode_header(mode)] + actions
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        if self.real:
            return None
        return self.bundle_path()
