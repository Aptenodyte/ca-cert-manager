"""Docker per-registry CA store: /etc/docker/certs.d/<registry>/ca.crt.

Docker trusts each registry's CA ONLY via these files (plus the system store for
HTTPS verification of the registry cert chain). Sandbox mirror: docker/certs.d/
with the same <registry>/ca.crt layout. Docker has no SPKI/blocklist mechanism —
both remediation modes remove the compromised CA file for the affected registry.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root

REAL_CERTS_D = Path("/etc/docker/certs.d")


class DockerCertsStore(TrustStore):
    id = "docker"
    display_name = "Docker registry CAs (certs.d)"
    icon = "🐳"

    def store_path(self) -> Path:
        return REAL_CERTS_D if self.real else sandbox_root() / "docker" / "certs.d"

    def _registry_ca_files(self) -> list[Path]:
        d = self.store_path()
        if not d.exists():
            return []
        return sorted(p for reg in sorted(d.iterdir()) if reg.is_dir()
                      for p in reg.glob("*.crt"))

    def assess(self) -> StoreAssessment:
        roots, findings = [], []
        for f in self._registry_ca_files():
            for c in _bundle.load_certs(f):
                info = _bundle.root_info(c)
                if info.flags:
                    findings.append(f"{f.parent.name}: {info.subject} [{','.join(info.flags)}]")
                roots.append(info)
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        out = []
        for f in self._registry_ca_files():
            for c in _bundle.load_certs(f):
                info = _bundle.root_info(c)
                if info.fingerprint == scenario.compromised_root_fingerprint:
                    out.append(Finding(self.id, "root_trusted",
                                       f"compromised root in certs.d/{f.parent.name}/ca.crt: {info.subject}",
                                       info.fingerprint))
                if info.spki_hash in (scenario.compromised_spki_hashes or []):
                    out.append(Finding(self.id, "spki_trusted",
                                       f"compromised SPKI in certs.d/{f.parent.name}/ca.crt: {info.subject}",
                                       info.fingerprint))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        actions = [_bundle.mode_header(mode),
                   "note: certs.d has no SPKI mechanism — both modes remove the compromised CA file"]
        bad_spkis = set(scenario.compromised_spki_hashes or [])
        removed = 0
        for f in self._registry_ca_files():
            certs = _bundle.load_certs(f)
            if not any(_bundle.root_info(c).fingerprint == scenario.compromised_root_fingerprint
                       or _bundle.root_info(c).spki_hash in bad_spkis for c in certs):
                continue
            dest = f.with_suffix(".crt.distrusted")
            f.rename(dest)
            removed += 1
            actions.append(f"distrusted certs.d/{f.parent.name}/ca.crt -> {dest.name}")
        if not removed:
            actions.append("nothing to do — no registry trusts the compromised root")
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        files = self._registry_ca_files()
        return files[0] if files else None
