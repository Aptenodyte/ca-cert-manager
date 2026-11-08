"""Java keystore (cacerts) trust store.

Sandbox: a JSON mirror — java/cacerts.json (trusted roots, keystore-style entries)
plus java/distrusted.json (SPKI-hash distrust list, OneCRL semantics; the JVM has no
native SPKI blocklist, but we model the policy layer). On real systems with keytool
available we also shell out to `keytool -delete` best-effort.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, RootInfo, Scenario, StoreAssessment, TrustStore, sandbox_root


def _real_cacerts_candidates() -> list[Path]:
    out = [Path("/etc/ssl/certs/java/cacerts")]
    jh = os.environ.get("JAVA_HOME")
    if jh:
        out.append(Path(jh) / "lib" / "security" / "cacerts")
    out.append(Path("/usr/lib/jvm/default-java/lib/security/cacerts"))
    return out


class JavaStore(TrustStore):
    id = "java"
    display_name = "Java keystore (cacerts)"
    icon = "☕"

    def keystore_path(self) -> Path:
        """Real mode: the actual JKS/PKCS12 cacerts file; sandbox mode: unused placeholder."""
        if self.real:
            for c in _real_cacerts_candidates():
                if c.exists():
                    return c
            return _real_cacerts_candidates()[0]
        return sandbox_root() / "java" / "cacerts.jks"

    def store_path(self) -> Path:
        if self.real:
            return self.keystore_path().parent
        return sandbox_root() / "java"

    def _certs_json(self) -> Path:
        # JSON mirror of the keystore's trusted certs (used in sandbox; in real mode
        # it's the auditable mirror kept next to the real keystore)
        return self.store_path() / "cacerts.json"

    def _distrusted_json(self) -> Path:
        return self.store_path() / "distrusted.json"

    def _load(self) -> tuple[list[dict], list[dict]]:
        cj, dj = self._certs_json(), self._distrusted_json()
        certs = json.loads(cj.read_text()) if cj.exists() else []
        distrusted = json.loads(dj.read_text()) if dj.exists() else []
        return certs, distrusted

    def _save(self, certs: list[dict], distrusted: list[dict]) -> None:
        self.store_path().mkdir(parents=True, exist_ok=True)
        self._certs_json().write_text(json.dumps(certs, indent=2))
        self._distrusted_json().write_text(json.dumps(distrusted, indent=2))

    def assess(self) -> StoreAssessment:
        certs, distrusted = self._load()
        blocked = {e["spki_hash"] for e in distrusted}
        roots, findings = [], []
        for c in certs:
            info = RootInfo(subject=c["subject"], fingerprint=c["fingerprint"],
                            spki_hash=c["spki_hash"], not_after=c.get("not_after", ""),
                            sig_alg=c.get("sig_alg", ""), flags=list(c.get("flags", [])))
            if info.spki_hash in blocked:
                info.flags.append("distrusted")
            if info.flags:
                findings.append(f"{info.subject} [{','.join(info.flags)}]")
            roots.append(info)
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        certs, distrusted = self._load()
        blocked = {e["spki_hash"] for e in distrusted}
        out = []
        for c in certs:
            if c["fingerprint"] == scenario.compromised_root_fingerprint and c["spki_hash"] not in blocked:
                out.append(Finding(self.id, "root_trusted",
                                   f"compromised root trusted in Java cacerts: {c['subject']}", c["fingerprint"]))
            if c["spki_hash"] in (scenario.compromised_spki_hashes or []) and c["spki_hash"] not in blocked:
                out.append(Finding(self.id, "spki_trusted",
                                   f"compromised SPKI trusted in Java cacerts: {c['subject']}", c["fingerprint"]))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        certs, distrusted = self._load()
        actions = [_bundle.mode_header(mode)]
        if mode == RemediationMode.ROOT:
            kept = []
            for c in certs:
                if c["fingerprint"] == scenario.compromised_root_fingerprint or \
                   c["spki_hash"] in (scenario.compromised_spki_hashes or []):
                    actions.append(f"deleted from keystore: {c['subject']} (fp {c['fingerprint'][:16]}…)")
                    distrusted.append({"spki_hash": c["spki_hash"], "subject": c["subject"],
                                       "source": "keystore-distrust", "reason": scenario.name})
                else:
                    kept.append(c)
            certs = kept
        else:
            for spki in scenario.compromised_spki_hashes or []:
                if not any(e["spki_hash"] == spki for e in distrusted):
                    subj = next((c["subject"] for c in certs if c["spki_hash"] == spki), "unknown")
                    distrusted.append({"spki_hash": spki, "subject": subj,
                                       "source": "spki-distrust", "reason": scenario.name})
                    actions.append(f"distrusted SPKI {spki[:16]}… in keystore policy ({subj})")
        # best-effort real keystore distrust when keytool + a real cacerts exist
        if self.real and shutil.which("keytool"):
            ks = self.keystore_path()
            if ks.exists():
                for e in distrusted:
                    subprocess.run(["keytool", "-delete", "-keystore", str(ks),
                                    "-storepass", "changeit", "-alias", e["subject"]],
                                   capture_output=True)
        self._save(certs, distrusted)
        if not actions[1:]:
            actions.append("nothing to do — already distrusted")
        actions.append(f"wrote {self._certs_json()} ({len(certs)} roots) + "
                       f"distrusted.json ({len(distrusted)} entries)")
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        return None  # keystore; probes reconstruct a CAfile from this store's roots
