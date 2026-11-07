"""Firefox NSS store + OneCRL semantics.

Sandbox: a fake profile dir with certs.json (trusted roots, NSS-style) and
onecrl.json (the OneCRL distrust list of SPKI hashes). On real systems with
certutil available we also shell out to `certutil -D/-M` best-effort.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, RootInfo, Scenario, StoreAssessment, TrustStore, sandbox_root


class FirefoxStore(TrustStore):
    id = "firefox"
    display_name = "Firefox (NSS cert9.db / OneCRL)"
    icon = "🦊"

    def profile_dir(self) -> Path:
        base = Path("/home") / ".mozilla" / "firefox" if self.real else sandbox_root() / "mozilla" / "firefox"
        profiles = sorted(p for p in base.iterdir() if p.is_dir()) if base.exists() else []
        if profiles:
            return profiles[0]
        return base / "demo.default-release"

    def store_path(self) -> Path:
        return self.profile_dir()

    def _certs_json(self) -> Path:
        return self.profile_dir() / "certs.json"

    def _onecrl(self) -> Path:
        return self.profile_dir() / "onecrl.json"

    def _load(self) -> tuple[list[dict], list[dict]]:
        cj, oj = self._certs_json(), self._onecrl()
        certs = json.loads(cj.read_text()) if cj.exists() else []
        onecrl = json.loads(oj.read_text()) if oj.exists() else []
        return certs, onecrl

    def _save(self, certs: list[dict], onecrl: list[dict]) -> None:
        self.profile_dir().mkdir(parents=True, exist_ok=True)
        self._certs_json().write_text(json.dumps(certs, indent=2))
        self._onecrl().write_text(json.dumps(onecrl, indent=2))

    def assess(self) -> StoreAssessment:
        certs, onecrl = self._load()
        blocked_spkis = {e["spki_hash"] for e in onecrl}
        roots, findings = [], []
        for c in certs:
            info = RootInfo(subject=c["subject"], fingerprint=c["fingerprint"],
                            spki_hash=c["spki_hash"], not_after=c.get("not_after", ""),
                            sig_alg=c.get("sig_alg", ""), flags=list(c.get("flags", [])))
            if info.spki_hash in blocked_spkis:
                info.flags.append("onecrl-distrusted")
            if info.flags:
                findings.append(f"{info.subject} [{','.join(info.flags)}]")
            roots.append(info)
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        certs, onecrl = self._load()
        blocked = {e["spki_hash"] for e in onecrl}
        out = []
        for c in certs:
            if c["fingerprint"] == scenario.compromised_root_fingerprint and c["spki_hash"] not in blocked:
                out.append(Finding(self.id, "root_trusted",
                                   f"compromised root trusted in NSS: {c['subject']}", c["fingerprint"]))
            if c["spki_hash"] in (scenario.compromised_spki_hashes or []) and c["spki_hash"] not in blocked:
                out.append(Finding(self.id, "spki_trusted",
                                   f"compromised SPKI trusted in NSS: {c['subject']}", c["fingerprint"]))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        certs, onecrl = self._load()
        actions = [f"mode={mode.value}"]
        if mode == RemediationMode.ROOT:
            kept = []
            for c in certs:
                if c["fingerprint"] == scenario.compromised_root_fingerprint or \
                   c["spki_hash"] in (scenario.compromised_spki_hashes or []):
                    actions.append(f"removed from NSS: {c['subject']} (fp {c['fingerprint'][:16]}…)")
                    onecrl.append({"spki_hash": c["spki_hash"], "subject": c["subject"],
                                   "source": "root-distrust", "reason": scenario.name})
                else:
                    kept.append(c)
            certs = kept
        else:
            for spki in scenario.compromised_spki_hashes or []:
                if not any(e["spki_hash"] == spki for e in onecrl):
                    subj = next((c["subject"] for c in certs if c["spki_hash"] == spki), "unknown")
                    onecrl.append({"spki_hash": spki, "subject": subj,
                                   "source": "OneCRL", "reason": scenario.name})
                    actions.append(f"added SPKI {spki[:16]}… to OneCRL distrust list ({subj})")
        # best-effort real NSS distrust when certutil exists
        if shutil.which("certutil"):
            for e in onecrl:
                subprocess.run(["certutil", "-D", "-d", f"sql:{self.profile_dir()}",
                                "-n", e["subject"]], capture_output=True)
        self._save(certs, onecrl)
        if not actions[1:]:
            actions.append("nothing to do — already distrusted")
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        return None  # NSS is a DB; probes use an extracted PEM if needed
