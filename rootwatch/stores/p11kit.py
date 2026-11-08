"""p11-kit / NSS shared trust store (p11-kit-trust module).

Used by GnuTLS apps, wget, and NSS-linked curl builds — a SECOND system-level store
that can diverge from /etc/ssl/certs. Real anchors live in /etc/pki/ca-trust/source/
anchors (RHEL) or /usr/share/p11-kit/anchors; Debian derives them from the system bundle.

Sandbox: p11kit/ca-bundle.pem (a real PEM bundle, usable directly as a probe CAfile)
plus p11kit/distrusted.json (SPKI distrust list). Real mode: edit the anchors dir
best-effort (move the compromised anchor's .pem aside) + keytool-style fallback N/A.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _bundle
from .base import Finding, RemediationMode, RemediationResult, Scenario, StoreAssessment, TrustStore, sandbox_root

REAL_ANCHOR_DIRS = [
    Path("/etc/pki/ca-trust/source/anchors"),
    Path("/usr/share/p11-kit/anchors"),
    Path("/usr/local/share/ca-certificates"),
]


class P11KitStore(TrustStore):
    id = "p11kit"
    display_name = "p11-kit / NSS shared trust"
    icon = "🧩"

    def store_path(self) -> Path:
        if self.real:
            for d in REAL_ANCHOR_DIRS:
                if d.exists():
                    return d
            return REAL_ANCHOR_DIRS[0]
        return sandbox_root() / "p11kit"

    def _bundle_file(self) -> Path:
        return self.store_path() / "ca-bundle.pem"

    def _distrusted_json(self) -> Path:
        return self.store_path() / "distrusted.json"

    def _load(self) -> tuple[list, list[dict]]:
        bf = self._bundle_file()
        certs = _bundle.load_certs(bf) if bf.exists() else []
        dj = self._distrusted_json()
        distrusted = json.loads(dj.read_text()) if dj.exists() else []
        return certs, distrusted

    def assess(self) -> StoreAssessment:
        certs, distrusted = self._load()
        blocked = {e["spki_hash"] for e in distrusted}
        roots, findings = [], []
        for c in certs:
            info = _bundle.root_info(c)
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
            info = _bundle.root_info(c)
            if info.fingerprint == scenario.compromised_root_fingerprint and info.spki_hash not in blocked:
                out.append(Finding(self.id, "root_trusted",
                                   f"compromised root in p11-kit anchors: {info.subject}", info.fingerprint))
            if info.spki_hash in (scenario.compromised_spki_hashes or []) and info.spki_hash not in blocked:
                out.append(Finding(self.id, "spki_trusted",
                                   f"compromised SPKI in p11-kit anchors: {info.subject}", info.fingerprint))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        certs, distrusted = self._load()
        actions = [_bundle.mode_header(mode)]
        bad_spkis = set(scenario.compromised_spki_hashes or [])
        if mode == RemediationMode.ROOT:
            kept, removed = [], []
            for c in certs:
                info = _bundle.root_info(c)
                if info.fingerprint == scenario.compromised_root_fingerprint or info.spki_hash in bad_spkis:
                    removed.append(c)
                    distrusted.append({"spki_hash": info.spki_hash, "subject": info.subject,
                                       "source": "anchor-removed", "reason": scenario.name})
                    actions.append(f"removed anchor {info.subject} (fp {info.fingerprint[:16]}…)")
                else:
                    kept.append(c)
            certs = kept
        else:
            for c in certs:
                info = _bundle.root_info(c)
                if info.spki_hash in bad_spkis and not any(e["spki_hash"] == info.spki_hash for e in distrusted):
                    distrusted.append({"spki_hash": info.spki_hash, "subject": info.subject,
                                       "source": "spki-distrust", "reason": scenario.name})
                    actions.append(f"distrusted SPKI {info.spki_hash[:16]}… ({info.subject})")
        self.store_path().mkdir(parents=True, exist_ok=True)
        _bundle.write_bundle(self._bundle_file(), certs)
        self._distrusted_json().write_text(json.dumps(distrusted, indent=2))
        if self.real:
            # best-effort: move the compromised anchors aside in the real anchors dir
            d = self.store_path()
            for f in d.glob("*.pem"):
                try:
                    if any(_bundle.root_info(c).fingerprint == scenario.compromised_root_fingerprint
                           for c in _bundle.load_certs(f)):
                        f.rename(f.with_suffix(".pem.distrusted"))
                        actions.append(f"moved real anchor {f.name} -> .distrusted")
                except Exception:
                    pass
        if not actions[1:]:
            actions.append("nothing to do — already distrusted")
        actions.append(f"wrote {self._bundle_file()} ({len(certs)} roots) + distrusted.json ({len(distrusted)})")
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        bf = self._bundle_file()
        return bf if (not self.real and bf.exists()) else None
