"""Chrome CRLSet store.

crlset.bin mini-format (documented here; real CRLSet is Google's binary blob —
we keep the same semantics: a set of revoked serials):
  magic "RCRL" (4) | version u8 | reserved 3 | count u32 | per entry: u16 len + hex-ascii serial
trusted_roots.json mirrors the roots Chrome trusts; policy.json holds enterprise
distrust decisions (root mode).
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from .base import Finding, RemediationMode, RemediationResult, RootInfo, Scenario, StoreAssessment, TrustStore, sandbox_root

MAGIC = b"RCRL"


def parse_crlset(data: bytes) -> list[int]:
    """Parse our crlset.bin -> list of revoked serial numbers (ints)."""
    if len(data) < 8 or data[:4] != MAGIC:
        return []
    count = struct.unpack(">I", data[8:12])[0]
    off, out = 12, []
    for _ in range(count):
        (ln,) = struct.unpack(">H", data[off:off+2]); off += 2
        out.append(int(data[off:off+ln].decode(), 16)); off += ln
    return out


def build_crlset(serials: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", len(s)) + s.encode()
                    for s in (format(n, "x") for n in serials))
    return MAGIC + bytes([1, 0, 0, 0]) + struct.pack(">I", len(serials)) + body


class ChromeStore(TrustStore):
    id = "chrome"
    display_name = "Chrome (CRLSet)"
    icon = "🧭"

    def store_path(self) -> Path:
        if self.real:
            return Path.home() / ".config" / "google-chrome"
        return sandbox_root() / "chrome"

    def crlset_path(self) -> Path:
        return self.store_path() / "crlset.bin"

    def _roots_json(self) -> Path:
        return self.store_path() / "trusted_roots.json"

    def _policy_json(self) -> Path:
        return self.store_path() / "policy.json"

    def _load_roots(self) -> list[dict]:
        p = self._roots_json()
        return json.loads(p.read_text()) if p.exists() else []

    def _save_roots(self, roots: list[dict]) -> None:
        self.store_path().mkdir(parents=True, exist_ok=True)
        self._roots_json().write_text(json.dumps(roots, indent=2))

    def assess(self) -> StoreAssessment:
        serials = parse_crlset(self.crlset_path().read_bytes()) if self.crlset_path().exists() else []
        roots = [RootInfo(subject=r["subject"], fingerprint=r["fingerprint"], spki_hash=r["spki_hash"],
                          not_after=r.get("not_after", ""), sig_alg=r.get("sig_alg", ""), flags=list(r.get("flags", [])))
                 for r in self._load_roots()]
        findings = [f"{r.subject} [{','.join(r.flags)}]" for r in roots if r.flags]
        if serials:
            findings.append(f"[blocked] CRLSet blocks {len(serials)} revoked serial(s)")
        return StoreAssessment(self.id, self.display_name, self.icon,
                               total_roots=len(roots), roots=roots, findings=findings)

    def audit(self, scenario: Scenario) -> list[Finding]:
        out = []
        blocked = set(parse_crlset(self.crlset_path().read_bytes())) if self.crlset_path().exists() else set()
        leaf_serial = int(scenario.revoked_serial, 16) if scenario.revoked_serial else -1
        if leaf_serial in blocked:
            return []  # revoked serial already blocked by CRLSet -> protected
        for r in self._load_roots():
            if r["fingerprint"] == scenario.compromised_root_fingerprint:
                out.append(Finding(self.id, "root_trusted",
                                   f"compromised root trusted by Chrome: {r['subject']}", r["fingerprint"]))
        return out

    def remediate(self, scenario: Scenario, mode: RemediationMode = RemediationMode.SPKI) -> RemediationResult:
        self.store_path().mkdir(parents=True, exist_ok=True)
        from . import _bundle
        actions = [_bundle.mode_header(mode)]
        serials = parse_crlset(self.crlset_path().read_bytes()) if self.crlset_path().exists() else []
        roots_before = len(self._load_roots())
        if mode == RemediationMode.SPKI:
            leaf_serial = int(scenario.revoked_serial, 16)
            if leaf_serial not in serials:
                serials.append(leaf_serial)
                actions.append(f"pushed revoked serial {scenario.revoked_serial} into CRLSet "
                               f"({len(serials)} entries)")
            else:
                actions.append("serial already in CRLSet")
            self.crlset_path().write_bytes(build_crlset(serials))
            kept = self._load_roots()
        else:
            roots = self._load_roots()
            kept = []
            bad_spkis = set(scenario.compromised_spki_hashes or [])
            for r in roots:
                if r["fingerprint"] == scenario.compromised_root_fingerprint or r["spki_hash"] in bad_spkis:
                    actions.append(f"distrusted via enterprise policy: {r['subject']}")
                else:
                    kept.append(r)
            self._save_roots(kept)
            pol = {"distrusted_roots": [scenario.compromised_root_fingerprint],
                   "distrusted_spkis": sorted(bad_spkis)}
            self._policy_json().write_text(json.dumps(pol, indent=2))
        actions.append(f"wrote crlset.bin ({len(serials)} serials), "
                       f"trusted_roots.json ({len(kept)} roots), policy.json "
                       f"under {self.store_path()}")
        return RemediationResult(self.id, success=True, actions=actions)

    def cafile(self) -> Path | None:
        return None
