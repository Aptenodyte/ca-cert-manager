"""Orchestration across stores. Used by both CLI (A) and web UI (B)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import yaml
from cryptography import x509

from .stores.base import (
    BlocklistEntry,
    Finding,
    RemediationMode,
    RemediationResult,
    Scenario,
    StoreAssessment,
    TrustStore,
    sandbox_root,
)


def assess_all(stores: list[TrustStore]) -> dict[str, StoreAssessment]:
    """DEFAULT view: system-wide posture of every trust store."""
    return {s.id: s.assess() for s in stores}


DEFAULT_REAL_CRL_URLS = [
    "http://x1.c.lencr.org/",                             # ISRG Root X1 (Let's Encrypt)
    "http://crl3.digicert.com/DigiCertGlobalRootCA.crl",  # DigiCert Global Root CA
    "http://crl4.digicert.com/DigiCertGlobalRootG2.crl",  # DigiCert Global Root G2
]


def real_crl_urls() -> list[str]:
    """Real CRL distribution points queried on 'Update CRL'. Override with the
    CATRUST_REAL_CRL_URLS env var (comma-separated); set it to "" to disable."""
    raw = os.environ.get("CATRUST_REAL_CRL_URLS")
    if raw is None:
        return list(DEFAULT_REAL_CRL_URLS)
    return [u.strip() for u in raw.split(",") if u.strip()]


def _load_crl(data: str | bytes) -> x509.CertificateRevocationList:
    """Parse a CRL as PEM or DER (CDPs usually serve DER)."""
    raw = data.encode() if isinstance(data, str) else data
    try:
        return x509.load_pem_x509_crl(raw)
    except ValueError:
        return x509.load_der_x509_crl(raw)


def _issuer_cert_in_bundle(crl: x509.CertificateRevocationList) -> x509.Certificate | None:
    """Find the CRL issuer's cert in the sandbox system bundle (for signature checks)."""
    from .stores import _bundle
    bundle = sandbox_root() / "etc" / "ssl" / "ca-bundle.crt"
    for c in _bundle.load_certs(bundle):
        if c.subject == crl.issuer:
            return c
    return None


def _parse_crl(data: str | bytes, source: str = "CRL") -> list[BlocklistEntry]:
    """Parse a CRL (PEM or DER) into blocklist entries. If the issuer cert is in the
    sandbox system bundle, the CRL signature is verified — forged CRLs are dropped."""
    crl = _load_crl(data)
    issuer_cert = _issuer_cert_in_bundle(crl)
    if issuer_cert is not None:
        try:
            if not crl.is_signature_valid(issuer_cert.public_key()):
                return []
        except Exception:
            return []
    entries = []
    for rc in crl:
        try:
            reason = str(rc.extensions.get_extension_for_class(x509.CRLReason).value.reason)
        except Exception:
            reason = "revoked"
        revoked_at = getattr(rc, "revocation_date_utc", None) or rc.revocation_date
        entries.append(BlocklistEntry(
            serial=format(rc.serial_number, "x"),
            subject="",
            issuer=crl.issuer.rfc4514_string(),
            revoked_at=revoked_at.date().isoformat() if hasattr(revoked_at, "date") else str(revoked_at),
            source=source,
            reason=reason,
        ))
    return entries


def _fetch_crl(url: str) -> bytes:
    import requests
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.content


def collect_blocklist(crl_pems: list[str] | None = None,
                      extra_spki_hashes: list[str] | None = None) -> list[BlocklistEntry]:
    """Application-level untrusted list from CRLs + explicit SPKI hashes (OneCRL-style)."""
    entries: list[BlocklistEntry] = []
    for pem in crl_pems or []:
        entries += _parse_crl(pem)
    for spki in extra_spki_hashes or []:
        entries.append(BlocklistEntry(spki_hash=spki, source="OneCRL", reason="distrusted key"))
    return entries


def update_crl(crl_pem: str | None = None, url: str | None = None) -> list[BlocklistEntry]:
    """'Update CRL': ingest CRLs into the sandbox blocklist state.

    Sources merged: an explicit `crl_pem`, an explicit `url` (fetched live), the
    scenario's CRL when neither is given, and — always — the REAL public CRL
    distribution points from `real_crl_urls()` (ISRG/DigiCert by default; override
    with CATRUST_REAL_CRL_URLS, "" disables). CRLs are parsed as PEM or DER and
    signature-verified against the issuer cert in the sandbox bundle when present.
    Unreachable CDPs are skipped, so this is safe offline."""
    sources: list[tuple[str, str | bytes]] = []
    if crl_pem:
        sources.append(("CRL", crl_pem))
    if url:
        sources.append((f"CRL {url}", _fetch_crl(url)))
    if not crl_pem and not url:
        # fall back to the scenario's CRL from the sandbox PKI
        rt = sandbox_root() / "scenario.runtime.json"
        if rt.exists():
            pem = json.loads(rt.read_text()).get("crl_pem")
            if pem:
                sources.append(("CRL (scenario)", pem))
    for u in real_crl_urls():
        try:
            sources.append((f"CRL {u}", _fetch_crl(u)))
        except Exception:
            continue  # offline or CDP down — skip this one
    entries: list[BlocklistEntry] = []
    for label, data in sources:
        entries += _parse_crl(data, source=label)
    state_file = sandbox_root() / "blocklist.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    existing = json.loads(state_file.read_text()) if state_file.exists() else []
    merged = {e["serial"]: e for e in existing}
    for e in entries:
        merged[e.serial] = {"serial": e.serial, "spki_hash": e.spki_hash, "subject": e.subject,
                            "issuer": e.issuer, "revoked_at": e.revoked_at,
                            "source": e.source, "reason": e.reason}
    state_file.write_text(json.dumps(list(merged.values()), indent=2))
    return [BlocklistEntry(**v) for v in merged.values()]


def probe_cafile(stores: list[TrustStore], store_id: str | None = None) -> str | None:
    """CAfile for the probe matrix, scoped to one store when `store_id` is given.

    Stores with a real bundle (system/requests/curl) use their own cafile. DB/JSON
    stores (firefox/chrome) have no cafile, so we reconstruct one: the system bundle
    filtered to exactly the roots that store currently trusts — which is what makes
    pre/post remediation probes reflect *that* store. Falls back to the first
    store with a cafile when store_id is None or unknown."""
    chosen = next((s for s in stores if s.id == store_id), None) if store_id else None
    if chosen is not None:
        cf = chosen.cafile()
        if cf and Path(cf).exists():
            return str(cf)
        target = chosen  # DB/JSON store: reconstruct its bundle below
    else:
        for st in stores:  # default: first store with a real cafile
            cf = st.cafile()
            if cf and Path(cf).exists():
                return str(cf)
        target = next((s for s in stores if not s.cafile()), None)
    if target is None:
        return None
    sys_bundle = sandbox_root() / "etc" / "ssl" / "ca-bundle.crt"
    if not sys_bundle.exists():
        return None
    from .stores import _bundle
    import tempfile
    fps = {r.fingerprint for r in target.assess().roots}
    kept = [c for c in _bundle.load_certs(sys_bundle) if _bundle.root_info(c).fingerprint in fps]
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    f.write("".join(_bundle.cert_to_pem(c) for c in kept))
    f.close()
    return f.name


def load_blocklist_state() -> list[BlocklistEntry]:
    state_file = sandbox_root() / "blocklist.json"
    if not state_file.exists():
        return []
    return [BlocklistEntry(**v) for v in json.loads(state_file.read_text())]


def affected_stores(stores: list[TrustStore], blocklist: list[BlocklistEntry]) -> set[str]:
    """Store ids whose assessed roots/SPKIs intersect the blocklist or known-bad list."""
    bad_spkis = {e.spki_hash for e in blocklist if e.spki_hash}
    out = set()
    for s in stores:
        a = s.assess()
        for r in a.roots:
            if r.spki_hash in bad_spkis or "known-bad" in r.flags:
                out.add(s.id)
                break
    return out


def audit_all(stores: list[TrustStore], scenario: Scenario) -> dict[str, list[Finding]]:
    return {s.id: s.audit(scenario) for s in stores}


def remediate_selected(stores: list[TrustStore], store_ids: list[str],
                       scenario: Scenario,
                       mode: RemediationMode = RemediationMode.SPKI) -> dict[str, RemediationResult]:
    out = {}
    for s in stores:
        if s.id in store_ids or not store_ids:
            out[s.id] = s.remediate(scenario, mode)
    return out


def load_scenario(path: str) -> Scenario:
    """Load scenario YAML; merge runtime PKI fields from the sandbox if present."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    rt_file = sandbox_root() / "scenario.runtime.json"
    rt = json.loads(rt_file.read_text()) if rt_file.exists() else {}
    return Scenario(
        name=data.get("name", rt.get("name", "scenario")),
        compromised_root_fingerprint=data.get("compromised_root_fingerprint") or rt.get("compromised_root_fingerprint", ""),
        revoked_serial=data.get("revoked_serial") or rt.get("revoked_serial", ""),
        revoked_subject_cn=data.get("revoked_subject_cn", "localhost"),
        narrative=data.get("description", ""),
        root_cert_pem=rt.get("root_cert_pem", ""),
        crl_pem=rt.get("crl_pem", ""),
        compromised_spki_hashes=data.get("compromised_spki_hashes") or rt.get("compromised_spki_hashes", []),
        leaf_spki_hash=data.get("leaf_spki_hash") or rt.get("leaf_spki_hash", ""),
    )
