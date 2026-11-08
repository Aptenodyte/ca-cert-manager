"""Sandbox setup: copy the machine's REAL trust stores into the sandbox (read-only
on the real ones), build the mock PKI, and plant the compromised root on top —
so the dashboard shows the real ~150 roots plus the eMudhra one.
Person A owns this file.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from cryptography import x509

from . import pki as pki_mod
from .stores import _bundle, sandbox_root
from .stores.base import KNOWN_BAD_FPS

REAL_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",     # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",        # RHEL/Fedora
    "/etc/ssl/cert.pem",                       # Alpine/macOS-ish
]


def _real_system_bundle() -> str:
    for c in REAL_BUNDLE_CANDIDATES:
        p = Path(c)
        if p.exists() and p.stat().st_size > 1000:
            return p.read_text()
    # fallback: concatenate the hashed cert dir
    d = Path("/etc/ssl/certs")
    if d.exists():
        return "".join(f.read_text() for f in sorted(d.glob("*.pem")) if f.is_file() and not f.is_symlink())
    return ""


def _real_certifi_bundle() -> str:
    try:
        import certifi
        return Path(certifi.where()).read_text()
    except Exception:
        return ""


def _real_firefox_roots() -> list[dict]:
    """Export trusted roots from real Firefox NSS profiles via certutil, if present."""
    base = Path.home() / ".mozilla" / "firefox"
    if not (base.exists() and shutil.which("certutil")):
        return []
    out = []
    for prof in sorted(p for p in base.iterdir() if p.is_dir() and (p / "cert9.db").exists()):
        r = subprocess.run(["certutil", "-L", "-d", f"sql:{prof}"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if not line.strip() or line.startswith("Certificate Nickname"):
                continue
            nick = line.split()[0]
            if not line.rstrip().endswith(("CT,C,C", "C,C,C", "CT,C,C")):
                pass  # include all listed; trust flags vary
            e = subprocess.run(["certutil", "-L", "-d", f"sql:{prof}", "-n", nick, "-a"],
                               capture_output=True, text=True)
            if "BEGIN CERTIFICATE" not in e.stdout:
                continue
            try:
                cert = x509.load_pem_x509_certificate(e.stdout.encode())
            except Exception:
                continue
            info = _bundle.root_info(cert)
            out.append({"subject": info.subject, "fingerprint": info.fingerprint,
                        "spki_hash": info.spki_hash, "not_after": info.not_after,
                        "sig_alg": info.sig_alg, "flags": info.flags,
                        "source": f"firefox:{prof.name}"})
    return out


def _real_java_roots() -> list[dict]:
    """Export trusted roots from the real Java cacerts via keytool (JKS, storepass
    'changeit' on Debian); fall back to the system bundle as the mirror source."""
    if not shutil.which("keytool"):
        return []
    for ks in (Path("/etc/ssl/certs/java/cacerts"),
               Path("/usr/lib/jvm/default-java/lib/security/cacerts")):
        if not ks.exists():
            continue
        r = subprocess.run(["keytool", "-list", "-rfc", "-keystore", str(ks),
                            "-storepass", "changeit"], capture_output=True, text=True)
        if "BEGIN CERTIFICATE" in r.stdout:
            return _certs_json_from_pem(r.stdout)
    return []


def _real_p11kit_bundle() -> str:
    """Real p11-kit anchors (RHEL/Fedora layout) if present, else the system bundle."""
    for d in (Path("/etc/pki/ca-trust/source/anchors"),
              Path("/usr/share/p11-kit/anchors"),
              Path("/usr/local/share/ca-certificates")):
        if d.exists():
            pems = [f.read_text() for f in sorted(d.glob("*.pem")) + sorted(d.glob("*.crt"))
                    if f.is_file()]
            if pems:
                return "".join(pems)
    return ""


def _certs_json_from_pem(pem: str) -> list[dict]:
    out = []
    for c in _bundle.load_certs(_pem_bytes(pem)):
        info = _bundle.root_info(c)
        out.append({"subject": info.subject, "fingerprint": info.fingerprint,
                    "spki_hash": info.spki_hash, "not_after": info.not_after,
                    "sig_alg": info.sig_alg, "flags": info.flags, "source": "bundle"})
    return out


def setup_sandbox(root: Path | None = None, use_real: bool = True,
                  plant_compromised: bool = False) -> Path:
    """Create the sandbox tree: pki/ + every store seeded from the machine's REAL
    trust stores (copied, never modified). Clean by default — NO fake data injected;
    pass plant_compromised=True (or run plant_incident / demo/load-emudhra.sh) to load
    the compromised eMudhra root into the stores for the demo. Returns the sandbox root."""
    root = Path(root) if root else sandbox_root()
    pki_dir = root / "pki"
    p = pki_mod.build_pki(pki_dir)
    pki_mod.revoke_leaf(p, pki_dir)

    real_sys = _real_system_bundle() if use_real else ""
    real_certifi = _real_certifi_bundle() if use_real else ""
    if use_real and not real_sys and not real_certifi:
        raise RuntimeError(
            "no real trust stores found on this machine (looked for "
            f"{', '.join(REAL_BUNDLE_CANDIDATES)} and certifi's cacert.pem) — "
            "refusing to seed the sandbox with synthetic decoy roots")

    # seed every store from the REAL bundles only — clean, no fake data by default
    sys_bundle = root / "etc" / "ssl" / "ca-bundle.crt"
    _bundle.write_bundle(sys_bundle, _bundle.load_certs(_pem_bytes(real_sys)))
    sys_dir = root / "etc" / "ssl" / "certs"
    sys_dir.mkdir(parents=True, exist_ok=True)
    for c in _bundle.load_certs(sys_bundle):
        (sys_dir / f"{_bundle.root_info(c).fingerprint[:8]}.pem").write_text(_bundle.cert_to_pem(c))

    _bundle.write_bundle(root / "certifi" / "cacert.pem",
                         _bundle.load_certs(_pem_bytes(real_certifi or real_sys)))
    _bundle.write_bundle(root / "curl" / "ca-bundle.crt",
                         _bundle.load_certs(_pem_bytes(real_sys)))

    # firefox: real NSS export if possible, else system bundle as the mirror source
    ff_roots = _real_firefox_roots() or _certs_json_from_pem(real_sys)
    prof = root / "mozilla" / "firefox" / "demo.default-release"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "certs.json").write_text(json.dumps(ff_roots, indent=2))
    (prof / "onecrl.json").write_text("[]")

    # chrome: system roots (Chrome uses them on Linux) + empty synthetic CRLSet
    chrome = root / "chrome"
    chrome.mkdir(parents=True, exist_ok=True)
    (chrome / "trusted_roots.json").write_text(
        json.dumps(_certs_json_from_pem(real_sys), indent=2))
    from .stores.chrome import build_crlset
    (chrome / "crlset.bin").write_bytes(build_crlset([]))

    # java cacerts: real keystore export via keytool when available, else system mirror
    java = root / "java"
    java.mkdir(parents=True, exist_ok=True)
    (java / "cacerts.json").write_text(
        json.dumps(_real_java_roots() or _certs_json_from_pem(real_sys), indent=2))
    (java / "distrusted.json").write_text("[]")

    # p11-kit: real anchors if present, else system bundle
    p11 = root / "p11kit"
    p11.mkdir(parents=True, exist_ok=True)
    _bundle.write_bundle(p11 / "ca-bundle.pem",
                         _bundle.load_certs(_pem_bytes(_real_p11kit_bundle() or real_sys)))
    (p11 / "distrusted.json").write_text("[]")

    # docker certs.d: copy real per-registry CAs if any exist, else empty tree
    dock = root / "docker" / "certs.d"
    real_dock = Path("/etc/docker/certs.d")
    if real_dock.exists():
        shutil.copytree(real_dock, dock, dirs_exist_ok=True)
    else:
        dock.mkdir(parents=True, exist_ok=True)

    (root / "blocklist.json").write_text("[]")
    (root / "known_bad.json").write_text("[]")
    (root / "scenario.runtime.json").write_text(json.dumps({
        "name": "emudhra-2026",
        "planted": False,
        "compromised_root_fingerprint": p.root_fingerprint,
        "revoked_serial": p.leaf_serial,
        "compromised_spki_hashes": [p.root_spki_hash, p.inter_spki_hash],
        "leaf_spki_hash": p.leaf_spki_hash,
        "revoked_subject_cn": "localhost",
        "crl_pem": p.crl_pem,
        "root_cert_pem": p.root_cert_pem,
        "seeded_from_real_stores": bool(real_sys or real_certifi),
    }, indent=2))
    if plant_compromised:
        plant_incident(root)
    return root


def plant_incident(root: Path | None = None) -> Path:
    """Load the compromised eMudhra root + issuing CA into every sandbox trust store.

    This is the demo's attack step — run explicitly (demo/load-emudhra.sh or
    `rootwatch inject`), never implicitly by `setup`. Idempotent."""
    root = Path(root) if root else sandbox_root()
    p = pki_mod.load_pki(root / "pki")
    bad = _bundle.load_certs(_pem_bytes(p.root_cert_pem + p.inter_cert_pem))
    bad_fps = {_bundle.root_info(c).fingerprint for c in bad}

    def add_to_bundle(path: Path) -> int:
        certs = _bundle.load_certs(path)
        have = {_bundle.root_info(c).fingerprint for c in certs}
        fresh = [c for c in bad if _bundle.root_info(c).fingerprint not in have]
        if fresh:
            _bundle.write_bundle(path, certs + fresh)
        return len(fresh)

    n_sys = add_to_bundle(root / "etc" / "ssl" / "ca-bundle.crt")
    sys_dir = root / "etc" / "ssl" / "certs"
    sys_dir.mkdir(parents=True, exist_ok=True)
    for c in bad:
        fp8 = _bundle.root_info(c).fingerprint[:8]
        (sys_dir / f"{fp8}.pem").write_text(_bundle.cert_to_pem(c))
    add_to_bundle(root / "certifi" / "cacert.pem")
    add_to_bundle(root / "curl" / "ca-bundle.crt")

    def add_to_json(path: Path) -> None:
        entries = json.loads(path.read_text()) if path.exists() else []
        have = {e.get("fingerprint") for e in entries}
        for c in bad:
            info = _bundle.root_info(c)
            if info.fingerprint not in have:
                entries.append({"subject": info.subject, "fingerprint": info.fingerprint,
                                "spki_hash": info.spki_hash, "not_after": info.not_after,
                                "sig_alg": info.sig_alg, "flags": info.flags, "source": "planted"})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries, indent=2))

    add_to_json(root / "mozilla" / "firefox" / "demo.default-release" / "certs.json")
    add_to_json(root / "chrome" / "trusted_roots.json")
    add_to_json(root / "java" / "cacerts.json")

    # p11-kit anchors bundle
    p11_bundle = root / "p11kit" / "ca-bundle.pem"
    if p11_bundle.exists():
        add_to_bundle(p11_bundle)

    # docker certs.d: plant a registry CA under a demo registry name
    reg = root / "docker" / "certs.d" / "registry.emudhra.local"
    reg.mkdir(parents=True, exist_ok=True)
    ca = reg / "ca.crt"
    existing = _bundle.load_certs(ca) if ca.exists() else []
    have = {_bundle.root_info(c).fingerprint for c in existing}
    fresh = [c for c in bad if _bundle.root_info(c).fingerprint not in have]
    if fresh:
        _bundle.write_bundle(ca, existing + fresh)

    KNOWN_BAD_FPS.add(p.root_fingerprint)
    (root / "known_bad.json").write_text(json.dumps([p.root_fingerprint]))
    rt_file = root / "scenario.runtime.json"
    rt = json.loads(rt_file.read_text()) if rt_file.exists() else {}
    rt["planted"] = True
    rt_file.write_text(json.dumps(rt, indent=2))
    print(f"☠️  planted compromised eMudhra root+intermediate into sandbox stores "
          f"({n_sys} new in system bundle, fp {p.root_fingerprint[:16]}…)")
    return root


def _pem_bytes(s: str) -> Path:
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    f.write(s)
    f.close()
    return Path(f.name)
