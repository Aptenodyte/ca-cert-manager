"""Person A backend tests: PKI, server, probes, stores, manager (sandboxed)."""
import os
import time
from pathlib import Path

import pytest


@pytest.fixture()
def sandbox_env(tmp_path, monkeypatch):
    root = tmp_path / "sandbox"
    monkeypatch.setenv("ROOTWATCH_ROOT", str(root))
    monkeypatch.setenv("ROOTWATCH_REAL_CRL_URLS", "")  # hermetic: no live CDP fetches
    from rootwatch import sandbox as sb
    sb.setup_sandbox(root, plant_compromised=True)  # tests exercise the planted incident
    return root


def test_pki_build_revoke_roundtrip(sandbox_env):
    from rootwatch import pki
    p = pki.load_pki(sandbox_env / "pki")
    assert p.root_fingerprint and p.leaf_serial and p.crl_pem
    assert "BEGIN X509 CRL" in p.crl_pem


def test_probe_matrix_pre_and_post_fix(sandbox_env):
    from rootwatch import probes, server
    t, port = server.start_server_background(port=0, pki_dir=sandbox_env / "pki")
    time.sleep(0.2)
    url = f"https://127.0.0.1:{port}/"
    ca = sandbox_env / "etc" / "ssl" / "ca-bundle.crt"
    from rootwatch import manager
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    pre = {r.client: r.success for r in probes.probe_all(url, cafile=str(ca), crl_pem=sc.crl_pem)}
    assert pre["requests"] and pre["curl"]          # attack works pre-fix
    assert not pre["requests-crl"] and not pre["openssl-crl"]  # CRL clients reject
    # remediate bundles, then all must reject
    from rootwatch.stores import all_stores
    from rootwatch.stores.base import RemediationMode
    manager.remediate_selected(all_stores(), [], sc, RemediationMode.SPKI)
    post = {r.client: r.success for r in probes.probe_all(url, cafile=str(ca), crl_pem=sc.crl_pem)}
    assert not any(post.values())


def test_stores_assess_audit_remediate(sandbox_env):
    from rootwatch import manager
    from rootwatch.stores import all_stores
    from rootwatch.stores.base import RemediationMode
    stores = all_stores()
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    assess = manager.assess_all(stores)
    assert set(assess) == {"system", "requests", "curl", "firefox", "chrome",
                           "java", "p11kit", "docker"}
    assert all(a.total_roots >= 2 for a in assess.values())  # docker certs.d starts with just the planted CA
    aud = manager.audit_all(stores, sc)
    assert all(v for v in aud.values())  # every store alerted pre-fix
    before = manager.assess_all(stores)["system"].total_roots
    # root mode removes the compromised root + intermediate (2 certs) everywhere
    res = manager.remediate_selected(stores, [], sc, RemediationMode.ROOT)
    assert all(r.success for r in res.values())
    aud2 = manager.audit_all(stores, sc)
    assert not any(aud2.values())
    assert manager.assess_all(stores)["system"].total_roots == before - 2


def test_update_crl_and_affected(sandbox_env):
    from rootwatch import manager
    from rootwatch.stores import all_stores
    bl = manager.update_crl()
    assert bl and bl[0].source.startswith("CRL") and bl[0].serial
    aff = manager.affected_stores(all_stores(), manager.load_blocklist_state())
    assert "system" in aff  # known-bad root flagged


def _crl_der(sandbox_env) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from rootwatch import pki
    pem = pki.load_pki(sandbox_env / "pki").crl_pem
    return x509.load_pem_x509_crl(pem.encode()).public_bytes(serialization.Encoding.DER)


def test_parse_crl_accepts_pem_and_der(sandbox_env):
    from rootwatch import manager, pki
    pem = pki.load_pki(sandbox_env / "pki").crl_pem
    from_pem = manager._parse_crl(pem)
    from_der = manager._parse_crl(_crl_der(sandbox_env))
    assert from_pem and from_der
    assert [e.serial for e in from_pem] == [e.serial for e in from_der]


def test_update_crl_queries_real_cdp(sandbox_env, monkeypatch):
    """ROOTWATCH_REAL_CRL_URLS entries are fetched live (mocked) and merged in."""
    import requests
    from rootwatch import manager

    class Resp:
        def __init__(self, content): self.content = content
        def raise_for_status(self): pass

    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    # a DIFFERENT CRL (different issuer/serial) as the "real" CDP payload
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    other = (x509.CertificateRevocationListBuilder()
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other CA")]))
             .last_update(now - datetime.timedelta(days=1))
             .next_update(now + datetime.timedelta(days=7))
             .add_revoked_certificate(x509.RevokedCertificateBuilder()
                 .serial_number(0xC0FFEE).revocation_date(now).build())
             .sign(key, hashes.SHA256()))
    other_der = other.public_bytes(serialization.Encoding.DER)
    seen = []
    monkeypatch.setenv("ROOTWATCH_REAL_CRL_URLS", "http://crl.example.test/root.crl")
    monkeypatch.setattr(requests, "get",
                        lambda url, timeout=5: (seen.append(url), Resp(other_der))[1])
    bl = manager.update_crl()
    assert seen == ["http://crl.example.test/root.crl"]
    sources = {e.source for e in bl}
    assert "CRL http://crl.example.test/root.crl" in sources       # real CDP entry
    assert any(s.startswith("CRL (scenario)") for s in sources)    # scenario fallback too
    assert any(e.serial == format(0xC0FFEE, "x") for e in bl)      # the real serial landed


def test_update_crl_offline_skips_real_cdps(sandbox_env, monkeypatch):
    """Unreachable CDPs must not break the update (offline-safe)."""
    import requests
    from rootwatch import manager
    monkeypatch.setenv("ROOTWATCH_REAL_CRL_URLS", "http://10.255.255.1/nope.crl")

    def boom(url, timeout=5):
        raise requests.ConnectionError("offline")
    monkeypatch.setattr(requests, "get", boom)
    bl = manager.update_crl()
    assert bl and all(e.source.startswith("CRL (scenario)") for e in bl)


def test_forged_crl_signature_rejected(sandbox_env):
    """A CRL claiming our issuer but signed by another key must be dropped."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from rootwatch import manager, pki
    inter = x509.load_pem_x509_certificate(
        (sandbox_env / "pki" / "inter.crt").read_bytes())
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    forged = (x509.CertificateRevocationListBuilder()
              .issuer_name(inter.subject)
              .last_update(now - datetime.timedelta(days=1))
              .next_update(now + datetime.timedelta(days=7))
              .add_revoked_certificate(x509.RevokedCertificateBuilder()
                  .serial_number(0xDEAD).revocation_date(now).build())
              .sign(attacker_key, hashes.SHA256()))
    der = forged.public_bytes(serialization.Encoding.DER)
    assert manager._parse_crl(der) == []          # issuer IS in bundle, sig invalid
    # and the genuine scenario CRL (signed by the real inter key) is accepted:
    assert manager._parse_crl(pki.load_pki(sandbox_env / "pki").crl_pem)


def test_default_setup_is_clean_then_plant_adds_incident(tmp_path, monkeypatch):
    """No fake data by default: plain setup seeds only real stores (all ok);
    plant_incident() (demo/load-emudhra.sh) loads the eMudhra certs -> alerts."""
    import json
    monkeypatch.setenv("ROOTWATCH_ROOT", str(tmp_path / "sandbox"))
    monkeypatch.setenv("ROOTWATCH_REAL_CRL_URLS", "")
    from rootwatch import manager, sandbox as sb
    from rootwatch.stores import all_stores
    root = sb.setup_sandbox(tmp_path / "sandbox")  # default: plant_compromised=False
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    stores = all_stores()
    rt = json.loads((root / "scenario.runtime.json").read_text())
    assert rt["planted"] is False
    assert json.loads((root / "known_bad.json").read_text()) == []
    assert not any(manager.audit_all(stores, sc).values()), "clean sandbox must not alert"
    sb.plant_incident(root)
    assert json.loads((root / "known_bad.json").read_text())
    assert any(manager.audit_all(stores, sc).values()), "planted incident must alert"
    assert "system" in manager.affected_stores(stores, manager.load_blocklist_state())


def test_java_p11kit_docker_stores(sandbox_env):
    """New stores: seeded from real data, planted incident alerts, root remediation cleans."""
    from rootwatch import manager
    from rootwatch.stores import all_stores
    from rootwatch.stores.base import RemediationMode
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    stores = {s.id: s for s in all_stores()}
    for sid in ("java", "p11kit", "docker"):
        assert sid in stores
        a = stores[sid].assess()
        assert a.total_roots > 0, f"{sid} should be seeded/planted with roots"
        assert stores[sid].audit(sc), f"{sid} should alert on the planted incident"
    res = manager.remediate_selected(list(stores.values()), [], sc, RemediationMode.ROOT)
    for sid in ("java", "p11kit", "docker"):
        assert res[sid].success, res[sid].actions
        assert stores[sid].audit(sc) == [], f"{sid} should be clean after root remediation"


def test_chrome_crlset_roundtrip():
    from rootwatch.stores.chrome import build_crlset, parse_crlset
    serials = [0x4F2A, 2**70 + 5]
    assert parse_crlset(build_crlset(serials)) == serials
    assert parse_crlset(b"garbage") == []


def test_cli_smoke(sandbox_env, capsys):
    from rootwatch.cli import main
    assert main(["audit"]) == 0
    out = capsys.readouterr().out
    assert "system-wide assessment" in out and "ALERT" in out
    assert main(["remediate", "--mode", "root"]) == 0
    assert main(["audit"]) == 0
    out = capsys.readouterr().out
    assert "status=ok" in out
