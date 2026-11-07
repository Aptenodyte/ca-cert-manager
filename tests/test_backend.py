"""Person A backend tests: PKI, server, probes, stores, manager (sandboxed)."""
import os
import time
from pathlib import Path

import pytest


@pytest.fixture()
def sandbox_env(tmp_path, monkeypatch):
    root = tmp_path / "sandbox"
    monkeypatch.setenv("CATRUST_ROOT", str(root))
    from catrust import sandbox as sb
    sb.setup_sandbox(root)
    return root


def test_pki_build_revoke_roundtrip(sandbox_env):
    from catrust import pki
    p = pki.load_pki(sandbox_env / "pki")
    assert p.root_fingerprint and p.leaf_serial and p.crl_pem
    assert "BEGIN X509 CRL" in p.crl_pem


def test_probe_matrix_pre_and_post_fix(sandbox_env):
    from catrust import probes, server
    t, port = server.start_server_background(port=0, pki_dir=sandbox_env / "pki")
    time.sleep(0.2)
    url = f"https://127.0.0.1:{port}/"
    ca = sandbox_env / "etc" / "ssl" / "ca-bundle.crt"
    from catrust import manager
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    pre = {r.client: r.success for r in probes.probe_all(url, cafile=str(ca), crl_pem=sc.crl_pem)}
    assert pre["requests"] and pre["curl"]          # attack works pre-fix
    assert not pre["requests-crl"] and not pre["openssl-crl"]  # CRL clients reject
    # remediate bundles, then all must reject
    from catrust.stores import all_stores
    from catrust.stores.base import RemediationMode
    manager.remediate_selected(all_stores(), [], sc, RemediationMode.SPKI)
    post = {r.client: r.success for r in probes.probe_all(url, cafile=str(ca), crl_pem=sc.crl_pem)}
    assert not any(post.values())


def test_stores_assess_audit_remediate(sandbox_env):
    from catrust import manager
    from catrust.stores import all_stores
    from catrust.stores.base import RemediationMode
    stores = all_stores()
    sc = manager.load_scenario("scenarios/emudhra.yaml")
    assess = manager.assess_all(stores)
    assert set(assess) == {"system", "requests", "curl", "firefox", "chrome"}
    assert all(a.total_roots >= 3 for a in assess.values())
    aud = manager.audit_all(stores, sc)
    assert all(v for v in aud.values())  # every store alerted pre-fix
    # root mode removes the root everywhere
    res = manager.remediate_selected(stores, [], sc, RemediationMode.ROOT)
    assert all(r.success for r in res.values())
    aud2 = manager.audit_all(stores, sc)
    assert not any(aud2.values())
    assert manager.assess_all(stores)["system"].total_roots == 2  # decoys remain


def test_update_crl_and_affected(sandbox_env):
    from catrust import manager
    from catrust.stores import all_stores
    bl = manager.update_crl()
    assert bl and bl[0].source == "CRL" and bl[0].serial
    aff = manager.affected_stores(all_stores(), manager.load_blocklist_state())
    assert "system" in aff  # known-bad root flagged


def test_chrome_crlset_roundtrip():
    from catrust.stores.chrome import build_crlset, parse_crlset
    serials = [0x4F2A, 2**70 + 5]
    assert parse_crlset(build_crlset(serials)) == serials
    assert parse_crlset(b"garbage") == []


def test_cli_smoke(sandbox_env, capsys):
    from catrust.cli import main
    assert main(["audit"]) == 0
    out = capsys.readouterr().out
    assert "system-wide assessment" in out and "ALERT" in out
    assert main(["remediate", "--mode", "root"]) == 0
    assert main(["audit"]) == 0
    out = capsys.readouterr().out
    assert "status=ok" in out
