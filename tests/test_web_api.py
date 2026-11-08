"""API-level tests for the web routes (Person B's web.py against Person A's manager)."""
import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ROOTWATCH_ROOT", str(tmp_path / "sandbox"))
    monkeypatch.setenv("ROOTWATCH_REAL_CRL_URLS", "")  # hermetic: no live CDP fetches
    monkeypatch.setenv("ROOTWATCH_SERVER_PORT", "0")   # ephemeral port: tests run in parallel with a live dashboard
    from rootwatch import sandbox
    sandbox.setup_sandbox(tmp_path / "sandbox", plant_compromised=True)
    from rootwatch.web import create_app
    app = create_app("scenarios/emudhra.yaml", real=False)
    app.testing = True
    return app.test_client()


def test_audit_alerts_all_stores(client):
    r = client.post("/api/audit")
    assert r.status_code == 200
    data = r.get_json()
    ALL = {"system", "requests", "curl", "firefox", "chrome", "java", "p11kit", "docker"}
    assert set(s["id"] for s in data["stores"]) == ALL
    assert sorted(data["affected"]) == sorted(ALL)
    assert any(s["alerts"] for s in data["stores"])
    assert data["blocklist"], "CRL blocklist should be populated from the scenario CRL"


def test_known_bad_flag_persisted(client):
    data = client.post("/api/audit").get_json()
    sys_store = next(s for s in data["stores"] if s["id"] == "system")
    assert any("known-bad" in (rt.get("flags") or []) for rt in sys_store["roots"])


def test_crl_update(client):
    r = client.post("/api/crl/update", json={})
    assert r.status_code == 200
    entries = r.get_json()["entries"]
    assert entries and entries[0]["source"] == "CRL" and entries[0]["serial"]


def test_remediate_spki_then_root_modes(client):
    # spki on one store
    r = client.post("/api/remediate", json={"store_id": "system", "mode": "spki"})
    assert r.get_json()["success"]
    # root mode on ALL stores via store_ids list
    r = client.post("/api/remediate", json={
        "store_ids": ["system", "requests", "curl", "firefox", "chrome",
                      "java", "p11kit", "docker"], "mode": "root"})
    data = r.get_json()
    assert data["success"], data
    assert all(v["success"] for v in data["results"].values())
    # after root remediation, audit shows no alerts
    aud = client.post("/api/audit").get_json()
    assert aud["affected"] == []
    assert all(s["status"] == "ok" for s in aud["stores"])


def test_probe_has_server_url(client):
    r = client.get("/api/probe")
    assert r.status_code == 200
    data = r.get_json()
    assert data["server_url"].startswith("https://127.0.0.1:")
    assert len(data["probes"]) == 4


def test_probe_scoped_to_remediated_store(client):
    """?store_id= must scope the probe CAfile to that store: after remediating ONLY
    firefox, firefox-scoped probes reject while system-scoped probes still accept."""
    pre = client.get("/api/probe?store_id=firefox").get_json()
    assert any(p["success"] for p in pre["probes"] if not p["crl_checked"])  # attack works
    r = client.post("/api/remediate", json={"store_id": "firefox", "mode": "root"})
    assert r.get_json()["success"]
    ff = client.get("/api/probe?store_id=firefox").get_json()
    assert all(not p["success"] for p in ff["probes"]), "firefox-scoped probes must reject post-fix"
    sy = client.get("/api/probe?store_id=system").get_json()
    assert any(p["success"] for p in sy["probes"] if not p["crl_checked"]), \
        "system store untouched — its probes must still accept (pre-fix)"
