"""Smoke test: the skeleton imports and the store registry wires up."""
from rootwatch.stores import all_stores
from rootwatch.stores.base import Scenario


def test_registry_has_eight_stores():
    stores = all_stores(real=False)
    ids = {s.id for s in stores}
    assert ids == {"system", "requests", "curl", "firefox", "chrome",
                   "java", "p11kit", "docker"}


def test_scenario_dataclass():
    s = Scenario(name="t", compromised_root_fingerprint="ab", revoked_serial="01",
                 revoked_subject_cn="localhost")
    assert s.name == "t"
