"""Trust store registry. Person A implements each store; registry wires them together."""
from __future__ import annotations

from .base import (
    KNOWN_BAD_FPS,
    BlocklistEntry,
    Finding,
    RemediationMode,
    RemediationResult,
    RootInfo,
    Scenario,
    StoreAssessment,
    TrustStore,
    sandbox_root,
)

__all__ = [
    "KNOWN_BAD_FPS",
    "BlocklistEntry",
    "Finding",
    "RemediationMode",
    "RemediationResult",
    "RootInfo",
    "Scenario",
    "StoreAssessment",
    "TrustStore",
    "sandbox_root",
    "all_stores",
]


def all_stores(real: bool = False) -> list[TrustStore]:
    """Instantiate every known store. Imported lazily to avoid hard deps at module import."""
    from .system import SystemStore
    from .requests_store import RequestsStore
    from .curl_store import CurlStore
    from .firefox import FirefoxStore
    from .chrome import ChromeStore

    return [
        SystemStore(real=real),
        RequestsStore(real=real),
        CurlStore(real=real),
        FirefoxStore(real=real),
        ChromeStore(real=real),
    ]
