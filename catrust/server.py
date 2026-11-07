"""Mock TLS server presenting the REVOKED leaf cert (Person A implements).

Contract:
- run_server(host="127.0.0.1", port=8443, pki=None, pki_dir=None) -> None  (blocking)
- make_ssl_context(pki: PKI) -> ssl.SSLContext  (server side, chain = leaf+intermediate)
- start_server_background(host, port, pki_dir) -> (threading.Thread, int)  (for web UI/demo)
- Serves a small HTML page on GET / and always presents the revoked leaf.
"""
from __future__ import annotations

import ssl
import threading
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8443


def make_ssl_context(pki) -> ssl.SSLContext:
    raise NotImplementedError


def start_server_background(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                            pki_dir: Path | None = None) -> tuple[threading.Thread, int]:
    """Start the mock server in a daemon thread; returns (thread, actual_port)."""
    raise NotImplementedError


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, pki_dir: Path | None = None) -> None:
    """Blocking server for CLI use."""
    raise NotImplementedError
