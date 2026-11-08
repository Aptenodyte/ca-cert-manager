"""Mock TLS server presenting the REVOKED leaf cert (Person A).

Serves a tiny page on https://127.0.0.1:8443 with the leaf+intermediate chain.
The leaf is revoked (see pki.revoke_leaf) — clients that don't check revocation
will still accept it: that's the attack.
"""
from __future__ import annotations

import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .pki import PKI, load_pki

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8443

PAGE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
        b"Connection: close\r\n\r\n%s")
BODY = (b"<h1>rootwatch mock server</h1><p>You are talking to a server whose "
        b"certificate has been REVOKED (CRL). If your client accepted this "
        b"handshake, revocation checking is not protecting you.</p>")


def make_ssl_context(pki: PKI) -> ssl.SSLContext:
    """Server-side context with the leaf+intermediate chain (revoked leaf)."""
    import tempfile
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory() as td:
        certf = Path(td) / "chain.pem"
        keyf = Path(td) / "leaf.key"
        certf.write_text(pki.chain_pem)
        keyf.write_text(pki.leaf_key_pem)
        ctx.load_cert_chain(certf, keyf)
    return ctx


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGE % (len(BODY), BODY)
        self.wfile.write(body)

    def log_message(self, *args):  # quiet
        pass


def _free_port(host: str) -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def start_server_background(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                            pki_dir: Path | None = None) -> tuple[threading.Thread, int]:
    """Start the mock server in a daemon thread; returns (thread, actual_port)."""
    pki = load_pki(pki_dir) if pki_dir else None
    if pki is None:
        raise ValueError("pki_dir required (sandbox must be set up first)")
    if port == 0:
        port = _free_port(host)
    ctx = make_ssl_context(pki)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    actual = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return t, actual


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
               pki_dir: Path | None = None) -> None:
    """Blocking server for CLI use."""
    import os
    pki_dir = pki_dir or Path(os.environ.get("ROOTWATCH_ROOT", ".sandbox")) / "pki"
    t, actual = start_server_background(host, port, pki_dir)
    print(f"rootwatch mock TLS server on https://{host}:{actual} (revoked leaf cert)")
    t.join()


class _BodyHandler(BaseHTTPRequestHandler):
    body = b"ok"

    def do_GET(self):
        self.wfile.write(PAGE % (len(self.body), self.body))

    def log_message(self, *args):  # quiet
        pass


def start_server_with_cert(host: str = DEFAULT_HOST, port: int = 0,
                           certfile: str | Path = "", keyfile: str | Path = "",
                           body: bytes = b"<h1>rootwatch MITM server</h1>") -> tuple[threading.Thread, int]:
    """Generic TLS server presenting an ARBITRARY cert chain (e.g. the attacker's
    freshly-minted, non-revoked cert from the compromised CA). Returns (thread, port)."""
    if port == 0:
        port = _free_port(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(certfile), str(keyfile))
    handler = type("_H", (_BodyHandler,), {"body": body})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.handle_error = lambda *a, **k: None  # quiet: rejected handshakes are expected here
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    actual = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return t, actual
