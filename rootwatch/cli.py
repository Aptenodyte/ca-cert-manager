"""Scripted CLI (entry point rootwatch=...). Person A.

Commands:
  rootwatch setup                 # build sandbox + mock PKI + seed all stores
  rootwatch audit                 # system-wide assessment + scenario findings (table)
  rootwatch remediate [--stores a,b] [--mode spki|root]
  rootwatch probe                 # handshake probes vs the mock server (starts it)
  rootwatch demo                  # scripted attack -> remediate -> proof
  rootwatch serve                 # mock TLS server (blocking)
  rootwatch web [--port 8080]     # launch the web UI
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import manager, sandbox
from .stores import all_stores
from .stores.base import RemediationMode


def _stores(real: bool):
    return all_stores(real=real)


def _scenario(args):
    return manager.load_scenario(args.scenario)


def cmd_setup(args) -> int:
    root = sandbox.setup_sandbox()
    print(f"✅ sandbox ready at {root}")
    print("   mock PKI in pki/ (root -> intermediate -> REVOKED leaf for localhost)")
    print("   all 5 trust stores seeded CLEAN from the machine's real trust stores")
    print("   (no incident planted — run `rootwatch inject` or demo/load-emudhra.sh to load the eMudhra certs)")
    return 0


def cmd_inject(args) -> int:
    root = sandbox.plant_incident()
    print(f"✅ eMudhra incident loaded into sandbox at {root}")
    return 0


def cmd_audit(args) -> int:
    stores = _stores(args.real)
    sc = _scenario(args)
    print(f"=== system-wide assessment (scenario: {sc.name}) ===")
    assess = manager.assess_all(stores)
    aud = manager.audit_all(stores, sc)
    # same blocklist as the web audit: scenario CRL + compromised SPKIs + persisted state
    bl = manager.collect_blocklist(
        crl_pems=[p for p in [sc.crl_pem] if p] or None,
        extra_spki_hashes=sc.compromised_spki_hashes or None,
    ) + manager.load_blocklist_state()
    aff = manager.affected_stores(stores, bl) if bl else set()
    for sid, a in assess.items():
        status = "ALERT" if (aud[sid] or sid in aff) else "ok"
        print(f"  {a.icon} {sid:9s} roots={a.total_roots:3d} findings={len(a.findings)} status={status}")
        for f in aud[sid]:
            print(f"      ⚠ {f.kind}: {f.detail}")
    print(f"  blocklist entries: {len(bl)} | affected stores: {sorted(aff) or 'none'}")
    return 0


def cmd_remediate(args) -> int:
    stores = _stores(args.real)
    sc = _scenario(args)
    ids = [] if args.stores == "all" else [s.strip() for s in args.stores.split(",")]
    mode = RemediationMode(args.mode)
    print(f"=== remediating {ids or 'all'} stores, mode={mode.value} ===")
    results = manager.remediate_selected(stores, ids, sc, mode)
    for sid, r in results.items():
        print(f"  {sid}: {'✅' if r.success else '❌'}")
        for a in r.actions:
            print(f"      · {a}")
    return 0 if all(r.success for r in results.values()) else 1


def cmd_probe(args) -> int:
    from . import probes, server
    pki_dir = Path(args.pki_dir) if args.pki_dir else sandbox.sandbox_root() / "pki"
    t, port = server.start_server_background(port=args.port, pki_dir=pki_dir)
    url = f"https://127.0.0.1:{port}/"
    sc = _scenario(args)
    cafile = None
    if not args.real:
        cf = sandbox.sandbox_root() / "etc" / "ssl" / "ca-bundle.crt"
        cafile = str(cf) if cf.exists() else None
    print(f"=== handshake probes vs {url} (revoked leaf cert) ===")
    for r in probes.probe_all(url, cafile=cafile, crl_pem=sc.crl_pem or None):
        mark = "ACCEPTED ⚠️  (attack works)" if r.success else f"REJECTED ✅ {r.verify_error[:70]}"
        print(f"  {r.client:14s} crl={r.crl_checked!s:5s} {mark}")
    return 0


def cmd_demo(args) -> int:
    """Scripted attack -> remediate -> proof (used by demo/ scripts)."""
    if not (sandbox.sandbox_root() / "pki" / "pki.json").exists():
        cmd_setup(args)
    print("=== [1/3] ATTACK: probes with compromised root still trusted ===")
    rc = cmd_probe(args)
    print("=== [2/3] REMEDIATE: distrust everywhere (mode from scenario/args) ===")
    args.stores = "all"
    cmd_remediate(args)
    print("=== [3/3] PROOF: same probes after remediation ===")
    cmd_probe(args)
    return rc


def cmd_web(args) -> int:
    from .web import main as web_main
    web_main(["--host", args.host, "--port", str(args.port),
              "--scenario", args.scenario] + (["--real"] if args.real else []))
    return 0


def cmd_serve(args) -> int:
    from .server import run_server
    pki_dir = Path(args.pki_dir) if args.pki_dir else sandbox.sandbox_root() / "pki"
    run_server(port=args.port, pki_dir=pki_dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rootwatch", description="System-wide CA distrust manager")
    p.add_argument("--real", action="store_true", help="operate on real system stores (dangerous)")
    p.add_argument("--scenario", default="scenarios/emudhra.yaml")
    p.add_argument("--pki-dir", default=None, help="mock PKI dir (default: $ROOTWATCH_ROOT/pki)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    sub.add_parser("inject", help="load the compromised eMudhra root+CA into the sandbox stores (demo attack step)")
    sub.add_parser("audit")
    r = sub.add_parser("remediate")
    r.add_argument("--stores", default="all")
    r.add_argument("--mode", default="spki", choices=["spki", "root"])
    pr = sub.add_parser("probe")
    pr.add_argument("--port", type=int, default=8443)
    sub.add_parser("demo")
    sub.add_parser("serve").add_argument("--port", type=int, default=8443)
    w = sub.add_parser("web", help="launch the web UI")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--host", default="127.0.0.1")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "setup": cmd_setup, "inject": cmd_inject, "audit": cmd_audit,
        "remediate": cmd_remediate,
        "probe": cmd_probe, "demo": cmd_demo, "serve": cmd_serve, "web": cmd_web,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
