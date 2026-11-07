"""Scripted CLI (Person A implements commands; entry point rootcanal=...).

Commands:
  rootcanal setup                 # build sandbox + mock PKI + populate stores (trusted)
  rootcanal audit                 # audit all stores against the scenario, print table
  rootcanal remediate [--stores a,b]   # distrust compromised root everywhere
  rootcanal probe                 # run handshake probes against the mock server
  rootcanal demo                  # scripted before/after demo (used by demo.sh)
  rootcanal serve                 # run the mock TLS server (blocking)
  rootcanal web [--port 8080]     # launch the web UI (delegates to catrust.web)
Global flags: --real (touch real system stores instead of sandbox), --scenario PATH
"""
from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rootcanal", description="System-wide CA distrust manager")
    p.add_argument("--real", action="store_true", help="operate on real system stores (dangerous)")
    p.add_argument("--scenario", default="scenarios/emudhra.yaml")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("setup")
    sub.add_parser("audit")
    r = sub.add_parser("remediate")
    r.add_argument("--stores", default="all", help="comma-separated store ids or 'all'")
    sub.add_parser("probe")
    sub.add_parser("demo")
    sub.add_parser("serve")
    w = sub.add_parser("web", help="launch the web UI")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--host", default="127.0.0.1")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raise NotImplementedError(f"command not implemented yet: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
