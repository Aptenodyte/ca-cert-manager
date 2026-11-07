"""Web interface (Person B implements routes against the manager contract).

Single-page dashboard, layout:
  [box 1] top row buttons: Audit CA stores · Update CRL · Jump to Affected
  [box 2] table: Application/CA store | Status | Alerts  (click row -> details:
          trusted roots list, CRL alert details, per-store buttons
          "Distrust SPKI hash" / "Distrust entire root")
  [box 3] live CLI log at the bottom

Routes (keep signatures):
  GET  /                  -> the UI (webapp/index.html)
  POST /api/audit         -> full state: { stores: [{ id, name, icon, status, total_roots,
                             roots: [RootInfo], alerts: [BlocklistEntry hitting this store] }],
                             blocklist: [BlocklistEntry] }
                             (manager.assess_all + manager.collect_blocklist + affected_stores)
  POST /api/crl/update    -> body {"crl_pem"?: str, "url"?: str} -> { entries: [BlocklistEntry] }
                             (manager.update_crl: ingest CRL into the app-level blocklist)
  POST /api/remediate     -> body {"store_id": str, "mode": "spki"|"root"}
                             -> { success, actions: [...], error }   (manager.remediate_selected)
Entry point: rootcanal-web = catrust.web:main ; also `rootcanal web` via CLI (Person A).
"""
from __future__ import annotations

import argparse


def create_app(scenario_path: str = "scenarios/emudhra.yaml", real: bool = False):
    """Build the Flask app. Person B fills in routes; keep signatures."""
    from flask import Flask

    app = Flask(__name__, static_folder="webapp", static_url_path="")

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.post("/api/audit")
    def api_audit():
        raise NotImplementedError

    @app.post("/api/crl/update")
    def api_crl_update():
        raise NotImplementedError

    @app.post("/api/remediate")
    def api_remediate():
        raise NotImplementedError

    return app


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="rootcanal-web")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--scenario", default="scenarios/emudhra.yaml")
    p.add_argument("--real", action="store_true", help="operate on real system stores")
    args = p.parse_args(argv)
    create_app(args.scenario, args.real).run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
