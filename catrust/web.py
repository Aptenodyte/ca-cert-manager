"""Web interface (Person B). Single-page dashboard served from catrust/webapp/.

Layout (fixed contract, see AGENTS.md / docs/PERSON-B.md):
  [box 1] top row: search bar + Audit CA stores · Update CRL · Jump to Affected
  [box 2] table: Application/CA store | Status | Roots | Alerts  (click row -> details:
          trusted roots list, CRL alert details, per-store buttons
          "Distrust SPKI hash" / "Distrust entire root")
  [box 3] live CLI log at the bottom
  NOTE: no attack/demo button on the page — the live attack demo is the external
  script demo/run-attack-demo.sh (Docker victim container), driven via the API.

Routes:
  GET  /                  -> the UI (webapp/index.html)
  GET  /api/health        -> { ok, scenario, real } (used by demo scripts)
  POST /api/audit         -> full state: { stores: [{ id, name, icon, status, total_roots,
                              roots: [RootInfo], alerts: [BlocklistEntry], findings: [Finding] }],
                              blocklist: [BlocklistEntry], affected: [store_id],
                              scenario: {...} }
                              (manager.assess_all + manager.audit_all + manager.collect_blocklist
                               + manager.affected_stores)
  GET  /api/stores        -> alias of POST /api/audit (used by demo scripts)
  POST /api/crl/update    -> body {"crl_pem"?: str, "url"?: str} -> { entries: [BlocklistEntry] }
                              (manager.update_crl; empty body falls back to the scenario CRL)
  POST /api/remediate     -> body {"store_id": str | "store_ids": [str], "mode": "spki"|"root"}
                              -> { success, actions: [...], error, results }   (manager.remediate_selected)
  GET  /api/probe         -> { url, cafile, probes: [ProbeResult] }  (manager/probes/server:
                              starts the mock TLS server on 127.0.0.1:8443 if needed and runs
                              probes.probe_all against it)
  POST /api/attack-demo   -> scripted attack -> remediate-all -> re-probe (demo.sh /
                              demo/run-attack-demo.sh only; NOT a UI button)
                              body {"mode"?: "spki"|"root"} (default "root" — eMudhra case)

Entry point: rootcanal-web = catrust.web:main ; also `rootcanal web` via CLI (Person A).
"""
from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path

from . import manager, probes, server
from .stores import all_stores
from .stores.base import RemediationMode, Scenario, sandbox_root

DEFAULT_SERVER_HOST = os.environ.get("CATRUST_SERVER_HOST", server.DEFAULT_HOST)
DEFAULT_SERVER_PORT = int(os.environ.get("CATRUST_SERVER_PORT", str(server.DEFAULT_PORT)))


def _to_dict(obj):
    """Recursively convert dataclasses to JSON-able dicts."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    return obj


def create_app(scenario_path: str = "scenarios/emudhra.yaml", real: bool = False):
    """Build the Flask app. Routes wired to the manager/probes/server contract."""
    from flask import Flask, jsonify, request

    app = Flask(__name__, static_folder="webapp", static_url_path="")
    app.config["CATRUST_SCENARIO_PATH"] = scenario_path
    app.config["CATRUST_REAL"] = real
    app.config["CATRUST_BLOCKLIST"] = []   # BlocklistEntry objects ingested via /api/crl/update
    app.config["CATRUST_SERVER"] = None     # (thread, port) once the mock server is up

    def stores():
        return all_stores(real=real)

    def scenario() -> Scenario:
        return manager.load_scenario(scenario_path)

    def ensure_server() -> int:
        """Start the mock TLS server once (daemon thread); return its port."""
        srv = app.config["CATRUST_SERVER"]
        if srv is not None:
            return srv[1]
        pki_dir = os.environ.get("CATRUST_PKI_DIR")
        if pki_dir:
            pki_dir = Path(pki_dir)
        elif not real:
            pki_dir = sandbox_root() / "pki"
        else:
            pki_dir = None
        try:
            thread, port = server.start_server_background(
                host=DEFAULT_SERVER_HOST, port=DEFAULT_SERVER_PORT, pki_dir=pki_dir
            )
        except Exception as e:
            raise RuntimeError(
                f"mock TLS server could not start ({e}); "
                "run `rootcanal setup` first so the sandbox PKI exists"
            ) from e
        app.config["CATRUST_SERVER"] = (thread, port)
        return port

    def probe_payload(store_id: str | None = None) -> dict:
        port = ensure_server()
        sc = scenario()
        # scope the probe CAfile to the requested store (default: first with one),
        # so pre/post remediation probes reflect the store that was actually fixed
        cafile = manager.probe_cafile(stores(), store_id)
        url = f"https://127.0.0.1:{port}/"
        results = probes.probe_all(url, cafile=cafile, crl_pem=sc.crl_pem or None)
        return {"server_url": url, "url": url, "cafile": cafile,
                "probes": [_to_dict(r) for r in results]}

    def audit_payload() -> dict:
        sc = scenario()
        stores_list = stores()
        assessments = manager.assess_all(stores_list)
        findings = manager.audit_all(stores_list, sc)
        crl_pems = [p for p in [sc.crl_pem] if p]
        blocklist = list(
            manager.collect_blocklist(
                crl_pems=crl_pems or None,
                extra_spki_hashes=sc.compromised_spki_hashes or None,
            )
        )
        # merge the persisted application-level blocklist (written by "Update CRL")
        # and any entries ingested in this process
        seen = {(e.serial, e.spki_hash) for e in blocklist}
        for e in list(manager.load_blocklist_state()) + list(app.config["CATRUST_BLOCKLIST"]):
            key = (e.serial, e.spki_hash)
            if key not in seen:
                blocklist.append(e)
                seen.add(key)
        affected = manager.affected_stores(stores_list, blocklist)

        out_stores = []
        for st in stores_list:
            a = assessments.get(st.id)
            roots = list(a.roots) if a else []
            root_spkis = {r.spki_hash for r in roots}
            alerts = [e for e in blocklist if e.spki_hash and e.spki_hash in root_spkis]
            if st.id in affected:
                # CRL serial entries hit every store trusting the chain that issued
                # the revoked leaf (the compromised root/intermediate SPKIs)
                for e in blocklist:
                    if e.serial and e.serial == sc.revoked_serial and e not in alerts:
                        alerts.append(e)
            if st.id in affected and not alerts:
                alerts = list(blocklist)
            fnd = findings.get(st.id, [])
            status = "alert" if (alerts or fnd or st.id in affected) else "ok"
            out_stores.append(
                {
                    "id": st.id,
                    "name": st.display_name,
                    "icon": st.icon,
                    "status": status,
                    "total_roots": a.total_roots if a else len(roots),
                    "roots": [_to_dict(r) for r in roots],
                    "alerts": [_to_dict(e) for e in alerts],
                    "findings": [_to_dict(f) for f in fnd],
                }
            )
        return {
            "stores": out_stores,
            "blocklist": [_to_dict(e) for e in blocklist],
            "affected": sorted(affected),
            "scenario": {
                "name": sc.name,
                "narrative": sc.narrative,
                "revoked_subject_cn": sc.revoked_subject_cn,
                "revoked_serial": sc.revoked_serial,
                "compromised_root_fingerprint": sc.compromised_root_fingerprint,
                "compromised_spki_hashes": list(sc.compromised_spki_hashes),
            },
        }

    def _err(e: Exception, code: int = 500):
        if isinstance(e, NotImplementedError):
            return jsonify({"error": f"backend not implemented yet: {e}"}), 503
        return jsonify({"error": f"{type(e).__name__}: {e}"}), code

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def api_health():
        return jsonify({"ok": True, "scenario": scenario_path, "real": real})

    @app.post("/api/audit")
    def api_audit():
        try:
            return jsonify(audit_payload())
        except Exception as e:  # noqa: BLE001 — API boundary, always JSON
            return _err(e)

    @app.get("/api/stores")
    def api_stores():
        """Alias of POST /api/audit for demo scripts."""
        return api_audit()

    @app.get("/api/blocklist")
    def api_blocklist():
        try:
            sc = scenario()
            entries = list(
                manager.collect_blocklist(
                    crl_pems=[p for p in [sc.crl_pem] if p] or None,
                    extra_spki_hashes=sc.compromised_spki_hashes or None,
                )
            ) + list(manager.load_blocklist_state()) + list(app.config["CATRUST_BLOCKLIST"])
            return jsonify({"entries": [_to_dict(e) for e in entries]})
        except Exception as e:  # noqa: BLE001
            return _err(e)

    @app.post("/api/crl/update")
    def api_crl_update():
        body = request.get_json(silent=True) or {}
        crl_pem = body.get("crl_pem")
        url = body.get("url")
        try:
            if not crl_pem and not url:
                # "Update CRL" button with empty body: ingest the scenario's CRL
                crl_pem = scenario().crl_pem or None
            entries = manager.update_crl(crl_pem=crl_pem, url=url)
        except Exception as e:  # noqa: BLE001
            return _err(e)
        app.config["CATRUST_BLOCKLIST"] = list(entries)
        return jsonify({"entries": [_to_dict(e) for e in entries]})

    @app.post("/api/remediate")
    def api_remediate():
        body = request.get_json(silent=True) or {}
        store_id = body.get("store_id")
        store_ids = body.get("store_ids")
        ids = store_ids if isinstance(store_ids, list) else ([store_id] if store_id else [])
        if not ids:
            return jsonify({"success": False, "actions": [],
                            "error": "body must include store_id or store_ids"}), 400
        try:
            mode = RemediationMode(body.get("mode", RemediationMode.SPKI.value))
        except ValueError:
            return jsonify({"success": False, "actions": [],
                            "error": f"bad mode {body.get('mode')!r}; want 'spki' or 'root'"}), 400
        try:
            results = manager.remediate_selected(stores(), ids, scenario(), mode)
        except Exception as e:  # noqa: BLE001
            return _err(e)
        results_json = {k: _to_dict(v) for k, v in results.items()}
        if len(ids) == 1 and ids[0] in results:
            r = results[ids[0]]
            return jsonify({"success": r.success, "actions": list(r.actions),
                            "error": r.error, "results": results_json})
        return jsonify({
            "success": all(r.success for r in results.values()) if results else False,
            "actions": [a for r in results.values() for a in r.actions],
            "error": "; ".join(r.error for r in results.values() if r.error),
            "results": results_json,
        })

    @app.get("/api/probe")
    def api_probe():
        """Run the handshake probe matrix against the mock server (starts it if needed).
        Optional ?store_id=<id> scopes the probe CAfile to that store's trust roots."""
        try:
            return jsonify(probe_payload(request.args.get("store_id")))
        except Exception as e:  # noqa: BLE001
            return _err(e)

    @app.post("/api/attack-demo")
    def api_attack_demo():
        """Scripted demo for demo.sh / demo/run-attack-demo.sh (NOT a UI button):
        probe (attack) -> remediate every store -> re-probe (proof)."""
        body = request.get_json(silent=True) or {}
        try:
            mode = RemediationMode(body.get("mode", RemediationMode.ROOT.value))
        except ValueError:
            return jsonify({"error": f"bad mode {body.get('mode')!r}; want 'spki' or 'root'"}), 400
        try:
            before = probe_payload()
            results = manager.remediate_selected(
                stores(), [st.id for st in stores()], scenario(), mode
            )
            after = probe_payload()
            audit = audit_payload()
        except Exception as e:  # noqa: BLE001
            return _err(e)
        return jsonify({
            "mode": mode.value,
            "before": before,
            "remediation": {k: _to_dict(v) for k, v in results.items()},
            "after": after,
            "stores": [{"id": s["id"], "name": s["name"], "status": s["status"]}
                       for s in audit["stores"]],
        })

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
