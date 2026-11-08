# Instructions — Person B (judge experience: web UI + demo + docs)

You own: `rootwatch/web.py`, `rootwatch/webapp/*` (index.html, app.js, css), `demo.sh`,
`README.md`, `docs/` (except PERSON-A.md).

DO NOT touch: `rootwatch/pki.py`, `rootwatch/server.py`, `rootwatch/probes.py` bodies,
`rootwatch/stores/*.py` bodies, `rootwatch/manager.py` bodies, `rootwatch/cli.py` bodies,
`tests/test_skeleton.py`. Build ONLY against these contracts:
- `rootwatch.stores.all_stores(real=False)` -> list[TrustStore] with `.id`, `.display_name`,
  `.icon`, `.audit(scenario)`, `.remediate(scenario)`, `.cafile()`
- `rootwatch.stores.base.Scenario` dataclass
- `rootwatch.manager.assess_all(stores) -> dict[store_id, StoreAssessment]` — DEFAULT
  system-wide posture view (all roots per store, flagged weak/expired/known-bad).
- `rootwatch.manager.audit_all(stores, scenario) -> dict[store_id, list[Finding]]` — incident overlay.
- `rootwatch.manager.remediate_selected(stores, ids, scenario, mode=SPKI) -> dict[store_id, RemediationResult]`
- `rootwatch.manager.load_scenario(path) -> Scenario`
- `rootwatch.probes.probe_all(url, cafile=..., crl_pem=...) -> list[ProbeResult]`
  (ProbeResult: client, url, success, verify_error, detail, crl_checked)
- `rootwatch.server.start_server_background(pki_dir=...) -> (thread, port)`
- Web API (implement in `web.py`, keep the route signatures already there):
  GET /api/stores, POST /api/remediate {store_ids}, GET /api/probe, POST /api/attack-demo.

## Stack note
The UI is **Vue 3 via the vendored global build** (`rootwatch/webapp/vendor/vue.global.prod.js`,
already downloaded — no npm/build step, works offline). `index.html` is the Vue template,
`app.js` the app logic, `style.css` the dark theme. Keep using the vendored file.

## Layout to build (fixed — judges asked for exactly this)
1. **Top box**: search bar + buttons **Audit CA stores**, **Update CRL**, **Jump to Affected**.
2. **Table box**: rows = Application/CA store | Status | Roots | Alerts. Click a row →
   expand: trusted-roots list; if CRL alerts hit this store, show alert details +
   **Distrust SPKI hash** / **Distrust entire root** buttons (per-row remediation).
3. **Live log** at the bottom, full width.

## API contract (implement these routes in `web.py`, keep signatures)
- `POST /api/audit` → `{ stores: [{id,name,icon,status,total_roots,roots:[RootInfo],alerts:[BlocklistEntry]}], blocklist: [...] }`
  (wire: `manager.assess_all` + `manager.collect_blocklist` + `manager.affected_stores`)
- `POST /api/crl/update` → body `{crl_pem?|url?}` → `{ entries: [BlocklistEntry] }` (`manager.update_crl`)
- `POST /api/remediate` → body `{store_id, mode: "spki"|"root"}` → `{ success, actions, error }`
  (`manager.remediate_selected([store], [store_id], scenario, mode)`)
Backend types (Person A owns): `rootwatch.stores.base` (`TrustStore.assess/audit/remediate(scenario, mode)`,
`RootInfo`, `StoreAssessment`, `BlocklistEntry`, `Finding`, `Scenario`, `RemediationMode`),
`rootwatch.manager` (`assess_all`, `collect_blocklist`, `update_crl`, `affected_stores`,
`audit_all`, `remediate_selected`, `load_scenario`), `rootwatch.probes`, `rootwatch.server`, `rootwatch.pki`.

## Build order
1. **API routes in `web.py`**: `POST /api/audit`, `POST /api/crl/update`, `POST /api/remediate`
   wired to manager (contracts above). Keep route signatures.
2. **Top box**: search (filters store rows by name/id/root subject/alert fields) +
   Audit / Update CRL / Jump to Affected buttons.
3. **Stores table**: one row per store (name | status | roots | alerts); click to expand
   the detail row: trusted roots list + CRL alert box with Distrust SPKI / Distrust root.
4. **Live log** at the bottom; every API call logs a line.
5. **Docker demo**: `demo/run-attack-demo.sh` spins a victim container, runs attack
   probes, remediates live, re-probes (no demo button on the page).

## Definition of done
- `rootwatch web --port 8080` serves the page; Audit populates the table; an alerted
  row expands to roots + alert with working Distrust SPKI / Distrust root buttons;
  after remediation the row flips to ok and the log shows the actions.
- `./demo/run-attack-demo.sh --image python:3.14-slim` runs attack → remediate → proof.
