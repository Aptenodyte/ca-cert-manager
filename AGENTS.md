# AGENTS.md — RootCanal

Read this first. It orients any AI coding tool (OpenCode, Claude Code, Cursor, …) working
in this repo. Full details: `docs/PLAN.md`, per-person orders: `docs/PERSON-A.md`,
`docs/PERSON-B.md`.

## What this is
RootCanal: a system-wide CA distrust manager for hackathons/demos. It audits every
fragmented trust store on a machine (system bundle, Firefox NSS/OneCRL, Chrome CRLSet,
certifi/requests, curl), distrusts a compromised root CA (mock "eMudhra" scenario) in one
action, and proves the fix with real TLS handshakes against a mock localhost server
(127.0.0.1:8443) presenting a **revoked** cert.

## Hard rules
1. **Sandbox by default.** All store paths resolve under `CATRUST_ROOT` (default
   `./.sandbox`). Never touch real system stores unless `--real` is passed explicitly.
   Exception (read-only): `cli setup` *copies* the machine's real trust stores
   (`/etc/ssl/certs` bundle, certifi `cacert.pem`, Firefox NSS via `certutil` when
   available, Chrome's use of the system roots) into the sandbox, then plants the
   compromised eMudhra root on top — so the dashboard shows the real ~150 roots plus
   the incident. `scenario.runtime.json` records `seeded_from_real_stores: true`.
2. **Contract stability.** Do not change signatures in `catrust/stores/base.py`,
   `catrust/probes.py`, `catrust/manager.py`, `catrust/pki.py`, `catrust/server.py`
   headers — the other workstream builds against them.
3. **File ownership.** Person A owns `catrust/{pki,server,probes,manager,cli}.py` bodies,
   `catrust/stores/*.py` bodies, `tests/`. Person B owns `catrust/web.py`,
   `catrust/webapp/*`, `demo.sh`, `README.md`. Don't edit the other person's files;
   propose changes via the contract.
4. **Cross-platform.** Person A is on Linux, Person B on macOS. Use `pathlib`, never
   hardcoded POSIX-only paths outside `real=True` branches; keep LF line endings
   (`.gitattributes` enforces); `demo.sh` must stay LF.
5. **Python ≥3.12**, deps in `pyproject.toml` (`flask`, `requests`, `cryptography`).
   `certutil` may not exist on macOS — the Firefox store must fall back to a JSON mirror.
6. **Two frontends: CLI + web.** The CLI (`catrust/cli.py`, Person A) and the web UI
   (`catrust/web.py` + `catrust/webapp/`, Person B) both sit on the same
   `manager`/`probes`/`stores` contract. Keep them in sync. The web UI is a **Vue 3
   dashboard** (vendored at `catrust/webapp/vendor/vue.global.prod.js` — no build step,
   no CDN at demo time; do not delete the vendor file).

## Commands
```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]   # works on Linux & macOS
.venv/bin/python -m pytest tests/ -q                        # tests
.venv/bin/python -m catrust.cli setup                       # build sandbox + mock PKI
.venv/bin/python -m catrust.cli serve                       # mock TLS server :8443
.venv/bin/python -m catrust.cli probe                       # handshake probes
.venv/bin/python -m catrust.cli remediate                   # distrust root everywhere
.venv/bin/python -m catrust.cli web --port 8080             # web UI (or: rootcanal-web)
./demo.sh                                                   # one-shot scripted demo
```

## Dashboard layout (the contract for the UI)
Single page, three boxes:
1. **Top box**: search bar + three buttons — **Audit CA stores** (`POST /api/audit`),
   **Update CRL** (`POST /api/crl/update`), **Jump to Affected** (opens first alerted row).
2. **Table box**: one row per Application/CA store — name | Status | Roots | Alerts.
   Clicking a row expands details: the store's **trusted roots list**, and if a CRL
   alert affects it, the **alert details + two buttons: "Distrust SPKI hash" (🔬 spki)
   or "Distrust entire root" (☢️ root)** → `POST /api/remediate {store_id, mode}`.
3. **Live CLI log** at the bottom (full width, auto-scroll).
No demo/attack button on the page — the live attack→remediation demo is the external
script `demo/run-attack-demo.sh` (Docker victim container), not a UI button.

## Web API (implemented in `catrust/web.py`; see docs/WEB-API.md)
- `POST /api/audit` → full state: `{stores: [{id,name,icon,status,total_roots,roots,alerts,findings}],
  blocklist, affected}` (also aliased as `GET /api/stores`, `GET /api/blocklist`, `GET /api/health`)
- `POST /api/crl/update` → `{crl_pem?|url?}` → `{entries}` (persisted blocklist).
  Empty body (the **Update CRL** button) ingests the scenario CRL **plus live fetches
  of real public CRL distribution points** — ISRG Root X1 (`http://x1.c.lencr.org/`)
  and DigiCert roots by default; override with `CATRUST_REAL_CRL_URLS`
  (comma-separated, `""` disables). CRLs are parsed as PEM *or* DER and
  signature-verified against the issuer cert in the sandbox bundle when present
  (forged CRLs are dropped); unreachable CDPs are skipped (offline-safe).
- `POST /api/remediate` → `{store_id|store_ids, mode: "spki"|"root"}` → `{success, actions, results}`
- `GET /api/probe` → `{server_url, cafile, probes[]}` (starts mock server on :8443 if needed)
- `POST /api/attack-demo` → `{mode, before, remediation, after, stores}` (for demo scripts; NOT a UI button)

## Demo narrative (what judges should see)
1. Mock eMudhra root trusted in all stores; `localhost` leaf cert minted then REVOKED (CRL).
2. Default clients (requests, curl — no revocation checking) → handshake **SUCCEEDS**.
3. CRL-aware clients (`openssl s_client -crl_check`) → reject.
4. One action distrusts the root in every store → **all** clients now REJECT.

## Remediation modes (SPKI vs root — expect judges to ask)
- `spki` (default, surgical): block only the compromised keys' SPKI sha256 hashes
  (OneCRL-style). Other certs from that CA and future key rotations keep working.
- `root` (nuclear): distrust the entire root CA — what Mozilla did with eMudhra, correct
  when the root's key material itself is compromised, at the cost of breaking every
  legit cert that CA issued. The web dashboard exposes both modes.
