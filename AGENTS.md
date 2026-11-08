# AGENTS.md — RootWatch

Read this first. It orients any AI coding tool (OpenCode, Claude Code, Cursor, …) working
in this repo. Full details: `docs/PLAN.md`, per-person orders: `docs/PERSON-A.md`,
`docs/PERSON-B.md`.

## What this is
RootWatch: a system-wide CA distrust manager for hackathons/demos. It audits every
fragmented trust store on a machine (system bundle, Firefox NSS/OneCRL, Chrome CRLSet,
certifi/requests, curl, Java cacerts, p11-kit shared trust, Docker certs.d),
distrusts a compromised root CA (mock "eMudhra" scenario) in one
action, and proves the fix with real TLS handshakes against a mock localhost server
(127.0.0.1:8443) presenting a **revoked** cert.

## Hard rules
1. **Sandbox by default.** All store paths resolve under `ROOTWATCH_ROOT` (default
   `./.sandbox`). Never touch real system stores unless `--real` is passed explicitly.
   Exception (read-only): `cli setup` *copies* the machine's real trust stores
   (`/etc/ssl/certs` bundle, certifi `cacert.pem`, Firefox NSS via `certutil` when
   available, Chrome's use of the system roots, Java `cacerts` via `keytool`, p11-kit
   anchors, Docker `certs.d`) into the sandbox — **clean, no fake
   data injected by default**. The compromised eMudhra root is loaded only on demand:
   `cli inject` / `demo/load-emudhra.sh` (`sandbox.plant_incident`), which sets
   `planted: true` in `scenario.runtime.json` and writes `known_bad.json`.
2. **Contract stability.** Do not change signatures in `rootwatch/stores/base.py`,
   `rootwatch/probes.py`, `rootwatch/manager.py`, `rootwatch/pki.py`, `rootwatch/server.py`
   headers — the other workstream builds against them.
3. **File ownership.** Person A owns `rootwatch/{pki,server,probes,manager,cli}.py` bodies,
   `rootwatch/stores/*.py` bodies, `tests/`. Person B owns `rootwatch/web.py`,
   `rootwatch/webapp/*`, `demo.sh`, `README.md`. Don't edit the other person's files;
   propose changes via the contract.
4. **Cross-platform.** Person A is on Linux, Person B on macOS. Use `pathlib`, never
   hardcoded POSIX-only paths outside `real=True` branches; keep LF line endings
   (`.gitattributes` enforces); `demo.sh` must stay LF.
5. **Python ≥3.12**, deps in `pyproject.toml` (`flask`, `requests`, `cryptography`).
   `certutil` may not exist on macOS — the Firefox store must fall back to a JSON mirror.
6. **Two frontends: CLI + web.** The CLI (`rootwatch/cli.py`, Person A) and the web UI
   (`rootwatch/web.py` + `rootwatch/webapp/`, Person B) both sit on the same
   `manager`/`probes`/`stores` contract. Keep them in sync. The web UI is a **Vue 3
   dashboard** (vendored at `rootwatch/webapp/vendor/vue.global.prod.js` — no build step,
   no CDN at demo time; do not delete the vendor file).

## Commands
```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]   # works on Linux & macOS
.venv/bin/python -m pytest tests/ -q                        # tests
.venv/bin/python -m rootwatch.cli setup                       # CLEAN sandbox from real stores + mock PKI
.venv/bin/python -m rootwatch.cli inject                      # plant the compromised eMudhra root (demo attack step; demo/load-emudhra.sh)
.venv/bin/python -m rootwatch.cli serve                       # mock TLS server :8443
.venv/bin/python -m rootwatch.cli probe                       # handshake probes
.venv/bin/python -m rootwatch.cli remediate                   # distrust root everywhere
.venv/bin/python -m rootwatch.cli web --port 8080             # web UI (or: rootwatch-web)
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

## Web API (implemented in `rootwatch/web.py`; see docs/WEB-API.md)
- `POST /api/audit` → full state: `{stores: [{id,name,icon,status,total_roots,roots,alerts,findings}],
  blocklist, affected}` (also aliased as `GET /api/stores`, `GET /api/blocklist`, `GET /api/health`)
- `POST /api/crl/update` → `{crl_pem?|url?}` → `{entries}` (persisted blocklist).
  Empty body (the **Update CRL** button) ingests the scenario CRL **plus live fetches
  of real public CRL distribution points** — ISRG Root X1 (`http://x1.c.lencr.org/`)
  and DigiCert roots by default; override with `ROOTWATCH_REAL_CRL_URLS`
  (comma-separated, `""` disables). CRLs are parsed as PEM *or* DER and
  signature-verified against the issuer cert in the sandbox bundle when present
  (forged CRLs are dropped); unreachable CDPs are skipped (offline-safe).
- `POST /api/remediate` → `{store_id|store_ids, mode: "spki"|"root"}` → `{success, actions, results}`
- `GET /api/probe` → `{server_url, cafile, probes[]}` (starts mock server on :8443 if needed).
  Optional `?store_id=<id>` scopes the probe CAfile to that store (`manager.probe_cafile`):
  its own bundle for bundle stores, or the system bundle filtered to that store's trusted
  roots for DB/JSON stores (firefox/chrome) — so pre/post remediation probes reflect the
  store that was actually fixed
- `POST /api/attack-demo` → `{mode, before, remediation, after, stores}` (for demo scripts; NOT a UI button)

## Demo narrative (what judges should see)
1. Mock eMudhra root trusted in all stores; `localhost` leaf cert minted then REVOKED (CRL).
2. Default clients (requests, curl — no revocation checking) → handshake **SUCCEEDS**.
3. CRL-aware clients (`openssl s_client -crl_check`) → reject.
4. One action distrusts the root in every store → **all** clients now REJECT.

MITM variant (`demo/run-mitm-demo.sh`, in-sandbox, no Docker): the attacker mints a
FRESH cert from the compromised CA — not on the CRL — so pre-fix even CRL-aware
clients accept it (`pki.mint_attacker_cert` + `server.start_server_with_cert`);
only root distrust (`remediate --mode root`) stops it.

Video demo (`demo/run-mitm-docker-demo.sh`): victim Docker container (`--network host`,
sandbox mounted at /sandbox, repo at /rootwatch) = "Bob" signing in to a fake
www.t-mobile.com served by a host phishing server (`rootwatch/mitmdemo.py`:
`mint_and_start` serves PHISH_PAGE, captures POSTed credentials to
`<sandbox>/attacker/loot.jsonl`). Pre-fix curl/urllib accept (even CRL-aware),
credentials are exfiltrated; then `pip install cryptography pyyaml requests` +
`PYTHONPATH=/rootwatch ROOTWATCH_ROOT=/sandbox python3 -m rootwatch.cli remediate
--mode root` INSIDE the container fixes all 8 stores and the retry is rejected.

Full visual variant (`demo/run-mitm-browser-demo.sh`): victim container with a real
desktop — Xvfb :99 + x11vnc + noVNC (host opens http://127.0.0.1:6080/vnc.html), Firefox
(profile /root/rw-profile) whose NSS DB is synced from the mounted sandbox bundle via
/usr/local/bin/sync-browser-trust, xterm open, container /etc/hosts maps
www.t-mobile.com -> 127.0.0.1, `--network host` reaches the host MITM server on :9443.
The RootWatch **dashboard also runs inside the container** (`rootwatch.cli web --host
0.0.0.0 --port 8081`, ROOTWATCH_ROOT=/sandbox, PYTHONPATH=/rootwatch) — open as Firefox
tab 2 or directly at http://127.0.0.1:8081/. Video flow: green-lock phishing page ->
Bob signs in -> loot in <sandbox>/attacker/loot.jsonl -> **fix in the web UI**: Audit ->
all 8 stores ALERT -> per store row "☢️ Distrust entire root" -> /usr/local/bin/watch-trust
auto re-syncs Firefox NSS when the bundle shrinks AND restarts Firefox (a running
Firefox caches its trust store in memory, so the NSS DB must be reloaded) -> the
phishing tab shows Firefox's "Warning: Security Risk" with a ⛔ Not Secure padlock.
Container helpers: browser-trust-check (does Firefox's NSS DB still trust the attacker
chain?), desktop-shot (PNG of the desktop), sync-browser-trust (manual re-import).
`--cleanup` stops the MITM server and removes the container
(pid/cid in /tmp/rootwatch-mitm-browser.*). All MITM scripts now kill a stale MITM
server from a previous run, remove leftover victim containers, fall back to an
ephemeral port if :9443 is busy, and verify the in-container dashboard is really up
and pointed at the victim's sandbox before declaring the stage ready.

## Remediation modes (SPKI vs root — expect judges to ask)
- `spki` (default, surgical): block only the compromised keys' SPKI sha256 hashes
  (OneCRL-style). Other certs from that CA and future key rotations keep working.
- `root` (nuclear): distrust the entire root CA — what Mozilla did with eMudhra, correct
  when the root's key material itself is compromised, at the cost of breaking every
  legit cert that CA issued. The web dashboard exposes both modes.
