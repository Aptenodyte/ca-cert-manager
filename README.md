# RootWatch 👁️

When the **eMudhra root CA compromise** came to light, browsers moved fast — Mozilla
distrusted the root in Firefox via OneCRL, Chrome pushed a CRLSet/policy update. But every
application that ships its **own CA trust store** — Python's `certifi` behind `requests`,
`curl`'s bundle, Java keystores, pinned internal bundles — needed its own per-application
patch or release before it stopped trusting the compromised CA. In that gap, revoked
certificates kept working.

**RootWatch closes that gap: instead of waiting for per-app patches, we patch the CA trust
stores ourselves — centrally, in one action.** It audits every fragmented trust store on a
machine (system bundle, Firefox NSS/OneCRL, Chrome CRLSet/policy, certifi/requests,
curl, Java `cacerts`, p11-kit shared trust, Docker `certs.d` — 8 stores),
distrusts a compromised root CA (the mock **eMudhra** scenario) everywhere it appears, and
**physically proves the fix** with real TLS handshakes against a mock localhost server
(`127.0.0.1:8443`) presenting a **revoked** certificate.

> 🧪 **Sandboxed by default.** Every store path resolves under `ROOTWATCH_ROOT` (default
> `./.sandbox`). Real system stores are only touched with an explicit `--real` flag.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # Linux & macOS
.venv/bin/python -m rootwatch.cli setup                          # clean sandbox from REAL stores + mock PKI (no fake data injected)
./demo/load-emudhra.sh                                          # plant the compromised eMudhra root into the sandbox (attack step)
.venv/bin/python -m rootwatch.cli web --port 8080                # dashboard: http://127.0.0.1:8080
./demo.sh                                                      # one-shot scripted demo (drives the web API)
./demo/run-attack-demo.sh --image python:3.14-slim             # live attack in a Docker victim container
./demo/run-mitm-demo.sh                                        # simulated MITM in-sandbox: fresh cert from the
                                                               # compromised CA (NOT on the CRL) — even CRL-aware
                                                               # clients accept it pre-fix; root distrust stops it
./demo/run-mitm-docker-demo.sh                                 # VIDEO demo: phishing site for www.t-mobile.com in a
                                                               # Docker victim container — Bob's credentials get
                                                               # exfiltrated, then RootWatch is installed IN the
                                                               # container and blocks the MITM (mode=root)
./demo/run-mitm-browser-demo.sh                                # FULL VISUAL demo: real Firefox desktop inside the
                                                               # victim container via noVNC — open
                                                               # http://127.0.0.1:6080/vnc.html, watch Bob get phished
                                                               # at www.t-mobile.com, then fix it live in the
                                                               # container terminal (--cleanup when done)
```

Other commands:

```bash
.venv/bin/python -m rootwatch.cli serve                          # mock TLS server on 127.0.0.1:8443 (blocking)
.venv/bin/python -m rootwatch.cli audit                          # audit all stores vs. the scenario
.venv/bin/python -m rootwatch.cli probe                          # handshake probes (requests/curl/openssl -crl_check)
.venv/bin/python -m rootwatch.cli remediate [--stores a,b] [--mode spki|root]
.venv/bin/python -m rootwatch.cli demo                           # scripted attack -> remediate -> proof
.venv/bin/python -m pytest tests/ -q                           # tests
# console scripts after install: rootwatch …, rootwatch-web …
```

## The demo story (what judges should see)

1. A mock **eMudhra** root CA is trusted in *all* stores; a `localhost` leaf cert is minted,
   then **revoked** via a CRL.
2. Default clients (**requests**, **curl**) do no revocation checking → the handshake
   **SUCCEEDS** = the attack works.
3. CRL-aware clients (`openssl s_client -crl_check`) **reject** the cert.
4. One action (the dashboard's **☢️ Distrust entire root**, or `POST /api/attack-demo`)
   distrusts the root in **every** store → **all** clients now **reject** the handshake.

**MITM variant** (`./demo/run-mitm-demo.sh`, no Docker): the attacker mints a *fresh*
cert for `bank.local` from the compromised CA. Its serial is **not on the CRL**, so
pre-fix even CRL-aware clients (`requests` with `VERIFY_CRL_CHECK_LEAF`,
`openssl -crl_check`) **accept** the handshake — revocation checking cannot help.
After one `remediate --mode root` across all 8 stores, every client **rejects** it.
That is the eMudhra lesson: when the root key is compromised, only distrusting the
root is sufficient.

**Video demo** (`./demo/run-mitm-docker-demo.sh`): a victim Docker container
(`--network host`, sandbox stores bind-mounted at `/sandbox`) plays **Bob**, who
signs in to a fake `www.t-mobile.com` served by a host-side phishing server with a
fresh eMudhra-signed cert (`curl --resolve www.t-mobile.com:9443:127.0.0.1`).
Pre-fix the TLS handshake is accepted — even by a CRL-aware client — and Bob's
credentials land in the attacker's loot file (`💀 stolen: {...}`). Then RootWatch
is pip-installed **inside the victim container**, `rootwatch audit` shows all 8
stores ALERT, one `rootwatch remediate --mode root` fixes them (the mounted bundle
updates in place), and Bob's reload is **rejected** (`unable to get local issuer
certificate`). ✅ DEMO PASS.

**Full visual demo** (`./demo/run-mitm-browser-demo.sh`): sets up a victim container
with a real desktop (Xvfb + x11vnc + noVNC on `:6080`, Firefox + xterm) **and the
RootWatch dashboard running inside that container** (port `:8081`, pointed at the
victim's `/sandbox`). Open `http://127.0.0.1:6080/vnc.html` in your host browser → the
container desktop: Firefox tab 1 is the phishing site, tab 2 is the dashboard (also
reachable directly at `http://127.0.0.1:8081/`). The container's `/etc/hosts` maps
`www.t-mobile.com` → 127.0.0.1 and its Firefox NSS DB is synced from the mounted
sandbox bundle, so Firefox loads the phishing page with a **green lock** (cert issued
by "eMudhra Demo Issuing CA" — click the lock to show it). Sign in as Bob →
credentials appear in `.sandbox/attacker/loot.jsonl`. Then **fix it in the web UI**:
click *🔍 Audit CA stores* → all 8 stores show ALERT → click a store row → *☢️
Distrust entire root* (repeat per store; the live log narrates every action). A
trust-sync watcher re-syncs Firefox's NSS DB from the fixed bundle automatically and
**restarts the browser** (a running Firefox caches its trust store in memory, so it must
reload the NSS DB), so tab 1 flips to **"Warning: Security Risk"** with a **⛔ Not
Secure** padlock — MITM blocked. (`./demo/run-mitm-browser-demo.sh --cleanup` tears
everything down.)

In-container helpers (for the video or for checking state):
- `browser-trust-check` → prints whether *Firefox's own NSS DB* still trusts the
  phishing cert (`FIREFOX TRUSTS … MITM works` / `FIREFOX REJECTS … MITM blocked`)
- `desktop-shot [file]` → PNG screenshot of the container desktop (video frames)
- `sync-browser-trust` → re-import the sandbox bundle into Firefox's NSS DB

## The dashboard (Vue 3, vendored — no build step, works offline)

Single page, three boxes (see `rootwatch/webapp/`):

1. **Top box** — search bar + **🔍 Audit CA stores** (`POST /api/audit`),
   **📥 Update CRL** (`POST /api/crl/update`), and sort buttons **🔥 Most urgent** /
   **🕒 Most recent** (click the active one again to reset). Light/dark theme toggle in
   the header. To jump to an incident: click the header's **● N ALERTS** pill (first
   affected store) or a row's red **ALERT** badge — both pop up a tab with the store's
   first 5 alerts.
2. **Table box** — one row per Application/CA store: *name | Status | Roots | Alerts*.
   Clicking a row expands the details: the store's **trusted roots list**, and if CRL
   alerts affect it, a **dropdown of the first 5 alerts** (with the selected alert's
   details) plus two remediation buttons:
   **🔬 Distrust SPKI hash** (`mode=spki`) or **☢️ Distrust entire root** (`mode=root`)
   → `POST /api/remediate {store_id, mode}`. After remediation the row flips to `ok`.
3. **Live log** at the bottom (full width, auto-scroll) — every API call logs a line.

There is deliberately **no attack/demo button** on the page — the live attack→remediation
demos are the external scripts `demo/run-attack-demo.sh` (Docker victim container) and
`demo/run-mitm-demo.sh` (simulated MITM, in-sandbox).

### Web API

| Route | Body | Returns |
|---|---|---|
| `GET /` | — | the dashboard |
| `GET /api/health` | — | `{ok, scenario, real}` |
| `POST /api/audit` (alias `GET /api/stores`) | — | `{stores: [{id,name,icon,status,total_roots,roots,alerts,findings}], blocklist, affected, scenario}` |
| `POST /api/crl/update` | `{crl_pem? \| url?}` | `{entries: [BlocklistEntry]}` — empty body also fetches **real public CRLs** (ISRG/DigiCert CDPs; `ROOTWATCH_REAL_CRL_URLS` to override, `""` disables); PEM or DER, signature-verified, offline-safe |
| `POST /api/remediate` | `{store_id \| store_ids, mode: "spki"\|"root"}` | `{success, actions, error, results}` |
| `GET /api/probe` | optional `?store_id=<id>` | `{server_url, cafile, probes: [ProbeResult]}` — `store_id` scopes the probe CAfile to that store (starts the mock server on :8443 if needed) |
| `POST /api/attack-demo` | `{mode?}` (default `root`) | `{before, remediation, after, stores}` — used by `demo.sh` |

See `docs/WEB-API.md` for full payload shapes.

## Remediation modes (judges will ask)

- **`spki` (surgical, OneCRL-style):** block only the compromised keys' SPKI sha256 hashes.
  Other certificates from that CA — and future key rotations — keep working.
- **`root` (nuclear):** distrust the entire root CA — what Mozilla actually did with eMudhra.
  Correct when the root's key material itself is compromised; breaks every legit cert that CA
  issued. The dashboard exposes both.

## Architecture

```
rootwatch/
├── pki.py            # mock PKI: root -> intermediate -> leaf(localhost), revoke, CRL
├── server.py         # TLS server on 127.0.0.1:8443 presenting the revoked cert
├── probes.py         # handshake proofs: requests, curl, openssl s_client -crl_check
├── manager.py        # audit + batch remediation orchestration across stores
├── cli.py            # scripted CLI (setup / audit / remediate / probe / serve / web / demo)
├── web.py            # Flask API + dashboard host (Person B)
├── webapp/           # Vue 3 dashboard (vendored, no build step)
└── stores/           # system bundle, certifi/requests, curl, Firefox NSS/OneCRL,
                       # Chrome CRLSet/policy, Java cacerts, p11-kit/NSS shared trust,
                       # Docker certs.d per-registry CAs  (8 stores)
scenarios/emudhra.yaml   # the mock incident (fingerprint/serial populated by `setup`)
demo.sh                  # one-shot scripted demo via the web API
demo/run-attack-demo.sh  # live attack demo in a Docker victim container
demo/run-mitm-demo.sh    # simulated MITM demo (in-sandbox, no Docker)
demo/run-mitm-docker-demo.sh  # video demo: phishing victim container + in-container fix
demo/run-mitm-browser-demo.sh # full visual demo: noVNC desktop in victim container, live fix
tests/
```

The shared contract lives in `rootwatch/stores/base.py` (`TrustStore`, `Scenario`, `RootInfo`,
`BlocklistEntry`, `Finding`, `RemediationResult`, `RemediationMode`) and the headers of
`manager.py` / `probes.py` / `server.py` / `pki.py`. See `docs/PLAN.md` for the full plan and
the two-person work split (`docs/PERSON-A.md`, `docs/PERSON-B.md`).

## Safety

- Sandbox by default: all store paths resolve under `ROOTWATCH_ROOT` (default `./.sandbox`);
  `--real` is required to touch actual system stores. `cli setup` *copies* the machine's
  real trust stores (system bundle, certifi, Firefox NSS via `certutil` when available)
  into the sandbox read-only, then plants the compromised root on top — so the dashboard
  shows your real ~150 roots plus the incident.
- The mock server binds `127.0.0.1:8443` by default. `demo/run-attack-demo.sh` runs the
  victim container with `--network host` so it reaches the mock server on `127.0.0.1:8443`
  (the certs involved are mock, sandbox-only).
- Docker demos need a reachable daemon: if you get
  `permission denied ... /var/run/docker.sock`, run
  `sudo usermod -aG docker $USER && newgrp docker` (then re-run), or use `sudo`.
  The scripts check this up front and print the fix. No Docker? Use
  `./demo/run-mitm-demo.sh` or `./demo.sh` — both are sandbox-only.
- LF line endings everywhere (`.gitattributes`); `demo*.sh` included.
