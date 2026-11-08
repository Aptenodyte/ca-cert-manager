# RootCanal 🦷

Centralized, **system-wide CA distrust manager**. RootCanal audits every fragmented trust
store on a machine — system bundle, Firefox NSS/OneCRL, Chrome CRLSet, certifi/requests,
curl — distrusts a compromised root CA (the mock **eMudhra** scenario) in **one action**, and
**physically proves the fix** with real TLS handshakes against a mock localhost server
(`127.0.0.1:8443`) presenting a **revoked** certificate.

> 🧪 **Sandboxed by default.** Every store path resolves under `CATRUST_ROOT` (default
> `./.sandbox`). Real system stores are only touched with an explicit `--real` flag.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # Linux & macOS
.venv/bin/python -m catrust.cli setup                          # build sandbox + mock PKI (revoked leaf)
.venv/bin/python -m catrust.cli web --port 8080                # dashboard: http://127.0.0.1:8080
./demo.sh                                                      # one-shot scripted demo (drives the web API)
./demo/run-attack-demo.sh --image python:3.14-slim             # live attack in a Docker victim container
```

Other commands:

```bash
.venv/bin/python -m catrust.cli serve                          # mock TLS server on 127.0.0.1:8443 (blocking)
.venv/bin/python -m catrust.cli audit                          # audit all stores vs. the scenario
.venv/bin/python -m catrust.cli probe                          # handshake probes (requests/curl/openssl -crl_check)
.venv/bin/python -m catrust.cli remediate [--stores a,b] [--mode spki|root]
.venv/bin/python -m catrust.cli demo                           # scripted attack -> remediate -> proof
.venv/bin/python -m pytest tests/ -q                           # tests
# console scripts after install: rootcanal …, rootcanal-web …
```

## The demo story (what judges should see)

1. A mock **eMudhra** root CA is trusted in *all* stores; a `localhost` leaf cert is minted,
   then **revoked** via a CRL.
2. Default clients (**requests**, **curl**) do no revocation checking → the handshake
   **SUCCEEDS** = the attack works.
3. CRL-aware clients (`openssl s_client -crl_check`) **reject** the cert.
4. One action (the dashboard's **☢️ Distrust entire root**, or `POST /api/attack-demo`)
   distrusts the root in **every** store → **all** clients now **reject** the handshake.

## The dashboard (Vue 3, vendored — no build step, works offline)

Single page, three boxes (see `catrust/webapp/`):

1. **Top box** — search bar + **🔍 Audit CA stores** (`POST /api/audit`),
   **📥 Update CRL** (`POST /api/crl/update`), **🚨 Jump to Affected** (opens the first
   alerted row).
2. **Table box** — one row per Application/CA store: *name | Status | Roots | Alerts*.
   Clicking a row expands the details: the store's **trusted roots list**, and if a CRL
   alert affects it, the **alert details** plus two remediation buttons:
   **🔬 Distrust SPKI hash** (`mode=spki`) or **☢️ Distrust entire root** (`mode=root`)
   → `POST /api/remediate {store_id, mode}`. After remediation the row flips to `ok`.
3. **Live log** at the bottom (full width, auto-scroll) — every API call logs a line.

There is deliberately **no attack/demo button** on the page — the live attack→remediation
demo is the external script `demo/run-attack-demo.sh` (Docker victim container).

### Web API

| Route | Body | Returns |
|---|---|---|
| `GET /` | — | the dashboard |
| `GET /api/health` | — | `{ok, scenario, real}` |
| `POST /api/audit` (alias `GET /api/stores`) | — | `{stores: [{id,name,icon,status,total_roots,roots,alerts,findings}], blocklist, affected, scenario}` |
| `POST /api/crl/update` | `{crl_pem? \| url?}` | `{entries: [BlocklistEntry]}` (empty body = scenario CRL) |
| `POST /api/remediate` | `{store_id \| store_ids, mode: "spki"\|"root"}` | `{success, actions, error, results}` |
| `GET /api/probe` | — | `{url, cafile, probes: [ProbeResult]}` (starts the mock server on :8443 if needed) |
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
catrust/
├── pki.py            # mock PKI: root -> intermediate -> leaf(localhost), revoke, CRL
├── server.py         # TLS server on 127.0.0.1:8443 presenting the revoked cert
├── probes.py         # handshake proofs: requests, curl, openssl s_client -crl_check
├── manager.py        # audit + batch remediation orchestration across stores
├── cli.py            # scripted CLI (setup / audit / remediate / probe / serve / web / demo)
├── web.py            # Flask API + dashboard host (Person B)
├── webapp/           # Vue 3 dashboard (vendored, no build step)
└── stores/           # system bundle, Firefox NSS/OneCRL, Chrome CRLSet, certifi, curl
scenarios/emudhra.yaml   # the mock incident (fingerprint/serial populated by `setup`)
demo.sh                  # one-shot scripted demo via the web API
demo/run-attack-demo.sh  # live attack demo in a Docker victim container
tests/
```

The shared contract lives in `catrust/stores/base.py` (`TrustStore`, `Scenario`, `RootInfo`,
`BlocklistEntry`, `Finding`, `RemediationResult`, `RemediationMode`) and the headers of
`manager.py` / `probes.py` / `server.py` / `pki.py`. See `docs/PLAN.md` for the full plan and
the two-person work split (`docs/PERSON-A.md`, `docs/PERSON-B.md`).

## Safety

- Sandbox by default: all store paths resolve under `CATRUST_ROOT` (default `./.sandbox`);
  `--real` is required to touch actual system stores.
- The mock server binds `127.0.0.1:8443` by default. `demo/run-attack-demo.sh` sets
  `CATRUST_SERVER_HOST=0.0.0.0` so the Docker victim container can reach it via
  `host.docker.internal` (the certs involved are mock, sandbox-only).
- LF line endings everywhere (`.gitattributes`); `demo*.sh` included.
