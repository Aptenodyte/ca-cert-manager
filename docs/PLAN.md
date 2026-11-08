# RootWatch — project outline & work split

**One-liner:** centralized, system-wide CA distrust manager that audits every fragmented
trust store on a machine, remediates compromised roots (e.g. eMudhra) in one action, and
physically proves the fix with real TLS handshakes against a mock server using a revoked cert.

## Architecture

```
rootwatch/
├── pyproject.toml
├── rootwatch/
│   ├── __init__.py
│   ├── pki.py            # mock PKI: root -> intermediate -> leaf(localhost), revoke, CRL
│   ├── server.py         # TLS server on 127.0.0.1:8443 presenting the revoked cert
│   ├── probes.py         # handshake proofs: requests, curl, openssl s_client (-crl_check)
│   ├── manager.py        # audit + batch remediation orchestration across stores
│   ├── cli.py            # scripted CLI (audit / remediate / probe / web / demo)
│   ├── web.py            # Flask web UI for judges (Person B)
│   └── webapp/           #   index.html + app.js single-page UI
│   └── stores/
│       ├── __init__.py   # registry of all stores
│       ├── base.py       # TrustStore contract (THE shared interface)
│       ├── system.py     # system CA bundle dir (sandboxed via ROOTWATCH_ROOT)
│       ├── firefox.py    # NSS cert9.db via certutil; OneCRL semantics
│       ├── chrome.py     # CRLSet binary parser: revoked-serial membership check
│       ├── requests_store.py  # certifi bundle
│       └── curl_store.py      # bundle curl uses (--cacert / system)
├── scenarios/
│   └── emudhra.yaml      # compromised root fingerprint, revoked serial, narrative
├── demo.sh               # one-shot scripted demo for judges
├── tests/
└── README.md
```

## Shared contract (owned by lead, both workers build against it)

- `stores/base.py`: `TrustStore` ABC with `id`, `display_name`, `audit(scenario) -> list[Finding]`,
  `remediate(scenario) -> RemediationResult`. `Finding` and `RemediationResult` dataclasses.
- `probes.py`: `ProbeResult` dataclass + `run_probe(client, url, cafile=..., crl=...)`.
- `manager.py`: `audit_all(stores, scenario)`, `remediate_selected(stores, ids, scenario)`.
- Sandbox: every store path resolves under `ROOTWATCH_ROOT` (default `./.sandbox`); `--real` flag
  targets the true system paths. Probes consume per-store cafile paths so behavior is faithful.

## Two-person split

### Person A — "Backend / attack infra" (files: pki.py, server.py, probes.py, stores/*, manager.py, cli.py, scenarios/emudhra.yaml, tests/)
1. Mock PKI + CRL + revoked leaf; TLS server on 127.0.0.1:8443.
2. Probe matrix: requests (default & verify), curl --cacert, openssl s_client -crl_check.
3. All TrustStore implementations (system, firefox, chrome CRLSet, certifi, curl) in sandbox mode.
4. Manager + CLI: `audit`, `remediate`, `probe`, `demo` (scripted).
5. eMudhra scenario file + pytest coverage.

### Person B — "Judge experience" (files: web.py, webapp/*, demo/ run-attack-demo.sh, demo.sh, README.md, docs/)
Layout (fixed): top box with search + [Audit CA stores] [Update CRL] [Jump to Affected];
table box with one row per store (name/status/roots/alerts), click row -> details
(trusted roots; CRL alert + Distrust SPKI / Distrust root buttons); live log at bottom.
Routes: POST /api/audit, POST /api/crl/update, POST /api/remediate {store_id, mode}.
Live attack demo = external Docker script (demo/run-attack-demo.sh), NOT a page button.

### Integration points
- B imports only from the contract above (`manager`, `probes`, `stores.base`, `pki`, `server`)
  and the web API routes declared in `rootwatch/web.py`.
- A must keep function signatures exactly as declared in base.py / probes.py / manager.py.
- Both work in the repo root; A never touches web.py/webapp/demo.sh/README,
  B never touches pki/server/stores/manager/cli.

## Demo narrative (for judges)
1. Mock eMudhra root is trusted in all stores; leaf cert for localhost is REVOKED (CRL exists).
2. Default clients (requests, curl) do no revocation checking -> handshake SUCCEEDS = attack works.
3. CRL-aware client (openssl -crl_check) REJECTS pre-fix.
4. One click in the web UI -> root distrusted everywhere -> ALL clients now REJECT the handshake.

## Remediation modes
- **spki (surgical, default)**: block the compromised keys' SPKI hashes (OneCRL-style).
  Chosen when only specific keys leaked; the CA's other customers survive.
- **root (nuclear)**: distrust the entire root CA. Chosen when the root key material is
  compromised (the eMudhra case — Mozilla removed the root, not just one key).
  `Scenario.compromised_spki_hashes` / `leaf_spki_hash` carry the surgical targets;
  `TrustStore.remediate(scenario, mode)` implements both.

## 24h build order
A: PKI+server+one curl probe (3h) -> stores (6h) -> probes+manager+CLI (3h) -> scenario+tests (2h) -> integration buffer (2h)
B: web UI shell + audit view (3h) -> remediate flow (3h) -> probe panel + attack demo (2h) -> demo.sh+README (3h) -> polish (3h)
