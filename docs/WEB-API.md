# Web API reference (Person B: `catrust/web.py`)

Served by `rootcanal-web` / `rootcanal web --port 8080` → `http://127.0.0.1:8080`.
The dashboard (`catrust/webapp/`) calls these; `demo.sh` and `demo/run-attack-demo.sh`
call them too. All routes return JSON; errors come back as
`{"error": "..."}` with a 4xx/5xx status (503 while the backend contract is unimplemented).

## Routes

### `GET /`
The single-page dashboard (`webapp/index.html`, Vue 3 vendored — no build step).

### `GET /api/health`
```json
{"ok": true, "scenario": "scenarios/emudhra.yaml", "real": false}
```

### `POST /api/audit`  (alias: `GET /api/stores`)
Full state in one call: `manager.assess_all` + `manager.audit_all` +
`manager.collect_blocklist` + `manager.affected_stores`.
```json
{
  "stores": [
    {
      "id": "system", "name": "System CA bundle (/etc/ssl/certs)", "icon": "🖥️",
      "status": "alert | ok",
      "total_roots": 3,
      "roots":   [{"subject": "...", "fingerprint": "sha256hex", "spki_hash": "sha256hex",
                   "not_after": "...", "sig_alg": "...", "flags": ["known-bad", ...]}],
      "alerts":  [{"serial": "...", "spki_hash": "...", "subject": "...", "issuer": "...",
                   "revoked_at": "...", "source": "CRL", "reason": "..."}],
      "findings": [{"store_id": "system", "kind": "root_trusted", "detail": "...", "fingerprint": "..."}]
    }
  ],
  "blocklist": [/* BlocklistEntry — the application-level untrusted list */],
  "affected": ["system", "requests", ...],
  "scenario": {"name": "emudhra-2026", "narrative": "...", "revoked_subject_cn": "localhost",
               "revoked_serial": "...", "compromised_root_fingerprint": "...",
               "compromised_spki_hashes": ["..."]}
}
```
`alerts` on a store = blocklist entries that intersect that store's roots (by SPKI hash;
CRL-serial entries fall back to the scenario's revoked serial for stores flagged affected).

### `POST /api/crl/update`
Body: `{"crl_pem": "-----BEGIN X509 CRL-----..."}` **or** `{"url": "https://.../crl.pem"}`.
Empty body `{}` ingests the scenario's CRL. → `manager.update_crl(...)`.
```json
{"entries": [/* BlocklistEntry — the new full application-level blocklist */]}
```
Ingested entries are persisted to the sandbox (`blocklist.json`, via
`manager.update_crl`) and merged into later `/api/audit` / `/api/blocklist`
responses through `manager.load_blocklist_state()`.

### `POST /api/remediate`
Body: `{"store_id": "firefox", "mode": "spki"}` — or `{"store_ids": ["system", "curl"], "mode": "root"}`.
`mode` is `"spki"` (surgical, default) or `"root"` (nuclear). → `manager.remediate_selected(...)`.
```json
{"success": true, "actions": ["removed root ... from ..."], "error": "",
 "results": {"firefox": {"store_id": "firefox", "success": true, "actions": [...], "error": ""}}}
```

### `GET /api/probe`
Starts the mock TLS server on `127.0.0.1:8443` if it isn't running
(`server.start_server_background`, honoring `CATRUST_SERVER_HOST`/`CATRUST_SERVER_PORT`),
then runs `probes.probe_all` with a store `cafile()` and the scenario CRL.
```json
{"server_url": "https://127.0.0.1:8443/", "url": "https://127.0.0.1:8443/",
 "cafile": ".sandbox/etc/ssl/ca-bundle.crt",
 "probes": [{"client": "requests|requests-crl|curl|openssl-crl", "url": "...",
             "success": true, "verify_error": "", "detail": "", "crl_checked": false,
             "elapsed_ms": 12}]}
```
`success: true` = the client **accepted** the revoked cert (attack works).

### `POST /api/attack-demo`
Scripted demo used by `demo.sh` / `demo/run-attack-demo.sh` — **not** a UI button.
Body: `{"mode": "root"}` (default `root`; `"spki"` allowed). Probes → remediate **all**
stores → re-probe.
```json
{"mode": "root", "before": {"probes": [...]}, "remediation": {"<store_id>": {...}},
 "after": {"probes": [...]}, "stores": [{"id": "...", "name": "...", "status": "ok"}]}
```

## Demo scripts

- `./demo.sh` — setup → start web UI → `POST /api/audit` → `GET /api/probe` (attack) →
  `POST /api/attack-demo` (remediate all + re-probe) → statuses after.
- `./demo/run-attack-demo.sh --image python:3.14-slim` — spins a **Docker victim container**
  with the sandbox store bind-mounted, runs real TLS handshakes from inside the victim
  against the host's mock server (pre-fix: ACCEPT), remediates via the API, re-probes
  (post-fix: REJECT). Prints `DEMO PASS` / `DEMO FAIL`.
