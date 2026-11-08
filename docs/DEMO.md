# Running the demos (Person B)

Both demos are **sandbox-only**: every store path resolves under `CATRUST_ROOT`
(default `./.sandbox`). Nothing touches real system stores unless `--real` is passed
explicitly.

## 1. One-shot scripted demo — `./demo.sh`

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
./demo.sh                 # PORT=9090 ./demo.sh to change the web port
```

Steps: `rootcanal setup` (sandbox + mock eMudhra PKI with a REVOKED `localhost` leaf) →
start the web dashboard → `POST /api/audit` → `GET /api/probe` (requests/curl **accept** the
revoked cert = attack works; `openssl -crl_check` rejects) → `POST /api/attack-demo`
(distrust the root in **all** stores, mode `root`) → re-probe (**every client rejects**).

## 2. Live attack in a Docker victim container — `./demo/run-attack-demo.sh`

```bash
./demo/run-attack-demo.sh --image python:3.14-slim
# options: --web-port 8080  --server-port 8443  --keep   (keep the victim container)
```

Flow:

1. `rootcanal setup` on the host; the web dashboard starts with
   `CATRUST_SERVER_HOST=0.0.0.0` so the victim container can reach the mock TLS server
   on :8443 via `host.docker.internal` (the certs are mock/sandbox-only).
2. Host probe matrix via `GET /api/probe` (requests/curl ACCEPT pre-fix).
3. Victim container (`--image`, default `python:3.14-slim`) is launched with the sandbox
   bind-mounted at `/sandbox`; its CA bundle **is** the RootCanal system store. A stdlib
   Python TLS client runs real handshakes from inside the victim: plain client →
   **ACCEPT** (VULNERABLE), CRL-aware client → REJECT.
4. `POST /api/remediate {store_id, mode:"root"}` for **every** store id — one action
   distrusts the root everywhere; the bind-mounted bundle updates in place.
5. The victim re-runs the same handshake → **REJECT** (SAFE). Host `GET /api/probe`
   shows every client rejecting too. Prints `✅ DEMO PASS` / `❌ DEMO FAIL`.

Note: inside the victim the hostname check is disabled (`check_hostname=False`) because the
cert SAN is `localhost`/`127.0.0.1` while the server is reached as `host.docker.internal` —
the demo proves **trust/revocation** behavior, not name matching.

## 3. Interactive dashboard

```bash
.venv/bin/python -m catrust.cli setup
.venv/bin/python -m catrust.cli web --port 8080     # http://127.0.0.1:8080
```

Top box: **🔍 Audit CA stores**, **📥 Update CRL**, **🚨 Jump to Affected** + search.
Table: one row per store; click to expand roots + CRL alert with
**🔬 Distrust SPKI hash** / **☢️ Distrust entire root**. Live log at the bottom.
No attack button on the page — use the scripts above for the live demo.
