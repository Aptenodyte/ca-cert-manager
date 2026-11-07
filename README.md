# RootCanal

Centralized, system-wide CA distrust manager. Audits every fragmented trust store on a
machine (system bundle, Firefox NSS/OneCRL, Chrome CRLSet, certifi/requests, curl),
distrusts a compromised root CA (e.g. eMudhra) in **one action**, and **physically proves
the fix** with real TLS handshakes against a mock localhost server using a revoked cert.

> Sandboxed by default: all store paths resolve under `CATRUST_ROOT` (default `./.sandbox`).
> `--real` targets actual system stores.

## Quickstart
```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]
.venv/bin/python -m catrust.cli setup     # build sandbox + mock PKI (revoked leaf)
.venv/bin/python -m catrust.cli web --port 8080   # live security dashboard (http://127.0.0.1:8080)
#   Vue 3 dashboard (vendored, no build step): red pulsing store cards, KPIs,
#   click-select + one-click remediate, handshake probe matrix, live log, attack demo
./demo.sh                                  # one-shot scripted demo (CLI)
```

## The demo story
1. A mock "eMudhra" root is trusted everywhere; a `localhost` cert is minted then REVOKED (CRL).
2. Default clients (requests, curl) don't check revocation → handshake **succeeds** = attack works.
3. CRL-aware clients (`openssl s_client -crl_check`) reject it.
4. One keypress distrusts the root in all stores → **every** client now rejects the handshake.

See `docs/PLAN.md` for architecture and work split.
