#!/usr/bin/env bash
# RootWatch — one-shot scripted demo for judges (Person B owns this file).
#
# Drives the web API end-to-end (sandbox only — never touches real system stores):
#   [1] setup sandbox + mock eMudhra PKI (root -> intermediate -> REVOKED leaf)
#   [2] start the web dashboard
#   [3] POST /api/audit   — enumerate every store + the CRL blocklist (alerts)
#   [4] GET  /api/probe   — ATTACK: default clients (requests/curl) ACCEPT the revoked cert
#   [5] POST /api/attack-demo — distrust the root in ALL stores, then re-probe (all REJECT)
#
# Usage: ./demo.sh            (PORT=9090 ./demo.sh to change the web port)
# For the Docker victim-container demo see demo/run-attack-demo.sh.
set -euo pipefail
cd "$(dirname "$0")"

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
PORT="${PORT:-8080}"
BASE="http://127.0.0.1:$PORT"

echo "=== [1/5] setup: sandbox + mock eMudhra PKI (root -> intermediate -> REVOKED leaf) ==="
"$PY" -m rootwatch.cli setup

echo "=== [2/5] starting web dashboard on $BASE ==="
"$PY" -m rootwatch.cli web --port "$PORT" &
WEB_PID=$!
trap 'kill "$WEB_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do
  curl -sf "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$BASE/api/health" >/dev/null   # fail loudly if the UI never came up

echo
echo "=== [3/5] POST /api/audit — stores + application blocklist (truncated) ==="
curl -sf -X POST "$BASE/api/audit" | "$PY" -m json.tool | head -50

echo
echo "=== [4/5] GET /api/probe — ATTACK: handshake probes against the revoked cert on :8443 ==="
echo "    (requests/curl do no revocation checking -> ACCEPT = attack works; openssl -crl_check -> REJECT)"
curl -sf "$BASE/api/probe" | "$PY" -m json.tool

echo
echo "=== [5/5] POST /api/attack-demo — distrust the root in ALL stores (mode=root), re-probe ==="
curl -sf -X POST -H 'Content-Type: application/json' -d '{"mode":"root"}' \
  "$BASE/api/attack-demo" | "$PY" -m json.tool

echo
echo "=== store statuses after remediation (GET /api/stores) ==="
curl -sf "$BASE/api/stores" \
  | "$PY" -c "import sys, json; [print('  %s %-45s %s' % (s['icon'], s['name'], s['status'])) for s in json.load(sys.stdin)['stores']]"

echo
echo "=== demo finished — interactive dashboard was at $BASE (Ctrl-C / kill to stop) ==="
