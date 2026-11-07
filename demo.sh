#!/usr/bin/env bash
# One-shot demo for judges, driven THROUGH THE WEB UI (Person B owns this file).
# Usage: ./demo.sh   (sandbox only; never touches real system stores)
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
PORT=8080

echo "=== [1/4] Setting up sandbox + mock eMudhra PKI (root -> intermediate -> REVOKED leaf) ==="
$PY -m catrust.cli setup

echo "=== [2/4] Launching the web dashboard on http://127.0.0.1:$PORT ==="
$PY -m catrust.cli web --port $PORT &
WEB_PID=$!
trap 'kill $WEB_PID 2>/dev/null || true' EXIT
sleep 2

echo "=== [3/4] Attack: audit + handshake probes via the web API (revoked cert on :8443) ==="
echo "--- GET /api/stores (audit) ---"
curl -s "http://127.0.0.1:$PORT/api/stores" | $PY -m json.tool | head -40
echo "--- GET /api/probe (default clients ACCEPT the revoked cert = attack works) ---"
curl -s "http://127.0.0.1:$PORT/api/probe" | $PY -m json.tool

echo "=== [4/4] POST /api/attack-demo — remediate ALL stores at once, then re-probe ==="
curl -s -X POST "http://127.0.0.1:$PORT/api/attack-demo" | $PY -m json.tool

echo "--- GET /api/stores after remediation (all clean) ---"
curl -s "http://127.0.0.1:$PORT/api/stores" | $PY -m json.tool | tail -20

echo "=== Demo finished. For the interactive dashboard visit http://127.0.0.1:$PORT ==="
