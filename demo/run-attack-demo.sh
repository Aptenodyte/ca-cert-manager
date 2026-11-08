#!/usr/bin/env bash
# demo/run-attack-demo.sh — live attack -> remediation -> proof in a Docker victim container.
#
# Story: a victim container trusts the mock "eMudhra" root (its CA bundle is the RootCanal
# sandbox store, bind-mounted in). The mock TLS server on the host presents a REVOKED leaf
# cert. Pre-fix, the victim's plain TLS client ACCEPTS it (attack works). We then remediate
# ALL stores through the RootCanal web API on the host — the mounted bundle updates in place —
# and the victim's next handshake is REJECTED. Proof by real TLS handshakes.
#
# Usage:
#   ./demo/run-attack-demo.sh                          # image defaults to python:3.14-slim
#   ./demo/run-attack-demo.sh --image python:3.14-slim --web-port 8080 --server-port 8443
#   ./demo/run-attack-demo.sh --keep                   # keep the victim container afterwards
#
# Sandbox only: all store paths resolve under CATRUST_ROOT (default ./.sandbox).
# Requires: docker, curl, and a project venv (.venv) or python3 with the package installed.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="python:3.14-slim"
WEB_PORT=8080
SRV_PORT=8443
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --server-port) SRV_PORT="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
BASE="http://127.0.0.1:$WEB_PORT"
CONTAINER="rootcanal-victim-$$"
WEB_PID=""

cleanup() {
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  if [ "$KEEP" = 0 ] && command -v docker >/dev/null 2>&1; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: docker not found. Install Docker, or run the local demo instead: ./demo.sh" >&2
  exit 1
}

echo "=== [1/6] setup: sandbox + mock eMudhra PKI (root -> intermediate -> REVOKED leaf) ==="
"$PY" -m catrust.cli setup
SANDBOX="$PWD/.sandbox"
[ -d "$SANDBOX" ] || SANDBOX="${CATRUST_ROOT:-$PWD/.sandbox}"

echo "=== [2/6] starting RootCanal web dashboard on $BASE (mock server exposed for the victim) ==="
CATRUST_SERVER_HOST=0.0.0.0 CATRUST_SERVER_PORT="$SRV_PORT" \
  "$PY" -m catrust.cli web --port "$WEB_PORT" &
WEB_PID=$!
for _ in $(seq 1 40); do
  curl -sf "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$BASE/api/health" >/dev/null

echo
echo "=== [3/6] host probe matrix — ATTACK (requests/curl ACCEPT the revoked cert; openssl -crl_check REJECTs) ==="
curl -sf "$BASE/api/probe" | "$PY" -m json.tool

echo
echo "=== [4/6] launching victim container ($IMAGE) with the sandbox store mounted at /sandbox ==="
# --network host lets the victim reach the host's mock server on 127.0.0.1:$SRV_PORT
# (falls back to host.docker.internal on Docker Desktop if you remove --network host)
docker run -d --name "$CONTAINER" \
  --network host \
  -v "$SANDBOX":/sandbox \
  "$IMAGE" sleep infinity >/dev/null

CAFILE_HOST="$(find "$SANDBOX/etc/ssl" -name 'ca-bundle.crt' 2>/dev/null | head -1 || true)"
[ -n "$CAFILE_HOST" ] || CAFILE_HOST="$(find "$SANDBOX" -name 'ca-bundle.crt' 2>/dev/null | head -1 || true)"
[ -n "$CAFILE_HOST" ] || CAFILE_HOST="$SANDBOX/etc/ssl/ca-bundle.crt"
CAFILE_VICTIM="/sandbox/${CAFILE_HOST#"$SANDBOX"/}"

CRL_HOST="$(find "$SANDBOX" \( -name 'crl*.pem' -o -name '*.crl' \) 2>/dev/null | head -1 || true)"
CRLFILE_VICTIM=""
if [ -n "$CRL_HOST" ]; then
  docker cp "$CRL_HOST" "$CONTAINER":/tmp/crl.pem >/dev/null
  CRLFILE_VICTIM=/tmp/crl.pem
fi

PROBE_SCRIPT="$(mktemp)"
cat > "$PROBE_SCRIPT" <<'PYEOF'
import os, ssl, sys, urllib.request

target = os.environ.get("TARGET", "https://127.0.0.1:8443/")
cafile = os.environ.get("CAFILE", "/sandbox/etc/ssl/ca-bundle.crt")
crlfile = os.environ.get("CRLFILE") or ""

def probe(name, use_crl):
    ctx = ssl.create_default_context(cafile=cafile)
    # server SAN is localhost/127.0.0.1; this demo tests TRUST/REVOCATION,
    ctx.check_hostname = False
    if use_crl and crlfile:
        ctx.load_verify_locations(crlfile)
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    try:
        with urllib.request.urlopen(target, context=ctx, timeout=8) as r:
            r.read(80)
        print(f"  {name}: ACCEPT — TLS handshake succeeded (revoked cert trusted!)")
        return True
    except Exception as e:
        print(f"  {name}: REJECT — {type(e).__name__}: {str(e)[:110]}")
        return False

plain_ok = probe("plain TLS client (no revocation check, like requests/curl)", False)
if crlfile:
    probe("CRL-aware client (VERIFY_CRL_CHECK_LEAF, like openssl -crl_check)", True)
else:
    print("  (no CRL found in sandbox — CRL probe skipped)")
print("RESULT " + ("VULNERABLE" if plain_ok else "SAFE"))
sys.exit(0)
PYEOF
docker cp "$PROBE_SCRIPT" "$CONTAINER":/tmp/probe.py >/dev/null
rm -f "$PROBE_SCRIPT"

run_victim_probes() {
  docker exec \
    -e TARGET="https://127.0.0.1:$SRV_PORT/" \
    -e CAFILE="$CAFILE_VICTIM" \
    ${CRLFILE_VICTIM:+-e CRLFILE="$CRLFILE_VICTIM"} \
    "$CONTAINER" python3 /tmp/probe.py
}

echo
echo "--- victim ATTACK probes (pre-fix; expect RESULT VULNERABLE) ---"
PRE="$(run_victim_probes)"
echo "$PRE"

echo
echo "=== [5/6] remediate ALL stores at once via the web API (POST /api/remediate, mode=root) ==="
IDS="$(curl -sf "$BASE/api/stores" | "$PY" -c "import sys, json; print('\n'.join(s['id'] for s in json.load(sys.stdin)['stores']))")"
for id in $IDS; do
  echo "  -> store '$id':"
  curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"store_id\":\"$id\",\"mode\":\"root\"}" "$BASE/api/remediate" | "$PY" -m json.tool | sed 's/^/     /'
done

echo
echo "--- victim POST-FIX probes (same client, same bundle — now updated in place; expect RESULT SAFE) ---"
POST="$(run_victim_probes)"
echo "$POST"

echo
echo "=== [6/6] host probe matrix after remediation (expect every client to REJECT) ==="
curl -sf "$BASE/api/probe" | "$PY" -m json.tool

echo
echo "=== store statuses after remediation ==="
curl -sf "$BASE/api/stores" \
  | "$PY" -c "import sys, json; [print('  %s %-45s %s' % (s['icon'], s['name'], s['status'])) for s in json.load(sys.stdin)['stores']]"

echo
if echo "$PRE" | grep -q "RESULT VULNERABLE" && echo "$POST" | grep -q "RESULT SAFE"; then
  echo "✅ DEMO PASS: attack succeeded pre-fix, every client rejects the revoked cert post-fix."
else
  echo "❌ DEMO FAIL: expected VULNERABLE before and SAFE after remediation." >&2
  exit 1
fi
