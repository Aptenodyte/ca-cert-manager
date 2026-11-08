#!/usr/bin/env bash
# demo/run-mitm-demo.sh — simulated MITM inside the sandbox (no Docker needed).
#
# Story: once the eMudhra root is compromised, the attacker mints a FRESH cert for
# bank.local. Its serial is NOT on the CRL (never revoked), so pre-fix EVERY client
# accepts the handshake — even CRL-aware ones. One root-distrust action across all
# stores, and the same handshake is rejected everywhere. Proof by real TLS handshakes.
#
# Contrast with demo/run-attack-demo.sh: there the leaf IS revoked, so CRL clients
# reject it pre-fix. Here revocation checking cannot help — only root distrust can.
#
# Usage:
#   ./demo/run-mitm-demo.sh                  # MITM server on :9443
#   MITM_PORT=9444 ./demo/run-mitm-demo.sh   # custom port
#
# Sandbox only: all store paths resolve under ROOTWATCH_ROOT (default ./.sandbox).
# Requires: curl and a project venv (.venv) or python3 with the package installed.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
export ROOTWATCH_ROOT="${ROOTWATCH_ROOT:-$PWD/.sandbox}"
PORT="${MITM_PORT:-9443}"
MITM_PID=""

cleanup() {
  [ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== [1/5] clean setup (real stores only) + plant compromised eMudhra root (attack step) ==="
"$PY" -m rootwatch.cli setup
./demo/load-emudhra.sh

echo
echo "=== [2/5] attacker mints a FRESH cert for bank.local from the compromised CA ==="
echo "    (new serial — NOT on the CRL, so revocation checking cannot catch it)"
"$PY" - <<'PYEOF'
from rootwatch import pki, sandbox
root = sandbox.sandbox_root()
cert, key, chain = pki.mint_attacker_cert(root / "pki", hostname="bank.local")
print(f"    wrote {cert.name} + {key.name} + {chain.name} under {root / 'pki'}")
PYEOF

echo
echo "=== [3/5] MITM server starts, presenting the attacker cert on :$PORT ==="
RUNNER="$(mktemp /tmp/rootwatch-mitm-server.XXXXXX.py)"
cat > "$RUNNER" <<'PYEOF'
import sys, time
from rootwatch import sandbox, server
root = sandbox.sandbox_root()
pki_dir = root / "pki"
body = (b"<h1>bank.local</h1><p>Simulated MITM: this certificate was freshly minted "
        b"by the compromised eMudhra CA and is NOT on any CRL.</p>")
t, actual = server.start_server_with_cert(port=int(sys.argv[1]),
                                          certfile=pki_dir / "attacker-chain.pem",
                                          keyfile=pki_dir / "attacker.key", body=body)
print(actual, flush=True)
while True:
    time.sleep(3600)
PYEOF
PORTFILE="$(mktemp /tmp/rootwatch-mitm.port.XXXXXX)"
start_mitm() {  # $1 = port (0 = ephemeral)
  : > "$PORTFILE"
  "$PY" "$RUNNER" "$1" > "$PORTFILE" 2> /tmp/rootwatch-mitm-demo.err &
  MITM_PID=$!
  for _ in $(seq 1 20); do
    [ -s "$PORTFILE" ] && return 0
    sleep 0.25
  done
  kill "$MITM_PID" 2>/dev/null || true
  return 1
}
if ! start_mitm "$PORT"; then
  echo "    port $PORT busy or failed — retrying on an ephemeral port…"
  start_mitm 0 || { echo "ERROR: MITM server failed to start:" >&2
                    sed 's/^/    /' /tmp/rootwatch-mitm-demo.err >&2; exit 1; }
fi
ACTUAL_PORT="$(cat "$PORTFILE")"
rm -f "$RUNNER" "$PORTFILE"
[ -n "$ACTUAL_PORT" ] || { echo "ERROR: MITM server failed to start on port $PORT" >&2; exit 1; }
URL="https://127.0.0.1:$ACTUAL_PORT/"
echo "    MITM server live at $URL  (chain: attacker.crt + inter.crt -> eMudhra root)"

PROBES="$(mktemp /tmp/rootwatch-mitm-probes.XXXXXX.py)"
cat > "$PROBES" <<'PYEOF'
import sys
from rootwatch import manager, probes, sandbox
root = sandbox.sandbox_root()
ca = root / "etc" / "ssl" / "ca-bundle.crt"
sc = manager.load_scenario("scenarios/emudhra.yaml")
results = probes.probe_all(sys.argv[1], cafile=str(ca) if ca.exists() else None,
                           crl_pem=sc.crl_pem or None)
vulnerable = False
for r in results:
    mark = "ACCEPT  ⚠️  MITM WORKS" if r.success else f"REJECT  ✅  {r.verify_error[:80]}"
    print(f"  {r.client:14s} crl={r.crl_checked!s:5s} {mark}")
    vulnerable = vulnerable or r.success
print("RESULT " + ("VULNERABLE" if vulnerable else "SAFE"))
PYEOF

echo
echo "=== [4/5] victim handshakes PRE-FIX (sandbox system bundle; expect ALL ACCEPT, CRL clients too) ==="
echo "    target: $URL"
PRE="$("$PY" "$PROBES" "$URL")"
echo "$PRE"

echo
echo "=== [5/5] ONE ACTION: distrust the entire root in ALL stores (remediate --mode root) ==="
"$PY" -m rootwatch.cli remediate --mode root | sed 's/^/    /'

echo
echo "--- victim handshakes POST-FIX (same bundle, updated in place; expect ALL REJECT) ---"
POST="$("$PY" "$PROBES" "$URL")"
echo "$POST"
rm -f "$PROBES"

echo
if echo "$PRE" | grep -q "RESULT VULNERABLE" \
   && echo "$PRE" | grep -qE "requests-crl +crl=True +ACCEPT" \
   && echo "$POST" | grep -q "RESULT SAFE"; then
  echo "✅ DEMO PASS: the freshly-minted MITM cert was accepted pre-fix — even by CRL-aware"
  echo "   clients (it is not on the CRL); after one root-distrust action every client rejects it."
else
  echo "❌ DEMO FAIL: expected VULNERABLE pre-fix (including the CRL-aware client) and SAFE post-fix." >&2
  exit 1
fi
