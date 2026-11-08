#!/usr/bin/env bash
# demo/run-mitm-docker-demo.sh — visual MITM/phishing demo in a Docker victim container.
#
# Story (for the video): Bob signs in to "T-Mobile" (www.t-mobile.com) from a victim
# container whose CA bundle is the RootWatch sandbox (bind-mounted at /sandbox).
# The site is really an MITM phishing server on the host presenting a FRESH cert minted
# with the leaked eMudhra root key — its serial is NOT on any CRL, so even CRL-aware
# clients accept it. Bob's credentials are exfiltrated to a loot file on the host.
# Then we load RootWatch INTO the victim container, distrust the root in all stores
# (the mounted bundle updates in place), and Bob's next attempt is rejected by TLS.
#
# Usage:
#   ./demo/run-mitm-docker-demo.sh                        # image defaults to python:3.14-slim
#   ./demo/run-mitm-docker-demo.sh --image python:3.14-slim --mitm-port 9443
#   ./demo/run-mitm-docker-demo.sh --keep                 # keep the victim container
#
# Sandbox only: all store paths resolve under ROOTWATCH_ROOT (default ./.sandbox).
# Requires: docker, curl, and a project venv (.venv) or python3 with the package installed.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="python:3.14-slim"
MITM_PORT=9443
HOSTNAME="www.t-mobile.com"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --mitm-port) MITM_PORT="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
export ROOTWATCH_ROOT="${ROOTWATCH_ROOT:-$PWD/.sandbox}"
CONTAINER="rootwatch-mitm-victim-$$"
MITM_PID=""

cleanup() {
  [ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null || true
  if [ "$KEEP" = 0 ] && command -v docker >/dev/null 2>&1; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: docker not found." >&2
  exit 1
}

echo "=== [1/6] clean sandbox (real stores only) + plant compromised eMudhra root (attack step) ==="
"$PY" -m rootwatch.cli setup
./demo/load-emudhra.sh

echo
echo "=== [2/6] attacker mints a FRESH phishing cert for $HOSTNAME and starts the MITM server on :$MITM_PORT ==="
echo "    (new serial — NOT on the CRL, so revocation checking cannot catch it)"
RUNNER="$(mktemp /tmp/rootwatch-mitm.XXXXXX.py)"
cat > "$RUNNER" <<'PYEOF'
import sys, time
from rootwatch import mitmdemo
info = mitmdemo.mint_and_start(port=int(sys.argv[1]), hostname=sys.argv[2])
print(info["url"])
print(info["cert_subject"])
print(info["note"], flush=True)
while True:
    time.sleep(3600)
PYEOF
PORTFILE="$(mktemp /tmp/rootwatch-mitm.port.XXXXXX)"
"$PY" "$RUNNER" "$MITM_PORT" "$HOSTNAME" > "$PORTFILE" &
MITM_PID=$!
for _ in $(seq 1 20); do
  [ -s "$PORTFILE" ] && break
  sleep 0.25
done
MITM_URL="$(sed -n 1p "$PORTFILE" 2>/dev/null || true)"
CERT_SUBJ="$(sed -n 2p "$PORTFILE" 2>/dev/null || true)"
rm -f "$RUNNER" "$PORTFILE"
[ -n "$MITM_URL" ] || { echo "ERROR: MITM server failed to start on port $MITM_PORT" >&2; exit 1; }
echo "    MITM server live at $MITM_URL"
echo "    cert subject: $CERT_SUBJ"
echo
echo "=== [3/6] launch victim container ($IMAGE): sandbox stores mounted at /sandbox, repo at /rootwatch ==="
# --network host lets the victim reach the host's MITM server on 127.0.0.1:$MITM_PORT
docker run -d --name "$CONTAINER" --network host \
  -v "$ROOTWATCH_ROOT":/sandbox -v "$PWD":/rootwatch \
  "$IMAGE" sleep infinity >/dev/null
echo "    installing curl + openssl in the victim (for the visible commands)…"
docker exec "$CONTAINER" sh -c \
  'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl openssl >/dev/null 2>&1' || true

CA=/sandbox/etc/ssl/ca-bundle.crt
CRL=/sandbox/pki/crl.pem
RESOLVE="$HOSTNAME:$MITM_PORT:127.0.0.1"

echo
echo "--- Bob opens https://$HOSTNAME:$MITM_PORT/ (curl --resolve maps the name to 127.0.0.1) ---"
docker exec "$CONTAINER" curl -sS --resolve "$RESOLVE" --cacert "$CA" \
  "https://$HOSTNAME:$MITM_PORT/" -o /tmp/page.html -w '    HTTP %{http_code} — TLS handshake ACCEPTED\n'
docker exec "$CONTAINER" sh -c 'grep -o "<title>[^<]*</title>" /tmp/page.html'
echo "    -> the browser shows a green lock and the (fake) T-Mobile login page"

echo
echo "--- smoking gun: which CA issued the cert Bob just trusted? ---"
docker exec "$CONTAINER" sh -c \
  "echo | openssl s_client -connect 127.0.0.1:$MITM_PORT -servername $HOSTNAME 2>/dev/null \
   | openssl x509 -noout -subject -issuer" | sed 's/^/    /'

echo
echo "--- even a CRL-AWARE client inside the victim accepts it (serial not on the CRL) ---"
CRLPROBE="$(mktemp /tmp/rootwatch-crlprobe.XXXXXX.py)"
cat > "$CRLPROBE" <<'PYEOF'
import ssl, sys, urllib.request
url, ca, crl = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
ctx.load_verify_locations(crl)
ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
try:
    with urllib.request.urlopen(url, context=ctx, timeout=8) as r:
        r.read(80)
    print(f"    CRL-aware client: ACCEPT (HTTP {r.status}) — revocation checking does NOT help")
except Exception as e:
    print(f"    CRL-aware client: REJECT — {type(e).__name__}: {str(e)[:100]}")
PYEOF
docker cp "$CRLPROBE" "$CONTAINER":/tmp/crlprobe.py >/dev/null
rm -f "$CRLPROBE"
docker exec "$CONTAINER" python3 /tmp/crlprobe.py "https://127.0.0.1:$MITM_PORT/" "$CA" "$CRL"
echo
echo "--- Bob enters his credentials on the phishing page and clicks Sign in ---"
docker exec "$CONTAINER" curl -sS --resolve "$RESOLVE" --cacert "$CA" \
  -d "username=bob.smith@example.com" -d "password=hunter2!!" \
  "https://$HOSTNAME:$MITM_PORT/login" -o /dev/null \
  -w '    HTTP %{http_code} — "signed in" (page says Welcome back, Bob)\n'
echo
echo "--- 💀 exfiltrated credentials (attacker loot file on the host) ---"
LOOT_COUNT="$("$PY" -c "from rootwatch import mitmdemo; print(len(mitmdemo.loot()['entries']))")"
"$PY" -c "
from rootwatch import mitmdemo
for e in mitmdemo.loot()['entries']:
    f = e['fields']
    print('    💀 stolen:', {k: v for k, v in f.items()})
"

echo
echo "=== [4/6] cut to RootWatch: load the tool INTO the victim container and audit ==="
docker exec "$CONTAINER" python3 -m pip install -q cryptography pyyaml requests >/dev/null 2>&1
docker exec -e ROOTWATCH_ROOT=/sandbox -e PYTHONPATH=/rootwatch -e ROOTWATCH_REAL_CRL_URLS= \
  -w /rootwatch "$CONTAINER" python3 -m rootwatch.cli audit | sed 's/^/    /'

echo
echo "=== [5/6] ONE ACTION inside the victim: distrust the eMudhra root in ALL 8 stores (mode=root) ==="
docker exec -e ROOTWATCH_ROOT=/sandbox -e PYTHONPATH=/rootwatch -e ROOTWATCH_REAL_CRL_URLS= \
  -w /rootwatch "$CONTAINER" python3 -m rootwatch.cli remediate --mode root | sed 's/^/    /'

echo
echo "=== [6/6] Bob reloads the site — same container, same mounted bundle (updated in place) ==="
if docker exec "$CONTAINER" curl -sS --resolve "$RESOLVE" --cacert "$CA" \
     "https://$HOSTNAME:$MITM_PORT/" -o /dev/null 2>/tmp/mitm-err.txt; then
  RETRY="ACCEPTED"
else
  RETRY="REJECTED"
fi
echo "    curl retry: $RETRY"
grep -o "SSL certificate problem.*" /tmp/mitm-err.txt 2>/dev/null | head -1 | sed 's/^/    /' || true
docker exec "$CONTAINER" python3 /tmp/crlprobe.py "https://127.0.0.1:$MITM_PORT/" "$CA" "$CRL"

echo
if [ "$LOOT_COUNT" -gt 0 ] && [ "$RETRY" = "REJECTED" ]; then
  echo "✅ DEMO PASS: the phishing cert (fresh eMudhra serial, not on any CRL) was accepted"
  echo "   pre-fix and Bob's credentials were exfiltrated; after loading RootWatch into the"
  echo "   victim and distrusting the root once, every client rejects the MITM."
else
  echo "❌ DEMO FAIL: expected credentials stolen pre-fix ($LOOT_COUNT) and REJECTED post-fix ($RETRY)." >&2
  exit 1
fi
