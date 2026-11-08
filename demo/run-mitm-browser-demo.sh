#!/usr/bin/env bash
# demo/run-mitm-browser-demo.sh — VISUAL MITM demo: a real browser inside a Docker
# victim container, driven through noVNC from your host browser.
#
# Stage set up by this script:
#   * host: clean RootWatch sandbox + compromised eMudhra root planted, and a phishing
#     server on 127.0.0.1:$MITM_PORT presenting a FRESH cert for $HOSTNAME (serial NOT
#     on any CRL — even CRL-aware clients accept it)
#   * victim container (--network host, so 127.0.0.1 reaches the host server):
#       - sandbox trust stores bind-mounted at /sandbox, repo at /rootwatch
#       - /etc/hosts maps $HOSTNAME -> 127.0.0.1
#       - Firefox profile whose NSS DB is synced from /sandbox/etc/ssl/ca-bundle.crt
#         (helper: sync-browser-trust, re-run after remediation)
#       - Xvfb + x11vnc + noVNC on :$VNC_PORT, Firefox and xterm already open
#
# Then YOU drive the video:
#   1. open http://127.0.0.1:$VNC_PORT/vnc.html in your host browser
#   2. in the container desktop, Firefox shows https://$HOSTNAME:$MITM_PORT/ with a
#      GREEN LOCK (cert issued by "eMudhra Demo Issuing CA") — sign in as Bob and the
#      credentials land in the attacker loot: cat /sandbox/attacker/loot.jsonl
#   3. in the container xterm, run RootWatch:  (ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch
#        python3 -m rootwatch.cli remediate --mode root)  then  sync-browser-trust
#   4. reload the page in Firefox -> "Warning: Potential Security Risk Ahead" (blocked)
#
# Usage:
#   ./demo/run-mitm-browser-demo.sh                 # set the stage (image python:3.14-slim)
#   ./demo/run-mitm-browser-demo.sh --cleanup       # kill MITM server + remove container
#   ./demo/run-mitm-browser-demo.sh --image python:3.14-slim --mitm-port 9443 --vnc-port 6080
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="python:3.14-slim"
MITM_PORT=9443
VNC_PORT=6080
HOSTNAME="www.t-mobile.com"
PIDFILE=/tmp/rootwatch-mitm-browser.pid
CIDFILE=/tmp/rootwatch-mitm-browser.container

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
export ROOTWATCH_ROOT="${ROOTWATCH_ROOT:-$PWD/.sandbox}"

if [ "${1:-}" = "--cleanup" ]; then
  [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
  [ -f "$CIDFILE" ] && docker rm -f "$(cat "$CIDFILE")" >/dev/null 2>&1 || true
  rm -f "$PIDFILE" "$CIDFILE"
  echo "cleaned up: MITM server stopped, victim container removed"
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --mitm-port) MITM_PORT="$2"; shift 2 ;;
    --vnc-port) VNC_PORT="$2"; shift 2 ;;
    --hostname) HOSTNAME="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found. Install Docker, or run ./demo/run-mitm-demo.sh (no Docker needed)." >&2; exit 1; }
docker info >/dev/null 2>&1 || {
  echo "ERROR: cannot reach the Docker daemon ('docker info' failed)." >&2
  echo "       If it says 'permission denied ... /var/run/docker.sock', run:" >&2
  echo "         sudo usermod -aG docker \$USER && newgrp docker" >&2
  echo "       then re-run this script (or run it with sudo)." >&2
  exit 1
}

echo "=== [1/4] clean sandbox (real stores) + plant compromised eMudhra root (attack step) ==="
"$PY" -m rootwatch.cli setup
./demo/load-emudhra.sh

echo
echo "=== [2/4] attacker mints a FRESH phishing cert for $HOSTNAME; phishing server on :$MITM_PORT ==="
RUNNER="$(mktemp /tmp/rootwatch-mitm.XXXXXX.py)"
cat > "$RUNNER" <<'PYEOF'
import sys, time
from rootwatch import mitmdemo
info = mitmdemo.mint_and_start(port=int(sys.argv[1]), hostname=sys.argv[2])
print(info["url"], flush=True)
print(info["cert_subject"], flush=True)
while True:
    time.sleep(3600)
PYEOF
"$PY" "$RUNNER" "$MITM_PORT" "$HOSTNAME" > /tmp/rootwatch-mitm-browser.out 2>/dev/null &
echo $! > "$PIDFILE"
for _ in $(seq 1 20); do
  [ -s /tmp/rootwatch-mitm-browser.out ] && break
  sleep 0.25
done
MITM_URL="$(sed -n 1p /tmp/rootwatch-mitm-browser.out 2>/dev/null || true)"
CERT_SUBJ="$(sed -n 2p /tmp/rootwatch-mitm-browser.out 2>/dev/null || true)"
rm -f "$RUNNER"
[ -n "$MITM_URL" ] || { echo "ERROR: MITM server failed to start on port $MITM_PORT" >&2; exit 1; }
echo "    MITM server live at $MITM_URL   cert subject: $CERT_SUBJ"
echo "    (fresh serial — NOT on any CRL; POSTed credentials go to $ROOTWATCH_ROOT/attacker/loot.jsonl)"
echo
echo "=== [3/4] launch victim desktop container ($IMAGE), sandbox at /sandbox, repo at /rootwatch ==="
CONTAINER="rootwatch-mitm-browser-$$"
echo "$CONTAINER" > "$CIDFILE"
# --network host: 127.0.0.1 inside the container IS the host, so the phishing
# server on 127.0.0.1:$MITM_PORT and the noVNC port :$VNC_PORT are directly reachable
docker run -d --name "$CONTAINER" --network host \
  -v "$ROOTWATCH_ROOT":/sandbox -v "$PWD":/rootwatch \
  "$IMAGE" sleep infinity >/dev/null

echo "    installing firefox-esr, Xvfb/x11vnc/noVNC, certutil, xterm, pip deps (one-time, a few min)…"
docker exec "$CONTAINER" sh -c \
  'apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
     firefox-esr xvfb x11vnc novnc websockify libnss3-tools xterm curl openssl >/dev/null 2>&1'
docker exec "$CONTAINER" python3 -m pip install -q cryptography pyyaml requests >/dev/null 2>&1

echo "    mapping $HOSTNAME -> 127.0.0.1 in the container /etc/hosts…"
docker exec "$CONTAINER" sh -c "echo '127.0.0.1 $HOSTNAME' >> /etc/hosts"

SYNC="$(mktemp /tmp/sync-browser-trust.XXXXXX.sh)"
cat > "$SYNC" <<'SHEOF'
#!/bin/sh
# Sync Firefox's NSS trust DB from the sandbox system bundle (what the OS does when
# the system CA bundle changes). Re-imports every cert in /sandbox/etc/ssl/ca-bundle.crt
# as rootwatch-<sha256-fp>; stale rootwatch-* entries are deleted first.
set -e
PROFILE=/root/rw-profile
BUNDLE=/sandbox/etc/ssl/ca-bundle.crt
DB="sql:$PROFILE"
mkdir -p "$PROFILE"
[ -f "$PROFILE/cert9.db" ] || certutil -N -d "$DB" --empty-password
certutil -L -d "$DB" 2>/dev/null | grep '^rootwatch-' | while read -r a _; do
  certutil -D -d "$DB" -n "$a" 2>/dev/null || true
done
rm -f /tmp/rwcert*.pem
awk -v pre=/tmp/rwcert 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} {print > (pre c ".pem")}' "$BUNDLE"
for f in /tmp/rwcert*.pem; do
  [ -s "$f" ] || continue
  fp=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':')
  [ -n "$fp" ] && certutil -A -d "$DB" -n "rootwatch-$fp" -t "CT,C,C" -i "$f"
done
rm -f /tmp/rwcert*.pem
echo "browser trust synced from $BUNDLE ($(certutil -L -d "$DB" 2>/dev/null | grep -c '^rootwatch-') roots)"
SHEOF
docker cp "$SYNC" "$CONTAINER":/usr/local/bin/sync-browser-trust >/dev/null
rm -f "$SYNC"
docker exec "$CONTAINER" chmod +x /usr/local/bin/sync-browser-trust
docker exec "$CONTAINER" sync-browser-trust
echo
echo "=== [4/4] start the container desktop: Xvfb :99, x11vnc, noVNC on :$VNC_PORT, Firefox, xterm ==="
docker exec -d "$CONTAINER" sh -c 'Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &'
sleep 1
docker exec -d "$CONTAINER" sh -c 'x11vnc -display :99 -forever -nopw -quiet >/tmp/x11vnc.log 2>&1 &'
docker exec -d "$CONTAINER" sh -c "websockify --web /usr/share/novnc $VNC_PORT localhost:5900 >/tmp/websockify.log 2>&1 &"
docker exec -d -e DISPLAY=:99 -e HOME=/root "$CONTAINER" sh -c \
  "firefox-esr --profile /root/rw-profile --no-remote 'https://$HOSTNAME:$MITM_PORT/' >/tmp/firefox.log 2>&1 &"
docker exec -d -e DISPLAY=:99 -e HOME=/root "$CONTAINER" sh -c \
  'xterm -geometry 100x28 -e "sh -c \"echo RootWatch victim terminal; echo; echo audit: ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch python3 -m rootwatch.cli audit; echo fix:   ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch python3 -m rootwatch.cli remediate --mode root; echo then:  sync-browser-trust; exec sh\"" >/tmp/xterm.log 2>&1 &'
sleep 6

echo
echo "✅ stage ready."
echo
echo "  👉 open this in YOUR host browser:   http://127.0.0.1:$VNC_PORT/vnc.html"
echo "     (container desktop; Firefox is already on https://$HOSTNAME:$MITM_PORT/)"
echo
echo "  VIDEO FLOW:"
echo "   1. in Firefox: the fake T-Mobile page loads with a GREEN LOCK — click the lock,"
echo "      the cert was issued by 'CN=eMudhra Demo Issuing CA' (fresh serial, not on any CRL)"
echo "   2. sign in as Bob (any credentials) — then on the HOST:  cat $ROOTWATCH_ROOT/attacker/loot.jsonl"
echo "      shows 💀 the exfiltrated credentials"
echo "   3. in the container xterm:  ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch \\"
echo "        python3 -m rootwatch.cli remediate --mode root        # one action, all 8 stores"
echo "      then:  sync-browser-trust                                  # re-sync Firefox NSS from the fixed bundle"
echo "   4. reload the page in Firefox -> 'Warning: Potential Security Risk Ahead' = MITM BLOCKED"
echo
echo "  container: $CONTAINER   MITM server pid: $(cat "$PIDFILE")"
echo "  cleanup when done:  ./demo/run-mitm-browser-demo.sh --cleanup"
