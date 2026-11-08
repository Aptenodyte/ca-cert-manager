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
DASH_PORT=8081
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
    --dash-port) DASH_PORT="$2"; shift 2 ;;
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
# self-heal: kill a stale MITM server left over from a previous (interrupted) run
[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
rm -f /tmp/rootwatch-mitm-browser.out /tmp/rootwatch-mitm-browser.err
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
start_mitm() {  # $1 = port (0 = ephemeral)
  "$PY" "$RUNNER" "$1" "$HOSTNAME" > /tmp/rootwatch-mitm-browser.out 2> /tmp/rootwatch-mitm-browser.err &
  echo $! > "$PIDFILE"
  for _ in $(seq 1 20); do
    [ -s /tmp/rootwatch-mitm-browser.out ] && return 0
    sleep 0.25
  done
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  return 1
}
if ! start_mitm "$MITM_PORT"; then
  echo "    port $MITM_PORT busy or failed — retrying on an ephemeral port…"
  : > /tmp/rootwatch-mitm-browser.err
  start_mitm 0 || {
    echo "ERROR: MITM server failed to start." >&2
    sed 's/^/    /' /tmp/rootwatch-mitm-browser.err >&2 || true
    exit 1
  }
fi
MITM_URL="$(sed -n 1p /tmp/rootwatch-mitm-browser.out)"
CERT_SUBJ="$(sed -n 2p /tmp/rootwatch-mitm-browser.out)"
rm -f "$RUNNER"
MITM_PORT="$(printf '%s' "$MITM_URL" | sed -E 's|.*:([0-9]+)/$|\1|')"
echo "    MITM server live at $MITM_URL   cert subject: $CERT_SUBJ"
echo "    (fresh serial — NOT on any CRL; POSTed credentials go to $ROOTWATCH_ROOT/attacker/loot.jsonl)"
echo
echo "=== [3/4] launch victim desktop container ($IMAGE), sandbox at /sandbox, repo at /rootwatch ==="
# clean up leftovers from a previous (interrupted) run: they keep the shared host
# network ports (VNC, dashboard) and their dashboard would serve a STALE sandbox
docker rm -f $(docker ps -aq --filter "name=rootwatch-mitm-browser-") >/dev/null 2>&1 || true
pkill -f "rootwatch.cli web --host 0.0.0.0 --port $DASH_PORT" 2>/dev/null || true
sleep 1
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
docker exec "$CONTAINER" python3 -m pip install -q cryptography pyyaml requests flask >/dev/null 2>&1

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

# profile prefs: no "Restore session?" dialog when the browser is restarted by the
# trust-sync watcher (it would block the demo)
docker exec "$CONTAINER" sh -c 'mkdir -p /root/rw-profile && cat > /root/rw-profile/user.js <<EOF
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.max_resumed_crashes", 0);
user_pref("browser.warnOnQuit", false);
user_pref("browser.startup.page", 0);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.privacyNotice.show", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
EOF'

# watcher: when the system bundle changes (i.e. the UI remediation rewrote it),
# re-sync Firefox's NSS DB — this is what the OS does in the real world — and,
# because a RUNNING Firefox caches its trust store in memory, restart the browser
# so it reloads the NSS DB. The restart is what makes the block visible.
WATCH="$(mktemp /tmp/watch-trust.XXXXXX.sh)"
cat > "$WATCH" <<'WEOF'
#!/bin/sh
# usage: watch-trust <phish-url> [dashboard-url]
PHISH="$1"; DASH="$2"
last=""
while true; do
  n=$(grep -c "BEGIN CERTIFICATE" /sandbox/etc/ssl/ca-bundle.crt 2>/dev/null || echo 0)
  if [ "$n" != "$last" ]; then
    prev="$last"; last="$n"
    /usr/local/bin/sync-browser-trust >> /tmp/watch-trust.log 2>&1
    if [ -n "$prev" ] && [ "$n" -lt "$prev" ]; then
      # the trust store shrank (root distrusted): reload it in Firefox
      echo "trust store shrank ($prev -> $n): restarting Firefox to reload the NSS DB" >> /tmp/watch-trust.log
      pkill -f "firefox-esr --profile /root/rw-profile" 2>/dev/null
      sleep 3
      rm -f /root/rw-profile/lock /root/.parentlock /root/rw-profile/.parentlock 2>/dev/null
      # drop the session store so Firefox doesn't show "Open previous tabs?" after the restart
      rm -f /root/rw-profile/sessionstore.jsonlz4 /root/rw-profile/sessionstore-backups/* 2>/dev/null
      DISPLAY=:99 HOME=/root firefox-esr --profile /root/rw-profile --no-remote \
        "$PHISH" ${DASH:+"$DASH"} >> /tmp/firefox.log 2>&1 &
      sleep 4
      DISPLAY=:99 xdotool search --onlyvisible --class firefox windowmove 0 0 windowsize 1280 780 2>/dev/null || true
    fi
  fi
  sleep 2
done
WEOF
docker cp "$WATCH" "$CONTAINER":/usr/local/bin/watch-trust >/dev/null
rm -f "$WATCH"
docker exec "$CONTAINER" chmod +x /usr/local/bin/watch-trust
docker exec -d "$CONTAINER" sh -c \
  "/usr/local/bin/watch-trust 'https://$HOSTNAME:$MITM_PORT/' 'http://127.0.0.1:$DASH_PORT/' >/dev/null 2>&1 &"
echo "    trust-sync watcher running (re-syncs Firefox + restarts it when the bundle shrinks)"

# browser-trust-check: what does FIREFOX's own trust DB decide about the phishing
# cert? The eMudhra root/intermediate aliases in the NSS DB are exactly what Firefox
# uses to validate the attacker chain, so their presence decides the outcome.
# (aliases are named rootwatch-<sha256 fingerprint>, so we compare fingerprints)
CHECK="$(mktemp /tmp/browser-trust-check.XXXXXX.sh)"
cat > "$CHECK" <<'CEOF'
#!/bin/sh
# usage: browser-trust-check
DB=sql:/root/rw-profile
# wait for a stable alias count (a re-sync deletes then re-adds them)
prev=-1; roots=0
i=0
while [ "$i" -lt 15 ]; do
  LIST="$(certutil -L -d "$DB" 2>/dev/null)"
  roots=$(printf '%s\n' "$LIST" | grep -c '^rootwatch-')
  [ "$roots" = "$prev" ] && break
  prev="$roots"; i=$((i+1)); sleep 1
done
hit=0
for f in /sandbox/pki/root.crt /sandbox/pki/inter.crt; do
  [ -f "$f" ] || continue
  fp=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':')
  [ -n "$fp" ] && printf '%s\n' "$LIST" | grep -qi "rootwatch-$fp" && hit=$((hit+1))
done
if [ "$hit" -gt 0 ]; then
  echo "FIREFOX TRUSTS the phishing cert ($hit/2 eMudhra CAs in its NSS DB, $roots roots) — MITM works"
  exit 0
else
  echo "FIREFOX REJECTS the phishing cert (no eMudhra CA in its NSS DB, $roots roots) — MITM blocked"
  exit 1
fi
CEOF
docker cp "$CHECK" "$CONTAINER":/usr/local/bin/browser-trust-check >/dev/null
rm -f "$CHECK"
docker exec "$CONTAINER" chmod +x /usr/local/bin/browser-trust-check
echo "    browser trust check: $(docker exec "$CONTAINER" browser-trust-check || true)"

# screenshot helper: capture the container desktop (for video frames / slides)
SHOT="$(mktemp /tmp/desktop-shot.XXXXXX.sh)"
cat > "$SHOT" <<'SEOF'
#!/bin/sh
# usage: desktop-shot [outfile]   (capture the X display inside the container)
out="${1:-/tmp/screen.png}"
DISPLAY=:99 import -window root "$out" 2>/dev/null && echo "screenshot: $out"
SEOF
docker cp "$SHOT" "$CONTAINER":/usr/local/bin/desktop-shot >/dev/null
rm -f "$SHOT"
docker exec "$CONTAINER" chmod +x /usr/local/bin/desktop-shot
docker exec "$CONTAINER" sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq imagemagick >/dev/null 2>&1' || true
echo
echo "=== [4/4] start the container desktop: Xvfb :99, x11vnc, noVNC on :$VNC_PORT, Firefox, xterm ==="
docker exec -d "$CONTAINER" sh -c 'Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &'
sleep 1
docker exec -d "$CONTAINER" sh -c 'x11vnc -display :99 -forever -nopw -quiet >/tmp/x11vnc.log 2>&1 &'
docker exec -d "$CONTAINER" sh -c "websockify --web /usr/share/novnc $VNC_PORT localhost:5900 >/tmp/websockify.log 2>&1 &"

# RootWatch dashboard INSIDE the victim container, pointed at the mounted sandbox:
# this is where the remediation is done — with the real web UI (buttons, live log).
docker exec -d -e ROOTWATCH_ROOT=/sandbox -e PYTHONPATH=/rootwatch \
  -e ROOTWATCH_REAL_CRL_URLS= -w /rootwatch "$CONTAINER" \
  sh -c "python3 -m rootwatch.cli web --host 0.0.0.0 --port $DASH_PORT >/tmp/dashboard.log 2>&1 &"
sleep 4
# make sure it is really up and really looking at the victim's sandbox
if ! curl -sf "http://127.0.0.1:$DASH_PORT/api/health" >/dev/null; then
  echo "ERROR: the in-container dashboard did not start (port $DASH_PORT busy?)." >&2
  docker exec "$CONTAINER" tail -5 /tmp/dashboard.log >&2 || true
  echo "       free the port or pass --dash-port <other> and re-run." >&2
  exit 1
fi
DASH_ROOTS="$(curl -sf -X POST "http://127.0.0.1:$DASH_PORT/api/audit" \
  | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(sum(s['total_roots'] for s in d['stores']))" 2>/dev/null || echo 0)"
[ "${DASH_ROOTS:-0}" -gt 0 ] || {
  echo "ERROR: the dashboard is up but sees no roots — stale container/mount?" >&2
  exit 1
}
echo "    dashboard up on :$DASH_PORT (sees $DASH_ROOTS roots in the victim's sandbox)"

# Firefox: ONE instance, two tabs — tab 1 = the phishing site (Bob),
# tab 2 = the RootWatch dashboard (where the fix happens)
docker exec -d -e DISPLAY=:99 -e HOME=/root "$CONTAINER" sh -c \
  "firefox-esr --profile /root/rw-profile --no-remote 'https://$HOSTNAME:$MITM_PORT/' 'http://127.0.0.1:$DASH_PORT/' >/tmp/firefox.log 2>&1 &"
sleep 6
# fill the virtual screen with the browser window (no window manager in the container)
docker exec "$CONTAINER" sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xdotool >/dev/null 2>&1' || true
docker exec -e DISPLAY=:99 "$CONTAINER" sh -c \
  'xdotool search --onlyvisible --class firefox windowmove 0 0 windowsize 1280 780 2>/dev/null || true'
docker exec -d -e DISPLAY=:99 -e HOME=/root "$CONTAINER" sh -c \
  'xterm -geometry 100x28 -e "sh -c \"echo RootWatch victim terminal; echo; echo (the fix can be done in the web UI tab; CLI also works:); echo; echo   ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch python3 -m rootwatch.cli remediate --mode root; echo; echo loot:  cat /sandbox/attacker/loot.jsonl; exec sh\"" >/tmp/xterm.log 2>&1 &'
sleep 6

echo
echo "✅ stage ready."
echo
echo "  👉 open this in YOUR host browser:   http://127.0.0.1:$VNC_PORT/vnc.html"
echo "     (container desktop: Firefox tab 1 = phishing site, tab 2 = RootWatch dashboard)"
echo
echo "  The RootWatch dashboard ALSO runs in the container: http://127.0.0.1:$DASH_PORT/"
echo "  (reachable from your host browser too — same UI, pointed at the victim's /sandbox)"
echo
echo "  VIDEO FLOW:"
echo "   1. in Firefox (tab 1): the fake T-Mobile page loads with a GREEN LOCK — click the"
echo "      lock: the cert was issued by 'CN=eMudhra Demo Issuing CA' (fresh serial, not on any CRL)"
echo "   2. sign in as Bob (any credentials) — then on the HOST:  cat $ROOTWATCH_ROOT/attacker/loot.jsonl"
echo "      shows 💀 the exfiltrated credentials"
echo "   3. cut to the RootWatch dashboard (tab 2, or http://127.0.0.1:$DASH_PORT/):"
echo "        • click '🔍 Audit CA stores'  -> all 8 stores show ALERT"
echo "        • click a store row to expand it, then click '☢️ Distrust entire root'"
echo "          (repeat for each affected store — the live log shows every action)"
echo "        • CLI alternative in the container xterm:"
echo "          ROOTWATCH_ROOT=/sandbox PYTHONPATH=/rootwatch \\"
echo "            python3 -m rootwatch.cli remediate --mode root"
echo "   4. reload tab 1 in Firefox -> 'Warning: Potential Security Risk Ahead' = MITM BLOCKED"
echo "      (the trust-sync watcher re-syncs Firefox's NSS DB automatically after the fix)"
echo
echo "  container: $CONTAINER   MITM server pid: $(cat "$PIDFILE")"
echo "  cleanup when done:  ./demo/run-mitm-browser-demo.sh --cleanup"
