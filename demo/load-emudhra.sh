#!/usr/bin/env bash
# demo/load-emudhra.sh — load the compromised eMudhra root + issuing CA into the
# sandbox trust stores. This is the demo's ATTACK step: RootWatch never injects
# fake data by default; `setup` seeds a clean copy of the machine's real stores,
# and THIS script plants the incident.
#
# Usage:
#   ./demo/load-emudhra.sh                 # uses ./.sandbox (creates it via `setup` if missing)
#   ROOTWATCH_ROOT=/path/to/sandbox ./demo/load-emudhra.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
export ROOTWATCH_ROOT="${ROOTWATCH_ROOT:-./.sandbox}"

if [ ! -f "$ROOTWATCH_ROOT/scenario.runtime.json" ]; then
  echo "sandbox not found at $ROOTWATCH_ROOT — running clean setup first…"
  "$PY" -m rootwatch.cli setup
fi

"$PY" -m rootwatch.cli inject
