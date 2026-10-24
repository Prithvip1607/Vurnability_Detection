#!/usr/bin/env bash
# EVVP — one command: collectors + API + dashboard on http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")/evvp-backend"
PY="${PYTHON:-python3}"

"$PY" - <<'PYCHECK' || { echo "✖ Python 3.10+ is required (set PYTHON=/path/to/python3.x)"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PYCHECK

if [ ! -x .venv/bin/python ]; then
  echo "▶ Creating virtualenv and installing dependencies (first run)…"
  "$PY" -m venv .venv
  if ! .venv/bin/pip install -q -r requirements.txt; then
    echo "⚠ Full install failed; retrying with the minimal core (flask, requests, python-dotenv)…"
    if .venv/bin/pip install -q "flask>=3.0,<4" "requests>=2.31,<3" "python-dotenv>=1.0,<2"; then
      echo "⚠ feedparser unavailable: the built-in RSS/Atom parser will be used."
    # No network / blocked index: fall back to packages already installed system-wide, if they are enough.
    elif "$PY" -c "import flask, requests, dotenv" 2>/dev/null; then
      echo "⚠ pip install failed; using system-installed flask/requests/python-dotenv (optional extras unavailable)."
      rm -rf .venv && "$PY" -m venv --system-site-packages .venv
    else
      rm -rf .venv
      echo "✖ Could not install dependencies. Run:  $PY -m pip install -r evvp-backend/requirements.txt"; exit 1
    fi
  fi
fi
[ -f .env ] || { [ -f ../.env.example ] && cp ../.env.example .env && echo "▶ Created evvp-backend/.env from the example (all values optional)."; }
echo "▶ Dashboard → http://${EVVP_HOST:-127.0.0.1}:${EVVP_PORT:-8000}    (Ctrl+C to stop)"
exec .venv/bin/python main.py "$@"
