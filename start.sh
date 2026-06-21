#!/usr/bin/env sh
set -eu

APP_PORT="${PORT:-4000}"

if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
elif [ -x ".venv/bin/python" ]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN=""
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "No Python interpreter found. Set PYTHON to a Python 3.10+ executable." >&2
  exit 127
fi

if [ "${LEGACY_STREAMLIT:-0}" = "1" ]; then
  exec "$PYTHON_BIN" -m streamlit run pqc_app.py \
    --server.address 127.0.0.1 \
    --server.port "$APP_PORT"
fi

if [ "${SKIP_WEB_BUILD:-0}" != "1" ]; then
  if [ ! -x "node_modules/.bin/vite" ]; then
    echo "Frontend dependencies are missing. Run npm install before ./start.sh." >&2
    exit 127
  fi
  npm run build
elif [ ! -f "static/app/index.html" ]; then
  echo "Built frontend not found. Run npm run build or unset SKIP_WEB_BUILD." >&2
  exit 127
fi

PORT="$APP_PORT" exec "$PYTHON_BIN" -m api_app
