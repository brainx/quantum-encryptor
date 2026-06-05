#!/usr/bin/env sh
set -eu

APP_PORT="${PORT:-4000}"

if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
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

exec "$PYTHON_BIN" -m streamlit run pqc_app.py \
  --server.address 127.0.0.1 \
  --server.port "$APP_PORT"
