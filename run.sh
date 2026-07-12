#!/usr/bin/env bash
# Janus — one-command launcher
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

echo "Running pipeline sanity check..."
python -m janus.pipeline | head -n 40

echo ""
echo "Starting Janus at http://127.0.0.1:8000 (Ctrl+C to stop)"
exec uvicorn janus.api:app --host 127.0.0.1 --port 8000
