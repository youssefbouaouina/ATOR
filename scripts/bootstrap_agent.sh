#!/usr/bin/env bash
set -e
BASE_URL="${1:-http://127.0.0.1:8000}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v python3 >/dev/null; then
    sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
fi
cd "$ROOT"
if [ ! -f .venv/bin/python ]; then
    python3 -m venv .venv
    ./.venv/bin/pip install -q -r requirements.txt
fi
./.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from agent import agent
cfg = agent.load_config()
cfg['server_url'] = '$BASE_URL'
print(agent.enroll(cfg))
" > /dev/null
echo "enrolled; running one collection"
./.venv/bin/python -m agent.agent once
