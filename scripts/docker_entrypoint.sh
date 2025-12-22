#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"

if [[ "${AAG_SKIP_PIP_INSTALL:-}" != "1" ]] && [[ -f /workspace/requirements.txt ]]; then
  python -m pip install -r /workspace/requirements.txt
fi

exec "$@"
