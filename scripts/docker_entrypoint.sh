#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"

if [[ "${AAG_SKIP_PIP_INSTALL:-}" != "1" ]] && [[ -f /workspace/requirements.txt ]]; then
  if ! python -c "from androguard.core.bytecodes.apk import APK" >/dev/null 2>&1; then
    python -m pip install -r /workspace/requirements.txt
  fi
fi

exec "$@"
