#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"

if [[ "${AAG_SKIP_PIP_INSTALL:-}" != "1" ]] && [[ -f /workspace/requirements.txt ]]; then
  if ! python - <<'PY' >/dev/null 2>&1; then
import importlib
for module_path in ("androguard.core.bytecodes.apk", "androguard.core.apk"):
    try:
        module = importlib.import_module(module_path)
        getattr(module, "APK")
        raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    python -m pip install -r /workspace/requirements.txt
  fi
fi

exec "$@"
