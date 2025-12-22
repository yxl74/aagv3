#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"

if [[ "${AAG_SKIP_PIP_INSTALL:-}" != "1" ]] && [[ -f /workspace/requirements.txt ]]; then
  if ! python - <<'PY' >/dev/null 2>&1; then
import importlib
checks = [
    ("androguard.core.bytecodes.apk", "APK"),
    ("androguard.core.apk", "APK"),
]
androguard_ok = False
for module_path, attr in checks:
    try:
        module = importlib.import_module(module_path)
        getattr(module, attr)
        androguard_ok = True
        break
    except Exception:
        continue
fastapi_ok = importlib.util.find_spec("fastapi") is not None
raise SystemExit(0 if androguard_ok and fastapi_ok else 1)
PY
    python -m pip install -r /workspace/requirements.txt
  fi
fi

exec "$@"
