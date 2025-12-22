#!/usr/bin/env bash
set -euo pipefail

if ! python -c "import apk_analyzer" >/dev/null 2>&1; then
  python -m pip install -e .
fi

exec "$@"
