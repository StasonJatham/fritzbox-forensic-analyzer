#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p output logs

if [[ -n "${FRITZBOX_IP:-}" ]]; then
  export FRITZBOX_ADDRESS="${FRITZBOX_IP}"
fi

if [[ -n "${FRITZBOX_ADMIN_PASS:-}" ]]; then
  export FRITZBOX_PASSWORD="${FRITZBOX_ADMIN_PASS}"
fi

if [[ -z "${FRITZBOX_USER+x}" ]]; then
  export FRITZBOX_USER=""
fi

export PYTHONPATH="${PYTHONPATH:-.}"
export FRITZBOX_CRITICAL_ACQUISITION=1
export FRITZBOX_ACQUISITION_DELAY="${FRITZBOX_ACQUISITION_DELAY:-2.0}"
export FRITZBOX_REQUEST_TIMEOUT="${FRITZBOX_REQUEST_TIMEOUT:-45}"
export FRITZBOX_HARD_TIMEOUT="${FRITZBOX_HARD_TIMEOUT:-90}"
export FRITZBOX_SUPPORT_CONNECT_TIMEOUT="${FRITZBOX_SUPPORT_CONNECT_TIMEOUT:-20}"
export FRITZBOX_SUPPORT_READ_TIMEOUT="${FRITZBOX_SUPPORT_READ_TIMEOUT:-480}"
export FRITZBOX_SUPPORT_HARD_TIMEOUT="${FRITZBOX_SUPPORT_HARD_TIMEOUT:-600}"
export FRITZBOX_WEBUI_TIMEOUT="${FRITZBOX_WEBUI_TIMEOUT:-45}"
export FRITZBOX_LOG_LEVEL="${FRITZBOX_LOG_LEVEL:-INFO}"
export FRITZBOX_LOG_FILE="${FRITZBOX_LOG_FILE:-logs/fritzforensic.log}"

echo "Starting critical raw-first FRITZ!Box acquisition..."
echo "Router: ${FRITZBOX_ADDRESS:-${FRITZBOX_IP:-192.168.178.1}}"
echo "Log: ${FRITZBOX_LOG_FILE}"

.venv/bin/python -m fritzbox_wifi_export \
  --dataset \
  --critical \
  --hours 100000 \
  --store-db fritzbox-analysis.sqlite3 \
  --format json \
  --output output/field-critical-latest.json

echo
echo "Latest critical raw directory:"
find output -maxdepth 1 -type d -name 'raw-critical-*' -print0 | xargs -0 ls -td | head -1
echo
echo "Recent acquisition log lines:"
tail -40 "${FRITZBOX_LOG_FILE}" || true
