#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

latest="${1:-}"
if [[ -z "${latest}" ]]; then
  latest="$(find output -maxdepth 1 -type d -name 'raw-critical-*' -print0 | xargs -0 ls -td 2>/dev/null | head -1 || true)"
fi

if [[ -z "${latest}" || ! -d "${latest}" ]]; then
  echo "No raw-critical acquisition directory found."
  exit 1
fi

echo "Raw dir: ${latest}"

if [[ -f "${latest}/summary.json" ]]; then
  jq -r '"Attempts: \(.attempt_count) | OK: \(.successful_count) | Failed: \(.failed_count)"' "${latest}/summary.json"
elif [[ -f "${latest}/manifest.jsonl" ]]; then
  awk '
    /"ok": true/ { ok += 1 }
    /"ok": false/ { fail += 1 }
    END { printf("Attempts: %d | OK: %d | Failed: %d\n", ok + fail, ok, fail) }
  ' "${latest}/manifest.jsonl"
else
  echo "No manifest found yet."
fi

required=(
  device_log_text_json
  hosts_tr064_generic_json
  landevice_query_json
  query_lua_landevice_all
  query_lua_landevice_topology
  data_lua_page_log
  data_lua_page_homeNet
  data_lua_page_wlan
  data_lua_page_wlanSta
  device_info_json
  router_time_json
  support_data_txt
)

if [[ -f "${latest}/manifest.jsonl" ]]; then
  echo
  echo "Critical artifacts:"
  for artifact in "${required[@]}"; do
    if grep -q "\"artifact\": \"${artifact}\".*\"ok\": true" "${latest}/manifest.jsonl"; then
      printf "  OK      %s\n" "${artifact}"
    elif grep -q "\"artifact\": \"${artifact}\".*\"ok\": false" "${latest}/manifest.jsonl"; then
      printf "  FAILED  %s\n" "${artifact}"
    else
      printf "  PENDING %s\n" "${artifact}"
    fi
  done
fi

echo
echo "Largest files:"
find "${latest}" -maxdepth 1 -type f -exec ls -lh {} + 2>/dev/null | sort -k5 -hr | head -8

echo
echo "Latest log lines:"
tail -20 "${FRITZBOX_LOG_FILE:-logs/fritzforensic.log}" 2>/dev/null || true

if [[ -f output/field-critical-latest.json ]]; then
  echo
  echo "Parsed summary:"
  jq -r '.summary | "events=\(.event_log_entries // 0) wifi_events=\(.wifi_events // 0) hosts=\(.known_hosts // 0) raw_dir=\(.raw_acquisition_dir // "")"' output/field-critical-latest.json
fi
