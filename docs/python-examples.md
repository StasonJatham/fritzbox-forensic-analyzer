# Python Examples

The scripts in [examples](examples) are intentionally small and use environment variables. They avoid hardcoded credentials and should not print secrets.

## Setup

```bash
cp .env.example .env
# Edit .env locally. Do not commit it.

python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

Required connection variables:

```bash
FRITZBOX_ADDRESS=192.168.178.1
FRITZBOX_USER=
FRITZBOX_PASSWORD=change-me
FRITZBOX_PORT=49000
FRITZBOX_TLS=0
```

## Scripts

| Script | Demonstrates |
|---|---|
| [tr064_device_log.py](examples/tr064_device_log.py) | Basic TR-064 connection and `DeviceInfo:GetDeviceLog`. |
| [avm_export_paths.py](examples/avm_export_paths.py) | Official export-path actions for device log, host list, mesh list, and WLAN device lists. |
| [webui_lua_sources.py](examples/webui_lua_sources.py) | Authenticated `query.lua` and `data.lua` reads using FRITZ!Box Web UI session handling. |
| [support_data_download.py](examples/support_data_download.py) | Hidden support-data workflow with safe metadata output. |
| [sqlite_full_text_search.py](examples/sqlite_full_text_search.py) | Local SQLite FTS search across stored evidence. |

## Full Dataset Export

Use the project CLI for the complete collector:

```bash
fritzbox-wifi-export \
  --dataset \
  --hours 10000 \
  --include-disconnects \
  --format json \
  --output fritzbox-export.json
```

Store directly in SQLite:

```bash
fritzbox-wifi-export \
  --dataset \
  --hours 10000 \
  --include-disconnects \
  --store-db fritzbox-analysis.sqlite3
```

## Dry-Run DynDNS + WireGuard Plan

```bash
fritzbox-vpn-provision --env-example
fritzbox-vpn-provision --output vpn-plan.json
```

The planner is dry-run only. It checks existing DynDNS and WireGuard state but does not write router settings.
