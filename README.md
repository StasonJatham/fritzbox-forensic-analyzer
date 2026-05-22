# FRITZ!Box Forensik SIEM

<p align="center">
  <img src="static/logo.svg" alt="FRITZ!Box Forensik SIEM logo" width="128">
</p>

Local-first FRITZ!Box Forensik SIEM for AVM router evidence, retained FRITZ!OS logs, WiFi forensics, TR-064/Web UI artifacts, host history, and incident-response triage. The tool collects the evidence a FRITZ!Box still exposes, preserves raw artifacts, normalizes parser output into SQLite, indexes everything with full-text search, and presents it in a clean SOC analyst dashboard for timeline review, entity pivoting, correlation, and evidence validation.

This project is built for local incident response, home-network forensics, and small SOC-style router investigations. It is not a cloud SIEM and it does not need tcpdump for historical analysis.

Search terms this project targets: FRITZ!Box SIEM, FritzBox forensics, FRITZ!Box Forensik, FRITZ!OS incident response, AVM router logs, WiFi forensics, TR-064 evidence, local SIEM, router forensic analyzer, home network security investigation.

## What It Does

- Pulls retained FRITZ!Box logs, host tables, mesh state, WLAN association snapshots, broad read-only TR-064 data, internal Web UI Lua data, telephony call/phonebook artifacts, AHA smart-home state, encrypted configuration export metadata, and support-data diagnostics when available.
- Stores raw artifacts, parser rows, normalized SIEM events, correlations, host records, WiFi observations, and run metadata in SQLite.
- Provides backend full-text search across logs, SIEM events, correlations, hosts, WiFi records, support findings, raw artifacts, entities, and timeline rows.
- Shows an analyst dashboard with stored-evidence review, explicit acquisition runs, sortable virtual tables, infinite scrolling, filters, charts, entity pivots, suspicion signals, SIEM correlations, and raw evidence drawers.
- Exports raw artifacts and a forensic acquisition package for offline review.
- Imports previously exported forensic packages or JSON datasets as separate analysis profiles, so analysts can switch between multiple FRITZ!Boxes without merging evidence into one dataset.
- Preserves evidence confidence labels so exact log entries are not confused with inferred observations.

## Documentation

The [docs](docs/README.md) directory contains the detailed FRITZ!Box forensics reference:

- [Data Sources](docs/data-sources.md): endpoint-by-endpoint mapping from FRITZ!Box surfaces to raw artifacts, parsed tables, forensic value, and caveats.
- [Architecture And Flowcharts](docs/architecture.md): visual evidence pipeline, storage module map, SIEM normalization flow, analyst workflow, and source trust model.
- [Evidence Model](docs/evidence-model.md): how raw artifacts become SQLite rows, FTS records, investigation results, and confidence labels.
- [Python Examples](docs/python-examples.md): small scripts for TR-064, AVM export paths, `query.lua`, `data.lua`, support data, and SQLite FTS.
- [Limitations](docs/limitations.md): what can and cannot be proven from retained FRITZ!Box data.

Example scripts:

```bash
python docs/examples/tr064_device_log.py
python docs/examples/avm_export_paths.py
python docs/examples/webui_lua_sources.py
python docs/examples/support_data_download.py
python docs/examples/sqlite_full_text_search.py "failed login"
```

## Forensic SIEM Scope

FRITZ!Box Forensik SIEM is useful when the router is the only available evidence source. It can help answer questions such as:

- Which retained router events mention a client, IP address, hostname, MAC address, or login source?
- Which devices were visible in the current host and mesh tables at acquisition time?
- When did retained authentication, WAN reconnect, firmware, WLAN, or channel events occur?
- Which events are exact raw log evidence and which are derived from current state?
- Which failed login bursts, unknown usernames, unexpected admin sources, or new devices need analyst review?
- Which typed parser rows were promoted into normalized SIEM events and correlations?

## Important Limits

A FRITZ!Box does not always retain exact WiFi association and disassociation rows for every client. If the raw retained log does not contain an exact connection row, this tool cannot prove an exact WiFi join or disconnect time.

Low-confidence rows such as `mesh_last_observed` are contextual observations, not proof of a precise connection timestamp. Absence from the retained log is not proof that an event did not happen. Packet-level broadcast traffic attribution is outside the scope of FRITZ!Box API export data.

FRITZ!Box web UI device-state values such as `firstused` and `lastused` can provide valuable "first seen" and "last connected/used" timestamps. These values are retained router state, not a complete per-session connection log. The dashboard shows source coverage so analysts can see whether that internal LAN-device artifact was collected for a run.

The collector also attempts selected unofficial FRITZ!Box Lua endpoints such as `query.lua`, `data.lua`, and the hidden support-data workflow behind `support.lua`. These are valuable because they mirror parts of the router UI and diagnostic bundle, but they are not stable public APIs. The raw responses are preserved and labeled separately from official TR-064 evidence.

Maximum acquisition mode also attempts firmware-dependent telephony, AHA/smart-home, configuration-backup, and dynamically discovered read-only TR-064 actions. These artifacts can be sensitive and may include phone call metadata, phonebook entries, smart-home device identifiers, router settings, internal service state, public IP information, and topology identifiers. The analyzer keeps them as raw evidence first, then parses only fields that can be labeled with a source and confidence.

## Quick Start

For a minimal local runbook after moving the project to `/Users/karl/Code/fritzforensic`, see [LOCAL_START.md](LOCAL_START.md).

```bash
git clone https://github.com/StasonJatham/fritzbox-forensic-analyzer.git
cd fritzbox-forensic-analyzer

python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# Edit .env locally. Do not commit real credentials.

fritzbox-forensics-dashboard --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`.

The UI only requires the FRITZ!Box IP address and admin password. It auto-detects the remaining connection settings where possible.

Use **Forensic Package** to export a full analysis package. Use **Import Package** to load that ZIP, or a CLI JSON dataset, later as a separate profile, then switch between profiles from the router/profile selector in the header.

Acquisition is a background pipeline, not a single blocking web request. The dashboard enqueues one acquisition job at a time, reports stage progress, writes every successful endpoint response immediately under `output/raw-acquisition-*`, records failed endpoints as local `.error.txt` files plus manifest rows, and parses/imports into SQLite afterward. A bad `data.lua`, `query.lua`, support-data, or TR-064 action should reduce source coverage, not fail the whole run.

## CLI Export

```bash
fritzbox-wifi-export \
  --dataset \
  --hours 10000 \
  --include-disconnects \
  --format json \
  --output fritzbox-export.json
```

Credentials can come from CLI flags, environment variables, or a local `.env`/`.fritzbox.env` file:

```bash
FRITZBOX_ADDRESS=192.168.178.1
FRITZBOX_USER=
FRITZBOX_PASSWORD=change-me
FRITZBOX_PORT=49000
FRITZBOX_TLS=0
FRITZBOX_REQUEST_TIMEOUT=20
FRITZBOX_WEBUI_TIMEOUT=12
FRITZBOX_ACQUISITION_DELAY=0.75
FRITZBOX_HARD_TIMEOUT=30
FRITZBOX_SUPPORT_HARD_TIMEOUT=180
FRITZBOX_DYNAMIC_TR064_MAX_ACTIONS=220
FRITZBOX_MAX_HOSTS=512
FRITZBOX_MAX_PORT_MAPPINGS=512
FRITZBOX_MAX_WLAN_ASSOCIATIONS=256
FRITZBOX_LOG_LEVEL=INFO
FRITZBOX_LOG_FILE=logs/fritzforensic.log
```

Runtime logs are written to `logs/fritzforensic.log` by default with rotation. Use `FRITZBOX_LOG_LEVEL=DEBUG` for endpoint-by-endpoint acquisition debugging. Secret-looking values such as SIDs, passwords, tokens, and keys are redacted before they hit the log file.

## DynDNS + WireGuard Planner

The project includes a dry-run helper for repeatable FRITZ!Box remote-access setup planning:

```bash
fritzbox-vpn-provision --env-example
fritzbox-vpn-provision --output vpn-plan.json
```

The planner reads current router state, checks custom DynDNS and existing WireGuard/VPN entries, then reports idempotent steps. It does **not** change router settings by default. `--apply` is intentionally disabled until a firmware-specific Web UI write workflow is mapped and tested for the target FRITZ!OS version.

Why dry-run first: FRITZ!Box exposes useful read-only state through TR-064 and internal Lua pages, but adding a WireGuard single-device connection is a Web UI wizard flow and may require router confirmation. The helper refuses to replace existing DynDNS domains or matching WireGuard client names unless explicit replacement flags are configured.

## Docker

```bash
cp .env.example .env
# Edit .env locally.
docker compose up --build
```

The dashboard binds to `127.0.0.1:8765` by default. The SQLite database is stored in a Docker volume.

## Dashboard Security

Keep the dashboard bound to `127.0.0.1` unless you are on a trusted network and understand the evidence exposure. Non-local binds require `FRITZBOX_ALLOW_PUBLIC_BIND=1`; when public bind is enabled, `/api/*` requires `FRITZBOX_API_TOKEN` via `X-API-Token` or `Authorization: Bearer`.

## Data Model

The local SQLite database stores:

- `export_runs`: acquisition metadata, router metadata, timestamp assumptions, and source endpoint inventory.
- `raw_artifacts`: raw FRITZ!Box responses with SHA-256 hashes.
- `event_log`: parsed retained router event log rows.
- `siem_events`: normalized local SIEM events derived from retained logs and typed evidence.
- `siem_correlations`: local correlation findings for bursts, sessions, exposure, and entity rollups.
- `wifi_connections`: exact or inferred WiFi-related observations with confidence labels.
- `hosts`: host table context from acquisition time.
- `record_observations`: immutable observation snapshots for comparison across runs.
- `records_fts`: SQLite FTS5 index for backend search.

## Privacy and Evidence Handling

Real router data can reveal personal devices, locations, account names, public IP addresses, MAC addresses, and local network topology. Keep these files private:

- `.env`
- `.fritzbox.env`
- `fritzbox-analysis.sqlite3`
- raw artifact archives
- acquisition packages
- `support_data_txt` raw artifacts
- `call_list_xml`, `phonebooks_xml_json`, `config_export_file`, and AHA smart-home raw artifacts
- JSON, CSV, or screenshot exports from a real network

This repository intentionally does not include real screenshots, sample exports, or captured router data.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
