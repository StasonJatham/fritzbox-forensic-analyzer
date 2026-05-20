# FRITZ!Box Forensic Analyzer

<p align="center">
  <img src="static/logo.svg" alt="FRITZ!Box Forensic Analyzer logo" width="128">
</p>

Local FRITZ!Box forensic analysis for AVM router logs, WiFi connection history, host tables, TR-064 data, and retained raw evidence. The tool collects the data a FRITZ!Box still exposes, stores it in SQLite with full-text search, and presents it in a clean SOC analyst dashboard for timeline review, entity pivoting, and evidence validation.

This project is built for local incident response and home-network forensics. It does not use packet capture and does not need tcpdump.

## What It Does

- Pulls retained FRITZ!Box logs, host tables, mesh state, WLAN association snapshots, TR-064 router/WAN/WLAN status, FRITZ!Box web UI LAN-device state, and support-data diagnostics when available.
- Stores raw artifacts, parsed events, host records, WiFi observations, and run metadata in SQLite.
- Provides backend full-text search across logs, hosts, WiFi records, entities, and timeline rows.
- Shows an analyst dashboard with stored-evidence review, explicit acquisition runs, sortable virtual tables, infinite scrolling, filters, charts, entity pivots, suspicion signals, and raw evidence drawers.
- Exports raw artifacts and a forensic acquisition package for offline review.
- Imports previously exported forensic packages or JSON datasets as separate analysis profiles, so analysts can switch between multiple FRITZ!Boxes without merging evidence into one dataset.
- Preserves evidence confidence labels so exact log entries are not confused with inferred observations.

## Forensic Scope

The analyzer is useful for FRITZ!Box forensic triage when the router is the only available data source. It can help answer questions such as:

- Which retained router events mention a client, IP address, hostname, MAC address, or login source?
- Which devices were visible in the current host and mesh tables at acquisition time?
- When did retained authentication, WAN reconnect, firmware, WLAN, or channel events occur?
- Which events are exact raw log evidence and which are derived from current state?
- Which failed login bursts, unknown usernames, unexpected admin sources, or new devices need analyst review?

## Important Limits

A FRITZ!Box does not always retain exact WiFi association and disassociation rows for every client. If the raw retained log does not contain an exact connection row, this tool cannot prove an exact WiFi join or disconnect time.

Low-confidence rows such as `mesh_last_observed` are contextual observations, not proof of a precise connection timestamp. Absence from the retained log is not proof that an event did not happen. Packet-level broadcast traffic attribution is outside the scope of FRITZ!Box API export data.

FRITZ!Box web UI device-state values such as `firstused` and `lastused` can provide valuable "first seen" and "last connected/used" timestamps. These values are retained router state, not a complete per-session connection log. The dashboard shows source coverage so analysts can see whether that internal LAN-device artifact was collected for a run.

The collector also attempts selected unofficial FRITZ!Box Lua endpoints such as `query.lua`, `data.lua`, and the hidden support-data workflow behind `support.lua`. These are valuable because they mirror parts of the router UI and diagnostic bundle, but they are not stable public APIs. The raw responses are preserved and labeled separately from official TR-064 evidence.

## Quick Start

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
```

## Docker

```bash
cp .env.example .env
# Edit .env locally.
docker compose up --build
```

The dashboard binds to `127.0.0.1:8765` by default. The SQLite database is stored in a Docker volume.

## Data Model

The local SQLite database stores:

- `export_runs`: acquisition metadata, router metadata, timestamp assumptions, and source endpoint inventory.
- `raw_artifacts`: raw FRITZ!Box responses with SHA-256 hashes.
- `event_log`: parsed retained router event log rows.
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
