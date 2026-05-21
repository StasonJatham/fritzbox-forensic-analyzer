# FRITZ!Box Forensics Documentation

This directory documents the FRITZ!Box data surfaces used by this project, how raw artifacts map into SQLite evidence tables, and how to reproduce the important collection paths with small Python scripts.

The documentation is written for analysts and maintainers. It deliberately separates:

- **Raw evidence**: bytes or text returned by the router and stored with a SHA-256 hash.
- **Parsed evidence**: normalized rows derived from raw artifacts.
- **Inferred evidence**: analyst-friendly context built from multiple sources.
- **Unsupported proof**: claims the FRITZ!Box export cannot support without packet capture or continuous polling.

## Documents

| Document | Purpose |
|---|---|
| [Data Sources](data-sources.md) | Endpoint-by-endpoint inventory of official TR-064, AVM export paths, internal Lua surfaces, support data, AHA, telephony, and configuration artifacts. |
| [TR-064 Artifacts](tr064-artifacts.md) | Official service/action reference used by the collector. |
| [Web UI Artifacts](webui-artifacts.md) | Internal `query.lua`, `data.lua`, and read-only Web UI artifact reference. |
| [Support Data](support-data.md) | Support bundle sections and parser coverage. |
| [WLAN Forensics](wlan-forensics.md) | WiFi connection, station-history, AP-side, and proximity evidence interpretation. |
| [Evidence Model](evidence-model.md) | How raw artifacts become SQLite rows, confidence labels, timelines, investigation rows, and security advisories. |
| [Structured Tables](structured-tables.md) | SQLite table reference for normalized evidence. |
| [Sensitivity and Redaction](sensitivity-and-redaction.md) | What to protect before sharing artifacts, screenshots, or reports. |
| [Parser Gap Register](parser-gap-register.md) | High-value raw fields still worth normalizing further. |
| [Python Examples](python-examples.md) | Small scripts for reproducing the main collection and query patterns. |
| [Limitations](limitations.md) | What can and cannot be proven from FRITZ!Box retained data. |

## Example Scripts

Runnable examples are in [examples](examples). They use `.env` / `.fritzbox.env` or environment variables and do not contain real credentials.

```bash
python docs/examples/tr064_device_log.py
python docs/examples/avm_export_paths.py
python docs/examples/webui_lua_sources.py
python docs/examples/support_data_download.py
python docs/examples/sqlite_full_text_search.py "failed login"
```

## Sensitive Data Handling

Treat all outputs as sensitive. FRITZ!Box artifacts can contain local device names, MAC addresses, public IP addresses, phone metadata, smart-home device IDs, router configuration, and account names.

Do not commit:

- `.env` or `.fritzbox.env`
- `fritzbox-analysis.sqlite3`
- Raw artifact ZIPs
- Forensic acquisition packages
- Screenshots containing real network data
- Support-data dumps
- Configuration exports
