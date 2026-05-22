# Structured Tables

This page summarizes the normalized SQLite tables used by the analyzer.

| Table | Source artifacts | Important fields | Notes |
|---|---|---|---|
| `export_runs` | Dataset metadata | `generated_at`, `router_address`, `router_metadata_json`, `source_endpoints_json` | One row per acquisition/import. |
| `raw_artifacts` | All `raw_exports` | `name`, `sha256`, `content`, `created_at` | Raw evidence store. |
| `event_log` | Device/support/data logs | `timestamp`, `category`, `mac`, `ip`, `message` | Retained log rows. |
| `wifi_connections` | Event log, support station history, mesh/WLAN lists | `derived_connected_at`, `event`, `hostname`, `mac`, `ip`, `source`, `evidence_level` | Mixed exact and derived WiFi observations. |
| `hosts` | TR-064 host table, `landevice` query | `hostname`, `mac`, `ip`, `interface`, `first_seen`, `last_seen`, `last_connected`, `vendor`, `model`, `flags` | Current/known device context. |
| `support_findings` | Support/data/query artifacts | `finding_type`, `section`, `key`, `value`, `line_number`, `raw_text` | Generic parsed diagnostic evidence. |
| `record_observations` | All ingest paths | `record_type`, `record_key`, `observed_at`, `event_time`, `source`, `content_json` | Per-run immutable observation layer. |
| `records_fts` | Search index | `record_type`, `record_id`, `content` | Backend full-text search. |
| `siem_events` | Event log and typed evidence promotion | `event_time`, `event_category`, `event_kind`, `severity`, `entity`, `mac`, `ip`, `source`, `record_type`, `record_id`, `fields_json` | Local normalized SIEM event stream. |
| `siem_correlations` | SIEM event windows and entity rollups | `rule_id`, `confidence`, `entity_key`, `first_seen`, `last_seen`, `event_count`, `severity`, `summary` | Analyst triage findings; validate linked evidence. |
| `siem_correlation_events` | Correlation support links | `correlation_id`, `event_id`, `role`, `reason`, `weight` | Many-to-many link from correlation findings to SIEM events. |
| `host_filter_profiles` | TR-064 HostFilter, query artifacts | `profile_id`, `name`, `access_mode`, `blocked`, `devices_json` | Parental/filter state. |
| `mesh_topology_links` | `mesh_list` | `node`, `peer`, `interface`, `link_type`, `state`, `last_connected` | Mesh topology and link timestamps. |
| `wan_port_mappings` | TR-064 WAN, `query.lua` port sharing | `protocol`, `external_port`, `internal_client`, `internal_port`, `enabled` | Exposure review. |
| `wlan_radios` | TR-064 WLAN | `radio_index`, `ssid`, `enabled`, `channel`, `total_associations`, counters | Radio state. |
| `wlan_associations` | WLAN device lists, mesh station snapshots | `observed_at`, `radio_index`, `mac`, `ip`, `hostname`, `signal_strength`, `guest` | Current association snapshot. |
| `wlan_station_state_snapshots` | Support `STATION_LIST`, Lua WLAN state | `observed_at`, `mac`, `hostname`, `ip`, `interface`, `active`, `guest`, `rssi`, `quality`, counters | Station state snapshot, not a complete history. |
| `wlan_station_intervals` | Support station history | `connected_at`, `disconnected_at`, `duration_seconds`, `mac`, `interface`, `disconnect_reason_code`, `open_interval` | Retained station interval evidence when firmware includes it. |
| `wlan_ap_client_events` | hostapd/AP-side support rows | `event_time`, `event_type`, `mac`, `interface`, `aid`, `status_code`, `reason_code` | Authentication/association lifecycle evidence. |
| `wlan_event_details` | Support `WLAN_EVENTS` | `event_time`, `event_id`, `band`, `channel`, `previous_channel`, `rate`, `mac`, `interface` | AP-side WLAN event details with firmware-dependent semantics. |
| `dhcp_leases` | `data.lua` / `query.lua` network state | `hostname`, `mac`, `ip`, `lease_expires_at`, `interface`, `source` | Lease state where exposed by firmware. |
| `telephony_records` | `call_list_xml`, `phonebooks_xml_json` | `record_kind`, `timestamp`, `direction`, `name`, `number`, `source` | Sensitive call/contact metadata. |
| `aha_device_states` | AHA HTTP artifacts | `ain`, `name`, `device_type`, `present`, `state_json`, `source` | Sensitive smart-home inventory/state. |
| `advertisement_hints` | Support/raw artifact keyword extraction and WLAN scans | `observed_at`, `protocol`, `hostname`, `mac`, `direction`, `confidence`, `summary` | Hints, not complete packet attribution. |
| `network_status_snapshots` | TR-064 counters, support WLAN environment | `observed_at`, `area`, `metric`, `value`, `unit` | WAN/LAN/WLAN counters and events. |
| `device_risk_summaries` | Derived from hosts and exposure | `device_key`, `risk_level`, `risk_score`, `reasons_json` | Analyst triage, not proof of compromise. |
| `security_advisories` | Derived from settings/exposure | `advisory_id`, `severity`, `category`, `subject`, `recommendation`, `confidence` | Review raw evidence before remediation. |

## FTS Query Example

```sql
SELECT record_type, record_id, snippet(records_fts, 2, '[', ']', '...', 12)
FROM records_fts
WHERE records_fts MATCH 'iphone AND wlan'
LIMIT 20;
```

## Record Observations

`record_observations` is useful for run comparison and timeline reconstruction because it records when a fact was observed by the collector, even when the underlying row already existed from a prior run.
