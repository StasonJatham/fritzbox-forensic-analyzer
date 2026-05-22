# Architecture And Flowcharts

This page gives maintainers and analysts a visual map of how FRITZ!Box Forensik SIEM moves from router surfaces to raw evidence, typed evidence, normalized SIEM events, and dashboard views.

The diagrams are Mermaid flowcharts so they stay reviewable in Git, render on GitHub, and can be changed alongside the code.

## Evidence Pipeline

```mermaid
flowchart LR
    router["FRITZ!Box / FRITZ!OS"]
    tr064["Official TR-064 actions"]
    exports["AVM export paths"]
    webui["Internal Web UI Lua pages"]
    support["Support-data workflow"]
    aha["AHA / Smart Home"]
    telephony["Telephony exports"]
    raw["Raw artifacts with SHA-256"]
    parsers["Parser layer"]
    typed["Typed evidence tables"]
    siem["Normalized SIEM events"]
    corr["SIEM correlations"]
    fts["SQLite FTS index"]
    views["Dashboard, API, exports"]

    router --> tr064
    router --> exports
    router --> webui
    router --> support
    router --> aha
    router --> telephony
    tr064 --> raw
    exports --> raw
    webui --> raw
    support --> raw
    aha --> raw
    telephony --> raw
    raw --> parsers
    parsers --> typed
    parsers --> siem
    typed --> siem
    siem --> corr
    typed --> fts
    siem --> fts
    corr --> fts
    fts --> views
    typed --> views
    corr --> views
```

## Storage Modules

```mermaid
flowchart TB
    facade["fritzbox_log_store.py facade"]
    schema["fritzbox_store_schema.py schema, migrations, indexes"]
    records["fritzbox_store_records.py row normalization + FTS"]
    ingest["fritzbox_store_ingest.py ingestion orchestration"]
    queries["fritzbox_store_queries.py search + timeline queries"]
    helpers["fritzbox_store_query_helpers.py query utilities"]
    settings["fritzbox_settings_store.py local settings"]
    snapshots["fritzbox_store_snapshots.py snapshot facade"]
    overview["snapshot_overview.py"]
    investigation["snapshot_investigation.py"]
    entities["snapshot_entities.py"]
    summaries["snapshot_summaries.py"]
    evidence["fritzbox_evidence_tables.py typed table registry"]
    extractors["fritzbox_evidence_extractors.py typed evidence extraction"]

    facade --> schema
    facade --> ingest
    facade --> queries
    facade --> snapshots
    facade --> settings
    ingest --> records
    ingest --> evidence
    ingest --> extractors
    queries --> helpers
    queries --> evidence
    snapshots --> overview
    snapshots --> investigation
    snapshots --> entities
    overview --> summaries
```

## SIEM Normalization

```mermaid
flowchart LR
    eventlog["event_log retained router rows"]
    wifi["wifi_connections"]
    hosts["hosts"]
    station["wlan_station_intervals / state"]
    ap["wlan_ap_client_events"]
    exposure["wan_port_mappings / advisories"]
    normalizer["fritzbox_siem.py"]
    events["siem_events"]
    correlations["siem_correlations"]
    links["siem_correlation_events"]

    eventlog --> normalizer
    wifi --> normalizer
    hosts --> normalizer
    station --> normalizer
    ap --> normalizer
    exposure --> normalizer
    normalizer --> events
    events --> correlations
    correlations --> links
    events --> links
```

## Analyst Workflow

```mermaid
flowchart TD
    acquire["Acquire from local FRITZ!Box"]
    manifest["Review source coverage"]
    search["Search raw + parsed + SIEM evidence"]
    pivot["Pivot by host, MAC, IP, rule, source"]
    window["Open investigation time window"]
    validate["Validate finding against raw artifact"]
    export["Export forensic package"]

    acquire --> manifest
    manifest --> search
    search --> pivot
    pivot --> window
    window --> validate
    validate --> export
```

## Source Trust Model

```mermaid
flowchart TB
    exact["Exact retained timestamps"]
    state["Router state snapshots"]
    inferred["Derived or inferred context"]
    rawonly["Raw-only or partial parser coverage"]

    exact -->|"event log, station interval, hostapd row"| high["High confidence if present"]
    state -->|"host table, mesh, current association"| medium["Medium to high at acquisition time"]
    inferred -->|"risk summary, discovery hints"| review["Analyst review required"]
    rawonly -->|"firmware-specific support or Lua fields"| preserve["Preserve raw and label coverage"]
```

## Research Notes

The official FRITZ! development page documents TR-064 as a local-network protocol and lists the current service families used by this project, including WAN, hosts, WLAN, telephony, app setup, device info, and smart-home interfaces. It also documents the AHA/Smart Home interfaces and points developers to `support.lua` for support information generation.

Because FRITZ!OS internal Web UI Lua schemas and support-data sections are firmware-dependent, this project keeps raw artifacts first and treats typed parser rows as derived views over those artifacts.
