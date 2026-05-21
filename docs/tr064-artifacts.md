# TR-064 Artifacts

TR-064 is the stable baseline for this project. It is discoverable through the FRITZ!Box service descriptions and accessed through `fritzconnection`.

## Connection Pattern

```python
from fritzconnection import FritzConnection

fc = FritzConnection(
    address="192.168.178.1",
    user="",
    password="change-me",
    port=49000,
    use_tls=False,
    use_cache=True,
)
```

## Actions Used Directly

| Service | Action | Main fields | Raw artifact / destination | Notes |
|---|---|---|---|---|
| `DeviceInfo:1` | `GetInfo` | model, firmware, hardware, serial | dataset `device_info`, `tr064_snapshot_json` | Router identity and firmware context. |
| `DeviceInfo:1` | `GetDeviceLog` | `NewDeviceLog` | fallback log text | Used if XML/path logs are unavailable. |
| `DeviceInfo:1` | `X_AVM-DE_GetDeviceLogPath` | `NewDeviceLogPath` | `device_log_xml` | Preferred retained log artifact. |
| `DeviceInfo:1` | `X_AVM-DE_GetDeviceLogPath` + `filter=wlan` | `NewDeviceLogPath` | `device_log_xml_wlan` | WLAN-filtered retained event log. Captured separately and merged during parsing. |
| `Time:1` | `GetInfo` | router clock | dataset `router_time`, `tr064_snapshot_json` | Used for clock context, not independent validation. |
| `Hosts:1` | `GetHostNumberOfEntries` | count | dataset `known_hosts` | Host iteration entry point. |
| `Hosts:1` | `GetGenericHostEntry` | host attributes | dataset `known_hosts` | Indexed host rows. |
| `Hosts:1` | `GetSpecificHostEntry` | host detail by MAC | dataset `known_hosts` | Enrichment for host rows. |
| `Hosts:1` | `X_AVM-DE_GetHostListPath` | host list path | `host_list_xml` | Official raw host XML. |
| `Hosts:1` | `X_AVM-DE_GetMeshListPath` | mesh list path | `mesh_list` | Mesh topology and station context. |
| `WLANConfiguration:{1..4}` | `X_AVM-DE_GetWLANDeviceListPath` | WLAN client list path | `wlan_device_list_xml_{n}` | Current radio association snapshot. |
| `WLANConfiguration:{1..4}` | `GetInfo` | SSID, enabled, channel/security-ish fields | `tr064_snapshot_json` -> `wlan_radios` | Per-radio state. |
| `WLANConfiguration:{1..4}` | `GetStatistics`, `GetPacketStatistics` | byte/packet counters | `network_status_snapshots` | Snapshot counters. |
| `WLANConfiguration:{1..4}` | `GetTotalAssociations` | association count | `wlan_radios` | Current count only. |
| `WANCommonIFC:1` | `GetCommonLinkProperties` | access type, rates | `network_status_snapshots` | WAN state. |
| `WANCommonIFC:1` | `GetTotalBytes*`, `GetTotalPackets*` | aggregate counters | `network_status_snapshots` | Router-wide WAN counters. |
| `WANIPConn:1` | `GetInfo`, `GetStatusInfo`, `GetExternalIPAddress` | public IP, status, uptime | `network_status_snapshots` | Public-IP evidence. |
| `WANDSLInterfaceConfig:1` | `GetInfo`, `GetStatisticsTotal` | link rates/errors | `network_status_snapshots` | DSL/fiber dependent. |
| `LANHostConfigManagement:1` | `GetInfo` | DHCP/gateway/subnet | `network_status_snapshots` | LAN config snapshot. |
| `LANEthernetInterfaceConfig:1` | `GetInfo`, `GetStatistics` | LAN status/counters | `network_status_snapshots` | LAN aggregate snapshot. |
| `X_AVM-DE_HostFilter:1` | `GetFilterProfiles` | profiles and restrictions | `host_filter_profiles` | Security review context. |
| `X_AVM-DE_AppSetup:1` | `GetConfig`, `GetAppRemoteInfo` | remote access, DDNS/MyFRITZ, external IP | `tr064_snapshot_json`, VPN planner | Remote-access and DynDNS context. |
| `X_AVM-DE_MyFritz:1` | `GetInfo` | MyFRITZ state | `security_advisories` and raw search | Availability varies. |

## Dynamic Read-Only Snapshot

The collector also inspects available TR-064 services and calls candidate read-only actions whose names start with `Get` or `X_AVM-DE_Get`, while blocking mutating words like `Set`, `Add`, `Delete`, `Reboot`, `Start`, and `Stop`.

This produces:

```text
tr064_snapshot_json.service_inventory
tr064_snapshot_json.dynamic_readonly
tr064_snapshot_json.indexed_results
```

Use this when a model exposes extra read-only state not covered by the static action list.

## Interpretation Rules

- TR-064 host and WLAN tables are usually **current state**.
- Device log rows are **retained history** only for as long as FRITZ!OS keeps them.
- WAN/LAN/WLAN counters are **snapshots**, not per-client activity.
- Empty WLAN association lists may mean no clients, disabled radios, unsupported endpoint, or separate AP handling WiFi.
