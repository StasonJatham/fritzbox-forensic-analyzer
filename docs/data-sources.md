# Data Sources

This page documents the data surfaces collected by the analyzer. The names in `Raw artifact key` match keys stored in the dataset under `raw_exports` and later in the SQLite `raw_artifacts` table.

## Source Classes

| Class | Stability | Sensitivity | Notes |
|---|---:|---:|---|
| Official TR-064 actions | High | Medium to high | Model-specific but documented and discoverable from service descriptions. |
| AVM TR-064 export paths | High | Medium to high | Official actions return temporary URLs for richer XML/JSON artifacts. |
| Internal Web UI `query.lua` / `data.lua` | Medium | Medium to high | Firmware-dependent and not a stable public API. Valuable because it mirrors FRITZ!OS UI state. |
| Hidden support-data workflow | Medium | Very high | Deep diagnostic bundle. Best raw coverage, but includes sensitive service/config state. |
| AHA HTTP interface | High | Medium | Smart-home context if FRITZ!DECT/AHA devices exist. |
| Telephony exports | High | High | Call lists and phonebooks where available. |
| Configuration export | High | Very high | Encrypted settings backup. Retain as sensitive evidence. |

## Collection Matrix

| Source / endpoint | Raw artifact key | Collected by | Parsed into | Forensic value | Caveats |
|---|---|---|---|---|---|
| `DeviceInfo:1#GetInfo` | `tr064_snapshot_json`, dataset `device_info` | `get_device_info`, `collect_tr064_snapshot` | `export_runs.router_metadata_json`, `network_status_snapshots` | Model, firmware, serial-ish context, device description. | No client activity by itself. |
| `DeviceInfo:1#GetDeviceLog` | Fallback log text, `tr064_snapshot_json` | `get_device_log` | `event_log`, `wifi_connections` | Retained router event log: auth, WLAN, WAN, firmware, channel events. | Retention is limited; absence is not proof. |
| `DeviceInfo:1#X_AVM-DE_GetDeviceLogPath` | `device_log_xml`, `device_log_text` | `fetch_avm_exports`, raw acquisition export-path stage | `event_log`, `wifi_connections` | Richer retained event-log XML path when exposed. | Same retention limits as UI event log. |
| `DeviceInfo:1#X_AVM-DE_GetDeviceLogPath&filter=wlan` | `device_log_xml_wlan` | raw acquisition export-path stage | `event_log`, `wifi_connections` | WLAN-filtered retained event log; useful when the generic event log omits or truncates WLAN rows. | Same retention limits as UI event log; firmware may ignore the filter. |
| `Hosts:1#GetHostNumberOfEntries`, `GetGenericHostEntry`, `GetSpecificHostEntry` | Dataset `known_hosts` | `get_hosts` | `hosts`, `record_observations`, entity pivots | Current/known host identity, IP, MAC, interface, active state. | Current state, not full historic sessions. |
| `Hosts:1#X_AVM-DE_GetHostListPath` | `host_list_xml` | `fetch_avm_exports` | `hosts`, raw search | Official host-list XML. | Fields vary by FRITZ!OS. |
| `Hosts:1#X_AVM-DE_GetMeshListPath` | `mesh_list` | `fetch_avm_exports` | `mesh_topology_links`, `wlan_associations`, `wifi_connections` context | Mesh topology, links, known WiFi devices, last-connected-like fields when present. | Often state snapshots, not full history. |
| `WLANConfiguration:{1..4}#GetInfo` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `wlan_radios`, `network_status_snapshots` | SSID, enabled state, radio config, security hints. | Per-index availability differs by model. |
| `WLANConfiguration:{1..4}#GetStatistics`, `GetPacketStatistics` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | Radio counters, bytes/packets where exposed. | Snapshot only. |
| `WLANConfiguration:{1..4}#GetTotalAssociations` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `wlan_radios` | Current association count per radio. | Not a historic join count. |
| `WLANConfiguration:{1..4}#X_AVM-DE_GetWLANDeviceListPath` | `wlan_device_list_xml_{n}`, `wlan_device_list_xml` | `fetch_avm_exports`, raw acquisition export-path stage | `wlan_associations` | Current associated WLAN clients: MAC/IP/name/auth/signal fields when exposed. | Current snapshot only. |
| `WANCommonIFC:1#GetCommonLinkProperties` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | WAN link state and nominal rates. | Not per-client usage. |
| `WANCommonIFC:1#GetTotalBytes*`, `GetTotalPackets*` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | Router WAN traffic counters. | Aggregate counters only. |
| `WANCommonIFC:1#X_AVM-DE_GetOnlineMonitor` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | WAN online monitor snapshot where supported. | Firmware/model-specific. |
| `WANIPConn:1#GetInfo`, `GetStatusInfo`, `GetExternalIPAddress` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots`, `wan_port_mappings` | External IP, connection status, port mappings via indexed calls. | Public IP may be sensitive. |
| `WANDSLInterfaceConfig:1`, `WANDSLLinkConfig:1` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | DSL/fiber link state, errors/rates where exposed. | Not useful on every access type. |
| `LANHostConfigManagement:1#GetInfo` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | DHCP scope, DNS, gateway/subnet details. | Snapshot only. |
| `LANEthernetInterfaceConfig:1#GetInfo`, `GetStatistics` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `network_status_snapshots` | LAN interface state/counters. | Usually aggregate. |
| `X_AVM-DE_HostFilter:1#GetFilterProfiles` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `host_filter_profiles`, `security_advisories` | Parental/filter profiles and blocked-device context. | Requires rights and firmware support. |
| `X_AVM-DE_AppSetup:1#GetConfig` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `security_advisories`, raw search | Access-rights context, internet access rights. | Not a full user audit. |
| `X_AVM-DE_AppSetup:1#GetAppRemoteInfo` | `tr064_snapshot_json` | `collect_tr064_snapshot`, VPN planner | `network_status_snapshots`, `security_advisories`, VPN planner | External IP, MyFRITZ/DynDNS state, subnet. | Read-only; does not configure DynDNS. |
| `X_AVM-DE_MyFritz:1#GetInfo` | `tr064_snapshot_json` | `collect_tr064_snapshot` | `security_advisories`, raw search | MyFRITZ remote access state. | Availability varies. |
| Dynamic read-only TR-064 service scan | `tr064_snapshot_json.dynamic_readonly` | `collect_dynamic_readonly_actions` | Raw search, selected `network_status_snapshots` | Broad model-specific read-only state inventory. | Avoids mutating actions by name filter, but still store as sensitive raw evidence. |
| `query.lua` `landevice:settings/landevice/list(...)` | `landevice_query_json`, `query_lua_artifacts_json.landevice_all` | `fetch_landevice_query`, `fetch_query_lua_artifacts` | `hosts`, `wifi_connections`, support findings | `firstused`, `lastused`, IP/MAC lists, interface, parent UID, guest/blocked, UPnP/PCP counters. | Unofficial; field names may change. |
| `query.lua` WLAN queries | `query_lua_artifacts_json` | `fetch_query_lua_artifacts` | Raw search, support findings, selected `wlan_radios`/associations | `wlan_stations`, `wlan_known_devices`, `wlan_radios`, guest state. | Some data remains raw/generic; future parser target. |
| `query.lua` network/security queries | `query_lua_artifacts_json` | `fetch_query_lua_artifacts` | `wan_port_mappings`, `security_advisories`, raw search | Port sharing, DNS/DHCP/routes, user rights, VPN/WireGuard lists. | Unofficial and firmware-dependent. |
| `data.lua?page=homeNet` | `data_lua_pages_json` | `fetch_data_lua_pages` | support findings, topology context | UI-style home network topology. | Unofficial; page schema varies. |
| `data.lua?page=log` | `data_lua_pages_json`, fallback log text | `fetch_data_lua_pages`, `parse_data_lua_log` | `event_log`, raw search | UI event-log JSON fallback. | Locale and firmware dependent. |
| `data.lua` WLAN/network/security pages | `data_lua_pages_json` | `fetch_data_lua_pages` | Raw search, support findings | Pages include `wlanSta`, `wlanMonitor`, `wlanRadar`, `wlanMesh`, `netDev`, `vpn`, `wireguard`, `remoteAccess`, `diagnosisSecurity`. | Many pages are currently raw/generic. |
| `support.lua` page | `support_lua_page_html` | `fetch_support_lua_page` | Raw artifact, coverage | Evidence that support workflow exists and labels controls. | Not the support dump itself. |
| `POST /cgi-bin/firmwarecfg` with `SupportDataEnhanced`/`SupportData` | `support_data_txt` | `fetch_support_data` | `support_findings`, `event_log`, `wifi_connections`, `advertisement_hints`, `network_status_snapshots`, investigation data | Deep diagnostics: retained logs, WLAN station history, hostapd lifecycle, scan/interference, multicast, config/service state. | Very sensitive. Firmware-dependent. |
| `support_data_txt` section `STATION_LIST` | `support_data_txt` | `parse_support_wifi_observations` | `wifi_connections`, investigation rows | Known WLAN station intervals, connect/disconnect history, counters. | Not guaranteed complete; station state fields are partly flattened today. |
| `support_data_txt` section `WLAN_EVENTS` | `support_data_txt` | `parse_support_wifi_observations` | `wifi_connections`, `event_log` context | AP-side WLAN event table. | Event IDs need model/firmware interpretation. |
| `support_data_txt` sections `WLAN_SCAN_RESULTS`, `SCAN_EVENTS`, `ENV_INTERFERENCE_HISTORY`, `WLAN_CHANNEL_INFO` | `support_data_txt` | `parse_support_wlan_environment` | `advertisement_hints`, `network_status_snapshots` | Nearby AP RF environment, scan events, channel/interference context. | Nearby APs are not nearby client devices. |
| Hidden capture page / WLAN management capture | Live only, optional PCAP response | `fritzbox_live_capture.py` | UI live capture response | Real-time 802.11 management-frame capture when firmware exposes it. | Not historical. Use carefully; radios must be enabled. |
| Telephony `X_AVM-DE_OnTel` paths | `call_list_xml`, `phonebooks_xml_json` | `fetch_telephony_exports` | Raw search, support findings | Call and phonebook context. | High personal-data sensitivity. |
| AHA HTTP commands | `aha_device_list_xml`, `aha_switch_list_txt`, `aha_device_stats_json` | `fetch_aha_artifacts` | Raw search, support findings | Smart-home device inventory/state. | Only relevant if FRITZ!DECT/AHA devices exist. |
| `DeviceConfig:1#X_AVM-DE_GetConfigFile` | `config_export_file` | `fetch_config_export` | Raw artifact, security advisory | Encrypted settings backup. | Very sensitive; requires export password. |
| Acquisition manifest | `acquisition_manifest_json` | `AcquisitionManifest` | source coverage UI | Records attempted/successful/failed artifacts. | Not router evidence by itself; important for completeness. |

## Example Raw Artifact Snippets

The docs use synthetic examples only.

### Device Log XML

```xml
<Event>
  <Date>20.05.26</Date>
  <Time>22:15:59</Time>
  <Log>Temporary channel switch to channel 36...</Log>
</Event>
```

### `query.lua` LAN Device

```json
{
  "UID": "landevice1234",
  "name": "analyst-laptop",
  "ip": "192.168.178.42",
  "mac": "aa:bb:cc:dd:ee:ff",
  "interface": "wlan",
  "firstused": "1716200000",
  "lastused": "1716220000",
  "allow_pcp_and_upnp": "0"
}
```

### Support `STATION_LIST`

```text
Station management:
  mac = aa:bb:cc:dd:ee:ff
  cnt_connect_success = 12
  cnt_connect_fail = 1
  history:
    connected 20.05.2026 10:00:00
    disconnected 20.05.2026 10:42:30
```

### Support `WLAN_SCAN_RESULTS`

```text
[ 0]: '11:22:33:44:55:66' 2437/2437/ 20/0000/  6-  8 'NeighborAP' -72 dBm [ 11N ] [ WPA2_PSK ]
```

This is evidence that the FRITZ!Box saw a neighboring access point. It is not evidence that a phone or other unassociated client was near the router.

## References

- FRITZ! TR-064 overview: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_TR-064_overview.pdf
- FRITZ! TR-064 first steps: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_TR-064_first_steps.pdf
- FRITZ! TR-064 AppSetup: https://fritz.support/resources/TR-064_App_Setup.pdf
- FRITZ! TR-064 Remote Access: https://fritz.support/resources/TR-064_Remote_Access.pdf
- FRITZ!Box Dynamic DNS help: https://help.avm.de/fritzbox.php?topic=hilfe_dyndns
