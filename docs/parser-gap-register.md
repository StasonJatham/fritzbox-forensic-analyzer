# Parser Gap Register

This is a living backlog of raw fields that are already collected but could be normalized better.

| Priority | Artifact / section | Raw field or pattern | Proposed target | Why it matters |
|---:|---|---|---|---|
| 1 | `support_data_txt` `STATION_LIST` | `last_seen`, `is_active`, `is_guest`, `rssi`, `quality`, `bssid`, `role_id`, `if_name`, `connect_state` | `wlan_station_state_snapshots` | Stronger answer to “connected or seen by AP”. |
| 1 | `support_data_txt` station history | connect/disconnect intervals | dedicated interval table or richer `wifi_connections` | Preserve duration and overlap semantics. |
| 1 | `support_data_txt` hostapd lines | auth/assoc/disassoc/reassoc/deauth reason codes | `wlan_ap_client_events` | AP-side client lifecycle. |
| 1 | `support_data_txt` `WLAN_EVENTS` | event ID, band, rate, channel, details hex | `wlan_event_details` | Useful for exact AP event analysis. |
| 2 | `query_lua_artifacts_json.wlan_known_devices` | last-connected/RSSI/speed | `wlan_known_devices` or `wlan_associations` | UI-level WLAN device history. |
| 2 | `query_lua_artifacts_json.wlan_stations` | AP/SSID/RSSI/speed/guest | `wlan_station_state_snapshots` | Current station context. |
| 2 | `data_lua_pages_json.wlanSta` | station UI state | typed WLAN table | May expose values not in TR-064. |
| 2 | `data_lua_pages_json.wlanRadar` | radar/channel events | `network_status_snapshots` | RF/channel timeline context. |
| 2 | `data_lua_pages_json.netDhcp` | leases/expiry | DHCP lease table | Device attribution over time. |
| 2 | `query_lua_artifacts_json.user_rights` | admin/vpn/frominternet | `security_advisories`/users table | Remote-access risk. |
| 3 | `support_data_txt` dmesg WLAN lines | assoc/deauth/management strings with kernel uptime | low-confidence kernel event table | Useful but timestamp-limited. |
| 3 | `support_data_txt` multicast/neighbor sections | IGMP/multicast/neighbor entries | richer broadcast hints | Context only; not packet proof. |
| 3 | `aha_device_stats_json` | smart-home stats | AHA device table | Environment context for some cases. |
| 3 | `phonebooks_xml_json`, `call_list_xml` | call metadata | telephony tables | Sensitive; only parse if needed. |

## Test Fixture Rules

New parser fixtures should:

- Use fake MAC addresses and RFC 5737 IPs.
- Include the raw section header when relevant.
- Assert both parsed fields and confidence labels.
- Include a false-positive fixture when matching probe/broadcast text.
