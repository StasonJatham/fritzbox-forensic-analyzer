# Parser Gap Register

This is a living backlog of raw fields that are already collected but could be normalized better.

## Closed In Current Parser

| Artifact / section | Normalized target | Notes |
|---|---|---|
| `support_data_txt` `STATION_LIST` state | `wlan_station_state_snapshots`, `wifi_connections`, SIEM events | Retains active/guest/visible flags, RSSI, quality, BSSID, role, interface, connect state, hostname/IP/speed when present, and counter context. |
| `support_data_txt` station history | `wlan_station_intervals`, `wifi_connections`, SIEM correlations | Retains connect/disconnect times, duration, open interval flag, and IEEE 802.11 reason-code labels. |
| `support_data_txt` hostapd lifecycle | `wlan_ap_client_events`, `wifi_connections`, SIEM events | Parses auth/assoc/reassoc/disassoc/deauth, AP-STA rows, AID, status code, reason code, and reason labels. |
| `support_data_txt` `WLAN_EVENTS` | `wlan_event_details`, `wifi_connections`, SIEM events | Retains event ID, band, rate, channel, previous channel, details hex/int, MAC, interface, and event time. |
| `query_lua_artifacts_json.wlan_known_devices` / `wlan_stations` | `wlan_associations`, `wlan_station_state_snapshots`, SIEM events | Handles common FRITZ!OS snake_case and camelCase field variants. |
| `data_lua_pages_json.wlanSta` | `wlan_associations`, `wlan_station_state_snapshots`, SIEM events | Captures UI-level station state where firmware exposes it. |
| `data_lua_pages_json.wlanRadar` | `network_status_snapshots`, SIEM events | Captures channel/radar status values as typed network evidence. |
| `data_lua_pages_json.netDhcp` | `dhcp_leases`, `network_status_snapshots`, SIEM events | Retains lease identity and normalizes Unix lease expiry timestamps when possible. |
| `query_lua_artifacts_json.user_rights` | `security_advisories`, SIEM events/correlations | Flags admin, VPN/WireGuard, FTP, and from-internet rights for analyst review. |
| `aha_device_stats_json` | `aha_device_states`, `network_status_snapshots`, SIEM events | Retains smart-home state/stats as sensitive contextual evidence. |
| `phonebooks_xml_json`, `call_list_xml` | `telephony_records`, `network_status_snapshots`, SIEM events | Retains sensitive call/contact metadata for local case review. |

## Remaining Firmware-Dependent Work

| Priority | Artifact / section | Remaining gap | Why it matters |
|---:|---|---|---|
| 1 | Real FRITZ!OS support bundles | Broaden fixtures across FRITZ!OS 7.x/8.x and router models. | AVM internal formats vary; synthetic fixtures cannot guarantee every field spelling. |
| 2 | `support_data_txt` dmesg/kernel WLAN lines | More uptime-relative timestamp handling for kernel-only assoc/deauth lines. | Useful when hostapd tables are absent, but timestamp confidence is lower. |
| 2 | `data_lua_pages_json` security pages | More typed extraction for `remoteAccess`, `vpn`, `wireguard`, and `diagnosisSecurity` page schemas. | Improves router-exposure SIEM detail on firmware that exposes these pages. |
| 3 | Multicast/neighbor sections | More typed IGMP/neighbor tables beyond keyword hints. | Context only; still not packet-level proof of every broadcast. |

## Test Fixture Rules

New parser fixtures should:

- Use fake MAC addresses and RFC 5737 IPs.
- Include the raw section header when relevant.
- Assert both parsed fields and confidence labels.
- Include a false-positive fixture when matching probe/broadcast text.
