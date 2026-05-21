# Support Data

The support-data artifact is downloaded through the hidden support workflow:

```text
POST /cgi-bin/firmwarecfg
files: sid=<web-ui-sid>, SupportDataEnhanced=
```

Fallback field:

```text
SupportData=
```

The result is stored as `support_data_txt`. It is one of the highest-value and highest-sensitivity artifacts in the project.

## Sections and Parser Coverage

| Section / pattern | Parsed by | Output | Value | Current gaps |
|---|---|---|---|---|
| Device log text | `parse_device_log` | `event_log`, `wifi_connections` | Retained system/WLAN/auth/WAN events. | Locale-specific messages need continual fixtures. |
| `STATION_LIST WLAN client list` | `parse_support_wifi_observations` | `wifi_connections`, investigation rows | WLAN station intervals, connect/disconnect history, counters. | Some state fields remain flattened: RSSI, quality, BSSID, role, forced disconnect counts. |
| `WLAN_EVENTS` | `parse_support_wifi_observations` | `wifi_connections`, raw support rows | AP-side WLAN event table. | Event IDs/rates/channels need richer typed table. |
| hostapd/AP-STA/WPA/EAPOL/RADIUS lines | support WiFi parser | `wifi_connections`, investigation rows | Auth/assoc/handshake/lifecycle evidence. | Reason codes and handshake details are partly collapsed. |
| `WLAN_SCAN_RESULTS` | `parse_support_wlan_environment` | `advertisement_hints` | Neighbor AP BSSID/SSID/RSSI/channel environment. | Not client proximity. |
| `SCAN_EVENTS` | `parse_support_wlan_environment` | `network_status_snapshots` | Scan request/finish events per radio. | Radio mapping can be model-specific. |
| `ENV_INTERFERENCE_HISTORY` | `parse_support_wlan_environment` | `network_status_snapshots` | Radar/interference/channel-change context. | Not client-specific. |
| `WLAN_CHANNEL_INFO` | `parse_support_wlan_environment` | `network_status_snapshots` | Channel load values. | Snapshot/diagnostic only. |
| `dmesg` WLAN management strings | generic support findings / probe text mining | raw search, investigation probe summary | Low-confidence kernel management context. | Monotonic time only; false positives common. |
| multicast / IGMP / ARP / DNS / UPnP strings | `build_advertisement_hints` | `advertisement_hints` | Network-layer discovery/broadcast hints. | Not 802.11 probe proof. |
| config/service/process listings | `parse_support_data` | `support_findings`, raw search | Service state and forensic context. | Sensitive and broad; parsers intentionally conservative. |

## Sensitivity

Support data can include:

- Device names, hostnames, MAC addresses, IP addresses.
- Public IP and provider state.
- Router service state.
- Logs for admin/API access.
- Telephony or smart-home context.
- Internal daemon and config snippets.

Do not publish real support data.

## Recommended Analyst Language

Use:

> The FRITZ!Box support artifact retained station-history evidence for this MAC.

Avoid:

> This is the complete WiFi session history.

Use:

> The router observed neighboring access points during a WLAN scan.

Avoid:

> These phones were nearby.
