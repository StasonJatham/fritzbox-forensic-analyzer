# WLAN Forensics

The WLAN evidence model distinguishes exact retained events, state snapshots, inferred observations, and low-confidence proximity hints.

## Evidence Types

| Evidence type | Source | Table/view | Time meaning | Confidence |
|---|---|---|---|---|
| Retained WLAN event-log row | `device_log_xml`, `device_log_xml_wlan`, support log | `event_log`, `wifi_connections` | Exact row timestamp. | High if present. |
| Support station interval | `support_data_txt` `STATION_LIST` | `wifi_connections`, investigation | Retained connect/disconnect interval. | Medium to high. |
| Current WLAN association | `WLANDeviceListPath`, TR-064 WLAN state | `wlan_associations` | Acquisition snapshot. | High at acquisition time only. |
| Mesh last connected | `mesh_list` | `mesh_topology_links`, `wifi_connections` | Router/mesh retained state timestamp. | Medium. |
| LAN-device lastused | `query.lua` LAN-device | `hosts`, investigation | Router retained device-state timestamp. | Medium. |
| hostapd auth/assoc/EAPOL | support data | `wifi_connections`, raw/support | Exact if wall-clock present; otherwise support artifact context. | Medium. |
| WLAN scan result | support `WLAN_SCAN_RESULTS` | `advertisement_hints` | Scan result timestamp/acquisition context. | Medium for nearby APs only. |
| Network-layer discovery hint | support/raw keyword extraction | `advertisement_hints` | Retained line or acquisition context. | Low. |
| 802.11 probe request | live capture or explicit retained line | live capture / investigation | Exact only if management-frame line/capture exists. | High for capture, medium for retained logs. |

## Connected vs Seen Near AP

**Connected** means there is retained evidence that a client was associated, authenticated, active, or listed as a WLAN station.

Examples:

- Event log says a WLAN device connected.
- Support `STATION_LIST` has a connected/disconnected interval.
- `WLANDeviceListPath` shows the device currently associated.
- hostapd logs show `AP-STA-CONNECTED`.

**Seen near AP** is weaker. It can mean:

- True probe request telemetry, if present.
- AP-side management-frame text containing client MAC and probe/auth/assoc semantics.
- Network-layer discovery traffic after association, such as mDNS or SSDP.

Do not treat network-layer discovery as proof that an unassociated device was nearby.

## Probe Requests

True probe requests are 802.11 management frames. The parser should only promote them when the line or capture includes:

- A client MAC address.
- Explicit probe-request wording such as `Probe Request`, `probereq`, or management-frame context.
- Timestamp or capture time.

False positives include:

- Driver function names containing `_probe`.
- DNS probe text.
- “probe lock” or “probe failed” kernel diagnostics.
- Generic “probing” text without client MAC and 802.11 context.

## Time-Range Investigations

When answering “who was connected or seen near the AP between start and end”:

1. Query exact event-log WLAN rows in the range.
2. Query retained station intervals overlapping the range.
3. Query `lastused`/`last_connected` point evidence inside the range.
4. Query current association snapshots if acquisition time falls inside the range.
5. Separately show low-confidence discovery/proximity hints.
6. State gaps and absence-of-evidence warnings.

## Current Parser Priorities

High-value improvements:

- Dedicated WLAN observation table with interval start/end.
- Preserve station state fields from support `STATION_LIST`.
- Typed hostapd lifecycle table.
- Typed `WLAN_EVENTS` fields: event ID, band, channel, rate, details.
- Structured dmesg WLAN management events with low confidence.
