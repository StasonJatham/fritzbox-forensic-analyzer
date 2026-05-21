# Forensic Limits

This tool is useful when the FRITZ!Box is the only available source, but it cannot make the router retain evidence it never stored.

## What Can Usually Be Answered

| Question | Best source | Confidence |
|---|---|---|
| Which retained events mention a device, IP, MAC, or hostname? | `event_log`, `support_data_txt`, FTS search | High if present |
| Which devices are known to the router now? | `Hosts`, `host_list_xml`, `landevice` query | Medium to high |
| When was a known device first/last used according to FRITZ!OS state? | `query.lua` LAN-device `firstused`/`lastused`, mesh state | Medium |
| Which WLAN clients are currently associated? | `WLANDeviceListPath`, WLAN TR-064 association snapshots | High at acquisition time |
| Which WiFi intervals are retained in support station history? | Support `STATION_LIST` | Medium to high when present |
| Which WAN/remote-exposure settings exist? | TR-064 WAN/AppSetup/HostFilter, port sharing queries | High |
| Are there signs of failed admin logins? | Device log and support logs | High if retained |
| What RF/channel/interference context exists? | Support `WLAN_SCAN_RESULTS`, `SCAN_EVENTS`, `ENV_INTERFERENCE_HISTORY` | Medium |

## What Cannot Be Proven From One Export

- That no device connected during a period with no retained rows.
- Exact WiFi join/disconnect times for every client.
- Continuous online duration unless an interval is retained.
- Which unassociated phones were nearby, unless true probe-request telemetry exists.
- Which device sent every broadcast packet.
- Which human operated a device.
- Packet payloads or per-flow traffic details.

## Probe Requests and Nearby Devices

True 802.11 probe requests are management frames. They are not the same as:

- DHCP
- ARP/NDP
- mDNS/Bonjour
- SSDP/UPnP
- IGMP/multicast
- DNS probe text in diagnostics
- Driver messages containing the word `probe`

The live capture feature can inspect real-time 802.11 management frames when the FRITZ!Box firmware exposes a WLAN management capture interface. That does not create historical probe data. Historical proximity must come from retained support logs, station history, or other router state, and should be labeled with confidence.

## Why Scheduled Polling Matters

Polling every 5-15 minutes turns state snapshots into a usable timeline:

- New host appears.
- Known device `lastused` changes.
- Current WLAN association appears/disappears.
- WAN IP changes.
- Port-sharing or remote-access state changes.

Without polling, a single acquisition is a point-in-time export plus whatever historic logs the router retained.
