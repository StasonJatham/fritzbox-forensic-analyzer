# Internal Web UI Artifacts

FRITZ!OS exposes useful internal endpoints used by its Web UI. They are not stable public APIs, but they often contain fields missing from official TR-064 output.

## Authentication

The collector uses the authenticated `fritzconnection` HTTP session and obtains a Web UI SID. Scripts should never log the SID.

## `query.lua`

`query.lua` accepts namespaced expressions such as:

```text
landevice:settings/landevice/list(UID,name,ip,mac,firstused,lastused)
```

### Queries Currently Collected

| Query name | Expression family | Useful fields | Current parser status |
|---|---|---|---|
| `landevice_all` | `landevice:settings/landevice/list(...)` | `UID`, `ip`, `iplist`, `mac`, `maclist`, `name`, `friendly_name`, `vendorname`, `modelname`, `interface`, `firstused`, `lastused`, `blocked`, `guest`, UPnP/PCP counters | Parsed into `hosts`, device activity, security/risk context. |
| `landevice_topology` | LAN-device topology subset | parent UID/source, interface, speed, last used | Partly parsed into host/topology context. |
| `hostfilter_profiles` | `filter:settings/profile/list(...)` | profile names, blocked/autoupdate/disabled | Parsed into `host_filter_profiles` where possible. |
| `hostfilter_rules` | `filter:settings/rule/list(...)` | rule/device/mac/ip/blocked | Generic support findings/raw search. |
| `wlan_stations` | `wlan:settings/station/list(...)` | station MAC/IP/name/active/guest/AP/SSID/RSSI/speed | Raw/generic today; high-value parser target. |
| `wlan_radios` | `wlan:settings/radio/list(...)` | radio enabled, SSID, channel, autochannel, standard, MAC, guest | Partly overlaps `wlan_radios`. |
| `wlan_known_devices` | `wlan:settings/known/list(...)` | MAC/name/active/guest/SSID/last connected/RSSI/speed | Raw/generic today; high-value parser target. |
| `wlan_guest` | `wlan:settings/guest(...)` | guest SSID/encryption/timeout | Security context. |
| `port_sharing` | `forwardrules:settings/rule/list(...)` | enabled, protocol, ports, internal host | Parsed into `wan_port_mappings`. |
| `net_routes`, `net_dns`, `net_dhcp` | route/DNS/DHCP namespaces | network config and leases | Raw/generic today. |
| `vpn_users`, `wireguard` | VPN/WireGuard namespaces | VPN peer names, enabled state, endpoints, last handshake | Used by VPN planner; generic evidence today. |
| `user_rights` | user namespace | admin/FTP/VPN/from-internet rights | Security context; raw/generic today. |
| `myfritz_services` | MyFRITZ services | internet-exposed service details | Security context; raw/generic today. |
| `usb_devices`, `dect_devices` | USB/DECT namespaces | attached local devices | Raw/generic today. |

## `data.lua`

`data.lua?page=...` mirrors UI pages. The collector requests many pages and stores them under `data_lua_pages_json`.

High-value pages:

| Page | Forensic value |
|---|---|
| `homeNet` | Home network device/topology state. |
| `log` | Event-log JSON fallback. |
| `netCnt`, `netMoni`, `onlineMoni` | Network counters and monitoring views. |
| `wlan`, `wlanSta`, `wlanMonitor`, `wlanRadar`, `wlanMesh` | WLAN radio/station/radar/mesh context. |
| `netDev`, `netDhcp`, `netDns`, `netNeighbor`, `netRoute` | LAN/DHCP/DNS/neighbor/route context. |
| `vpn`, `wireguard`, `remoteAccess`, `myfritz`, `portShare`, `forwardRules` | Remote access and exposure state. |
| `diagnosisSecurity`, `diagnosisFunction`, `support` | Diagnostic/security summaries. |
| `foncalls`, `phonebook`, `dect`, `usb`, `nas` | Telephony/device context. |

## Read-Only Web UI GET Artifacts

The collector also fetches:

| Endpoint | Artifact |
|---|---|
| `/juis_boxinfo.xml` | `webui_readonly_artifacts_json.endpoints.juis_boxinfo_xml` |
| `/login_sid.lua?version=2` | `webui_readonly_artifacts_json.endpoints.login_sid_v2` |
| `/menus/menu_data.lua` | `webui_readonly_artifacts_json.endpoints.menu_data_lua` |
| `/internet/inetstat_monitor.lua` | `webui_readonly_artifacts_json.endpoints.inetstat_monitor_lua` |
| `/internet/inetstat_counter.lua` | `webui_readonly_artifacts_json.endpoints.inetstat_counter_lua` |

## Caveats

- These endpoints can change between FRITZ!OS releases.
- Some pages return localized labels.
- A successful HTTP 200 can still be a login HTML page.
- Store raw data and source coverage so parser gaps remain visible.
