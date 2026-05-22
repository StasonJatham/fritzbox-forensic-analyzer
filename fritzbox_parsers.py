from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fritzbox_siem_parser import parse_fritzbox_log_message
from fritzbox_support_parsers import (
    parse_hostapd_lifecycle_event,
    parse_station_key_value,
    reason_name,
    station_state_snapshot_to_dict,
    support_uptime_seconds,
    wlan_event_row_to_dict,
)

LOG_TS_RE = re.compile(
    r"^(?P<date>\d{1,2}\.\d{1,2}\.(?:\d{2}|\d{4}))\s+" r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)\s+(?P<message>.*)$"
)
SUPPORT_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+" r"(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+-\s+(?P<message>.*)$"
)
STEERING_HISTORY_RE = re.compile(
    r"OPTIMISATION\s+RCPI\s+STA\s+(?P<sta>[0-9a-fA-F:]{17})\s+"
    r"from\s+(?P<source_bssid>[0-9a-fA-F:]{17})\s+"
    r"\(RX\s+(?P<source_rssi>-?\d+)\s+dBm\)\s+"
    r"start\s+(?P<start>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\([^)]+\)\s+mode\s+(?P<mode>\S+)\s+to\s+(?P<target>.*?)\s+"
    r"(?:(?:moved)\s+(?P<moved>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\([^)]+\)\s+)?"
    r"ended\s+with\s+(?P<result>.*?)\s+at\s+(?P<end>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
    re.I,
)
WLAN_EVENTS_ROW_RE = re.compile(
    r"^\s*(?P<timestamp>\d{8}-\d{6})\s*/\s*"
    r"(?P<iface>[^/]+?)\s*/\s*"
    r"(?P<mac>[0-9a-fA-F:]{17})\s*/\s*"
    r"(?P<event_id>\d+)\s*/\s*"
    r"(?P<band>\d+)\s*/\s*"
    r"(?P<rate>\d+)\s*/.*?/\s*"
    r"(?P<channel>\d+)\s*/\s*"
    r"(?P<prev_channel>\d+)\s*/\s*"
    r"(?P<details>0x[0-9a-fA-F]+)\s*$"
)
STATION_HISTORY_ROW_RE = re.compile(
    r"^\s*(?P<role>\d+)\s*/\s*(?P<iface>ath\d+)\s*/\s*"
    r"(?P<connected>\d{8}-\d{6}|)\s*"
    r"\((?P<connect_status>0x[0-9a-fA-F]+)\s+(?P<connect_initiator>0x[0-9a-fA-F]+)\s+"
    r"(?P<connect_reason>0x[0-9a-fA-F]+)\)\s*/\s*"
    r"(?P<disconnected>\d{8}-\d{6}|)\s*"
    r"\((?P<disconnect_status>0x[0-9a-fA-F]+)\s+(?P<disconnect_initiator>0x[0-9a-fA-F]+)\s+"
    r"(?P<disconnect_reason>0x[0-9a-fA-F]+)\)\s*/\s*"
    r"(?P<wlan_mode>0x[0-9a-fA-F]+)\s*/\s*(?P<quality>\d+)\s*$"
)
WLAN_SCAN_RESULT_RE = re.compile(
    r"^\[\s*(?P<index>\d+)\]:\s+'(?P<bssid>[0-9a-fA-F:]{17})'\s+"
    r"(?P<frequency>\d+)/(?P<center_frequency>\d+)/\s*(?P<width>\S+)/(?P<flags>\S+)/\s*"
    r"(?P<channel_low>\d+)-\s*(?P<channel_high>\d+)\s+'(?P<ssid>[^']*)'.*?"
    r"(?P<rssi>-?\d+)\s+dBm\s+\[(?P<mode>[^\]]*)\]\s+\[(?P<caps>[^\]]*)\]",
    re.I,
)
WLAN_SCAN_TIME_RE = re.compile(
    r"^Scan time:\s*(?P<date>\d{1,2}\.\d{1,2}\.\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2})",
    re.I,
)
WLAN_SCAN_EVENT_RE = re.compile(
    r"^\[(?P<index>\d+)\]\s+t=(?P<date>\d{1,2}\.\d{1,2}\.\d{4})\s+"
    r"(?P<time>\d{1,2}:\d{2}:\d{2})/\[[^\]]+\]:\s+"
    r"(?P<event>[A-Z_]+)\s*,\s+radio\s+'(?P<radio>[^']+)'(?:\s+\"(?P<reason>[^\"]*)\")?",
    re.I,
)
WLAN_INTERFERENCE_RE = re.compile(
    r"^\[(?P<index>\d+)\]\s+t=(?P<date>\d{1,2}\.\d{1,2}\.\d{4})\s+"
    r"(?P<time>\d{1,2}:\d{2}:\d{2})/\[[^\]]+\]:\s+"
    r"(?P<event>[A-Z_]+)\s*,\s+radio\s+'(?P<radio>[^']+)',\s+primary freq\s+"
    r"(?P<frequency>\d+)\s+MHz,\s+(?P<state>active|inactive),\s+"
    r"(?P<change>[^.]+)",
    re.I,
)
WLAN_CHANNEL_LOAD_RE = re.compile(
    r"^(?P<frequency>\d+)\s+MHz\s+\(\s*(?P<channel>\d+)\)\s+\|\s+(?P<load>\d+)\s+%",
    re.I,
)
AP_STA_EVENT_RE = re.compile(
    r"(?P<iface>ath\d+):\s+(?P<event>AP-STA-CONNECTED|AP-STA-DISCONNECTED|EAPOL-4WAY-HS-COMPLETED)\s+"
    r"(?P<mac>[0-9a-fA-F:]{17})(?P<detail>.*)",
    re.I,
)
HOSTAPD_CLIENT_LIFECYCLE_RE = re.compile(
    r"(?P<iface>ath\d+):\s+(?:STA\s+)?(?P<mac>[0-9a-fA-F:]{17}).{0,80}?"
    r"(?P<event>authenticated|associated|reassociated|disassociated|deauthenticated|auth|assoc|reassoc|disassoc|deauth)"
    r"(?:.*?(?:reason|reason_code|status|status_code)[=:\s]+(?P<reason>\d+|0x[0-9a-fA-F]+))?",
    re.I,
)
WPA_HANDSHAKE_RE = re.compile(
    r"(?P<iface>ath\d+):\s+STA\s+(?P<mac>[0-9a-fA-F:]{17})\s+WPA:\s+"
    r"(?P<kind>pairwise|group)\s+key handshake completed\s+\((?P<cipher>[^)]+)\)",
    re.I,
)
RADIUS_ACCOUNTING_RE = re.compile(
    r"(?P<iface>ath\d+):\s+STA\s+(?P<mac>[0-9a-fA-F:]{17})\s+RADIUS:\s+"
    r"starting accounting session\s+(?P<session>\S+)",
    re.I,
)
ASSOCIATION_REQUEST_RE = re.compile(
    r"STA\s+(?P<mac>[0-9a-fA-F:]{17}).*Association Request|" r"Association Request.*STA\s+(?P<mac2>[0-9a-fA-F:]{17})",
    re.I,
)
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUPPORT_KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_. /()[\]#:+-]{2,90})\s*(?:=|:)\s*(?P<value>.+?)\s*$")
WIFI_EVENT_KEYWORDS = (
    "wlan-gerät",
    "wlan device",
    "wireless device",
    "wlan",
    "wi-fi",
    "wifi",
    "802.11",
    "ieee802.11",
    "ieee 802.11",
)
CONNECTED_KEYWORDS = (
    "angemeldet",
    "verbunden",
    "connected",
    "registered",
    "anmeldung",
    "associated",
)
DISCONNECTED_KEYWORDS = (
    "abgemeldet",
    "getrennt",
    "disconnected",
    "unregistered",
    "abmeldung",
    "disassociated",
)
SUPPORT_KEYWORDS = (
    "auth",
    "channel",
    "config",
    "device",
    "dhcp",
    "dns",
    "firmware",
    "gateway",
    "host",
    "internet",
    "ipv4",
    "ipv6",
    "login",
    "mac",
    "mesh",
    "network",
    "ssid",
    "uptime",
    "user",
    "wan",
    "wlan",
)


@dataclass(slots=True)
class FritzLogEntry:
    timestamp: datetime | None
    message: str
    raw: str
    source: str = "device_log"


def parse_device_log_xml(content: str) -> str:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return ""
    lines: list[str] = []
    for event in root.findall(".//Event"):
        date = event.findtext("date") or ""
        time = event.findtext("time") or ""
        msg = event.findtext("msg") or ""
        if date and time and msg:
            lines.append(f"{date} {time} {msg}")
    return "\n".join(lines)


def parse_data_lua_log(content: str | None) -> str:
    if not content:
        return ""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return ""
    log_page = payload.get("log") or {}
    data = log_page.get("data") if isinstance(log_page, dict) else None
    if not isinstance(data, dict):
        return ""
    rows = data.get("log") or data.get("events") or []
    if not isinstance(rows, list):
        return ""
    lines: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        date = row.get("date") or row.get("Date")
        time = row.get("time") or row.get("Time")
        message = row.get("msg") or row.get("message") or row.get("Message")
        if date and time and message:
            lines.append(f"{date} {time} {message}")
    return "\n".join(lines)


def parse_support_data(
    content: str | None, observed_at: str | None = None, max_findings: int = 3000
) -> list[dict[str, Any]]:
    if not content:
        return []
    findings: list[dict[str, Any]] = []
    section = "support_data"
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        section_candidate = support_section_title(line)
        if section_candidate:
            section = section_candidate
            findings.append(
                {
                    "finding_type": "section",
                    "section": section,
                    "key": None,
                    "value": section,
                    "line_number": line_number,
                    "observed_at": observed_at,
                    "raw_text": raw_line,
                    "evidence_level": "parsed_from_raw",
                    "evidence_note": "Section marker parsed from FRITZ!Box support-data raw artifact.",
                }
            )
            if len(findings) >= max_findings:
                break
            continue
        key_value = SUPPORT_KEY_VALUE_RE.match(line)
        parsed_key_value = False
        if key_value:
            key = key_value.group("key").strip()
            value = key_value.group("value").strip()
            if key.count(":") < 2 and len(value) <= 800:
                parsed_key_value = True
                findings.append(
                    {
                        "finding_type": "key_value",
                        "section": section,
                        "key": key,
                        "value": value,
                        "line_number": line_number,
                        "observed_at": observed_at,
                        "raw_text": raw_line,
                        "evidence_level": "parsed_from_raw",
                        "evidence_note": "Key/value parsed from FRITZ!Box support-data raw artifact.",
                    }
                )
        if not parsed_key_value and support_line_is_forensic_signal(line):
            findings.append(
                {
                    "finding_type": "signal_line",
                    "section": section,
                    "key": None,
                    "value": line[:1000],
                    "line_number": line_number,
                    "observed_at": observed_at,
                    "raw_text": raw_line,
                    "evidence_level": "parsed_from_raw",
                    "evidence_note": "Forensic keyword line parsed from FRITZ!Box support-data raw artifact.",
                }
            )
        if len(findings) >= max_findings:
            break
    return findings


def support_section_title(line: str) -> str | None:
    stripped = line.strip(" #*=-\t")
    if not stripped or len(stripped) > 120:
        return None
    marker_count = sum(line.startswith(marker) for marker in ("#", "*", "=", "-"))
    if marker_count:
        return stripped
    if line.startswith(("#####", "====", "----", "***")):
        return stripped
    return None


def support_line_is_forensic_signal(line: str) -> bool:
    lower = line.casefold()
    return any(keyword in lower for keyword in SUPPORT_KEYWORDS) and (
        parse_mac(line) is not None or parse_ip(line) is not None
    )


def parse_wlan_device_lists(exports: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    lists: dict[str, str] = {}
    combined = exports.get("wlan_device_list_xml")
    if isinstance(combined, str):
        try:
            decoded = json.loads(combined)
            if isinstance(decoded, dict):
                lists.update({str(key): str(value) for key, value in decoded.items()})
        except json.JSONDecodeError:
            lists["1"] = combined
    for key, value in exports.items():
        match = re.fullmatch(r"wlan_device_list_xml_(\d+)", str(key))
        if match and isinstance(value, str):
            lists[match.group(1)] = value

    records: list[dict[str, Any]] = []
    for radio_index, content in sorted(lists.items()):
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            continue
        for item in root.findall(".//Item"):
            channel = element_text(item, "AssociatedDeviceChannel")
            if channel in ("", "0", None):
                continue
            mac = parse_mac(element_text(item, "AssociatedDeviceMACAddress") or "")
            ip = element_text(item, "AssociatedDeviceIPAddress")
            records.append(
                {
                    "observed_at": observed_at,
                    "radio_index": radio_index,
                    "association_index": element_text(item, "AssociatedDeviceIndex"),
                    "mac": mac,
                    "ip": ip or None,
                    "hostname": None,
                    "auth_state": element_text(item, "AssociatedDeviceAuthState"),
                    "speed": element_text(item, "X_AVM-DE_Speed"),
                    "signal_strength": element_text(item, "X_AVM-DE_SignalStrength"),
                    "channel": channel,
                    "channel_width": element_text(item, "X_AVM-DE_ChannelWidth"),
                    "guest": truthy(element_text(item, "AssociatedDeviceGuest")),
                    "source": f"wlan_device_list_xml_{radio_index}",
                }
            )
    return records


def element_text(parent: ET.Element, name: str) -> str | None:
    value = parent.findtext(name)
    return value.strip() if isinstance(value, str) else None


def parse_mesh_wifi_devices(content: str | None) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    devices: list[dict[str, Any]] = []
    for node in data.get("nodes", []):
        wlan_interfaces = [iface for iface in node.get("node_interfaces", []) if iface.get("type") == "WLAN"]
        if not wlan_interfaces:
            continue
        ip_addresses = [addr.get("value") for addr in node.get("ip_addresses", []) if addr.get("value")]
        metrics = node.get("metrics") or {}
        latency = metrics.get("latency_measurement") or {}
        last_observed = mesh_timestamp_to_iso(latency.get("timestamp"))
        for iface in wlan_interfaces:
            if iface.get("opmode") and iface.get("opmode") != "STATION":
                continue
            devices.append(
                {
                    "hostname": node.get("device_name") or node.get("device_friendly_name"),
                    "friendly_name": node.get("device_friendly_name"),
                    "mac": node.get("device_mac_address") or iface.get("mac_address"),
                    "ip_addresses": ip_addresses,
                    "interface": "WLAN",
                    "ssid": iface.get("ssid") or None,
                    "security": iface.get("security"),
                    "current_channel": iface.get("current_channel"),
                    "primary_frequency": (iface.get("current_channel_info") or {}).get("primary_freq"),
                    "primary_center": (iface.get("current_channel_info") or {}).get("primary_center"),
                    "channel_width": (iface.get("current_channel_info") or {}).get("channel_width"),
                    "phymodes": iface.get("phymodes") or [],
                    "latency_status_code": latency.get("status_code"),
                    "rt_latency": metrics.get("rt_latency"),
                    "ip_attributes": [addr.get("attributes") for addr in node.get("ip_addresses", [])],
                    "last_observed": last_observed,
                    "last_connected": None,
                    "source": "mesh_list",
                    "confidence": "known_wifi_device_no_connection_timestamp",
                }
            )
    return sorted(devices, key=lambda item: (item.get("hostname") or "", item.get("mac") or ""))


def mesh_timestamp_to_iso(value: Any) -> str | None:
    if not isinstance(value, int | float) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000).astimezone().isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def unix_timestamp_to_iso(value: Any) -> str | None:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if numeric < 946684800:
        return None
    try:
        return datetime.fromtimestamp(numeric).astimezone().isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def parse_landevice_query(content: str | None) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    rows = extract_landevice_rows(data)
    if not isinstance(rows, list):
        return []

    records: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        records.append(
            {
                "uid": row.get("UID") or row.get("uid"),
                "hostname": row.get("name") or row.get("friendly_name") or row.get("neighbour_name"),
                "friendly_name": row.get("friendly_name"),
                "neighbour_name": row.get("neighbour_name"),
                "mac": parse_mac(str(row.get("mac") or "")),
                "ip": row.get("ip") or None,
                "ip_list": row.get("iplist") or None,
                "mac_list": row.get("maclist") or None,
                "interface": row.get("interface") or None,
                "wlan_station_type": row.get("wlan_station_type") or None,
                "wlan_uids": row.get("wlan_UIDs") or None,
                "plc_uids": row.get("plc_UIDs") or None,
                "ethernet_port": row.get("ethernetport") or None,
                "vendor": row.get("vendorname") or row.get("manu_name") or None,
                "model": row.get("modelname") or None,
                "speed": row.get("speed") or None,
                "source_flags": row.get("source") or None,
                "parent_uid": row.get("parentuid") or None,
                "flags": row.get("flags") or None,
                "modification_flags": row.get("modification_flags") or None,
                "dhcp": row.get("dhcp") or None,
                "static_dhcp": row.get("static_dhcp") or None,
                "blocked": row.get("blocked") or None,
                "guest": row.get("guest") or None,
                "allow_pcp_and_upnp": row.get("allow_pcp_and_upnp") or None,
                "pcp_count": row.get("igd_fw_cnt_pcp") or None,
                "upnp_count": row.get("igd_fw_cnt_upnp") or None,
                "myfritz_enabled": row.get("myfritz_enabled") or None,
                "firstused_raw": row.get("firstused"),
                "lastused_raw": row.get("lastused"),
                "active_now": truthy(row.get("active")) or truthy(row.get("online")),
                "online": truthy(row.get("online")),
                "first_seen": unix_timestamp_to_iso(row.get("firstused")),
                "last_connected": unix_timestamp_to_iso(row.get("lastused")),
                "last_seen": unix_timestamp_to_iso(row.get("lastused")),
                "source": "webui_landevice_query",
            }
        )
    return records


def extract_landevice_rows(data: Any) -> list[Any]:
    if not isinstance(data, dict):
        return []
    rows = data.get("mq_landevices") or data.get("landevice") or data.get("devices")
    if isinstance(rows, dict):
        rows = rows.get("list") or rows.get("devices") or rows.get("landevice")
    if isinstance(rows, list):
        return rows
    for key in ("landevice_all", "landevice_topology", "mq_landevices"):
        value = data.get(key)
        if isinstance(value, dict):
            nested = value.get("data")
            if isinstance(nested, dict):
                found = extract_landevice_rows(nested)
                if found:
                    return found
            raw = value.get("raw")
            if isinstance(raw, str):
                try:
                    found = extract_landevice_rows(json.loads(raw))
                except json.JSONDecodeError:
                    found = []
                if found:
                    return found
        elif isinstance(value, list):
            return value
    for value in data.values():
        if isinstance(value, dict):
            nested = value.get("data") if "data" in value else value
            found = extract_landevice_rows(nested)
            if found:
                return found
    return []


def lan_device_host_rows(
    lan_devices: list[dict[str, Any]], existing_hosts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    existing_keys = {
        (
            str(host.get("mac") or "").lower(),
            str(host.get("ip") or ""),
            str(host.get("hostname") or "").casefold(),
        )
        for host in existing_hosts
    }
    rows: list[dict[str, Any]] = []
    for device in lan_devices:
        key = (
            str(device.get("mac") or "").lower(),
            str(device.get("ip") or ""),
            str(device.get("hostname") or "").casefold(),
        )
        if key in existing_keys:
            continue
        if not any(key):
            continue
        rows.append(
            {
                "hostname": device.get("hostname"),
                "mac": device.get("mac"),
                "ip": device.get("ip"),
                "interface": device.get("interface"),
                "interface_detail": device.get("interface"),
                "active_now": bool(device.get("active_now")),
                "online": device.get("online"),
                "lease_time_remaining": None,
                "uid": device.get("uid"),
                "friendly_name": device.get("friendly_name"),
                "neighbour_name": device.get("neighbour_name"),
                "ip_list": device.get("ip_list"),
                "mac_list": device.get("mac_list"),
                "wlan_station_type": device.get("wlan_station_type"),
                "wlan_uids": device.get("wlan_uids"),
                "plc_uids": device.get("plc_uids"),
                "ethernet_port": device.get("ethernet_port"),
                "vendor": device.get("vendor"),
                "model": device.get("model"),
                "speed": device.get("speed"),
                "source_flags": device.get("source_flags"),
                "parent_uid": device.get("parent_uid"),
                "flags": device.get("flags"),
                "modification_flags": device.get("modification_flags"),
                "dhcp": device.get("dhcp"),
                "static_dhcp": device.get("static_dhcp"),
                "blocked": device.get("blocked"),
                "guest": device.get("guest"),
                "allow_pcp_and_upnp": device.get("allow_pcp_and_upnp"),
                "pcp_count": device.get("pcp_count"),
                "upnp_count": device.get("upnp_count"),
                "myfritz_enabled": device.get("myfritz_enabled"),
                "first_seen": device.get("first_seen"),
                "last_seen": device.get("last_seen"),
                "last_connected": device.get("last_connected"),
                "last_activity": device.get("last_connected") or device.get("last_seen") or device.get("first_seen"),
                "last_activity_source": (
                    "fritzbox_landevice_lastused" if device.get("last_connected") else "fritzbox_landevice_state"
                ),
                "last_activity_confidence": "medium" if device.get("last_connected") else "low",
                "last_activity_note": "FRITZ!Box web UI LAN-device state retained this device even when the official host list did not expose it.",
            }
        )
        existing_keys.add(key)
    return rows


def build_available_wifi_connections(
    wifi_events: list[dict[str, Any]],
    mesh_wifi_devices: list[dict[str, Any]],
    wlan_associations: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    wlan_associations = wlan_associations or []
    for event in wifi_events:
        event_name = event.get("event")
        derived_time_type = "connection_event" if event_name == "connected" else "disconnect_or_other_event"
        derived_confidence = "high" if event_name == "connected" else "medium"
        if event_name == "authenticated":
            derived_time_type = "80211_authentication_event"
            derived_confidence = "medium"
        elif event_name == "steering_observation":
            derived_time_type = "80211_steering_history"
            derived_confidence = "medium"
        elif event_name == "station_history_interval":
            derived_time_type = "80211_station_history_interval"
            derived_confidence = "high"
        elif event_name == "station_state_snapshot":
            derived_time_type = "80211_station_state_snapshot"
            derived_confidence = "medium"
        elif event_name == "wlan_event_table_row":
            derived_time_type = "80211_wlan_events_table"
            derived_confidence = "medium"
        elif event_name in {
            "wpa_pairwise_handshake",
            "wpa_group_handshake",
            "radius_accounting_start",
            "association_request_observed",
            "ap_sta_connected",
            "ap_sta_disconnected",
            "eapol_4way_completed",
        }:
            derived_time_type = f"80211_{event_name}"
            derived_confidence = "high" if event_name in {"ap_sta_connected", "wpa_pairwise_handshake"} else "medium"
        if event.get("hostapd_action") in {"assoc", "reassoc", "disassoc", "deauth"}:
            derived_time_type = f"80211_hostapd_{event.get('hostapd_action')}"
            derived_confidence = "high" if event.get("hostapd_action") in {"assoc", "reassoc"} else "medium"
        timestamped_presence_events = {
            "connected",
            "steering_observation",
            "station_history_interval",
            "station_state_snapshot",
            "wlan_event_table_row",
            "wpa_pairwise_handshake",
            "wpa_group_handshake",
            "radius_accounting_start",
            "association_request_observed",
            "ap_sta_connected",
            "eapol_4way_completed",
        }
        exact_connection_events = {"connected", "station_history_interval", "ap_sta_connected"}
        records.append(
            {
                "timestamp": event.get("timestamp"),
                "derived_connected_at": event.get("timestamp") if event_name in timestamped_presence_events else None,
                "derived_time_type": derived_time_type,
                "derived_time_confidence": derived_confidence,
                "exact_connection_time_available": event_name in exact_connection_events,
                "event": event_name,
                "hostname": event.get("hostname"),
                "mac": event.get("mac"),
                "ip": event.get("ip"),
                "last_connected": event.get("timestamp") if event_name in exact_connection_events else None,
                "source": event.get("source") or "device_log",
                "confidence": (
                    "support_steering_history"
                    if event_name == "steering_observation"
                    else event.get("confidence") or "connection_event"
                ),
                "message": event.get("message"),
                "disconnected_at": event.get("disconnected_at"),
                "duration_seconds": event.get("duration_seconds"),
                "interval_open": event.get("interval_open"),
                "reason_code": event.get("reason_code"),
                "reason_name": event.get("reason_name"),
                "connect_reason_code": event.get("connect_reason_code"),
                "connect_reason_name": event.get("connect_reason_name"),
                "disconnect_reason_code": event.get("disconnect_reason_code"),
                "disconnect_reason_name": event.get("disconnect_reason_name"),
                "hostapd_event": event.get("hostapd_event"),
                "hostapd_action": event.get("hostapd_action"),
                "last_seen": event.get("last_seen"),
                "is_active": event.get("is_active"),
                "is_guest": event.get("is_guest"),
                "station_visible": event.get("station_visible"),
                "rssi": event.get("rssi"),
                "quality": event.get("quality"),
                "bssid": event.get("bssid"),
                "role_id": event.get("role_id"),
                "if_name": event.get("if_name"),
                "connect_state": event.get("connect_state"),
                "event_id": event.get("event_id"),
                "details_hex": event.get("details_hex"),
            }
        )
    for device in mesh_wifi_devices:
        records.append(
            {
                "timestamp": device.get("last_observed"),
                "derived_connected_at": device.get("last_observed"),
                "derived_time_type": "mesh_last_observed",
                "derived_time_confidence": "low",
                "exact_connection_time_available": False,
                "event": "known_wifi_device",
                "hostname": device.get("hostname"),
                "mac": device.get("mac"),
                "ip": ", ".join(device.get("ip_addresses") or []),
                "last_connected": device.get("last_connected"),
                "source": device.get("source"),
                "confidence": device.get("confidence"),
                "message": (
                    f"Known WLAN device on channel {device.get('current_channel') or 'unknown'}, "
                    f"frequency {device.get('primary_frequency') or 'unknown'} kHz, "
                    f"width {device.get('channel_width') or 'unknown'}"
                ),
            }
        )
    for assoc in wlan_associations:
        records.append(
            {
                "timestamp": assoc.get("observed_at"),
                "derived_connected_at": assoc.get("observed_at"),
                "derived_time_type": "wlan_association_snapshot",
                "derived_time_confidence": "medium",
                "exact_connection_time_available": False,
                "event": "associated_now",
                "hostname": assoc.get("hostname"),
                "mac": assoc.get("mac"),
                "ip": assoc.get("ip"),
                "last_connected": assoc.get("observed_at"),
                "source": assoc.get("source") or "wlan_device_list_xml",
                "confidence": "official_current_association_snapshot",
                "message": (
                    f"Current WLAN association on radio {assoc.get('radio_index')}, "
                    f"channel {assoc.get('channel') or 'unknown'}, signal {assoc.get('signal_strength') or 'unknown'}"
                ),
            }
        )
    return sorted(records, key=lambda item: item.get("timestamp") or "", reverse=True)


def parse_support_wifi_observations(content: str | None, observed_at: str | None = None) -> list[dict[str, Any]]:
    if not content:
        return []
    observations: list[dict[str, Any]] = []
    section = ""
    station_subsection = ""
    current_station_mac: str | None = None
    current_station_state: dict[str, Any] = {}
    uptime_seconds = support_uptime_seconds(content)

    def flush_station_state() -> None:
        nonlocal current_station_state
        snapshot = station_state_snapshot_to_dict(
            current_station_state,
            observed_at=observed_at,
            uptime_seconds=uptime_seconds,
        )
        if snapshot:
            observations.append(
                {
                    **snapshot,
                    "event": "station_state_snapshot",
                    "hostname": snapshot.get("hostname"),
                    "ip": snapshot.get("ip"),
                    "interface": snapshot.get("if_name"),
                    "source": "support_data_station_list",
                    "confidence": "support_station_state_snapshot",
                    "message": (
                        f"STATION_LIST state snapshot for {snapshot.get('mac')}: "
                        f"active={snapshot.get('is_active')} guest={snapshot.get('is_guest')} "
                        f"visible={snapshot.get('station_visible')} rssi={snapshot.get('rssi')} "
                        f"quality={snapshot.get('quality')} bssid={snapshot.get('bssid')} "
                        f"role={snapshot.get('role_id')} if={snapshot.get('if_name')} "
                        f"connect_state={snapshot.get('connect_state')}"
                    ),
                }
            )
        current_station_state = {}

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.rstrip()
        section_candidate = support_section_title(line)
        if section_candidate:
            if "STATION_LIST" in section:
                flush_station_state()
            section = section_candidate
            station_subsection = ""
            current_station_mac = None
            continue
        if "STATION_LIST" in section:
            if line.startswith("----------------------------------------") or "Station management:" in line:
                flush_station_state()
                current_station_mac = None
                current_station_state = {"block_line": line_number}
                station_subsection = "station"
                continue
            if "Station connection:" in line:
                station_subsection = "connection"
                continue
            if "Networking infos:" in line:
                station_subsection = "networking"
                continue
            if "Connect history:" in line:
                station_subsection = "history"
                continue
            station_key_value = parse_station_key_value(line)
            if station_key_value:
                key, value = station_key_value
                if key == "mac":
                    current_station_mac = parse_mac(value) or current_station_mac
                    current_station_state["mac"] = current_station_mac
                    current_station_state["mac_line"] = line_number
                elif key == "last_seen" and station_subsection == "station":
                    current_station_state["station_last_seen"] = value
                    current_station_state["station_last_seen_line"] = line_number
                elif key == "last_seen" and station_subsection == "networking":
                    current_station_state["networking_last_seen"] = value
                    current_station_state["networking_last_seen_line"] = line_number
                else:
                    current_station_state[key] = value
                continue
        wlan_row = WLAN_EVENTS_ROW_RE.match(line)
        if wlan_row:
            details = wlan_event_row_to_dict(wlan_row, line_number)
            event_id = str(details["event_id"])
            observations.append(
                {
                    "timestamp": details["timestamp"],
                    "event": "wlan_event_table_row",
                    "hostname": None,
                    "mac": details["mac"],
                    "ip": None,
                    "interface": details["interface"],
                    "radio_band": str(details["band"]),
                    "radio_band_id": details["band"],
                    "rate": str(details["rate"]),
                    "rate_value": details["rate"],
                    "channel": str(details["channel"]),
                    "channel_number": details["channel"],
                    "previous_channel": str(details["previous_channel"]),
                    "previous_channel_number": details["previous_channel"],
                    "raw_event_id": event_id,
                    "event_id": details["event_id"],
                    "raw_details": details["details_hex"],
                    "details_hex": details["details_hex"],
                    "details_int": details["details_int"],
                    "source": "support_data_wlan_events",
                    "confidence": "support_wlan_events_table",
                    "message": (
                        f"WLAN_EVENTS row: event_id={event_id} band={details['band']} "
                        f"rate={details['rate']} channel={details['channel']} "
                        f"details={details['details_hex']}"
                    ),
                    "line_number": line_number,
                }
            )
            continue
        station_row = STATION_HISTORY_ROW_RE.match(line)
        if station_row and current_station_mac:
            connected_at = parse_compact_support_timestamp(station_row.group("connected"))
            disconnected_at = parse_compact_support_timestamp(station_row.group("disconnected"))
            if connected_at is None:
                continue
            duration_seconds = (
                int((disconnected_at - connected_at).total_seconds()) if disconnected_at is not None else None
            )
            connect_reason_code = int(station_row.group("connect_reason"), 16)
            disconnect_reason_code = int(station_row.group("disconnect_reason"), 16)
            observations.append(
                {
                    "timestamp": connected_at.isoformat(),
                    "event": "station_history_interval",
                    "hostname": None,
                    "mac": current_station_mac,
                    "ip": None,
                    "interface": station_row.group("iface"),
                    "role": station_row.group("role"),
                    "disconnected_at": disconnected_at.isoformat() if disconnected_at else None,
                    "connect_status": station_row.group("connect_status"),
                    "connect_initiator": station_row.group("connect_initiator"),
                    "connect_reason": station_row.group("connect_reason"),
                    "disconnect_status": station_row.group("disconnect_status"),
                    "disconnect_initiator": station_row.group("disconnect_initiator"),
                    "disconnect_reason": station_row.group("disconnect_reason"),
                    "connect_reason_code": connect_reason_code,
                    "connect_reason_name": reason_name(connect_reason_code),
                    "disconnect_reason_code": disconnect_reason_code,
                    "disconnect_reason_name": reason_name(disconnect_reason_code),
                    "duration_seconds": duration_seconds,
                    "interval_open": disconnected_at is None,
                    "wlan_mode": station_row.group("wlan_mode"),
                    "quality": station_row.group("quality"),
                    "source": "support_data_station_list",
                    "confidence": "support_station_history_interval",
                    "message": (
                        f"STATION_LIST retained interval on {station_row.group('iface')}: "
                        f"connected {station_row.group('connected')}, "
                        f"disconnected {station_row.group('disconnected') or 'open'}, "
                        f"quality {station_row.group('quality')}"
                    ),
                    "line_number": line_number,
                }
            )
    if "STATION_LIST" in section:
        flush_station_state()
    return observations


STATION_STATE_KEYS = {
    "last_seen",
    "is_active",
    "is_guest",
    "rssi",
    "quality",
    "bssid",
    "role_id",
    "if_name",
    "connect_state",
    "speed",
    "hostname",
    "ip",
    "ipv4",
    "ip_addr",
    "ip_address",
}


def parse_support_wifi_details(content: str | None, observed_at: str) -> dict[str, list[dict[str, Any]]]:
    """Parse support-data WLAN sections into typed evidence rows.

    FRITZ!OS support-data formats vary by firmware. This parser is deliberately
    tolerant: it promotes well-known STATION_LIST key/value fields and reuses the
    existing WLAN_EVENTS / station-history recognizers without assuming one exact
    section layout.
    """

    rows = {
        "wlan_station_state_snapshots": [],
        "wlan_station_intervals": [],
        "wlan_ap_client_events": parse_support_ap_client_events(content),
        "wlan_event_details": [],
    }
    for observation in parse_support_wifi_observations(content, observed_at):
        if observation.get("event") == "station_state_snapshot":
            rows["wlan_station_state_snapshots"].append(station_state_row(observation))
        elif observation.get("event") == "station_history_interval":
            rows["wlan_station_intervals"].append(station_interval_row(observation))
        elif observation.get("event") == "wlan_event_table_row":
            rows["wlan_event_details"].append(wlan_event_detail_row(observation))
    return rows


def parse_support_station_state_snapshots(content: str | None, observed_at: str) -> list[dict[str, Any]]:
    if not content:
        return []
    rows: list[dict[str, Any]] = []
    section = ""
    current: dict[str, Any] = {}

    def flush() -> None:
        if not current.get("mac"):
            return
        rows.append(
            {
                "observed_at": observed_at,
                "mac": current.get("mac"),
                "hostname": current.get("hostname") or current.get("name"),
                "ip": current.get("ip"),
                "interface": current.get("if_name") or current.get("interface"),
                "bssid": parse_mac(str(current.get("bssid") or "")),
                "role_id": current.get("role_id"),
                "connect_state": current.get("connect_state"),
                "active": current.get("is_active"),
                "guest": current.get("is_guest"),
                "last_seen": support_value_to_timestamp(current.get("last_seen")) or current.get("last_seen"),
                "rssi": current.get("rssi"),
                "quality": current.get("quality"),
                "speed": current.get("speed"),
                "source": "support_station_list",
                "evidence_note": (
                    "WLAN station state parsed from FRITZ!Box support-data STATION_LIST. "
                    "This is router-retained state, not a guaranteed complete session log."
                ),
            }
        )

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        section_candidate = support_section_title(line)
        if section_candidate:
            if "STATION_LIST" in section:
                flush()
                current = {}
            section = section_candidate
            continue
        if "STATION_LIST" not in section:
            continue
        key_value = SUPPORT_KEY_VALUE_RE.match(line.strip())
        if not key_value:
            continue
        key = key_value.group("key").strip()
        value = key_value.group("value").strip()
        normalized_key = key.casefold().replace("-", "_")
        if normalized_key == "mac":
            flush()
            current = {"mac": parse_mac(value) or parse_mac(line)}
            continue
        if normalized_key in STATION_STATE_KEYS or normalized_key in {"name", "interface"}:
            current[normalized_key] = value
    if "STATION_LIST" in section:
        flush()
    return rows


def support_value_to_timestamp(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    compact = parse_compact_support_timestamp(text)
    if compact:
        return compact.isoformat()
    iso = parse_iso_local_timestamp(text)
    if iso:
        return iso.isoformat()
    return None


def station_interval_row(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "connected_at": observation.get("timestamp"),
        "disconnected_at": observation.get("disconnected_at"),
        "mac": observation.get("mac"),
        "interface": observation.get("interface"),
        "role": observation.get("role"),
        "connect_status": observation.get("connect_status"),
        "connect_initiator": observation.get("connect_initiator"),
        "connect_reason": observation.get("connect_reason"),
        "disconnect_status": observation.get("disconnect_status"),
        "disconnect_initiator": observation.get("disconnect_initiator"),
        "disconnect_reason": observation.get("disconnect_reason"),
        "wlan_mode": observation.get("wlan_mode"),
        "quality": observation.get("quality"),
        "source": observation.get("source") or "support_data_station_list",
        "evidence_note": (
            "WLAN station history interval parsed from FRITZ!Box support-data STATION_LIST. "
            "Intervals are retained diagnostic history and may be incomplete."
        ),
    }


def station_state_row(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "observed_at": observation.get("observed_at") or observation.get("timestamp"),
        "mac": observation.get("mac"),
        "hostname": observation.get("hostname"),
        "ip": observation.get("ip"),
        "interface": observation.get("interface") or observation.get("if_name"),
        "bssid": observation.get("bssid"),
        "role_id": observation.get("role_id"),
        "connect_state": observation.get("connect_state"),
        "active": observation.get("is_active"),
        "guest": observation.get("is_guest"),
        "last_seen": observation.get("last_seen") or observation.get("timestamp"),
        "rssi": observation.get("rssi"),
        "quality": observation.get("quality"),
        "speed": observation.get("speed") or observation.get("station_type"),
        "source": observation.get("source") or "support_data_station_list",
        "evidence_note": (
            "WLAN station state parsed from FRITZ!Box support-data STATION_LIST. "
            "This is router-retained state, not a guaranteed complete session log."
        ),
    }


def wlan_event_detail_row(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_time": observation.get("timestamp"),
        "event_id": observation.get("raw_event_id"),
        "mac": observation.get("mac"),
        "interface": observation.get("interface"),
        "band": observation.get("radio_band"),
        "rate": observation.get("rate"),
        "channel": observation.get("channel"),
        "previous_channel": observation.get("previous_channel"),
        "details": observation.get("raw_details"),
        "source": observation.get("source") or "support_data_wlan_events",
        "evidence_note": "WLAN_EVENTS row parsed from FRITZ!Box support-data diagnostics.",
    }


def parse_support_ap_client_events(content: str | None) -> list[dict[str, Any]]:
    if not content:
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        entry = next(iter(parse_device_log(raw_line, source="support_data_hostapd")), None)
        if entry is None:
            continue
        parsed = parse_support_ap_wifi_event(entry)
        if not parsed:
            lifecycle = HOSTAPD_CLIENT_LIFECYCLE_RE.search(entry.message)
            if not lifecycle:
                continue
            parsed = {
                "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                "event": hostapd_event_kind(lifecycle.group("event")),
                "mac": parse_mac(lifecycle.group("mac")),
                "interface": lifecycle.group("iface"),
                "reason_code": lifecycle.group("reason"),
                "source": "support_data_hostapd",
                "confidence": "support_hostapd_lifecycle",
                "message": entry.message,
            }
        rows.append(
            {
                "event_time": parsed.get("timestamp"),
                "event_kind": parsed.get("event"),
                "mac": parsed.get("mac"),
                "client_mac": parsed.get("mac"),
                "source_bssid": parsed.get("source_bssid") or parsed.get("bssid"),
                "bssid": parsed.get("bssid") or parsed.get("source_bssid"),
                "channel": parsed.get("channel"),
                "interface": parsed.get("interface"),
                "reason_code": parsed.get("reason_code")
                or parsed.get("connect_reason")
                or parsed.get("disconnect_reason"),
                "reason_name": parsed.get("reason_name"),
                "status_code": parsed.get("status_code"),
                "cipher": parsed.get("cipher"),
                "session": parsed.get("session"),
                "hostapd_event": parsed.get("hostapd_event"),
                "hostapd_action": parsed.get("hostapd_action"),
                "source": parsed.get("source") or "support_data_hostapd",
                "message": parsed.get("message"),
                "line_number": line_number,
                "evidence_note": "AP-side client lifecycle event parsed from hostapd/support-data diagnostics.",
            }
        )
    return rows


def hostapd_event_kind(value: str | None) -> str:
    lowered = str(value or "").casefold()
    if lowered in {"auth", "authenticated"}:
        return "authenticated"
    if lowered in {"assoc", "associated"}:
        return "associated"
    if lowered in {"reassoc", "reassociated"}:
        return "reassociated"
    if lowered in {"disassoc", "disassociated"}:
        return "disassociated"
    if lowered in {"deauth", "deauthenticated"}:
        return "deauthenticated"
    return lowered or "client_event"


def parse_support_wlan_environment(
    content: str | None, observed_at: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not content:
        return [], []
    scan_hints: list[dict[str, Any]] = []
    status_rows: list[dict[str, Any]] = []
    section = ""
    scan_radio: str | None = None
    scan_time: str | None = None
    current_station_mac: str | None = None
    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        section_candidate = support_section_title(line)
        if section_candidate:
            section = section_candidate
            current_station_mac = None
            if "WLAN_SCAN_RESULTS" not in section:
                scan_radio = None
                scan_time = None
            continue

        if "WLAN_SCAN_RESULTS" in section:
            if line.startswith("Scan results for radio"):
                scan_radio = first_quoted_value(line)
                continue
            scan_time_match = WLAN_SCAN_TIME_RE.match(line.strip())
            if scan_time_match:
                timestamp = parse_fritz_timestamp(scan_time_match.group("date"), scan_time_match.group("time"))
                scan_time = timestamp.isoformat() if timestamp else observed_at
                continue
            scan_row = WLAN_SCAN_RESULT_RE.match(line.strip())
            if scan_row:
                scan_hints.append(
                    {
                        "observed_at": scan_time or observed_at,
                        "hint_type": "wlan_environment_scan_bssid",
                        "protocol": "802.11 scan result",
                        "hostname": scan_row.group("ssid") or None,
                        "mac": parse_mac(scan_row.group("bssid")),
                        "ip": None,
                        "direction": "neighbor_ap_seen_by_router",
                        "confidence": "medium",
                        "summary": (
                            f"Nearby AP scan result on radio {scan_radio or 'unknown'}: "
                            f"SSID '{scan_row.group('ssid') or '<hidden>'}', "
                            f"RSSI {scan_row.group('rssi')} dBm, "
                            f"frequency {scan_row.group('frequency')} MHz, "
                            f"channels {scan_row.group('channel_low')}-{scan_row.group('channel_high')}, "
                            f"mode {scan_row.group('mode').strip()}, caps {scan_row.group('caps').strip()}."
                        ),
                        "source": "support_wlan_scan_results",
                    }
                )
                continue

        if "SCAN_EVENTS" in section:
            event = WLAN_SCAN_EVENT_RE.match(line.strip())
            if event:
                timestamp = parse_fritz_timestamp(event.group("date"), event.group("time"))
                status_rows.append(
                    {
                        "observed_at": timestamp.isoformat() if timestamp else observed_at,
                        "area": "wlan_scan_event",
                        "metric": event.group("event").lower(),
                        "value": event.group("radio"),
                        "unit": event.group("reason") or "",
                        "source": "support_scan_events",
                        "confidence": "medium",
                    }
                )
                continue

        if "ENV_INTERFERENCE_HISTORY" in section:
            interference = WLAN_INTERFERENCE_RE.match(line.strip())
            if interference:
                timestamp = parse_fritz_timestamp(interference.group("date"), interference.group("time"))
                status_rows.append(
                    {
                        "observed_at": timestamp.isoformat() if timestamp else observed_at,
                        "area": "wlan_interference",
                        "metric": interference.group("event").lower(),
                        "value": (
                            f"radio {interference.group('radio')} {interference.group('state')} "
                            f"{interference.group('frequency')} MHz"
                        ),
                        "unit": interference.group("change"),
                        "source": "support_env_interference_history",
                        "confidence": "medium",
                    }
                )
                continue

        if "WLAN_CHANNEL_INFO" in section:
            load = WLAN_CHANNEL_LOAD_RE.match(line.strip())
            if load:
                status_rows.append(
                    {
                        "observed_at": observed_at,
                        "area": "wlan_channel_load",
                        "metric": f"channel_{load.group('channel')}",
                        "value": load.group("load"),
                        "unit": "%",
                        "source": "support_wlan_channel_info",
                        "confidence": "medium",
                    }
                )
                continue

        if "STATION_LIST" in section:
            if re.match(r"^\s+mac\s+=", line):
                current_station_mac = parse_mac(line) or current_station_mac
                continue
            counter_match = SUPPORT_KEY_VALUE_RE.match(line.strip())
            if current_station_mac and counter_match:
                key = counter_match.group("key").strip()
                if key in {"cnt_connect_success", "cnt_connect_fail", "cnt_disconnect_forced", "time_mean_connect"}:
                    status_rows.append(
                        {
                            "observed_at": observed_at,
                            "area": "wlan_station_counters",
                            "metric": key,
                            "value": counter_match.group("value").strip(),
                            "unit": "seconds" if key == "time_mean_connect" else "count",
                            "source": "support_station_list",
                            "confidence": "medium",
                            "mac": current_station_mac,
                        }
                    )
    return scan_hints, status_rows


def first_quoted_value(value: str) -> str | None:
    match = re.search(r"'([^']+)'", value)
    return match.group(1) if match else None


def parse_device_log(raw_log: str, source: str = "device_log") -> list[FritzLogEntry]:
    entries: list[FritzLogEntry] = []
    for raw_line in raw_log.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = LOG_TS_RE.match(line)
        if match is not None:
            entries.append(
                FritzLogEntry(
                    timestamp=parse_fritz_timestamp(match.group("date"), match.group("time")),
                    message=match.group("message").strip(),
                    raw=line,
                    source=source,
                )
            )
            continue
        support_match = SUPPORT_TS_RE.match(line)
        if support_match is not None:
            timestamp = parse_support_timestamp(support_match.group("date"), support_match.group("time"))
            entries.append(
                FritzLogEntry(
                    timestamp=timestamp,
                    message=support_match.group("message").strip(),
                    raw=line,
                    source=source,
                )
            )
            continue
        entries.append(FritzLogEntry(timestamp=None, message=line, raw=line, source=source))
    return entries


def parse_support_timestamp(date: str, time_value: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(f"{date} {time_value}", fmt).astimezone()
        except ValueError:
            continue
    return None


def parse_wifi_event(entry: FritzLogEntry, hosts_by_mac: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    steering_event = parse_steering_history_event(entry)
    if steering_event:
        return steering_event
    support_event = parse_support_ap_wifi_event(entry)
    if support_event:
        return support_event

    message = entry.message.casefold()
    if (
        "last_connected" in message
        or "query.lua" in message
        or re.search(r"^unix\s+\d+\s+\[.*\]\s+stream\s+connected", message)
    ):
        return None
    if not any(keyword in message for keyword in WIFI_EVENT_KEYWORDS):
        return None

    event_type = None
    if any(keyword in message for keyword in DISCONNECTED_KEYWORDS):
        event_type = "disconnected"
    elif "authenticated" in message:
        event_type = "authenticated"
    elif any(keyword in message for keyword in CONNECTED_KEYWORDS):
        event_type = "connected"
    if event_type is None:
        return None

    mac = parse_mac(entry.message)
    host = hosts_by_mac.get(mac or "", {})
    hostname = host.get("NewHostName") or parse_hostname(entry.message, mac)
    if hostname and "ieee 802.11" in str(hostname).casefold():
        hostname = None
    ip = parse_ip(entry.message) or host.get("NewIPAddress")

    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "event": event_type,
        "hostname": hostname or None,
        "mac": mac,
        "ip": ip or None,
        "interface": host.get("NewInterfaceType"),
        "active_now": truthy(host.get("NewActive")) if host else None,
        "source": entry.source,
        "message": entry.message,
    }


def parse_support_ap_wifi_event(entry: FritzLogEntry) -> dict[str, Any] | None:
    ap_sta = AP_STA_EVENT_RE.search(entry.message)
    if ap_sta:
        raw_event = ap_sta.group("event").upper()
        event_map = {
            "AP-STA-CONNECTED": "ap_sta_connected",
            "AP-STA-DISCONNECTED": "ap_sta_disconnected",
            "EAPOL-4WAY-HS-COMPLETED": "eapol_4way_completed",
        }
        reason_match = re.search(r"\breason[=:\s]+(?P<reason>\d+)\b", ap_sta.group("detail") or "", re.I)
        reason_code = int(reason_match.group("reason")) if reason_match else None
        status_match = re.search(r"\bstatus(?:[_\s]+code)?[=:\s]+(?P<status>\d+)\b", ap_sta.group("detail") or "", re.I)
        status_code = int(status_match.group("status")) if status_match else None
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "event": event_map[raw_event],
            "hostname": None,
            "mac": parse_mac(ap_sta.group("mac")),
            "ip": None,
            "interface": ap_sta.group("iface"),
            "active_now": None,
            "hostapd_event": raw_event.lower(),
            "hostapd_action": event_map[raw_event].replace("ap_sta_", ""),
            "reason_code": reason_code,
            "reason_name": reason_name(reason_code),
            "status_code": status_code,
            "source": "support_data_hostapd",
            "confidence": "support_ap_sta_event",
            "message": entry.message,
        }

    lifecycle = parse_hostapd_lifecycle_event(entry.message)
    if lifecycle:
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "hostname": None,
            "ip": None,
            "active_now": None,
            "source": "support_data_hostapd",
            "confidence": "support_hostapd_lifecycle_event",
            "message": entry.message,
            **lifecycle,
        }

    handshake = WPA_HANDSHAKE_RE.search(entry.message)
    if handshake:
        kind = handshake.group("kind").casefold()
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "event": f"wpa_{kind}_handshake",
            "hostname": None,
            "mac": parse_mac(handshake.group("mac")),
            "ip": None,
            "interface": handshake.group("iface"),
            "active_now": None,
            "cipher": handshake.group("cipher"),
            "source": "support_data_hostapd",
            "confidence": "support_wpa_handshake",
            "message": entry.message,
        }

    radius = RADIUS_ACCOUNTING_RE.search(entry.message)
    if radius:
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "event": "radius_accounting_start",
            "hostname": None,
            "mac": parse_mac(radius.group("mac")),
            "ip": None,
            "interface": radius.group("iface"),
            "active_now": None,
            "session": radius.group("session"),
            "source": "support_data_hostapd",
            "confidence": "support_radius_accounting",
            "message": entry.message,
        }

    association_request = ASSOCIATION_REQUEST_RE.search(entry.message)
    if association_request:
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "event": "association_request_observed",
            "hostname": None,
            "mac": parse_mac(association_request.group("mac") or association_request.group("mac2")),
            "ip": None,
            "interface": None,
            "active_now": None,
            "source": "support_data_hostapd",
            "confidence": "support_association_request",
            "message": entry.message,
        }
    return None


def parse_steering_history_event(entry: FritzLogEntry) -> dict[str, Any] | None:
    match = STEERING_HISTORY_RE.search(entry.message)
    if not match:
        return None
    start = parse_iso_local_timestamp(match.group("start"))
    end = parse_iso_local_timestamp(match.group("end"))
    moved = parse_iso_local_timestamp(match.group("moved")) if match.group("moved") else None
    target_raw = (match.group("target") or "").strip()
    target_bssid = parse_mac(target_raw)
    result = re.sub(r"\s+", " ", match.group("result") or "").strip()
    return {
        "timestamp": start.isoformat() if start else None,
        "event": "steering_observation",
        "hostname": None,
        "mac": parse_mac(match.group("sta")),
        "ip": None,
        "interface": "WLAN",
        "active_now": None,
        "source_bssid": parse_mac(match.group("source_bssid")),
        "target_bssid": target_bssid,
        "source_rssi": f"{match.group('source_rssi')} dBm",
        "mode": match.group("mode"),
        "result": result,
        "ended_at": end.isoformat() if end else None,
        "moved_at": moved.isoformat() if moved else None,
        "source": entry.source or "support_data_steering",
        "message": entry.message,
    }


def parse_iso_local_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").astimezone()
    except ValueError:
        return None


def parse_compact_support_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y%m%d-%H%M%S").astimezone()
    except ValueError:
        return None


def clean_dash(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in {"", "---", "----"} else stripped


def entry_to_dict(entry: FritzLogEntry) -> dict[str, Any]:
    fallback_category = classify_log_entry(entry.message)
    parsed = parse_fritzbox_log_message(entry.message, fallback_category)
    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "message": entry.message,
        "category": parsed["category"],
        "mac": parsed["mac"] or parse_mac(entry.message),
        "ip": parsed["ip"] or parse_ip(entry.message),
        "source": entry.source,
    }


def classify_log_entry(message: str) -> str:
    parsed = parse_fritzbox_log_message(message, "")
    if parsed.get("fields", {}).get("parser_rule_id") != "router.fallback":
        return str(parsed["category"])
    lower = message.casefold()
    if any(keyword in lower for keyword in WIFI_EVENT_KEYWORDS):
        return "wifi"
    if "internet" in lower or "wan" in lower or "dsl" in lower:
        return "internet"
    if "dhcp" in lower or "ip-adresse" in lower or "ip address" in lower:
        return "network"
    if "telefon" in lower or "telephone" in lower or "ruf" in lower:
        return "telephony"
    if "anmeldung" in lower or "login" in lower:
        return "auth"
    return "system"


def build_host_seen_index(
    hosts: list[dict[str, Any]],
    event_log: list[dict[str, Any]],
    wifi_events: list[dict[str, Any]],
    mesh_wifi_devices: list[dict[str, Any]] | None = None,
    landevice_records: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {host_identity(host): {} for host in hosts}
    mesh_wifi_devices = mesh_wifi_devices or []
    landevice_records = landevice_records or []

    for host in hosts:
        identity = host_identity(host)
        host_mac = str(host.get("NewMACAddress") or "").lower()
        host_ip = str(host.get("NewIPAddress") or "")
        host_name = str(host.get("NewHostName") or "").casefold()
        timestamps: list[str] = []
        connected_timestamps: list[str] = []
        activity_candidates: list[tuple[str, str, str, str]] = []

        for entry in event_log:
            if not entry.get("timestamp"):
                continue
            if log_matches_host(entry, host_mac, host_ip, host_name):
                timestamp = str(entry["timestamp"])
                timestamps.append(timestamp)
                activity_candidates.append(
                    (timestamp, "retained_log_match", "medium", "Retained router log mentions this host/IP/MAC/name.")
                )

        for event in wifi_events:
            if not event.get("timestamp"):
                continue
            if event_matches_host(event, host_mac, host_ip, host_name):
                timestamp = str(event["timestamp"])
                timestamps.append(timestamp)
                if event.get("event") in {"connected", "station_history_interval", "ap_sta_connected"}:
                    connected_timestamps.append(timestamp)
                    activity_candidates.append(
                        (
                            timestamp,
                            (
                                "exact_wifi_connection"
                                if event.get("event") == "connected"
                                else f"support_{event.get('event')}"
                            ),
                            "high",
                            "Retained WLAN/AP-side connection evidence matched this host.",
                        )
                    )
                else:
                    activity_candidates.append(
                        (timestamp, "wifi_event", "medium", "Retained WLAN-related log entry matched this host.")
                    )

        for device in mesh_wifi_devices:
            if not device.get("last_observed"):
                continue
            if event_matches_host(device, host_mac, host_ip, host_name):
                timestamp = str(device["last_observed"])
                timestamps.append(timestamp)
                activity_candidates.append(
                    (
                        timestamp,
                        "mesh_last_observed",
                        "low",
                        "Mesh data observed this WLAN device; this is not an exact association time.",
                    )
                )

        for device in landevice_records:
            if not event_matches_host(device, host_mac, host_ip, host_name):
                continue
            for key in (
                "uid",
                "friendly_name",
                "neighbour_name",
                "ip_list",
                "mac_list",
                "wlan_station_type",
                "wlan_uids",
                "plc_uids",
                "ethernet_port",
                "vendor",
                "model",
                "speed",
                "source_flags",
                "parent_uid",
                "flags",
                "modification_flags",
                "dhcp",
                "static_dhcp",
                "blocked",
                "allow_pcp_and_upnp",
                "pcp_count",
                "upnp_count",
                "myfritz_enabled",
                "online",
            ):
                if device.get(key) not in (None, ""):
                    index[identity][key] = device.get(key)
            if device.get("interface"):
                index[identity]["interface_detail"] = device.get("interface")
            if device.get("first_seen"):
                timestamps.append(str(device["first_seen"]))
            if device.get("last_connected"):
                timestamp = str(device["last_connected"])
                timestamps.append(timestamp)
                connected_timestamps.append(timestamp)
                activity_candidates.append(
                    (
                        timestamp,
                        "fritzbox_landevice_lastused",
                        "medium",
                        "FRITZ!Box web UI LAN-device state reported this client last connected/used at this time.",
                    )
                )

        if truthy(host.get("NewActive")) and generated_at:
            activity_candidates.append(
                (
                    generated_at,
                    "active_host_snapshot",
                    "medium",
                    "Host table reported this client active at acquisition time; this is an observation, not a session start time.",
                )
            )

        if timestamps:
            sorted_timestamps = sorted(set(timestamps))
            index[identity]["first_seen"] = sorted_timestamps[0]
            index[identity]["last_seen"] = sorted_timestamps[-1]
        else:
            index[identity]["first_seen"] = None
            index[identity]["last_seen"] = None

        index[identity]["last_connected"] = max(connected_timestamps) if connected_timestamps else None
        if activity_candidates:
            last_activity = max(activity_candidates, key=lambda item: item[0])
            index[identity]["last_activity"] = last_activity[0]
            index[identity]["last_activity_source"] = last_activity[1]
            index[identity]["last_activity_confidence"] = last_activity[2]
            index[identity]["last_activity_note"] = last_activity[3]
        else:
            index[identity]["last_activity"] = None
            index[identity]["last_activity_source"] = None
            index[identity]["last_activity_confidence"] = None
            index[identity]["last_activity_note"] = None

    return index


def host_identity(host: dict[str, Any]) -> str:
    return "|".join(
        [
            str(host.get("NewMACAddress") or "").lower(),
            str(host.get("NewIPAddress") or ""),
            str(host.get("NewHostName") or "").casefold(),
        ]
    )


def log_matches_host(entry: dict[str, Any], mac: str, ip: str, hostname: str) -> bool:
    message = str(entry.get("message") or "").casefold()
    return bool(
        (mac and str(entry.get("mac") or "").lower() == mac)
        or (ip and str(entry.get("ip") or "") == ip)
        or (hostname and hostname in message)
    )


def event_matches_host(event: dict[str, Any], mac: str, ip: str, hostname: str) -> bool:
    event_ips = [part.strip() for part in str(event.get("ip") or "").split(",")]
    return bool(
        (mac and str(event.get("mac") or "").lower() == mac)
        or (ip and (str(event.get("ip") or "") == ip or ip in event_ips))
        or (hostname and str(event.get("hostname") or "").casefold() == hostname)
    )


def host_to_dict(host: dict[str, Any], seen: dict[str, Any] | None = None) -> dict[str, Any]:
    seen = seen or {}
    return {
        "hostname": host.get("NewHostName") or None,
        "mac": host.get("NewMACAddress") or None,
        "ip": host.get("NewIPAddress") or None,
        "interface": host.get("NewInterfaceType") or None,
        "interface_detail": seen.get("interface_detail"),
        "active_now": truthy(host.get("NewActive")),
        "online": seen.get("online"),
        "lease_time_remaining": host.get("NewLeaseTimeRemaining"),
        "uid": seen.get("uid"),
        "friendly_name": seen.get("friendly_name") or host.get("NewX_AVM-DE_FriendlyName"),
        "neighbour_name": seen.get("neighbour_name"),
        "ip_list": seen.get("ip_list"),
        "mac_list": seen.get("mac_list"),
        "wlan_station_type": seen.get("wlan_station_type"),
        "wlan_uids": seen.get("wlan_uids"),
        "plc_uids": seen.get("plc_uids"),
        "ethernet_port": seen.get("ethernet_port"),
        "vendor": seen.get("vendor"),
        "model": seen.get("model") or host.get("NewX_AVM-DE_Model"),
        "speed": seen.get("speed") or host.get("NewX_AVM-DE_Speed"),
        "source_flags": seen.get("source_flags"),
        "parent_uid": seen.get("parent_uid"),
        "flags": seen.get("flags"),
        "modification_flags": seen.get("modification_flags"),
        "dhcp": seen.get("dhcp"),
        "static_dhcp": seen.get("static_dhcp"),
        "blocked": seen.get("blocked"),
        "guest": seen.get("guest") or host.get("NewX_AVM-DE_Guest"),
        "vpn": host.get("NewX_AVM-DE_VPN"),
        "wan_access": host.get("NewX_AVM-DE_WANAccess"),
        "filter_profile_id": host.get("NewX_AVM-DE_FilterProfileID"),
        "allow_pcp_and_upnp": seen.get("allow_pcp_and_upnp"),
        "pcp_count": seen.get("pcp_count"),
        "upnp_count": seen.get("upnp_count"),
        "myfritz_enabled": seen.get("myfritz_enabled"),
        "first_seen": seen.get("first_seen"),
        "last_seen": seen.get("last_seen"),
        "last_connected": seen.get("last_connected"),
        "last_activity": seen.get("last_activity"),
        "last_activity_source": seen.get("last_activity_source"),
        "last_activity_confidence": seen.get("last_activity_confidence"),
        "last_activity_note": seen.get("last_activity_note"),
    }


def build_forensic_findings(
    exports: dict[str, Any],
    known_hosts: list[dict[str, Any]],
    wifi_records: list[dict[str, Any]],
    observed_at: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(tr064_snapshot_findings(exports.get("tr064_snapshot_json"), observed_at))
    findings.extend(mesh_topology_findings(exports.get("mesh_list"), observed_at))
    findings.extend(data_lua_findings(exports.get("data_lua_pages_json"), observed_at))
    findings.extend(query_lua_findings(exports.get("query_lua_artifacts_json"), observed_at))
    findings.extend(device_risk_findings(known_hosts, wifi_records, observed_at))
    return findings


def finding(
    finding_type: str,
    section: str,
    key: str | None,
    value: Any,
    observed_at: str,
    source: str,
    raw: Any,
    note: str,
) -> dict[str, Any]:
    rendered = json.dumps(value, sort_keys=True, default=str) if isinstance(value, dict | list) else str(value)
    return {
        "finding_type": finding_type,
        "section": section,
        "key": key,
        "value": rendered[:2000],
        "line_number": None,
        "observed_at": observed_at,
        "source": source,
        "raw_text": rendered[:4000],
        "evidence_level": "parsed_from_raw",
        "evidence_note": note,
        "raw_json": raw,
    }


def tr064_snapshot_findings(content: str | None, observed_at: str) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    actions = data.get("actions") or {}
    indexed = data.get("indexed_results") or {}

    for key in ("host_filter_profiles", "lan_host_config", "wan_ip_info", "wan_ip_status", "wan_ip_external"):
        response = (actions.get(key) or {}).get("response")
        if response:
            findings.append(
                finding(
                    key,
                    "tr064_status",
                    key,
                    response,
                    observed_at,
                    "tr064_snapshot_json",
                    response,
                    "Read-only TR-064 action response parsed from the acquisition snapshot.",
                )
            )

    for mapping_key in ("wan_ip_port_mappings", "wan_ppp_port_mappings"):
        for item in (indexed.get(mapping_key) or {}).get("items") or []:
            response = item.get("response") or {}
            if not response:
                continue
            enabled = truthy(response.get("NewEnabled"))
            label = (
                f"{response.get('NewProtocol') or 'protocol'} "
                f"{response.get('NewExternalPort') or '?'} -> "
                f"{response.get('NewInternalClient') or '?'}:{response.get('NewInternalPort') or '?'}"
            )
            findings.append(
                finding(
                    "wan_port_mapping_enabled" if enabled else "wan_port_mapping_disabled",
                    "wan_exposure",
                    label,
                    response,
                    observed_at,
                    "tr064_snapshot_json",
                    response,
                    "WAN port mapping parsed from TR-064 indexed port-mapping results.",
                )
            )

    for key, bucket in indexed.items():
        if not key.startswith("wlan_") or not key.endswith("_associations"):
            continue
        for item in bucket.get("items") or []:
            response = item.get("response") or {}
            if response:
                findings.append(
                    finding(
                        "wlan_association_tr064",
                        "wlan_association_snapshot",
                        response.get("NewAssociatedDeviceMACAddress") or key,
                        response,
                        observed_at,
                        "tr064_snapshot_json",
                        response,
                        "Current WLAN association parsed from TR-064 indexed association results.",
                    )
                )

    for radio in data.get("wlan") or []:
        info = (radio.get("info") or {}).get("response") or {}
        stats = (radio.get("statistics") or {}).get("response") or {}
        packet_stats = (radio.get("packet_statistics") or {}).get("response") or {}
        if info or stats or packet_stats:
            findings.append(
                finding(
                    "wlan_radio",
                    "wlan_radio_state",
                    f"radio_{radio.get('index')}",
                    {"info": info, "statistics": stats, "packet_statistics": packet_stats},
                    observed_at,
                    "tr064_snapshot_json",
                    radio,
                    "Per-radio WLAN state and counters parsed from TR-064.",
                )
            )
    return findings


def mesh_topology_findings(content: str | None, observed_at: str) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for node in data.get("nodes") or []:
        node_label = node.get("device_name") or node.get("device_friendly_name") or node.get("device_mac_address")
        findings.append(
            finding(
                "mesh_node",
                "mesh_topology",
                node_label,
                {
                    "name": node_label,
                    "mac": node.get("device_mac_address"),
                    "uid": node.get("uid"),
                    "ips": node.get("ip_addresses"),
                },
                observed_at,
                "mesh_list",
                node,
                "Mesh node parsed from the official mesh topology artifact.",
            )
        )
        for interface in node.get("node_interfaces") or []:
            for link in interface.get("node_links") or []:
                link_value = {
                    "device": node_label,
                    "interface": interface.get("name") or interface.get("type"),
                    "link_type": link.get("type") or interface.get("type"),
                    "state": link.get("state"),
                    "last_connected": mesh_timestamp_to_iso(link.get("last_connected"))
                    or unix_timestamp_to_iso(link.get("last_connected")),
                    "rx": link.get("cur_data_rate_rx"),
                    "tx": link.get("cur_data_rate_tx"),
                    "raw": link,
                }
                findings.append(
                    finding(
                        "mesh_link",
                        "mesh_topology",
                        f"{node_label}:{link_value['interface']}",
                        link_value,
                        observed_at,
                        "mesh_list",
                        link,
                        "Mesh link parsed from topology; last_connected is router-provided when present.",
                    )
                )
    return findings


def data_lua_findings(content: str | None, observed_at: str) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        pages = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for page, payload in pages.items():
        if not isinstance(payload, dict) or not payload.get("ok"):
            continue
        raw_data = payload.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        if page == "homeNet":
            findings.extend(home_net_findings(data, observed_at))
        elif page in {"netCnt", "netMoni", "inetstat", "dsl", "wlan", "wGuest", "mesh"} and data:
            findings.append(
                finding(
                    f"data_lua_{page}",
                    "webui_internal",
                    page,
                    summarize_payload(data),
                    observed_at,
                    "data_lua_pages_json",
                    data,
                    "Firmware-dependent data.lua page parsed as internal Web UI evidence.",
                )
            )
    return findings


def home_net_findings(data: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    nested_data = data.get("data")
    nested_data = nested_data if isinstance(nested_data, dict) else {}
    nested_net = nested_data.get("net")
    nested_net = nested_net if isinstance(nested_net, dict) else {}
    topology = data.get("topology")
    topology = topology if isinstance(topology, dict) else {}
    devices = data.get("devices") or topology.get("devices") or nested_net.get("devices") or []
    if isinstance(devices, dict):
        devices = list(devices.values())
    if nested_net:
        findings.append(
            finding(
                "homenet_summary",
                "webui_homenet_topology",
                "homeNet.net",
                {
                    "active_count": nested_net.get("active_count"),
                    "count": nested_net.get("count"),
                },
                observed_at,
                "data_lua_pages_json",
                nested_net,
                "Home network summary parsed from internal data.lua page.",
            )
        )
    for device in devices if isinstance(devices, list) else []:
        if not isinstance(device, dict):
            continue
        state = device.get("stateinfo") or {}
        connection = device.get("conninfo") or {}
        name = (device.get("nameinfo") or {}).get("name") or device.get("name") or device.get("UID")
        findings.append(
            finding(
                "homenet_device",
                "webui_homenet_topology",
                name,
                {
                    "uid": device.get("UID") or device.get("uid"),
                    "name": name,
                    "mac": device.get("mac"),
                    "active": state.get("active"),
                    "online": state.get("online") if "online" in state else device.get("online"),
                    "realtime": state.get("realtime"),
                    "guest": device.get("guest"),
                    "blocked": device.get("blocked") or device.get("internetBlocked"),
                    "type": device.get("type"),
                    "kind": connection.get("kind"),
                    "speed": connection.get("speed"),
                    "parent": device.get("parent") or device.get("parentuid"),
                    "ipinfo": device.get("ipinfo"),
                },
                observed_at,
                "data_lua_pages_json",
                device,
                "Home network topology device parsed from internal data.lua page.",
            )
        )
    return findings


def query_lua_findings(content: str | None, observed_at: str) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        artifacts = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for name, payload in artifacts.items():
        if not isinstance(payload, dict) or not payload.get("ok"):
            continue
        data = payload.get("data")
        if not data:
            continue
        findings.append(
            finding(
                f"query_lua_{name}",
                "webui_internal_query",
                name,
                summarize_payload(data),
                observed_at,
                "query_lua_artifacts_json",
                data,
                "Firmware-dependent query.lua response retained as parsed internal Web UI evidence.",
            )
        )
    return findings


def parse_webui_typed_artifacts(exports: dict[str, Any], observed_at: str) -> dict[str, list[dict[str, Any]]]:
    """Promote firmware-dependent Web UI artifacts into typed evidence rows."""

    return {
        "wlan_station_state_snapshots": [
            *parse_query_lua_wlan_state(exports.get("query_lua_artifacts_json"), observed_at),
            *parse_data_lua_wlan_state(exports.get("data_lua_pages_json"), observed_at),
        ],
        "dhcp_leases": parse_data_lua_dhcp_leases(exports.get("data_lua_pages_json"), observed_at),
        "aha_device_states": parse_aha_device_states(exports, observed_at),
        "telephony_records": parse_telephony_records(exports, observed_at),
        "security_advisories": parse_query_lua_user_rights(exports.get("query_lua_artifacts_json"), observed_at),
    }


def parse_query_lua_wlan_state(content: Any, observed_at: str) -> list[dict[str, Any]]:
    artifacts = decode_json_object(content)
    rows: list[dict[str, Any]] = []
    for artifact_name in ("wlan_known_devices", "wlan_stations"):
        payload = artifacts.get(artifact_name)
        data = payload.get("data") if isinstance(payload, dict) else payload
        for index, row in enumerate(iter_payload_rows(data)):
            if not isinstance(row, dict):
                continue
            if not first_payload_value(
                row,
                "mac",
                "macAddress",
                "macAddr",
                "bssid",
                "rssi",
                "signalStrength",
                "lastConnected",
                "last_connected",
                "lastSeen",
            ):
                continue
            rows.append(wlan_station_state_row(row, observed_at, f"query_lua_{artifact_name}", index))
    return rows


def parse_data_lua_wlan_state(content: Any, observed_at: str) -> list[dict[str, Any]]:
    pages = decode_json_object(content)
    rows: list[dict[str, Any]] = []
    for page_name in ("wlanSta", "wlan", "wGuest"):
        payload = pages.get(page_name)
        data = payload.get("data") if isinstance(payload, dict) else payload
        for index, row in enumerate(iter_payload_rows(data)):
            if not isinstance(row, dict):
                continue
            if not first_payload_value(
                row,
                "mac",
                "macaddr",
                "macAddress",
                "macAddr",
                "bssid",
                "rssi",
                "quality",
                "connect_state",
                "connectState",
                "if_name",
                "ifName",
            ):
                continue
            rows.append(wlan_station_state_row(row, observed_at, f"data_lua_{page_name}", index))
    return rows


def wlan_station_state_row(row: dict[str, Any], observed_at: str, source: str, index: int) -> dict[str, Any]:
    mac = parse_mac(
        str(
            first_payload_value(
                row,
                "mac",
                "macaddr",
                "mac_address",
                "macAddress",
                "mac_addr",
                "macAddr",
                "sta_mac",
                "staMac",
                "address",
            )
            or ""
        )
    )
    ip = first_payload_value(row, "ip", "ipv4", "ipaddr", "ip_address", "ipAddress", "ip_addr")
    hostname = first_payload_value(row, "hostname", "host", "hostName", "name", "devname", "device_name", "deviceName")
    return {
        "observed_at": observed_at,
        "mac": mac,
        "hostname": hostname,
        "ip": ip,
        "interface": first_payload_value(row, "if_name", "ifName", "iface", "interface", "radio", "ap", "apId"),
        "bssid": parse_mac(str(first_payload_value(row, "bssid", "ap_mac", "apMac", "apBssid") or "")),
        "role_id": first_payload_value(row, "role_id", "role", "station_type"),
        "connect_state": first_payload_value(row, "connect_state", "state", "status"),
        "active": first_payload_value(row, "is_active", "isActive", "active", "online", "connected"),
        "guest": first_payload_value(row, "is_guest", "isGuest", "guest", "guestDevice"),
        "last_seen": unix_timestamp_to_iso(
            first_payload_value(row, "last_seen", "lastSeen", "lastused", "lastUsed", "last_connected", "lastConnected")
        )
        or first_payload_value(row, "last_seen", "lastSeen", "lastused", "lastUsed", "last_connected", "lastConnected"),
        "rssi": first_payload_value(row, "rssi", "rssiDbm", "signal", "signal_strength", "signalStrength"),
        "quality": first_payload_value(row, "quality", "quality_percent", "qualityPercent"),
        "speed": first_payload_value(row, "speed", "txrate", "txRate", "rxrate", "rxRate", "rate", "linkRate"),
        "source": source,
        "record_index": index,
        "raw": row,
        "evidence_note": (
            "WLAN station state parsed from internal FRITZ!Box Web UI data. "
            "Field availability is firmware-dependent."
        ),
    }


def parse_data_lua_dhcp_leases(content: Any, observed_at: str) -> list[dict[str, Any]]:
    pages = decode_json_object(content)
    rows: list[dict[str, Any]] = []
    for page_name in ("netDhcp", "netDev", "homeNet"):
        payload = pages.get(page_name)
        data = payload.get("data") if isinstance(payload, dict) else payload
        for index, row in enumerate(iter_payload_rows(data)):
            if not isinstance(row, dict):
                continue
            ip = first_payload_value(row, "ip", "ipv4", "ipaddr", "ip_address", "ipAddress", "ip_addr")
            mac = parse_mac(
                str(first_payload_value(row, "mac", "macaddr", "mac_address", "macAddress", "macAddr") or "")
            )
            if not ip and not mac:
                continue
            lease_expires = first_payload_value(
                row,
                "lease_expires",
                "leaseExpires",
                "expires",
                "expiresAt",
                "valid_until",
                "validUntil",
                "lease_time",
                "leaseTime",
                "leaseEnd",
            )
            rows.append(
                {
                    "observed_at": observed_at,
                    "hostname": first_payload_value(
                        row, "hostname", "host", "hostName", "name", "devname", "deviceName"
                    ),
                    "mac": mac,
                    "ip": ip,
                    "lease_expires": unix_timestamp_to_iso(lease_expires) or lease_expires,
                    "active": first_payload_value(row, "active", "isActive", "online", "connected"),
                    "source": f"data_lua_{page_name}",
                    "record_index": index,
                    "raw": row,
                    "evidence_note": "DHCP/client lease context parsed from internal FRITZ!Box Web UI data.",
                }
            )
    return rows


def parse_query_lua_user_rights(content: Any, observed_at: str) -> list[dict[str, Any]]:
    artifacts = decode_json_object(content)
    payload = artifacts.get("user_rights")
    data = payload.get("data") if isinstance(payload, dict) else payload
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(iter_payload_rows(data)):
        if not isinstance(row, dict):
            continue
        username = first_payload_value(row, "name", "username", "user")
        rights = {key: value for key, value in row.items() if key not in {"name", "username", "user"}}
        enabled_remote = any(
            truthy(first_payload_value(row, key))
            for key in (
                "frominternet",
                "fromInternet",
                "remote_access",
                "remoteAccess",
                "vpn",
                "vpnAccess",
                "wireguard",
                "admin",
                "box_admin",
                "boxAdmin",
                "box_admin_rights",
            )
        )
        if not username and not rights:
            continue
        rows.append(
            {
                "advisory_id": "webui_user_remote_rights" if enabled_remote else "webui_user_rights",
                "severity": "medium" if enabled_remote else "low",
                "category": "Authentication",
                "title": "FRITZ!Box user rights parsed from Web UI state",
                "subject": str(username or f"user_{index}"),
                "status": "review",
                "recommendation": "Verify each FRITZ!Box user, remote access right, VPN right, and admin permission is expected.",
                "source": "query_lua_user_rights",
                "confidence": "medium",
                "evidence_json": {"observed_at": observed_at, "rights": rights},
                "evidence_level": "inferred",
                "evidence_note": "Security advisory derived from internal query.lua user-rights state.",
            }
        )
    return rows


def parse_aha_device_states(exports: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(parse_aha_xml_devices(exports.get("aha_device_list_xml"))):
        rows.append(aha_device_state_row(row, observed_at, "aha_device_list_xml", index))
    stats = decode_json_object(exports.get("aha_device_stats_json"))
    for index, row in enumerate(iter_payload_rows(stats)):
        if isinstance(row, dict):
            rows.append(aha_device_state_row(row, observed_at, "aha_device_stats_json", index))
    return rows


def parse_aha_xml_devices(content: Any) -> list[dict[str, Any]]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for device in root.findall(".//device"):
        rows.append(
            {
                "device_id": device.get("identifier") or device.get("id"),
                "name": device.findtext("name"),
                "productname": device.get("productname"),
                "manufacturer": device.get("manufacturer"),
                "functionbitmask": device.get("functionbitmask"),
                "state": device.findtext(".//state"),
                "temperature": device.findtext(".//temperature/celsius"),
                "humidity": device.findtext(".//humidity/rel_humidity"),
                "power": device.findtext(".//powermeter/power"),
                "energy": device.findtext(".//powermeter/energy"),
            }
        )
    return rows


def aha_device_state_row(row: dict[str, Any], observed_at: str, source: str, index: int) -> dict[str, Any]:
    return {
        "observed_at": observed_at,
        "device_id": first_payload_value(row, "device_id", "identifier", "ain", "id"),
        "name": first_payload_value(row, "name", "device_name"),
        "productname": first_payload_value(row, "productname", "product", "model"),
        "manufacturer": first_payload_value(row, "manufacturer", "vendor"),
        "functionbitmask": first_payload_value(row, "functionbitmask"),
        "state": first_payload_value(row, "state", "switch_state", "present"),
        "temperature": first_payload_value(row, "temperature", "celsius"),
        "humidity": first_payload_value(row, "humidity", "rel_humidity"),
        "power": first_payload_value(row, "power"),
        "energy": first_payload_value(row, "energy"),
        "source": source,
        "record_index": index,
        "raw": row,
        "evidence_note": "AHA/smart-home device state parsed from FRITZ!Box AHA artifacts.",
    }


def parse_telephony_records(exports: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(parse_call_list_xml(exports.get("call_list_xml"), observed_at))
    rows.extend(parse_phonebooks_xml(exports.get("phonebooks_xml_json"), observed_at))
    return rows


def parse_call_list_xml(content: Any, observed_at: str) -> list[dict[str, Any]]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for index, call in enumerate(root.findall(".//Call")):
        rows.append(
            {
                "observed_at": observed_at,
                "record_type": "call",
                "name": call.findtext("Name"),
                "number": call.findtext("Caller") or call.findtext("Called") or call.findtext("Number"),
                "direction": call.findtext("Type"),
                "timestamp": call.findtext("Date"),
                "duration": call.findtext("Duration"),
                "source": "call_list_xml",
                "record_index": index,
                "evidence_note": "Sensitive telephony call-list metadata parsed from FRITZ!Box telephony artifact.",
            }
        )
    return rows


def parse_phonebooks_xml(content: Any, observed_at: str) -> list[dict[str, Any]]:
    books = decode_json_object(content)
    rows: list[dict[str, Any]] = []
    for name, value in books.items():
        xml_text = value if isinstance(value, str) else value.get("content") if isinstance(value, dict) else ""
        if not isinstance(xml_text, str) or not xml_text.strip():
            continue
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            continue
        for index, contact in enumerate(root.findall(".//contact")):
            display_name = contact.findtext(".//realName") or contact.findtext(".//uniqueid")
            numbers = [number.text for number in contact.findall(".//number") if number.text]
            rows.append(
                {
                    "observed_at": observed_at,
                    "record_type": "phonebook_contact",
                    "name": display_name,
                    "number": ", ".join(numbers),
                    "direction": None,
                    "timestamp": None,
                    "duration": None,
                    "source": "phonebooks_xml_json",
                    "record_index": f"{name}:{index}",
                    "evidence_note": "Sensitive phonebook metadata parsed from FRITZ!Box telephony artifact.",
                }
            )
    return rows


def decode_json_object(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str) or not content.strip():
        return {}
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def iter_payload_rows(value: Any) -> Iterable[Any]:
    if isinstance(value, list):
        yield from value
        return
    if not isinstance(value, dict):
        return
    for key in ("list", "rows", "devices", "stations", "wlan_stations", "wlan_known_devices", "leases", "data"):
        nested = value.get(key)
        if isinstance(nested, list):
            yield from nested
            return
        if isinstance(nested, dict):
            yield from iter_payload_rows(nested)
            return
    for nested in value.values():
        if isinstance(nested, list):
            yield from nested
        elif isinstance(nested, dict):
            yield from iter_payload_rows(nested)


def first_payload_value(row: dict[str, Any], *keys: str) -> Any:
    lowered = {normalize_payload_key(str(key)): value for key, value in row.items()}
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
        value = lowered.get(normalize_payload_key(key))
        if value not in (None, ""):
            return value
    return None


def normalize_payload_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def summarize_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        summary: dict[str, Any] = {"keys": sorted(str(key) for key in value)[:40]}
        for key, item in value.items():
            if isinstance(item, list):
                summary[f"{key}_count"] = len(item)
            elif isinstance(item, dict):
                summary[f"{key}_keys"] = sorted(str(child) for child in item)[:20]
        return summary
    if isinstance(value, list):
        return {"rows": len(value), "sample": value[:3]}
    return {"value": value}


def device_risk_findings(
    known_hosts: list[dict[str, Any]], wifi_records: list[dict[str, Any]], observed_at: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    wifi_macs = {str(row.get("mac") or "").lower() for row in wifi_records if row.get("mac")}
    for host in known_hosts:
        risk_flags = []
        if not host.get("vendor") and host.get("mac"):
            risk_flags.append("unknown_vendor")
        if truthy(host.get("blocked")):
            risk_flags.append("blocked_or_restricted")
        if truthy(host.get("guest")):
            risk_flags.append("guest_network_device")
        if truthy(host.get("allow_pcp_and_upnp")):
            risk_flags.append("upnp_or_pcp_allowed")
        if numeric_positive(host.get("pcp_count")) or numeric_positive(host.get("upnp_count")):
            risk_flags.append("active_port_sharing_rules")
        if host.get("mac") and str(host.get("mac")).lower() in wifi_macs and not host.get("last_connected"):
            risk_flags.append("wifi_seen_without_exact_join_time")
        if not risk_flags:
            continue
        findings.append(
            finding(
                "device_risk",
                "device_risk",
                host.get("hostname") or host.get("mac") or host.get("ip"),
                {
                    "hostname": host.get("hostname"),
                    "mac": host.get("mac"),
                    "ip": host.get("ip"),
                    "interface": host.get("interface"),
                    "first_seen": host.get("first_seen"),
                    "last_connected": host.get("last_connected"),
                    "last_activity": host.get("last_activity"),
                    "risk_flags": risk_flags,
                },
                observed_at,
                "derived_from_parsed_sources",
                host,
                "Risk cue derived from parsed host/WLAN evidence. Treat as triage guidance, not proof of compromise.",
            )
        )
    return findings


def numeric_positive(value: Any) -> bool:
    try:
        return float(str(value).strip()) > 0
    except (TypeError, ValueError):
        return False


def filter_recent(entries: Iterable[FritzLogEntry], hours: int) -> list[FritzLogEntry]:
    cutoff = datetime.now().astimezone() - timedelta(hours=hours)
    return [entry for entry in entries if entry.timestamp is None or entry.timestamp >= cutoff]


def parse_fritz_timestamp(date_part: str, time_part: str) -> datetime | None:
    for fmt in ("%d.%m.%Y %H:%M:%S", "%d.%m.%y %H:%M:%S", "%d.%m.%Y %H:%M", "%d.%m.%y %H:%M"):
        try:
            return datetime.strptime(f"{date_part} {time_part}", fmt).astimezone()
        except ValueError:
            continue
    return None


def index_hosts_by_mac(hosts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for host in hosts:
        mac = str(host.get("NewMACAddress") or "").lower()
        if mac:
            indexed[mac] = host
    return indexed


def parse_mac(message: str) -> str | None:
    match = MAC_RE.search(message)
    return match.group(0).lower() if match else None


def parse_ip(message: str) -> str | None:
    match = IPV4_RE.search(message)
    return match.group(0) if match else None


def parse_hostname(message: str, mac: str | None) -> str | None:
    clean = message
    if mac:
        clean = clean.replace(mac, "")
    for separator in (":", ","):
        if separator in clean:
            candidate = clean.split(separator, 1)[1].strip(" .")
            if candidate and not MAC_RE.fullmatch(candidate):
                return candidate[:120]
    return None


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
