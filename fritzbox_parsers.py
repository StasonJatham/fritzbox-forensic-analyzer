from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ET

LOG_TS_RE = re.compile(
    r"^(?P<date>\d{1,2}\.\d{1,2}\.(?:\d{2}|\d{4}))\s+"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)\s+(?P<message>.*)$"
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
)
CONNECTED_KEYWORDS = (
    "angemeldet",
    "verbunden",
    "connected",
    "registered",
    "anmeldung",
)
DISCONNECTED_KEYWORDS = (
    "abgemeldet",
    "getrennt",
    "disconnected",
    "unregistered",
    "abmeldung",
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
                    "channel_width": (iface.get("current_channel_info") or {}).get("channel_width"),
                    "phymodes": iface.get("phymodes") or [],
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
    rows = data.get("mq_landevices") or data.get("landevice") or data.get("devices") or []
    if isinstance(rows, dict):
        rows = rows.get("list") or rows.get("devices") or []
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
                "allow_pcp_and_upnp": row.get("allow_pcp_and_upnp") or None,
                "pcp_count": row.get("igd_fw_cnt_pcp") or None,
                "upnp_count": row.get("igd_fw_cnt_upnp") or None,
                "myfritz_enabled": row.get("myfritz_enabled") or None,
                "active_now": truthy(row.get("active")) or truthy(row.get("online")),
                "online": truthy(row.get("online")),
                "first_seen": unix_timestamp_to_iso(row.get("firstused")),
                "last_connected": unix_timestamp_to_iso(row.get("lastused")),
                "last_seen": unix_timestamp_to_iso(row.get("lastused")),
                "source": "webui_landevice_query",
            }
        )
    return records


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
                "allow_pcp_and_upnp": device.get("allow_pcp_and_upnp"),
                "pcp_count": device.get("pcp_count"),
                "upnp_count": device.get("upnp_count"),
                "myfritz_enabled": device.get("myfritz_enabled"),
                "first_seen": device.get("first_seen"),
                "last_seen": device.get("last_seen"),
                "last_connected": device.get("last_connected"),
                "last_activity": device.get("last_connected") or device.get("last_seen") or device.get("first_seen"),
                "last_activity_source": "fritzbox_landevice_lastused"
                if device.get("last_connected")
                else "fritzbox_landevice_state",
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
        records.append(
            {
                "timestamp": event.get("timestamp"),
                "derived_connected_at": event.get("timestamp") if event.get("event") == "connected" else None,
                "derived_time_type": "connection_event"
                if event.get("event") == "connected"
                else "disconnect_or_other_event",
                "derived_time_confidence": "high" if event.get("event") == "connected" else "medium",
                "exact_connection_time_available": event.get("event") == "connected",
                "event": event.get("event"),
                "hostname": event.get("hostname"),
                "mac": event.get("mac"),
                "ip": event.get("ip"),
                "last_connected": event.get("timestamp") if event.get("event") == "connected" else None,
                "source": "device_log",
                "confidence": "connection_event",
                "message": event.get("message"),
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
                "message": f"Known WLAN device on channel {device.get('current_channel') or ''}".strip(),
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


def parse_device_log(raw_log: str) -> list[FritzLogEntry]:
    entries: list[FritzLogEntry] = []
    for raw_line in raw_log.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = LOG_TS_RE.match(line)
        if match is None:
            entries.append(FritzLogEntry(timestamp=None, message=line, raw=line))
            continue
        entries.append(
            FritzLogEntry(
                timestamp=parse_fritz_timestamp(match.group("date"), match.group("time")),
                message=match.group("message").strip(),
                raw=line,
            )
        )
    return entries


def parse_wifi_event(entry: FritzLogEntry, hosts_by_mac: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    message = entry.message.casefold()
    if not any(keyword in message for keyword in WIFI_EVENT_KEYWORDS):
        return None

    event_type = "connected" if any(keyword in message for keyword in CONNECTED_KEYWORDS) else None
    if event_type is None and any(keyword in message for keyword in DISCONNECTED_KEYWORDS):
        event_type = "disconnected"
    if event_type is None:
        return None

    mac = parse_mac(entry.message)
    host = hosts_by_mac.get(mac or "", {})
    hostname = parse_hostname(entry.message, mac) or host.get("NewHostName")
    ip = parse_ip(entry.message) or host.get("NewIPAddress")

    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "event": event_type,
        "hostname": hostname or None,
        "mac": mac,
        "ip": ip or None,
        "interface": host.get("NewInterfaceType"),
        "active_now": truthy(host.get("NewActive")) if host else None,
        "message": entry.message,
    }


def entry_to_dict(entry: FritzLogEntry) -> dict[str, Any]:
    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "message": entry.message,
        "category": classify_log_entry(entry.message),
        "mac": parse_mac(entry.message),
        "ip": parse_ip(entry.message),
    }


def classify_log_entry(message: str) -> str:
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
                if event.get("event") == "connected":
                    connected_timestamps.append(timestamp)
                    activity_candidates.append(
                        (
                            timestamp,
                            "exact_wifi_connection",
                            "high",
                            "Retained WLAN connection log entry matched this host.",
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
        "friendly_name": seen.get("friendly_name"),
        "neighbour_name": seen.get("neighbour_name"),
        "ip_list": seen.get("ip_list"),
        "mac_list": seen.get("mac_list"),
        "wlan_station_type": seen.get("wlan_station_type"),
        "wlan_uids": seen.get("wlan_uids"),
        "plc_uids": seen.get("plc_uids"),
        "ethernet_port": seen.get("ethernet_port"),
        "vendor": seen.get("vendor"),
        "model": seen.get("model"),
        "speed": seen.get("speed"),
        "source_flags": seen.get("source_flags"),
        "parent_uid": seen.get("parent_uid"),
        "flags": seen.get("flags"),
        "modification_flags": seen.get("modification_flags"),
        "dhcp": seen.get("dhcp"),
        "static_dhcp": seen.get("static_dhcp"),
        "blocked": seen.get("blocked"),
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
