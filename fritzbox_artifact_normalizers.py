from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")


def json_artifact(content: Any) -> Any:
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None
    if isinstance(content, dict | list):
        return content
    return None


def first_value(row: dict[str, Any], *keys: str) -> Any:
    normalized = {normalize_key(str(key)): value for key, value in row.items()}
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
        value = normalized.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return None


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on", "enabled", "active"}


def parse_mac(value: Any) -> str | None:
    match = MAC_RE.search(str(value or ""))
    return match.group(0).lower() if match else None


def unix_seconds_to_iso(value: Any) -> str | None:
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


def artifact_data(artifacts: dict[str, Any], name: str) -> Any:
    wrapper = artifacts.get(name)
    if not isinstance(wrapper, dict) or wrapper.get("ok") is False:
        return None
    if "data" in wrapper:
        return wrapper.get("data")
    raw = wrapper.get("raw")
    return json_artifact(raw) if isinstance(raw, str) else raw


def row_list(value: Any, preferred_keys: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[int] = set()

    def add_rows(candidate: Any) -> None:
        if isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, dict) and id(item) not in seen:
                    seen.add(id(item))
                    found.append(item)
        elif isinstance(candidate, dict):
            for key in (*preferred_keys, "list", "items", "rows", "devices", "stations", "leases", "users"):
                nested = candidate.get(key)
                if isinstance(nested, list):
                    add_rows(nested)

    def walk(candidate: Any) -> None:
        add_rows(candidate)
        if isinstance(candidate, dict):
            for item in candidate.values():
                if isinstance(item, dict | list):
                    walk(item)
        elif isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, dict | list):
                    walk(item)

    walk(value)
    return found


def extract_query_lua_wlan_associations(content: Any, observed_at: str) -> list[dict[str, Any]]:
    artifacts = json_artifact(content)
    if not isinstance(artifacts, dict):
        return []
    rows: list[dict[str, Any]] = []
    for name in ("wlan_stations", "wlan_known_devices"):
        data = artifact_data(artifacts, name)
        for index, item in enumerate(row_list(data, (name, "station", "known"))):
            mac = parse_mac(first_value(item, "mac", "MAC", "macAddress", "macAddr", "bssid"))
            if not mac:
                continue
            last_connected = first_value(
                item, "last_connected", "lastConnected", "lastused", "lastUsed", "last_seen", "lastSeen"
            )
            rows.append(
                {
                    "observed_at": observed_at,
                    "radio_index": first_value(item, "radio_index", "radio", "ap", "apId"),
                    "association_index": first_value(item, "UID", "uid", "index") or str(index),
                    "mac": mac,
                    "ip": first_value(item, "ip", "ipv4", "ipAddress", "ip_addr"),
                    "hostname": first_value(item, "name", "hostname", "host", "hostName", "deviceName"),
                    "auth_state": first_value(item, "active", "isActive", "connected", "auth_state"),
                    "speed": first_value(item, "speed", "rxrate", "rxRate", "txrate", "txRate", "linkRate"),
                    "signal_strength": first_value(
                        item, "rssi", "rssiDbm", "signal", "signal_strength", "signalStrength"
                    ),
                    "channel": first_value(item, "channel", "current_channel", "currentChannel"),
                    "guest": first_value(item, "guest", "isGuest", "guestDevice"),
                    "ssid": first_value(item, "ssid", "SSID"),
                    "last_connected": unix_seconds_to_iso(last_connected) or last_connected,
                    "source": f"query_lua_{name}",
                    "evidence_note": (
                        "WLAN station/known-device row parsed from FRITZ!Box query.lua; "
                        "observed_at is acquisition time, not an exact association time."
                    ),
                    "raw": item,
                }
            )
    return rows


def extract_data_lua_wlan_associations(content: Any, observed_at: str) -> list[dict[str, Any]]:
    pages = json_artifact(content)
    if not isinstance(pages, dict):
        return []
    payload = pages.get("wlanSta")
    data = payload.get("data") if isinstance(payload, dict) and payload.get("ok") is not False else payload
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(row_list(data, ("wlanSta", "stations", "known", "active"))):
        mac = parse_mac(first_value(item, "mac", "MAC", "macAddress", "macAddr", "bssid"))
        if not mac:
            continue
        rows.append(
            {
                "observed_at": observed_at,
                "radio_index": first_value(item, "radio_index", "radio", "ap", "apId", "apname"),
                "association_index": first_value(item, "UID", "uid", "index") or str(index),
                "mac": mac,
                "ip": first_value(item, "ip", "ipv4", "ipAddress", "ip_addr"),
                "hostname": first_value(item, "name", "hostname", "host", "hostName", "deviceName"),
                "auth_state": first_value(item, "active", "isActive", "connected", "auth_state"),
                "speed": first_value(item, "speed", "rxrate", "rxRate", "txrate", "txRate", "linkRate"),
                "signal_strength": first_value(item, "rssi", "rssiDbm", "signal", "signal_strength", "signalStrength"),
                "channel": first_value(item, "channel", "current_channel", "currentChannel"),
                "guest": first_value(item, "guest", "isGuest", "guestDevice"),
                "ssid": first_value(item, "ssid", "SSID"),
                "source": "data_lua_page_wlanSta",
                "evidence_note": (
                    "WLAN station row parsed from FRITZ!Box data.lua page=wlanSta; "
                    "observed_at is acquisition time, not an exact association time."
                ),
                "raw": item,
            }
        )
    return rows


def extract_data_lua_network_status(content: Any, observed_at: str) -> list[dict[str, Any]]:
    pages = json_artifact(content)
    if not isinstance(pages, dict):
        return []
    rows: list[dict[str, Any]] = []
    for page, area in (("netDhcp", "dhcp"), ("wlanRadar", "wlan_radar")):
        payload = pages.get(page)
        data = payload.get("data") if isinstance(payload, dict) and payload.get("ok") is not False else payload
        if not data:
            continue
        if page == "netDhcp":
            for index, item in enumerate(row_list(data, ("leases", "dhcp", "netDhcp"))[:200]):
                mac = parse_mac(first_value(item, "mac", "MAC", "macAddress", "macAddr"))
                ip = first_value(item, "ip", "ipv4", "IPAddress", "ipAddress", "ip_addr")
                host = first_value(item, "hostname", "name", "host", "hostName", "deviceName")
                if not any((mac, ip, host)):
                    continue
                rows.append(
                    network_row(
                        observed_at,
                        area,
                        f"dhcp_lease:{ip or mac or index}",
                        item,
                        "data_lua_page_netDhcp",
                        "DHCP lease row parsed from FRITZ!Box data.lua page=netDhcp.",
                    )
                )
            continue
        for metric, value in flattened_scalars(data, prefix=page)[:200]:
            rows.append(
                network_row(
                    observed_at,
                    area,
                    metric,
                    value,
                    "data_lua_page_wlanRadar",
                    "WLAN radar/channel value parsed from FRITZ!Box data.lua page=wlanRadar.",
                )
            )
    return rows


def flattened_scalars(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []

    def walk(candidate: Any, path: str) -> None:
        if isinstance(candidate, dict):
            for key, item in candidate.items():
                walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(candidate, list):
            for index, item in enumerate(candidate):
                walk(item, f"{path}[{index}]")
        elif candidate not in (None, ""):
            rows.append((path, candidate))

    walk(value, prefix)
    return rows


def network_row(
    observed_at: str,
    area: str,
    metric: str,
    value: Any,
    source: str,
    note: str,
    confidence: str = "medium",
) -> dict[str, Any]:
    return {
        "observed_at": observed_at,
        "area": area,
        "metric": metric,
        "value": value,
        "source": source,
        "confidence": confidence,
        "evidence_level": "parsed_from_raw",
        "evidence_note": note,
    }


def extract_query_lua_user_right_advisories(content: Any) -> list[dict[str, Any]]:
    artifacts = json_artifact(content)
    if not isinstance(artifacts, dict):
        return []
    data = artifact_data(artifacts, "user_rights")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(row_list(data, ("user_rights", "users"))):
        user = first_value(item, "name", "username", "user") or f"user:{index}"
        if not truthy(first_value(item, "enabled", "active", "is_enabled")):
            continue
        rights = {
            key: first_value(item, key)
            for key in (
                "box_admin",
                "boxAdmin",
                "admin",
                "ftp_access",
                "ftpAccess",
                "vpn_access",
                "vpnAccess",
                "vpn",
                "frominternet",
                "fromInternet",
                "internet_access",
            )
            if first_value(item, key) not in (None, "")
        }
        risky = [normalize_key(key) for key, value in rights.items() if truthy(value)]
        if not risky:
            continue
        severity = "high" if "frominternet" in risky and ("boxadmin" in risky or "admin" in risky) else "medium"
        rows.append(
            {
                "advisory_id": "query_lua_user_remote_rights",
                "severity": severity,
                "category": "User rights",
                "title": "FRITZ!Box user has administrative, VPN, FTP, or internet access rights",
                "subject": str(user),
                "status": "review",
                "recommendation": "Confirm the user and rights are expected; remove unused remote, VPN, FTP, or admin access.",
                "source": "query_lua_user_rights",
                "confidence": "medium",
                "evidence_json": {"user": user, "rights": rights, "raw": item},
                "evidence_level": "inferred",
                "evidence_note": "Security advisory derived from FRITZ!Box query.lua user-rights evidence.",
            }
        )
    return rows


def extract_aha_device_stats(content: Any, observed_at: str) -> list[dict[str, Any]]:
    stats = json_artifact(content)
    if not isinstance(stats, dict):
        return []
    rows: list[dict[str, Any]] = []
    for ain, payload in stats.items():
        if isinstance(payload, str):
            rows.extend(aha_xml_stats(str(ain), payload, observed_at))
        elif isinstance(payload, dict):
            for metric, value in flattened_scalars(payload, prefix=str(ain))[:80]:
                rows.append(
                    network_row(
                        observed_at,
                        "aha",
                        metric,
                        value,
                        "aha_device_stats_json",
                        "AHA/smart-home device statistic parsed from retained getbasicdevicestats output.",
                    )
                )
    return rows


def aha_xml_stats(ain: str, xml_content: str, observed_at: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return [
            network_row(
                observed_at,
                "aha",
                f"{ain}.raw",
                xml_content[:500],
                "aha_device_stats_json",
                "AHA/smart-home device statistic retained as non-XML raw text.",
                "low",
            )
        ]
    rows: list[dict[str, Any]] = []
    for element in root.iter():
        text = (element.text or "").strip()
        if text:
            rows.append(
                network_row(
                    observed_at,
                    "aha",
                    f"{ain}.{strip_namespace(element.tag)}",
                    text,
                    "aha_device_stats_json",
                    "AHA/smart-home device statistic parsed from retained getbasicdevicestats XML.",
                )
            )
        for attr, value in element.attrib.items():
            rows.append(
                network_row(
                    observed_at,
                    "aha",
                    f"{ain}.{strip_namespace(element.tag)}.{attr}",
                    value,
                    "aha_device_stats_json",
                    "AHA/smart-home device statistic attribute parsed from retained getbasicdevicestats XML.",
                )
            )
    return rows[:200]


def extract_telephony_context(call_list_xml: Any, phonebooks_xml_json: Any, observed_at: str) -> list[dict[str, Any]]:
    rows = call_list_rows(call_list_xml, observed_at)
    phonebooks = json_artifact(phonebooks_xml_json)
    if isinstance(phonebooks, dict):
        for phonebook_id, xml_content in phonebooks.items():
            if isinstance(xml_content, str):
                rows.extend(phonebook_rows(str(phonebook_id), xml_content, observed_at))
    return rows


def call_list_rows(content: Any, observed_at: str) -> list[dict[str, Any]]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for index, call in enumerate(root.findall(".//Call")):
        fields = {strip_namespace(child.tag): (child.text or "").strip() for child in list(call)}
        subject = fields.get("Name") or fields.get("Caller") or fields.get("Called") or str(index)
        rows.append(
            network_row(
                observed_at,
                "telephony",
                f"call:{fields.get('Type') or 'unknown'}:{fields.get('Id') or index}",
                fields,
                "call_list_xml",
                "Call-list metadata parsed from retained FRITZ!Box telephony XML.",
            )
            | {"subject": subject}
        )
    return rows


def phonebook_rows(phonebook_id: str, content: str, observed_at: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for index, contact in enumerate(root.findall(".//contact")):
        name = (contact.findtext(".//realName") or "").strip()
        numbers = [
            (number.text or "").strip() for number in contact.findall(".//number") if (number.text or "").strip()
        ]
        if not name and not numbers:
            continue
        rows.append(
            network_row(
                observed_at,
                "telephony",
                f"phonebook_contact:{phonebook_id}:{contact.findtext('uniqueid') or index}",
                {"phonebook_id": phonebook_id, "name": name, "numbers": numbers},
                "phonebooks_xml_json",
                "Phonebook contact metadata parsed from retained FRITZ!Box telephony XML.",
            )
        )
    return rows


def strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
