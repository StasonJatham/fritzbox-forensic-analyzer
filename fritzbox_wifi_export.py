#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from getpass import getpass
import json
import os
from pathlib import Path
import re
import sys
import urllib.request
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from fritzbox_log_store import ingest_dataset


LOG_TS_RE = re.compile(
    r"^(?P<date>\d{1,2}\.\d{1,2}\.(?:\d{2}|\d{4}))\s+"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)\s+(?P<message>.*)$"
)
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
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


@dataclass(slots=True)
class FritzLogEntry:
    timestamp: datetime | None
    message: str
    raw: str


def main() -> None:
    load_env_file(Path(".env"))
    parser = argparse.ArgumentParser(
        prog="fritzbox-wifi-export",
        description="Export WiFi connection events from the FRITZ!Box event log.",
    )
    parser.add_argument("--address", default=os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1")
    parser.add_argument("--user", default=os.getenv("FRITZBOX_USER"))
    parser.add_argument("--password", default=os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS"))
    parser.add_argument("--port", type=int, default=int(os.getenv("FRITZBOX_PORT", "49000")))
    parser.add_argument("--tls", action="store_true", default=os.getenv("FRITZBOX_TLS") == "1")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--env-file", type=Path, default=Path(".fritzbox.env"))
    parser.add_argument("--include-disconnects", action="store_true")
    parser.add_argument("--dataset", action="store_true", help="Export full dataset with raw event-log entries and host table.")
    parser.add_argument("--store-db", type=Path, help="Store raw and parsed records in a local SQLite database.")
    args = parser.parse_args()

    load_env_file(args.env_file)
    data = export_dataset(args) if args.dataset else export_wifi_events(args)
    if args.store_db:
        if not isinstance(data, dict):
            data = export_dataset(args)
        ingest_dataset(data, args.store_db)
    write_output(data, args.format, args.output)


def export_wifi_events(args: argparse.Namespace) -> list[dict[str, Any]]:
    return export_dataset(args)["wifi_events"]


def export_dataset(args: argparse.Namespace) -> dict[str, Any]:
    try:
        from fritzconnection import FritzConnection
    except ImportError as exc:
        raise SystemExit("Missing dependency. Install with: python3 -m pip install fritzconnection") from exc

    password = args.password or os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS")
    if password is None:
        try:
            password = getpass("FRITZ!Box password: ")
        except EOFError as exc:
            raise SystemExit(
                "No FRITZ!Box password was provided. Set FRITZBOX_PASSWORD in .fritzbox.env "
                "or run this command in an interactive terminal."
            ) from exc

    fc = FritzConnection(
        address=args.address,
        user=args.user or os.getenv("FRITZBOX_USER"),
        password=password,
        port=args.port,
        use_tls=args.tls,
        use_cache=True,
    )

    generated_at = datetime.now().astimezone().isoformat()
    hosts = get_hosts(fc)
    hosts_by_mac = index_hosts_by_mac(hosts)
    device_info = get_device_info(fc)
    router_time = get_router_time(fc)
    avm_exports = fetch_avm_exports(fc, args.address, args.port)
    raw_log = avm_exports.get("device_log_text") or parse_data_lua_log(avm_exports.get("data_lua_pages_json")) or get_device_log(fc)
    entries = filter_recent(parse_device_log(raw_log), args.hours)
    events = []
    for entry in entries:
        event = parse_wifi_event(entry, hosts_by_mac)
        if event is None:
            continue
        if event["event"] == "disconnected" and not args.include_disconnects:
            continue
        events.append(event)

    event_log = [entry_to_dict(entry) for entry in sorted(entries, key=lambda item: item.timestamp.isoformat() if item.timestamp else "", reverse=True)]
    wifi_events = sorted(events, key=lambda item: item["timestamp"] or "", reverse=True)
    mesh_wifi_devices = parse_mesh_wifi_devices(avm_exports.get("mesh_list"))
    wlan_associations = parse_wlan_device_lists(avm_exports, generated_at)
    landevice_records = parse_landevice_query(avm_exports.get("landevice_query_json"))
    seen_by_host = build_host_seen_index(
        hosts,
        event_log,
        wifi_events,
        mesh_wifi_devices,
        landevice_records,
        generated_at=generated_at,
    )
    known_hosts = [host_to_dict(host, seen_by_host.get(host_identity(host), {})) for host in hosts]
    known_hosts.extend(lan_device_host_rows(landevice_records, known_hosts))
    active_hosts = [host for host in known_hosts if host["active_now"]]
    last_wifi_connection = next((event["timestamp"] for event in wifi_events if event["event"] == "connected"), None)
    available_wifi_connections = build_available_wifi_connections(wifi_events, mesh_wifi_devices, wlan_associations)

    return {
        "generated_at": generated_at,
        "window_hours": args.hours,
        "router": {
            "address": args.address,
            "port": args.port,
            "tls": args.tls,
        },
        "device_info": device_info,
        "router_time": router_time,
        "summary": {
            "event_log_entries": len(event_log),
            "wifi_events": len(wifi_events),
            "available_wifi_connections": len(available_wifi_connections),
            "current_wlan_associations": len(wlan_associations),
            "known_hosts": len(known_hosts),
            "active_hosts": len(active_hosts),
            "last_wifi_connection": last_wifi_connection,
            "oldest_event": event_log[-1]["timestamp"] if event_log else None,
            "newest_event": event_log[0]["timestamp"] if event_log else None,
        },
        "wifi_events": wifi_events,
        "available_wifi_connections": available_wifi_connections,
        "mesh_wifi_devices": mesh_wifi_devices,
        "wlan_associations": wlan_associations,
        "event_log": event_log,
        "known_hosts": sorted(known_hosts, key=lambda item: (not item["active_now"], item["hostname"] or "", item["ip"] or "")),
        "raw_exports": {key: value for key, value in avm_exports.items() if key != "device_log_text"},
        "source_endpoints": {
            "tr064": ["DeviceInfo:GetDeviceLog", "Hosts:GetGenericHostEntry", "DeviceInfo:GetInfo", "Time:GetInfo"],
            "avm_exports": [
                "device_log_xml",
                "mesh_list",
                "host_list_xml",
                "wlan_device_list_xml",
                "landevice_query_json",
                "data_lua_pages_json",
                "tr064_snapshot_json",
            ],
        },
        "notes": [
            "This export uses FRITZ!Box TR-064 DeviceInfo:GetDeviceLog and Hosts:GetGenericHostEntry plus the FRITZ!Box web UI LAN-device query when available.",
            "It can only show event-log entries still retained by the router.",
            "LAN-device firstused/lastused values are router-retained device state, not a complete session log.",
            "Mesh WLAN device rows are current/known-device records, not guaranteed historical association records.",
            "If a separate access point handles WiFi, the FRITZ!Box may only show that access point as an Ethernet host.",
        ],
    }


def get_device_log(fc: Any) -> str:
    try:
        response = fc.call_action("DeviceInfo:1", "GetDeviceLog")
    except Exception as exc:
        raise SystemExit(f"Could not read FRITZ!Box device log via TR-064: {type(exc).__name__}: {exc}") from exc
    return str(response.get("NewDeviceLog") or "")


def get_device_info(fc: Any) -> dict[str, Any]:
    try:
        response = fc.call_action("DeviceInfo:1", "GetInfo")
    except Exception:
        return {}
    return {
        "manufacturer": response.get("NewManufacturerName"),
        "model": response.get("NewModelName") or response.get("NewProductClass"),
        "description": response.get("NewDescription"),
        "firmware": response.get("NewSoftwareVersion"),
        "hardware": response.get("NewHardwareVersion"),
        "serial": response.get("NewSerialNumber"),
    }


def get_router_time(fc: Any) -> dict[str, Any]:
    try:
        response = fc.call_action("Time:1", "GetInfo")
    except Exception:
        return {
            "current_time": None,
            "status": "unavailable",
            "note": "TR-064 Time:GetInfo did not return a router clock value.",
        }
    current_time = response.get("NewCurrentLocalTime") or response.get("NewCurrentTime")
    return {
        "current_time": current_time,
        "status": "reported" if current_time else "not_reported",
        "raw": json.loads(json.dumps(response, default=str)),
    }


def get_hosts(fc: Any) -> list[dict[str, Any]]:
    try:
        count_response = fc.call_action("Hosts:1", "GetHostNumberOfEntries")
        count = int(count_response.get("NewHostNumberOfEntries") or 0)
    except Exception:
        return []

    hosts: list[dict[str, Any]] = []
    for index in range(count):
        try:
            host = fc.call_action("Hosts:1", "GetGenericHostEntry", NewIndex=index)
        except Exception:
            continue
        hosts.append(host)
    return hosts


def fetch_avm_exports(fc: Any, address: str, port: int) -> dict[str, Any]:
    exports: dict[str, Any] = {}
    path_specs = [
        ("device_log_xml", "DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath", "NewDeviceLogPath"),
        ("mesh_list", "Hosts:1", "X_AVM-DE_GetMeshListPath", "NewX_AVM-DE_MeshListPath"),
        ("host_list_xml", "Hosts:1", "X_AVM-DE_GetHostListPath", "NewX_AVM-DE_HostListPath"),
    ]
    for key, service, action, field in path_specs:
        try:
            path = fc.call_action(service, action).get(field)
        except Exception:
            continue
        if not path:
            continue
        content = fetch_avm_path(address, port, str(path))
        if content is not None:
            exports[key] = content

    wlan_device_lists: dict[str, str] = {}
    for index in range(1, 5):
        try:
            path = fc.call_action(f"WLANConfiguration:{index}", "X_AVM-DE_GetWLANDeviceListPath").get("NewX_AVM-DE_WLANDeviceListPath")
        except Exception:
            continue
        if not path:
            continue
        content = fetch_avm_path(address, port, str(path))
        if content is None:
            continue
        key = f"wlan_device_list_xml_{index}"
        exports[key] = content
        wlan_device_lists[str(index)] = content
    if wlan_device_lists:
        exports["wlan_device_list_xml"] = json.dumps(wlan_device_lists, sort_keys=True)

    if "device_log_xml" in exports:
        parsed_log = parse_device_log_xml(exports["device_log_xml"])
        if parsed_log:
            exports["device_log_text"] = parsed_log
    data_lua_pages = fetch_data_lua_pages(fc)
    if data_lua_pages:
        exports["data_lua_pages_json"] = json.dumps(data_lua_pages, sort_keys=True, default=str)
    landevice_query = fetch_landevice_query(fc)
    if landevice_query:
        exports["landevice_query_json"] = landevice_query
    tr064_snapshot = collect_tr064_snapshot(fc)
    if tr064_snapshot:
        exports["tr064_snapshot_json"] = json.dumps(tr064_snapshot, sort_keys=True, default=str)
    return exports


def fetch_data_lua_pages(fc: Any) -> dict[str, Any]:
    pages: dict[str, Any] = {}
    for page in ("homeNet", "log", "netCnt", "netMoni"):
        try:
            response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/data.lua", {"page": page})
        except Exception as exc:
            pages[page] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            continue
        raw = getattr(response, "text", "")
        if not raw:
            pages[page] = {"ok": False, "error": "empty response"}
            continue
        try:
            pages[page] = {"ok": True, "data": json.loads(raw)}
        except json.JSONDecodeError:
            pages[page] = {"ok": True, "raw": raw}
    return pages


def fetch_landevice_query(fc: Any) -> str | None:
    rich_fields = [
        "UID",
        "ip",
        "iplist",
        "mac",
        "maclist",
        "name",
        "friendly_name",
        "neighbour_name",
        "vendorname",
        "modelname",
        "manu_name",
        "parentuid",
        "parentsource",
        "source",
        "flags",
        "modification_flags",
        "interface",
        "wlan_station_type",
        "wlan_UIDs",
        "plc_UIDs",
        "ethernetport",
        "active",
        "online",
        "speed",
        "dhcp",
        "static_dhcp",
        "deleteable",
        "wakeup",
        "auto_wakeup",
        "firstused",
        "lastused",
        "blocked",
        "allow_pcp_and_upnp",
        "igd_fw_cnt_pcp",
        "igd_fw_cnt_upnp",
        "myfritz_enabled",
        "url",
    ]
    fallback_fields = ["UID", "ip", "mac", "name", "friendly_name", "active", "online", "interface", "firstused", "lastused"]
    for fields in (rich_fields, fallback_fields):
        query = f"landevice:settings/landevice/list({','.join(fields)})"
        try:
            response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/query.lua", {"mq_landevices": query})
        except Exception:
            continue
        text = getattr(response, "text", "")
        if text and "landevice" in text:
            return text
    return None


def collect_tr064_snapshot(fc: Any) -> dict[str, Any]:
    actions = [
        ("device_info", "DeviceInfo:1", "GetInfo", {}),
        ("time_info", "Time:1", "GetInfo", {}),
        ("user_interface", "UserInterface:1", "GetInfo", {}),
        ("app_config", "X_AVM-DE_AppSetup:1", "GetConfig", {}),
        ("app_remote_info", "X_AVM-DE_AppSetup:1", "GetAppRemoteInfo", {}),
        ("myfritz_info", "X_AVM-DE_MyFritz:1", "GetInfo", {}),
        ("host_count", "Hosts:1", "GetHostNumberOfEntries", {}),
        ("host_filter_profiles", "X_AVM-DE_HostFilter:1", "GetFilterProfiles", {}),
        ("lan_host_config", "LANHostConfigManagement:1", "GetInfo", {}),
        ("lan_eth_info", "LANEthernetInterfaceConfig:1", "GetInfo", {}),
        ("lan_eth_stats", "LANEthernetInterfaceConfig:1", "GetStatistics", {}),
        ("wan_common_link", "WANCommonIFC:1", "GetCommonLinkProperties", {}),
        ("wan_common_bytes_sent", "WANCommonIFC:1", "GetTotalBytesSent", {}),
        ("wan_common_bytes_received", "WANCommonIFC:1", "GetTotalBytesReceived", {}),
        ("wan_common_packets_sent", "WANCommonIFC:1", "GetTotalPacketsSent", {}),
        ("wan_common_packets_received", "WANCommonIFC:1", "GetTotalPacketsReceived", {}),
        ("wan_common_online_monitor", "WANCommonIFC:1", "X_AVM-DE_GetOnlineMonitor", {}),
        ("wan_ip_info", "WANIPConn:1", "GetInfo", {}),
        ("wan_ip_status", "WANIPConn:1", "GetStatusInfo", {}),
        ("wan_ip_external", "WANIPConn:1", "GetExternalIPAddress", {}),
        ("wan_dsl_interface", "WANDSLInterfaceConfig:1", "GetInfo", {}),
        ("wan_dsl_stats", "WANDSLInterfaceConfig:1", "GetStatisticsTotal", {}),
        ("wan_dsl_link", "WANDSLLinkConfig:1", "GetInfo", {}),
    ]
    snapshot: dict[str, Any] = {"actions": {}, "wlan": []}
    for key, service, action, arguments in actions:
        snapshot["actions"][key] = safe_call_action(fc, service, action, arguments)
    for index in range(1, 5):
        service = f"WLANConfiguration:{index}"
        radio = {
            "index": index,
            "info": safe_call_action(fc, service, "GetInfo", {}),
            "statistics": safe_call_action(fc, service, "GetStatistics", {}),
            "packet_statistics": safe_call_action(fc, service, "GetPacketStatistics", {}),
            "total_associations": safe_call_action(fc, service, "GetTotalAssociations", {}),
            "channel_info": safe_call_action(fc, service, "GetChannelInfo", {}),
            "ext_info": safe_call_action(fc, service, "X_AVM-DE_GetWLANExtInfo", {}),
            "wps_info": safe_call_action(fc, service, "X_AVM-DE_GetWPSInfo", {}),
        }
        if any(value.get("ok") for key, value in radio.items() if isinstance(value, dict)):
            snapshot["wlan"].append(radio)
    return snapshot


def safe_call_action(fc: Any, service: str, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        response = fc.call_action(service, action, arguments=arguments) if arguments else fc.call_action(service, action)
        return {"ok": True, "service": service, "action": action, "response": json.loads(json.dumps(response, default=str))}
    except Exception as exc:
        return {"ok": False, "service": service, "action": action, "error": f"{type(exc).__name__}: {exc}"}


def fetch_avm_path(address: str, port: int, path: str) -> str | None:
    for base in (f"http://{address}:{port}", f"http://{address}"):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


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


def lan_device_host_rows(lan_devices: list[dict[str, Any]], existing_hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
                "last_activity_source": "fritzbox_landevice_lastused" if device.get("last_connected") else "fritzbox_landevice_state",
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
                "derived_time_type": "connection_event" if event.get("event") == "connected" else "disconnect_or_other_event",
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
                activity_candidates.append((timestamp, "retained_log_match", "medium", "Retained router log mentions this host/IP/MAC/name."))

        for event in wifi_events:
            if not event.get("timestamp"):
                continue
            if event_matches_host(event, host_mac, host_ip, host_name):
                timestamp = str(event["timestamp"])
                timestamps.append(timestamp)
                if event.get("event") == "connected":
                    connected_timestamps.append(timestamp)
                    activity_candidates.append((timestamp, "exact_wifi_connection", "high", "Retained WLAN connection log entry matched this host."))
                else:
                    activity_candidates.append((timestamp, "wifi_event", "medium", "Retained WLAN-related log entry matched this host."))

        for device in mesh_wifi_devices:
            if not device.get("last_observed"):
                continue
            if event_matches_host(device, host_mac, host_ip, host_name):
                timestamp = str(device["last_observed"])
                timestamps.append(timestamp)
                activity_candidates.append((timestamp, "mesh_last_observed", "low", "Mesh data observed this WLAN device; this is not an exact association time."))

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


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def write_output(events: list[dict[str, Any]] | dict[str, Any], output_format: str, output: Path | None) -> None:
    if output_format == "json":
        rendered = json.dumps(events, indent=2, sort_keys=True, default=str)
    elif output_format == "csv":
        rows = events["wifi_events"] if isinstance(events, dict) else events
        rendered = render_csv(rows)
    else:
        rows = events["wifi_events"] if isinstance(events, dict) else events
        rendered = render_table(rows)

    if output is None:
        print(rendered)
    else:
        output.write_text(rendered + "\n", encoding="utf-8")


def render_csv(events: list[dict[str, Any]]) -> str:
    import io

    fields = ["timestamp", "event", "hostname", "mac", "ip", "interface", "active_now", "message"]
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for event in events:
        writer.writerow({field: event.get(field) for field in fields})
    return handle.getvalue().rstrip("\n")


def render_table(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No WiFi connection events found in the selected FRITZ!Box event-log window."
    rows = ["timestamp\tevent\thostname\tmac\tip\tactive_now"]
    for event in events:
        rows.append(
            "\t".join(
                str(event.get(field) or "")
                for field in ("timestamp", "event", "hostname", "mac", "ip", "active_now")
            )
        )
    return "\n".join(rows)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(1)
