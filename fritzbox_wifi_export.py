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

    hosts = get_hosts(fc)
    hosts_by_mac = index_hosts_by_mac(hosts)
    device_info = get_device_info(fc)
    router_time = get_router_time(fc)
    avm_exports = fetch_avm_exports(fc, args.address, args.port)
    raw_log = avm_exports.get("device_log_text") or get_device_log(fc)
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
    seen_by_host = build_host_seen_index(hosts, event_log, wifi_events)
    known_hosts = [host_to_dict(host, seen_by_host.get(host_identity(host), {})) for host in hosts]
    active_hosts = [host for host in known_hosts if host["active_now"]]
    last_wifi_connection = next((event["timestamp"] for event in wifi_events if event["event"] == "connected"), None)

    return {
        "generated_at": datetime.now().astimezone().isoformat(),
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
            "available_wifi_connections": len(build_available_wifi_connections(wifi_events, mesh_wifi_devices)),
            "known_hosts": len(known_hosts),
            "active_hosts": len(active_hosts),
            "last_wifi_connection": last_wifi_connection,
            "oldest_event": event_log[-1]["timestamp"] if event_log else None,
            "newest_event": event_log[0]["timestamp"] if event_log else None,
        },
        "wifi_events": wifi_events,
        "available_wifi_connections": build_available_wifi_connections(wifi_events, mesh_wifi_devices),
        "mesh_wifi_devices": mesh_wifi_devices,
        "event_log": event_log,
        "known_hosts": sorted(known_hosts, key=lambda item: (not item["active_now"], item["hostname"] or "", item["ip"] or "")),
        "raw_exports": {key: value for key, value in avm_exports.items() if key != "device_log_text"},
        "source_endpoints": {
            "tr064": ["DeviceInfo:GetDeviceLog", "Hosts:GetGenericHostEntry", "DeviceInfo:GetInfo", "Time:GetInfo"],
            "avm_exports": ["device_log_xml", "mesh_list", "host_list_xml", "wlan_device_list_xml"],
        },
        "notes": [
            "This export uses FRITZ!Box TR-064 DeviceInfo:GetDeviceLog and Hosts:GetGenericHostEntry only.",
            "It can only show event-log entries still retained by the router.",
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
        ("wlan_device_list_xml", "WLANConfiguration:1", "X_AVM-DE_GetWLANDeviceListPath", "NewX_AVM-DE_WLANDeviceListPath"),
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

    if "device_log_xml" in exports:
        parsed_log = parse_device_log_xml(exports["device_log_xml"])
        if parsed_log:
            exports["device_log_text"] = parsed_log
    return exports


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


def build_available_wifi_connections(
    wifi_events: list[dict[str, Any]],
    mesh_wifi_devices: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
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
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {host_identity(host): {} for host in hosts}

    for host in hosts:
        identity = host_identity(host)
        host_mac = str(host.get("NewMACAddress") or "").lower()
        host_ip = str(host.get("NewIPAddress") or "")
        host_name = str(host.get("NewHostName") or "").casefold()
        timestamps: list[str] = []
        connected_timestamps: list[str] = []

        for entry in event_log:
            if not entry.get("timestamp"):
                continue
            if log_matches_host(entry, host_mac, host_ip, host_name):
                timestamps.append(str(entry["timestamp"]))

        for event in wifi_events:
            if not event.get("timestamp"):
                continue
            if event_matches_host(event, host_mac, host_ip, host_name):
                timestamps.append(str(event["timestamp"]))
                if event.get("event") == "connected":
                    connected_timestamps.append(str(event["timestamp"]))

        if timestamps:
            sorted_timestamps = sorted(set(timestamps))
            index[identity]["first_seen"] = sorted_timestamps[0]
            index[identity]["last_seen"] = sorted_timestamps[-1]
        else:
            index[identity]["first_seen"] = None
            index[identity]["last_seen"] = None

        index[identity]["last_connected"] = max(connected_timestamps) if connected_timestamps else None

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
    return bool(
        (mac and str(event.get("mac") or "").lower() == mac)
        or (ip and str(event.get("ip") or "") == ip)
        or (hostname and str(event.get("hostname") or "").casefold() == hostname)
    )


def host_to_dict(host: dict[str, Any], seen: dict[str, Any] | None = None) -> dict[str, Any]:
    seen = seen or {}
    return {
        "hostname": host.get("NewHostName") or None,
        "mac": host.get("NewMACAddress") or None,
        "ip": host.get("NewIPAddress") or None,
        "interface": host.get("NewInterfaceType") or None,
        "active_now": truthy(host.get("NewActive")),
        "lease_time_remaining": host.get("NewLeaseTimeRemaining"),
        "first_seen": seen.get("first_seen"),
        "last_seen": seen.get("last_seen"),
        "last_connected": seen.get("last_connected"),
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
