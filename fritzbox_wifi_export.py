#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from datetime import datetime
from getpass import getpass
import json
import os
from pathlib import Path
import sys
from typing import Any

from fritzbox_collectors import fetch_avm_exports, get_device_info, get_device_log, get_hosts, get_router_time
from fritzbox_log_store import ingest_dataset
from fritzbox_parsers import (
    FritzLogEntry as FritzLogEntry,
    build_available_wifi_connections,
    build_host_seen_index,
    entry_to_dict,
    filter_recent,
    host_identity,
    host_to_dict,
    index_hosts_by_mac,
    lan_device_host_rows,
    parse_data_lua_log,
    parse_device_log,
    parse_landevice_query,
    parse_mesh_wifi_devices,
    parse_wlan_device_lists,
    parse_wifi_event,
)


def main() -> None:
    load_env_file(Path(".env"))
    parser = argparse.ArgumentParser(
        prog="fritzbox-wifi-export",
        description="Export WiFi connection events from the FRITZ!Box event log.",
    )
    parser.add_argument(
        "--address", default=os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1"
    )
    parser.add_argument("--user", default=os.getenv("FRITZBOX_USER"))
    parser.add_argument("--password", default=os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS"))
    parser.add_argument("--port", type=int, default=int(os.getenv("FRITZBOX_PORT", "49000")))
    parser.add_argument("--tls", action="store_true", default=os.getenv("FRITZBOX_TLS") == "1")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--env-file", type=Path, default=Path(".fritzbox.env"))
    parser.add_argument("--include-disconnects", action="store_true")
    parser.add_argument(
        "--dataset", action="store_true", help="Export full dataset with raw event-log entries and host table."
    )
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
    raw_log = (
        avm_exports.get("device_log_text")
        or parse_data_lua_log(avm_exports.get("data_lua_pages_json"))
        or get_device_log(fc)
    )
    entries = filter_recent(parse_device_log(raw_log), args.hours)
    events = []
    for entry in entries:
        event = parse_wifi_event(entry, hosts_by_mac)
        if event is None:
            continue
        if event["event"] == "disconnected" and not args.include_disconnects:
            continue
        events.append(event)

    event_log = [
        entry_to_dict(entry)
        for entry in sorted(
            entries, key=lambda item: item.timestamp.isoformat() if item.timestamp else "", reverse=True
        )
    ]
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
        "known_hosts": sorted(
            known_hosts, key=lambda item: (not item["active_now"], item["hostname"] or "", item["ip"] or "")
        ),
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
                str(event.get(field) or "") for field in ("timestamp", "event", "hostname", "mac", "ip", "active_now")
            )
        )
    return "\n".join(rows)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(1)
