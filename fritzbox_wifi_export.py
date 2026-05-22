#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.request import urlopen
from xml.etree import ElementTree as ET

from fritzbox_log_store import ingest_dataset
from fritzbox_logging import get_logger
from fritzbox_parsers import (
    FritzLogEntry as FritzLogEntry,
)
from fritzbox_parsers import (
    build_available_wifi_connections,
    build_forensic_findings,
    build_host_seen_index,
    entry_to_dict,
    filter_recent,
    host_identity,
    host_to_dict,
    index_hosts_by_mac,
    lan_device_host_rows,
    parse_data_lua_log,
    parse_device_log,
    parse_device_log_xml,
    parse_landevice_query,
    parse_mesh_wifi_devices,
    parse_support_data,
    parse_support_wifi_observations,
    parse_support_wlan_environment,
    parse_wifi_event,
    parse_wlan_device_lists,
)
from fritzbox_raw_acquisition import (
    acquire_critical_bundle,
    acquire_hard_timeout_bundle,
    acquire_raw_bundle,
    load_raw_bundle,
)

logger = get_logger("wifi_export")


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
    parser.add_argument("--password", default=os.getenv("FRITZBOX_ADMIN_PASS") or os.getenv("FRITZBOX_PASSWORD"))
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
    parser.add_argument(
        "--critical",
        action="store_true",
        help="Collect only high-value forensic artifacts first: support data, LAN-device history, WLAN/log pages.",
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
    logger.info(
        "dataset export started address=%s port=%s tls=%s hours=%s include_disconnects=%s",
        args.address,
        args.port,
        args.tls,
        args.hours,
        args.include_disconnects,
    )
    password = args.password or os.getenv("FRITZBOX_ADMIN_PASS") or os.getenv("FRITZBOX_PASSWORD")
    if password is None:
        try:
            password = getpass("FRITZ!Box password: ")
        except EOFError as exc:
            raise SystemExit(
                "No FRITZ!Box password was provided. Set FRITZBOX_PASSWORD in .fritzbox.env "
                "or run this command in an interactive terminal."
            ) from exc

    if getattr(args, "critical", False) or os.getenv("FRITZBOX_CRITICAL_ACQUISITION") == "1":
        acquire = acquire_critical_bundle
    elif os.getenv("FRITZBOX_DISABLE_HARD_TIMEOUT_ACQUISITION"):
        acquire = acquire_raw_bundle
    else:
        acquire = acquire_hard_timeout_bundle
    user = args.user or os.getenv("FRITZBOX_USER") or detect_fritzbox_user(args.address, args.tls)
    if user and not args.user:
        logger.info("detected FRITZ!Box web user for acquisition")

    raw_result = acquire(
        SimpleNamespace(
            address=args.address,
            user=user,
            password=password,
            port=args.port,
            tls=args.tls,
        ),
        progress_callback=getattr(args, "progress_callback", None),
    )
    raw_exports = load_raw_bundle(raw_result.directory)
    dataset = build_dataset_from_raw_exports(args, raw_exports, raw_result.generated_at, raw_result.directory)
    logger.info(
        "dataset export parsed raw_dir=%s raw_artifacts=%s event_log=%s wifi_events=%s hosts=%s",
        raw_result.directory,
        len(raw_exports),
        dataset["summary"]["event_log_entries"],
        dataset["summary"]["wifi_events"],
        dataset["summary"]["known_hosts"],
    )
    return dataset


def detect_fritzbox_user(address: str, use_tls: bool, timeout: int = 5) -> str | None:
    """Return the default Web UI username advertised by login_sid.lua."""

    scheme = "https" if use_tls else "http"
    host = address.removeprefix("http://").removeprefix("https://").rstrip("/")
    url = f"{scheme}://{host}/login_sid.lua?version=2"
    try:
        with urlopen(url, timeout=timeout) as response:
            payload = response.read(64 * 1024)
    except Exception as exc:
        logger.debug("FRITZ!Box user auto-detection failed: %s", exc)
        return None
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        logger.debug("FRITZ!Box user auto-detection returned invalid XML: %s", exc)
        return None
    users = root.find("Users")
    if users is None:
        return None
    preferred = users.find("./User[@last='1']")
    node = preferred if preferred is not None else users.find("User")
    if node is None or not node.text:
        return None
    return node.text.strip() or None


def build_dataset_from_raw_exports(
    args: argparse.Namespace,
    raw_exports: dict[str, str],
    generated_at: str | None = None,
    raw_directory: Path | None = None,
) -> dict[str, Any]:
    logger.debug("building dataset from raw exports count=%s raw_directory=%s", len(raw_exports), raw_directory)
    generated_at = generated_at or datetime.now().astimezone().isoformat()
    hosts = load_json_artifact(raw_exports, "hosts_tr064_generic_json", [])
    hosts_by_mac = index_hosts_by_mac(hosts)
    device_info = load_json_artifact(raw_exports, "device_info_json", {})
    router_time = load_json_artifact(raw_exports, "router_time_json", {})
    avm_exports = dict(raw_exports)
    raw_logs = [
        (source, value)
        for source, value in (
            ("device_log_text", avm_exports.get("device_log_text")),
            ("device_log_xml", parse_device_log_xml(avm_exports.get("device_log_xml") or "")),
            ("device_log_xml_wlan", parse_device_log_xml(avm_exports.get("device_log_xml_wlan") or "")),
            ("data_lua_pages_json", parse_data_lua_log(avm_exports.get("data_lua_pages_json"))),
        )
        if value
    ]
    support_raw = avm_exports.get("support_data_txt") or ""
    support_log = parse_device_log(support_raw, "support_data_txt")
    raw_entries = [entry for source, raw_log in raw_logs for entry in parse_device_log(raw_log, source)]
    entries = filter_recent(deduplicate_log_entries([*raw_entries, *support_log]), args.hours)
    events = []
    for entry in entries:
        event = parse_wifi_event(entry, hosts_by_mac)
        if event is None:
            continue
        if event["event"] == "disconnected" and not args.include_disconnects:
            continue
        events.append(event)
    events = deduplicate_wifi_events(
        [*events, *filter_recent_wifi_events(parse_support_wifi_observations(support_raw, generated_at), args.hours)]
    )

    event_log = [
        entry_to_dict(entry)
        for entry in sorted(
            entries, key=lambda item: item.timestamp.isoformat() if item.timestamp else "", reverse=True
        )
    ]
    wifi_events = sorted(events, key=lambda item: item["timestamp"] or "", reverse=True)
    mesh_wifi_devices = parse_mesh_wifi_devices(avm_exports.get("mesh_list"))
    wlan_associations = parse_wlan_device_lists(avm_exports, generated_at)
    landevice_records = parse_landevice_query(avm_exports.get("landevice_query_json")) or parse_landevice_query(
        avm_exports.get("query_lua_artifacts_json")
    )
    support_findings = parse_support_data(avm_exports.get("support_data_txt"), generated_at)
    wlan_environment_hints, wlan_status_snapshots = parse_support_wlan_environment(
        avm_exports.get("support_data_txt"), generated_at
    )
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
    support_findings.extend(build_forensic_findings(avm_exports, known_hosts, available_wifi_connections, generated_at))

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
            "support_findings": len(support_findings),
            "known_hosts": len(known_hosts),
            "active_hosts": len(active_hosts),
            "last_wifi_connection": last_wifi_connection,
            "oldest_event": event_log[-1]["timestamp"] if event_log else None,
            "newest_event": event_log[0]["timestamp"] if event_log else None,
            "raw_acquisition_dir": str(raw_directory) if raw_directory else None,
        },
        "wifi_events": wifi_events,
        "available_wifi_connections": available_wifi_connections,
        "mesh_wifi_devices": mesh_wifi_devices,
        "wlan_associations": wlan_associations,
        "advertisement_hints": wlan_environment_hints,
        "network_status_snapshots": wlan_status_snapshots,
        "event_log": event_log,
        "support_findings": support_findings,
        "known_hosts": sorted(
            known_hosts, key=lambda item: (not item["active_now"], item["hostname"] or "", item["ip"] or "")
        ),
        "raw_exports": {key: value for key, value in avm_exports.items() if key != "device_log_text"},
        "source_endpoints": {
            "tr064": ["DeviceInfo:GetDeviceLog", "Hosts:GetGenericHostEntry", "DeviceInfo:GetInfo", "Time:GetInfo"],
            "avm_exports": [
                "device_log_xml",
                "device_log_xml_wlan",
                "mesh_list",
                "host_list_xml",
                "wlan_device_list_xml",
                "landevice_query_json",
                "query_lua_artifacts_json",
                "data_lua_pages_json",
                "tr064_snapshot_json",
                "call_list_xml",
                "phonebooks_xml_json",
                "aha_device_list_xml",
                "aha_switch_list_txt",
                "aha_device_stats_json",
                "config_export_file",
                "support_data_txt",
            ],
        },
        "notes": [
            "This export uses FRITZ!Box TR-064, AVM export paths, internal Web UI endpoints, support data, telephony artifacts, AHA smart-home endpoints, and the encrypted configuration export when available.",
            "It can only show event-log entries still retained by the router.",
            "LAN-device firstused/lastused values are router-retained device state, not a complete session log.",
            "Mesh WLAN device rows are current/known-device records, not guaranteed historical association records.",
            "Unofficial data.lua/query.lua artifacts are firmware-dependent and labeled as internal Web UI evidence.",
            "Support-data exports are high-sensitivity diagnostic artifacts and may contain settings, identifiers, logs, and service state.",
            "Configuration exports are high-sensitivity encrypted artifacts and may still reveal metadata in headers.",
            "If a separate access point handles WiFi, the FRITZ!Box may only show that access point as an Ethernet host.",
            "Acquisition writes raw artifacts to disk before parsing; failed endpoints are retained in acquisition_manifest_json instead of aborting the run.",
        ],
    }


def load_json_artifact(raw_exports: dict[str, str], name: str, default: Any) -> Any:
    try:
        value = json.loads(raw_exports.get(name) or "")
    except json.JSONDecodeError:
        return default
    return value if value is not None else default


def deduplicate_log_entries(entries: list[FritzLogEntry]) -> list[FritzLogEntry]:
    seen: set[tuple[str, str]] = set()
    unique: list[FritzLogEntry] = []
    for entry in entries:
        key = (entry.timestamp.isoformat() if entry.timestamp else "", entry.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def filter_recent_wifi_events(events: list[dict[str, Any]], hours: int) -> list[dict[str, Any]]:
    if hours <= 0:
        return events
    cutoff = datetime.now().astimezone().timestamp() - hours * 3600
    filtered: list[dict[str, Any]] = []
    for event in events:
        timestamp = event.get("timestamp")
        if not timestamp:
            continue
        try:
            parsed = datetime.fromisoformat(str(timestamp))
        except ValueError:
            continue
        if parsed.timestamp() >= cutoff:
            filtered.append(event)
    return filtered


def deduplicate_wifi_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        key = (
            str(event.get("timestamp") or ""),
            str(event.get("event") or ""),
            str(event.get("mac") or "").lower(),
            str(event.get("source") or ""),
            str(event.get("message") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    return unique


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
