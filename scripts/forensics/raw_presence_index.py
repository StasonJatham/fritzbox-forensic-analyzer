#!/usr/bin/env python3
"""Build a raw-artifact source index and device-presence extraction.

This script intentionally reads raw FRITZ!Box artifacts directly. It does not
depend on the SQLite ingestion layer because this investigation is about parser
gaps and retained forensic hints in the raw support data.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAC_RE = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"
DEFAULT_TZ = timezone(timedelta(hours=2))


@dataclass
class SourceIndexEntry:
    source_id: str
    path: str
    section: str
    line_start: int | None
    line_end: int | None
    evidence_class: str
    timestamp_semantics: str
    identity_fields: list[str]
    patterns: list[str]
    notes: str


@dataclass
class PresenceEvent:
    observed_at: str
    date: str
    evidence_class: str
    device: str
    mac: str
    ip: str
    source_id: str
    source_path: str
    line: int | None
    details: str


def normalize_mac(value: str | None) -> str:
    return (value or "").upper()


def parse_iso_local(value: str) -> datetime:
    return datetime.fromisoformat(value)


def in_window(value: datetime, start: datetime, end: datetime) -> bool:
    return start <= value < end


def read_lines(path: Path) -> list[str]:
    return path.read_text(errors="replace").splitlines()


def find_section(lines: list[str], marker: str) -> tuple[int | None, int | None]:
    start = None
    for idx, line in enumerate(lines, 1):
        if marker in line:
            start = idx
            break
    if start is None:
        return None, None
    end = len(lines)
    for idx in range(start, len(lines)):
        if idx > start and lines[idx - 1].startswith("##### END SECTION"):
            end = idx
            break
    return start, end


def support_now(lines: list[str], raw_dir: Path) -> datetime:
    for line in lines[:20]:
        match = re.search(
            r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
            r"(\d+) (\d\d):(\d\d):(\d\d) CEST (\d{4})",
            line,
        )
        if match:
            _, month, day, hour, minute, second, year = match.groups()
            parsed = datetime.strptime(
                f"{month} {day} {year} {hour}:{minute}:{second}",
                "%b %d %Y %H:%M:%S",
            )
            return parsed.replace(tzinfo=DEFAULT_TZ)
    metadata_path = raw_dir / "00_metadata.json"
    return parse_iso_local(json.loads(metadata_path.read_text())["generated_at"])


def support_uptime_seconds(lines: list[str]) -> int | None:
    for line in lines:
        match = re.search(r"\buptime\s*=\s*(\d+)\b", line)
        if match:
            return int(match.group(1))
    return None


def parse_duration_seconds(value: str) -> int | None:
    total = 0
    day_match = re.search(r"(\d+)\s+days?", value)
    if day_match:
        total += int(day_match.group(1)) * 86400
    hour_match = re.search(r"(\d{1,2}):(\d{2}):(\d{2})\s+hours?", value)
    if hour_match:
        hours, minutes, seconds = (int(part) for part in hour_match.groups())
        return total + hours * 3600 + minutes * 60 + seconds
    minute_match = re.search(r"(\d{1,2}):(\d{2})\s+minutes?", value)
    if minute_match:
        minutes, seconds = (int(part) for part in minute_match.groups())
        return total + minutes * 60 + seconds
    second_match = re.search(r"(\d+)\s+seconds?", value)
    if second_match:
        return total + int(second_match.group(1))
    return total or None


def build_host_maps(raw_dir: Path) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    by_mac: dict[str, dict[str, str]] = {}
    by_ip: dict[str, dict[str, str]] = {}
    files = [
        "query_lua_landevice_all.json",
        "landevice_query_json.json",
        "query_lua_landevice_topology.json",
        "hosts_tr064_generic_json.json",
        "data_lua_page_homeNet.json",
        "data_lua_page_netDev.json",
    ]

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            mac = item.get("mac") or item.get("NewMACAddress") or item.get("MACAddress") or item.get("mac_address")
            ip = item.get("ip") or item.get("NewIPAddress") or item.get("IPAddress")
            name = item.get("name") or item.get("hostname") or item.get("NewHostName") or item.get("HostName")
            if isinstance(mac, str) and re.fullmatch(MAC_RE, mac, re.IGNORECASE):
                entry = by_mac.setdefault(normalize_mac(mac), {})
                for key, value in {
                    "name": name,
                    "ip": ip,
                    "interface": item.get("interface") or item.get("NewInterfaceType"),
                    "port": item.get("ethernetport"),
                    "vendor": item.get("vendorname"),
                    "model": item.get("modelname"),
                }.items():
                    if value and not entry.get(key):
                        entry[key] = str(value)
            if ip and name:
                entry = by_ip.setdefault(str(ip), {})
                entry.setdefault("name", str(name))
                if isinstance(mac, str):
                    entry.setdefault("mac", normalize_mac(mac))
            for value in item.values():
                visit(value)
        elif isinstance(item, list):
            for value in item:
                visit(value)

    for filename in files:
        path = raw_dir / filename
        if not path.exists():
            continue
        try:
            visit(json.loads(path.read_text(errors="replace")))
        except json.JSONDecodeError:
            continue
    return by_mac, by_ip


def build_source_index(raw_dir: Path, lines: list[str]) -> list[SourceIndexEntry]:
    support = raw_dir / "support_data_txt.txt"
    section_specs = [
        (
            "support_events",
            "##### BEGIN SECTION Events",
            "exact_router_log",
            "absolute local dd.mm.yy timestamps",
            ["timestamp", "device_name", "mac", "message"],
            [r"Netzwerkgerät Name: ..., MAC: ... verbunden"],
            "Retained FRITZ!Box event log; strongest source for router-recognized connection events.",
        ),
        (
            "support_dhcpd",
            "##### BEGIN SECTION dhcpd",
            "dhcp_lease",
            "lease-derived from remaining seconds and support capture time",
            ["mac", "ip", "hostname", "lease_remaining"],
            [r"lease <mac> <ip> <remaining> \"<hostname>\""],
            "DHCP lease starts are useful; lease-overlap alone is weak and separated in output.",
        ),
        (
            "support_wlan_events",
            "##### BEGIN SECTION WLAN_EVENTS",
            "wlan_radio_event",
            "absolute compact local YYYYMMDD-HHMMSS when present",
            ["timestamp", "iface", "mac", "event_id", "band", "rate", "channel"],
            [r"YYYYMMDD-HHMMSS / iface / mac / id / band / rate"],
            "May contain AP-side client events; zero MAC rows are aggregate/radio events.",
        ),
        (
            "support_wps",
            "##### BEGIN SECTION WPS",
            "wps_or_wifi_button_event",
            "snapshot counters and possible absolute log correlation",
            ["wps counters", "activation counters"],
            [r"cnt_activate", r"WPS"],
            "WPS can indicate nearby join attempts if dated entries exist; this bundle exposes counters only.",
        ),
        (
            "support_role_state_history",
            "##### BEGIN SECTION ROLE_STATE_HISTORY",
            "radio_role_state",
            "uptime or snapshot role-state timeline",
            ["role", "ath interface", "state", "channel"],
            [r"ath0", r"ath1", r"role"],
            "Radio role/channel context; not a client identity source unless MACs appear.",
        ),
        (
            "support_csi_socket",
            "##### BEGIN SECTION CSI_SOCKET",
            "wlan_csi_socket_state",
            "snapshot counters",
            ["connect_state", "async status"],
            [r"CSI", r"connect_state"],
            "CSI is the internal channel for station/radio telemetry; included to show it was checked.",
        ),
        (
            "support_station_list",
            "##### BEGIN SECTION STATION_LIST",
            "wlan_station_history",
            "absolute compact local timestamps plus uptime-derived last_seen",
            ["mac", "ath", "connect_time", "disconnect_time", "reason", "quality", "last_seen"],
            [r"mac = <mac>", r"<role> / athX / YYYYMMDD-HHMMSS"],
            "Best raw source for near/probing/attempted WiFi station evidence.",
        ),
        (
            "support_neighbours",
            "##### BEGIN SECTION neighbours",
            "neighbor_cache",
            "age-derived from support capture time",
            ["mac", "ip", "name", "interface", "port", "age"],
            [r"[<mac>] ... <age>", r"<ip> <age> ... <mac>"],
            "Presence/cache evidence; useful correlation for last observed LAN/IP activity.",
        ),
        (
            "support_neigh_tracking",
            "##### BEGIN SECTION neigh_tracking",
            "neighbor_tracking",
            "snapshot/age-derived if ages present",
            ["mac", "ip", "interface", "state"],
            [r"<mac>", r"<ip>"],
            "Secondary neighbor tracker; mostly snapshot context in this bundle.",
        ),
        (
            "support_bridge_fdb",
            "##### BEGIN SECTION Ethernet bridge fdb",
            "bridge_fdb_snapshot",
            "snapshot at support capture time",
            ["mac", "bridge_interface"],
            [r"<mac> dev <interface>"],
            "Low-confidence current/snapshot layer-2 evidence; not target-date proof by itself.",
        ),
        (
            "support_mesh_daemon",
            "##### BEGIN SECTION MESH daemon",
            "mesh_topology_or_wlan_service",
            "mixed absolute, uptime, and snapshot fields",
            ["timestamp", "mac", "node", "interface", "last_connected"],
            [r"Local STA interface <mac>", r"last_connected"],
            "Can expose WLAN service client-state lines and topology links.",
        ),
        (
            "support_landevices",
            "##### BEGIN SECTION landevices",
            "host_inventory_history",
            "Unix epoch lastused/firstused and snapshot fields",
            ["uid", "name", "mac", "ip", "interface", "ethernetport", "lastused"],
            [r"ip=", r"mac=", r"name=", r"lastused="],
            "Rich host table, including FRITZ!Box UI last-used values.",
        ),
        (
            "support_upnp_av",
            "##### BEGIN SECTION upnp_av",
            "upnp_media_discovery",
            "absolute local YYYY-MM-DD timestamps",
            ["timestamp", "ip", "device_name", "user_agent"],
            [r"upnp_device_new <ip> ... (name=...)"],
            "Discovery/advertisement evidence for UPnP media devices.",
        ),
        (
            "support_multicast",
            "##### BEGIN SECTION multicast",
            "multicast_ssdp_snapshot",
            "snapshot at support capture time",
            ["ip", "multicast_group", "interface"],
            [r"239.255.255.250", r"IGMP"],
            "Can hint at discovery traffic but dated target-window evidence is usually absent.",
        ),
        (
            "support_pcp",
            "##### BEGIN SECTION PCP",
            "pcp_upnp_mapping",
            "snapshot or embedded timestamps if present",
            ["internal_ip", "port", "protocol", "mapping_description"],
            [r"PCP", r"UPnP", r"192.168."],
            "Port-mapping/advertisement-adjacent evidence; mostly capture-time in this bundle.",
        ),
        (
            "support_wlan_scan_results",
            "##### BEGIN SECTION WLAN_SCAN_RESULTS",
            "nearby_ap_scan",
            "snapshot/uptime timestamp from scan result",
            ["bssid", "ssid", "channel", "rssi"],
            [r"BSSID", r"SSID", r"RSSI"],
            "Nearby APs, not client devices; useful location RF context only.",
        ),
        (
            "support_dmesg",
            "##### BEGIN SECTION dmesg",
            "kernel_wlan_driver_log",
            "uptime-derived kernel timestamps",
            ["uptime", "ath interface", "driver message", "mac if present"],
            [r"AVM/WLAN", r"MLME", r"disassocing/deauth all stations", r"wlan_scan_start"],
            "Kernel/driver radio log. In this bundle it has scan/deauth-all messages but no May 15/16 client MAC identity.",
        ),
        (
            "support_debug_kernel",
            "##### BEGIN SECTION debug Kernel output",
            "kernel_debug_log",
            "uptime-derived kernel timestamps",
            ["uptime", "interface", "driver message", "mac if present"],
            [r"WLAN", r"ath", r"MLME", r"probe", r"assoc", r"deauth"],
            "Kernel debug source checked for radio/802.11 management hints.",
        ),
    ]

    entries: list[SourceIndexEntry] = []
    for source_id, marker, evidence_class, ts_semantics, fields, patterns, notes in section_specs:
        start, end = find_section(lines, marker)
        entries.append(
            SourceIndexEntry(
                source_id=source_id,
                path=str(support),
                section=marker.replace("##### BEGIN SECTION ", ""),
                line_start=start,
                line_end=end,
                evidence_class=evidence_class,
                timestamp_semantics=ts_semantics,
                identity_fields=fields,
                patterns=patterns,
                notes=notes,
            )
        )

    json_specs = [
        (
            "json_landevice_all",
            "query_lua_landevice_all.json",
            "webui_host_inventory",
            "snapshot plus raw firstused/lastused if present",
            ["name", "mac", "ip", "interface", "active", "online", "lastused"],
        ),
        (
            "json_landevice_query",
            "landevice_query_json.json",
            "webui_host_inventory",
            "snapshot plus raw firstused/lastused if present",
            ["name", "mac", "ip", "interface", "active", "online", "lastused"],
        ),
        (
            "json_hosts_tr064",
            "hosts_tr064_generic_json.json",
            "tr064_host_snapshot",
            "snapshot; lease time remaining can derive rough DHCP start",
            ["NewHostName", "NewMACAddress", "NewIPAddress", "NewActive", "NewLeaseTimeRemaining"],
        ),
        (
            "json_device_log_text",
            "device_log_text_json.json",
            "tr064_device_log",
            "absolute local dd.mm.yy timestamps inside NewDeviceLog",
            ["timestamp", "message", "mac", "ip"],
        ),
        (
            "json_device_info_log",
            "device_info_json.json",
            "tr064_device_info_log",
            "absolute local dd.mm.yy timestamps inside NewDeviceLog",
            ["timestamp", "message", "mac", "ip"],
        ),
        (
            "json_data_lua_pages",
            "data_lua_page_*.json",
            "webui_overview_snapshots",
            "snapshot at acquisition time",
            ["active devices", "names", "types"],
        ),
    ]
    for source_id, filename, evidence_class, ts_semantics, fields in json_specs:
        entries.append(
            SourceIndexEntry(
                source_id=source_id,
                path=str(raw_dir / filename),
                section=filename,
                line_start=1,
                line_end=1,
                evidence_class=evidence_class,
                timestamp_semantics=ts_semantics,
                identity_fields=fields,
                patterns=[],
                notes="Raw JSON/UI artifact considered during correlation.",
            )
        )
    return entries


def extract_events(
    raw_dir: Path,
    lines: list[str],
    *,
    start: datetime,
    end: datetime,
) -> list[PresenceEvent]:
    now = support_now(lines, raw_dir)
    uptime = support_uptime_seconds(lines)
    by_mac, by_ip = build_host_maps(raw_dir)
    events: list[PresenceEvent] = []
    support_path = raw_dir / "support_data_txt.txt"

    def add(
        observed: datetime,
        evidence_class: str,
        *,
        device: str = "",
        mac: str = "",
        ip: str = "",
        source_id: str,
        line: int | None,
        details: str,
    ) -> None:
        mac = normalize_mac(mac)
        if not device and mac in by_mac:
            device = by_mac[mac].get("name", "")
        if not ip and mac in by_mac:
            ip = by_mac[mac].get("ip", "")
        if not device and ip in by_ip:
            device = by_ip[ip].get("name", "")
        if not mac and ip in by_ip:
            mac = by_ip[ip].get("mac", "")
        events.append(
            PresenceEvent(
                observed_at=observed.isoformat(),
                date=observed.date().isoformat(),
                evidence_class=evidence_class,
                device=device or "",
                mac=mac or "",
                ip=ip or "",
                source_id=source_id,
                source_path=str(support_path),
                line=line,
                details=details.strip(),
            )
        )

    for line_no, line in enumerate(lines, 1):
        match = re.search(
            rf"(?P<date>\d{{2}}\.\d{{2}}\.\d{{2}})\s+"
            rf"(?P<time>\d{{2}}:\d{{2}}:\d{{2}})\s+Netzwerkgerät Name:\s+"
            rf"(?P<name>.*?),\s+MAC:\s+(?P<mac>{MAC_RE}).*verbunden",
            line,
        )
        if match:
            observed = datetime.strptime(
                f"{match.group('date')} {match.group('time')}",
                "%d.%m.%y %H:%M:%S",
            ).replace(tzinfo=DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    "exact_router_connect",
                    device=match.group("name"),
                    mac=match.group("mac"),
                    source_id="support_events",
                    line=line_no,
                    details=line,
                )

        match = re.search(r'notified_at\s*=\s*"(2026-05-(?:15|16) \d\d:\d\d:\d\d)"', line)
        if match:
            mac = ""
            for previous in range(max(0, line_no - 8), line_no):
                mac_match = re.search(rf"\bmac\s*=\s*({MAC_RE})", lines[previous], re.IGNORECASE)
                if mac_match:
                    mac = mac_match.group(1)
            observed = datetime.fromisoformat(match.group(1).replace(" ", "T")).replace(tzinfo=DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    "new_device_security_notification",
                    mac=mac,
                    source_id="support_events",
                    line=line_no,
                    details=line,
                )

        match = re.search(
            rf"(?P<ts>2026-05-(?:15|16) \d\d:\d\d:\d\d\.\d+).*"
            rf"upnp_device_new\s+(?P<ip>{IP_RE}).*?\(name=(?P<name>[^)]+)\)",
            line,
            re.IGNORECASE,
        )
        if match:
            observed = datetime.fromisoformat(match.group("ts").replace(" ", "T")).replace(tzinfo=DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    "upnp_media_discovery",
                    device=match.group("name"),
                    ip=match.group("ip"),
                    source_id="support_upnp_av",
                    line=line_no,
                    details=line,
                )

        match = re.search(
            rf"(?P<ts>2026-05-(?:15|16) \d\d:\d\d:\d\d\.\d+).*" rf"Local STA interface (?P<mac>{MAC_RE}).*drop update",
            line,
            re.IGNORECASE,
        )
        if match:
            observed = datetime.fromisoformat(match.group("ts").replace(" ", "T")).replace(tzinfo=DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    "wlan_mesh_client_state_update",
                    mac=match.group("mac"),
                    source_id="support_mesh_daemon",
                    line=line_no,
                    details=line,
                )

    # STATION_LIST: absolute connect history plus uptime/age-derived last_seen.
    current: dict[str, Any] = {}
    section = ""
    in_station = False

    def flush_station() -> None:
        if not current.get("mac"):
            return
        mac = current["mac"]
        if uptime and current.get("station_last_seen") is not None:
            observed = now - timedelta(seconds=max(0, uptime - current["station_last_seen"]))
            if in_window(observed, start, end):
                add(
                    observed,
                    "wlan_station_last_seen",
                    mac=mac,
                    source_id="support_station_list",
                    line=current.get("station_last_seen_line"),
                    details=(
                        f"station_last_seen={current['station_last_seen']} uptime={uptime}; "
                        f"success={current.get('success', '')}; fail={current.get('fail', '')}; "
                        f"visible={current.get('visible', '')}"
                    ),
                )
        if current.get("networking_last_seen") is not None:
            observed = now - timedelta(seconds=current["networking_last_seen"])
            if in_window(observed, start, end):
                add(
                    observed,
                    "wlan_station_networking_last_seen",
                    mac=mac,
                    source_id="support_station_list",
                    line=current.get("networking_last_seen_line"),
                    details=(
                        f"networking_last_seen_age={current['networking_last_seen']}; "
                        f"success={current.get('success', '')}; fail={current.get('fail', '')}"
                    ),
                )

    for line_no, line in enumerate(lines, 1):
        if "##### BEGIN SECTION STATION_LIST" in line:
            in_station = True
        if in_station and "##### END SECTION STATION_LIST" in line:
            flush_station()
            in_station = False
        if not in_station:
            continue
        if line.startswith("----------------------------------------"):
            flush_station()
            current = {}
            section = ""
            continue
        if "Station management:" in line:
            flush_station()
            current = {}
            section = "station"
            continue
        if "Station connection:" in line:
            section = "connection"
            continue
        if "Networking infos:" in line:
            section = "networking"
            continue
        if "Connect history:" in line:
            section = "history"
            continue
        match = re.search(rf"\bmac\s*=\s*({MAC_RE})", line)
        if match:
            current["mac"] = normalize_mac(match.group(1))
        match = re.search(r"\bstation_visible\s*=\s*(\S+)", line)
        if match:
            current["visible"] = match.group(1)
        match = re.search(r"\b(?:cnt_connect_fail|count_connect_fail)\s*=\s*(\d+)", line)
        if match:
            current["fail"] = match.group(1)
        match = re.search(r"\b(?:cnt_connect_success|count_connect_success)\s*=\s*(\d+)", line)
        if match:
            current["success"] = match.group(1)
        match = re.search(r"\blast_seen\s*=\s*(\d+)", line)
        if match and section == "station":
            current["station_last_seen"] = int(match.group(1))
            current["station_last_seen_line"] = line_no
        elif match and section == "networking":
            current["networking_last_seen"] = int(match.group(1))
            current["networking_last_seen_line"] = line_no
        match = re.search(
            r"(\d+)\s*/\s*(ath\d+)\s*/\s*(202605(?:15|16)-\d{6})\s*" r"\(([^)]*)\)\s*/\s*(?:(202605(?:15|16)-\d{6}))?",
            line,
        )
        if match and current.get("mac"):
            observed = datetime.strptime(match.group(3), "%Y%m%d-%H%M%S").replace(tzinfo=DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    "wlan_station_history",
                    mac=current["mac"],
                    source_id="support_station_list",
                    line=line_no,
                    details=(
                        f"{match.group(2)} connect={match.group(3)} "
                        f"disconnect={match.group(5) or 'open'} raw={line.strip()}"
                    ),
                )

    # landevices: Unix epoch lastused/firstused.
    in_landevices = False
    host: dict[str, str] = {}
    for line_no, line in enumerate(lines, 1):
        if "##### BEGIN SECTION landevices" in line:
            in_landevices = True
        if in_landevices and "##### END SECTION" in line:
            in_landevices = False
        if not in_landevices:
            continue
        if re.match(r"\s*landevice\d+/", line):
            host = {}
            continue
        field = re.match(r"\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not field:
            continue
        key, value = field.group(1), field.group(2).strip()
        if key in {
            "ip",
            "mac",
            "name",
            "interface",
            "ethernetport",
            "vendorname",
            "modelname",
            "active",
            "online",
            "flags",
        }:
            host[key] = value
        if key in {"lastused", "firstused"} and value.isdigit() and int(value) > 0:
            observed = datetime.fromtimestamp(int(value), DEFAULT_TZ)
            if in_window(observed, start, end):
                add(
                    observed,
                    f"landevice_{key}",
                    device=host.get("name", ""),
                    mac=host.get("mac", ""),
                    ip=host.get("ip", ""),
                    source_id="support_landevices",
                    line=line_no,
                    details=(
                        f"{key}={value}; interface={host.get('interface', '')}; "
                        f"port={host.get('ethernetport', '')}; active={host.get('active', '')}; "
                        f"online={host.get('online', '')}; flags={host.get('flags', '')}"
                    ),
                )

    # DHCP lease starts only. Lease overlap is indexed but intentionally not emitted here.
    lease_duration = 864000
    for line_no, line in enumerate(lines, 1):
        match = re.search(
            rf"^w?lease\s+({MAC_RE})\s+({IP_RE})\s+(\d+)\s+\"([^\"]*)\"",
            line.strip(),
            re.IGNORECASE,
        )
        if not match:
            continue
        mac, ip, remaining, device = match.group(1), match.group(2), int(match.group(3)), match.group(4)
        if remaining <= 0:
            continue
        acquired = now - timedelta(seconds=lease_duration - remaining)
        expires = now + timedelta(seconds=remaining)
        if in_window(acquired, start, end):
            add(
                acquired,
                "dhcp_lease_start",
                device=device,
                mac=mac,
                ip=ip,
                source_id="support_dhcpd",
                line=line_no,
                details=f"remaining={remaining}s; lease_end={expires.isoformat()}",
            )

    # Neighbour ages.
    section_start, section_end = find_section(lines, "##### BEGIN SECTION neighbours")
    if section_start and section_end:
        duration_pattern = r"(?:\d+\s+days?\s+)?\s*\d{1,2}:\d{2}(?::\d{2})?\s+" r"(?:hours?|minutes?)|\d+\s+seconds?"
        for line_no, line in enumerate(lines[section_start - 1 : section_end], section_start):
            macs = re.findall(MAC_RE, line, re.IGNORECASE)
            if not macs:
                continue
            age_match = re.search(duration_pattern, line)
            if not age_match:
                continue
            seconds = parse_duration_seconds(age_match.group(0))
            if seconds is None:
                continue
            observed = now - timedelta(seconds=seconds)
            if in_window(observed, start, end):
                ips = re.findall(IP_RE, line)
                add(
                    observed,
                    "neighbor_last_seen",
                    mac=macs[0],
                    ip=ips[0] if ips else "",
                    source_id="support_neighbours",
                    line=line_no,
                    details=line,
                )

    seen: set[tuple[str, str, str, str, str, int | None]] = set()
    deduped: list[PresenceEvent] = []
    for event in sorted(events, key=lambda item: (item.observed_at, item.mac, item.evidence_class, item.line or 0)):
        key = (
            event.observed_at,
            event.mac,
            event.ip,
            event.evidence_class,
            event.source_id,
            event.line,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def grouped_summary(events: list[PresenceEvent]) -> list[dict[str, Any]]:
    grouped: dict[str, list[PresenceEvent]] = defaultdict(list)
    for event in events:
        key = event.mac or event.ip or event.device
        grouped[key].append(event)
    rows: list[dict[str, Any]] = []
    for values in grouped.values():
        sorted_values = sorted(values, key=lambda item: item.observed_at)
        rows.append(
            {
                "first_observed": sorted_values[0].observed_at,
                "last_observed": sorted_values[-1].observed_at,
                "dates": sorted({item.date for item in sorted_values}),
                "device": next((item.device for item in sorted_values if item.device), ""),
                "mac": next((item.mac for item in sorted_values if item.mac), ""),
                "ip": next((item.ip for item in sorted_values if item.ip), ""),
                "evidence_classes": sorted({item.evidence_class for item in sorted_values}),
                "files_found_in": sorted({item.source_path for item in sorted_values}),
                "sources": sorted({f"{item.source_id}:{item.line}" for item in sorted_values if item.line}),
                "event_count": len(sorted_values),
            }
        )
    return sorted(rows, key=lambda row: (row["first_observed"], row["mac"]))


def write_markdown(
    *,
    path: Path,
    raw_dir: Path,
    index_entries: list[SourceIndexEntry],
    events: list[PresenceEvent],
    summary: list[dict[str, Any]],
    start: datetime,
    end: datetime,
) -> None:
    lines = [
        "# Raw Device Presence Index",
        "",
        f"- Raw directory: `{raw_dir}`",
        f"- Window: `{start.isoformat()}` to `{end.isoformat()}`",
        "- Scope: raw artifacts only; SQLite parser output is not used.",
        "- DHCP lease overlap without an in-window lease start is indexed but excluded from the device result table.",
        "",
        "## Source Index",
        "",
        "| Source ID | Path | Lines | Evidence | Timestamp Semantics | Identity Fields | Notes |",
        "|---|---|---:|---|---|---|---|",
    ]
    for entry in index_entries:
        line_range = (
            f"{entry.line_start}-{entry.line_end}"
            if entry.line_start is not None and entry.line_end is not None
            else "-"
        )
        fields = ", ".join(entry.identity_fields)
        notes = entry.notes.replace("|", "\\|")
        lines.append(
            f"| `{entry.source_id}` | `{entry.path}` | {line_range} | "
            f"{entry.evidence_class} | {entry.timestamp_semantics} | {fields} | {notes} |"
        )
    lines.extend(
        [
            "",
            "## Device Summary",
            "",
            "| First | Last | Dates | Device | MAC | IP | Evidence | Sources |",
            "|---|---|---|---|---:|---:|---|---|",
        ]
    )
    for row in summary:
        lines.append(
            "| "
            + " | ".join(
                [
                    row["first_observed"],
                    row["last_observed"],
                    ", ".join(row["dates"]),
                    row["device"] or "-",
                    f"`{row['mac']}`" if row["mac"] else "-",
                    f"`{row['ip']}`" if row["ip"] else "-",
                    ", ".join(row["evidence_classes"]),
                    ", ".join(row["sources"][:8]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Chronological Events",
            "",
            "| Time | Device | MAC | IP | Evidence | Source | Detail |",
            "|---|---|---:|---:|---|---|---|",
        ]
    )
    for event in events:
        detail = event.details.replace("|", "\\|")[:220]
        source = f"{event.source_id}:{event.line}" if event.line else event.source_id
        lines.append(
            "| "
            + " | ".join(
                [
                    event.observed_at,
                    event.device or "-",
                    f"`{event.mac}`" if event.mac else "-",
                    f"`{event.ip}`" if event.ip else "-",
                    event.evidence_class,
                    source,
                    detail,
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    support_path = args.raw_dir / "support_data_txt.txt"
    lines = read_lines(support_path)
    start = parse_iso_local(args.start)
    end = parse_iso_local(args.end)

    index_entries = build_source_index(args.raw_dir, lines)
    events = extract_events(args.raw_dir, lines, start=start, end=end)
    summary = grouped_summary(events)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "source_index.json").write_text(
        json.dumps([asdict(entry) for entry in index_entries], indent=2, ensure_ascii=False) + "\n"
    )
    (args.out_dir / "presence_events.json").write_text(
        json.dumps([asdict(event) for event in events], indent=2, ensure_ascii=False) + "\n"
    )
    (args.out_dir / "device_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    write_markdown(
        path=args.out_dir / "raw_device_presence_index.md",
        raw_dir=args.raw_dir,
        index_entries=index_entries,
        events=events,
        summary=summary,
        start=start,
        end=end,
    )
    print(f"source_index={args.out_dir / 'source_index.json'}")
    print(f"presence_events={args.out_dir / 'presence_events.json'}")
    print(f"device_summary={args.out_dir / 'device_summary.json'}")
    print(f"markdown={args.out_dir / 'raw_device_presence_index.md'}")
    print(f"devices={len(summary)} events={len(events)} sources={len(index_entries)}")


if __name__ == "__main__":
    main()
