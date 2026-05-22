#!/usr/bin/env python3
"""Deep FRITZ!Box raw-artifact presence analysis for a time window.

This helper is intentionally conservative: it separates exact retained events
from derived evidence such as DHCP lease windows and neighbor-cache ages.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

MAC_RE = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"


@dataclass
class Evidence:
    device: str
    mac: str
    ip: str
    evidence_type: str
    observed_at: str
    confidence: str
    source: str
    line: int | None
    detail: str


def parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def load_support_now(raw_dir: Path, support_lines: list[str]) -> datetime:
    metadata_path = raw_dir / "00_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    generated = parse_dt(metadata["generated_at"])
    for line in support_lines[:40]:
        match = re.search(r"uptime:\s+(\d{2}):(\d{2}):(\d{2})\s+up", line)
        if match:
            hour, minute, second = (int(part) for part in match.groups())
            return generated.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return generated


def load_support_uptime_seconds(support_lines: list[str]) -> int | None:
    for line in support_lines:
        match = re.search(r"\buptime\s*=\s*(\d+)\b", line)
        if match:
            return int(match.group(1))
    for line in support_lines[:40]:
        match = re.search(r"uptime:\s+\d{2}:\d{2}:\d{2}\s+up\s+(\d+)\s+days,\s+(\d+):(\d{2})", line)
        if match:
            days, hours, minutes = (int(part) for part in match.groups())
            time_match = re.search(r"uptime:\s+(\d{2}):(\d{2}):(\d{2})", line)
            seconds = int(time_match.group(3)) if time_match else 0
            return days * 86400 + hours * 3600 + minutes * 60 + seconds
    return None


def parse_duration_to_seconds(text: str) -> int | None:
    text = " ".join(text.strip().split())
    total = 0
    day_match = re.search(r"(\d+)\s+days?", text)
    if day_match:
        total += int(day_match.group(1)) * 86400
    hour_match = re.search(r"(\d{1,2}):(\d{2}):(\d{2})\s+hours?", text)
    if hour_match:
        hours, minutes, seconds = (int(part) for part in hour_match.groups())
        total += hours * 3600 + minutes * 60 + seconds
        return total
    minute_match = re.search(r"(\d{1,2}):(\d{2})\s+minutes?", text)
    if minute_match:
        minutes, seconds = (int(part) for part in minute_match.groups())
        total += minutes * 60 + seconds
        return total
    second_match = re.search(r"(\d+)\s+seconds?", text)
    if second_match:
        total += int(second_match.group(1))
        return total
    return total if total else None


def normalize_mac(mac: str) -> str:
    return mac.upper()


def line_window(lines: list[str], begin_marker: str, end_marker: str) -> tuple[int, int]:
    begin = 0
    end = len(lines)
    for idx, line in enumerate(lines):
        if begin_marker in line:
            begin = idx
            break
    for idx in range(begin + 1, len(lines)):
        if end_marker in lines[idx]:
            end = idx
            break
    return begin, end


def load_host_names(raw_dir: Path) -> dict[str, dict[str, str]]:
    host_names: dict[str, dict[str, str]] = {}
    for filename in ("query_lua_landevice_all.json", "landevice_query_json.json"):
        path = raw_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError:
            continue
        stacks: list[object] = [data]
        while stacks:
            item = stacks.pop()
            if isinstance(item, dict):
                mac = item.get("mac") or item.get("MACAddress") or item.get("NewMACAddress")
                if isinstance(mac, str) and re.fullmatch(MAC_RE, mac):
                    entry = host_names.setdefault(normalize_mac(mac), {})
                    for source_key, target_key in (
                        ("name", "name"),
                        ("hostname", "name"),
                        ("NewHostName", "name"),
                        ("ip", "ip"),
                        ("NewIPAddress", "ip"),
                        ("interface", "interface"),
                        ("ethernetport", "port"),
                        ("vendorname", "vendor"),
                        ("modelname", "model"),
                    ):
                        value = item.get(source_key)
                        if value and target_key not in entry:
                            entry[target_key] = str(value)
                stacks.extend(item.values())
            elif isinstance(item, list):
                stacks.extend(item)
    return host_names


def parse_exact_connection_events(
    lines: list[str],
    start: datetime,
    end: datetime,
) -> list[Evidence]:
    events: list[Evidence] = []
    pattern = re.compile(
        rf"(?P<date>\d{{2}}\.\d{{2}}\.\d{{2}})\s+"
        rf"(?P<time>\d{{2}}:\d{{2}}:\d{{2}})\s+Netzwerkgerät Name:\s+"
        rf"(?P<name>.*?),\s+MAC:\s+(?P<mac>{MAC_RE}).*verbunden",
    )
    for line_no, line in enumerate(lines, 1):
        match = pattern.search(line)
        if not match:
            continue
        naive = datetime.strptime(
            f"{match.group('date')} {match.group('time')}",
            "%d.%m.%y %H:%M:%S",
        )
        observed = naive.replace(tzinfo=start.tzinfo)
        if start <= observed < end:
            events.append(
                Evidence(
                    device=match.group("name"),
                    mac=normalize_mac(match.group("mac")),
                    ip="",
                    evidence_type="exact_router_connected_event",
                    observed_at=observed.isoformat(),
                    confidence="high",
                    source="support_data_txt",
                    line=line_no,
                    detail=line.strip(),
                )
            )
    return events


def parse_station_histories(
    lines: list[str],
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    current_mac = ""
    current_line = None
    history_pattern = re.compile(r"\b\d+\s*/\s*(ath\d+)\s*/\s*(\d{8}-\d{6})")
    for line_no, line in enumerate(lines, 1):
        mac_match = re.search(rf"\bmac\s*=\s*({MAC_RE})", line)
        if mac_match:
            current_mac = normalize_mac(mac_match.group(1))
            current_line = line_no
            continue
        history_match = history_pattern.search(line)
        if not history_match or not current_mac:
            continue
        observed = datetime.strptime(history_match.group(2), "%Y%m%d-%H%M%S").replace(tzinfo=start.tzinfo)
        if start <= observed < end:
            meta = host_names.get(current_mac, {})
            events.append(
                Evidence(
                    device=meta.get("name", ""),
                    mac=current_mac,
                    ip=meta.get("ip", ""),
                    evidence_type="wlan_station_history_attempt",
                    observed_at=observed.isoformat(),
                    confidence="medium",
                    source="support_data_txt_station_history",
                    line=line_no,
                    detail=f"{history_match.group(1)} station-history row; station block starts at line {current_line}",
                )
            )
    return events


def parse_station_last_seen(
    lines: list[str],
    support_now: datetime,
    support_uptime_seconds: int | None,
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    begin, finish = line_window(lines, "##### BEGIN SECTION STATION_LIST", "##### END SECTION STATION_LIST")
    if begin == finish:
        return events

    current: dict[str, str | int | None] = {}
    section = ""

    def to_int(value: str | int | None) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return None

    def add_event(
        *,
        observed: datetime,
        evidence_type: str,
        line_no: int | None,
        detail_prefix: str,
    ) -> None:
        if not (start <= observed < end):
            return
        mac = normalize_mac(str(current.get("mac", "")))
        if not mac:
            return
        meta = host_names.get(mac, {})
        events.append(
            Evidence(
                device=meta.get("name", ""),
                mac=mac,
                ip=meta.get("ip", ""),
                evidence_type=evidence_type,
                observed_at=observed.isoformat(),
                confidence="medium",
                source="support_data_txt_station_list",
                line=line_no,
                detail=(
                    f"{detail_prefix}; station_visible={current.get('station_visible', '')}; "
                    f"is_active={current.get('is_active', '')}; is_guest={current.get('is_guest', '')}; "
                    f"success={current.get('success', '')}; fail={current.get('fail', '')}; "
                    f"role={current.get('role_id', '')}; if={current.get('if_name', '')}; "
                    f"type={current.get('type', '')}"
                ),
            )
        )

    def flush_current() -> None:
        if not current.get("mac"):
            return
        station_last_seen = to_int(current.get("station_last_seen"))
        station_line = to_int(current.get("station_last_seen_line"))
        if station_last_seen is not None and support_uptime_seconds is not None:
            age_seconds = max(0, support_uptime_seconds - station_last_seen)
            add_event(
                observed=support_now - timedelta(seconds=age_seconds),
                evidence_type="wlan_station_last_seen",
                line_no=station_line,
                detail_prefix=f"Station management last_seen={station_last_seen}; uptime={support_uptime_seconds}",
            )

        networking_age = to_int(current.get("networking_last_seen"))
        networking_line = to_int(current.get("networking_last_seen_line"))
        if networking_age is not None:
            add_event(
                observed=support_now - timedelta(seconds=networking_age),
                evidence_type="wlan_station_networking_last_seen",
                line_no=networking_line,
                detail_prefix=f"Networking infos last_seen age={networking_age}s",
            )

    for offset, line in enumerate(lines[begin:finish], begin + 1):
        if line.startswith("----------------------------------------"):
            flush_current()
            current = {}
            section = ""
            continue
        if "Station management:" in line:
            flush_current()
            current = {"block_line": offset}
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

        match = re.match(r"\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        value = value.strip().strip("'")
        if key == "mac" and re.fullmatch(MAC_RE, value):
            current["mac"] = normalize_mac(value)
            current["mac_line"] = offset
        elif section == "station" and key == "last_seen" and value.isdigit():
            current["station_last_seen"] = int(value)
            current["station_last_seen_line"] = offset
        elif section == "networking" and key == "last_seen" and value.isdigit():
            current["networking_last_seen"] = int(value)
            current["networking_last_seen_line"] = offset
        elif key in {"station_visible", "is_active", "is_guest", "type", "role_id", "if_name"}:
            current[key] = value
        elif key in {"cnt_connect_success", "count_connect_success"}:
            current["success"] = value
        elif key in {"cnt_connect_fail", "count_connect_fail"}:
            current["fail"] = value

    flush_current()
    return events


def parse_security_notifications(
    lines: list[str],
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    current_mac = ""
    current_line: int | None = None
    for line_no, line in enumerate(lines, 1):
        mac_match = re.search(rf"\bmac\s*=\s*({MAC_RE});", line, re.IGNORECASE)
        if mac_match:
            current_mac = normalize_mac(mac_match.group(1))
            current_line = line_no
            continue
        notified_match = re.search(r'notified_at\s*=\s*"([^"]+)";', line)
        if not notified_match or not current_mac:
            continue
        observed = datetime.strptime(notified_match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=start.tzinfo)
        if start <= observed < end:
            meta = host_names.get(current_mac, {})
            events.append(
                Evidence(
                    device=meta.get("name", ""),
                    mac=current_mac,
                    ip=meta.get("ip", ""),
                    evidence_type="new_device_security_notification",
                    observed_at=observed.isoformat(),
                    confidence="high",
                    source="support_data_txt_security_notifications",
                    line=line_no,
                    detail=f"Security/new-device notification; MAC line={current_line}",
                )
            )
    return events


def parse_landevice_lastused(
    lines: list[str],
    start: datetime,
    end: datetime,
) -> list[Evidence]:
    events: list[Evidence] = []
    current: dict[str, str | int] = {}
    in_landevices = False
    for line_no, line in enumerate(lines, 1):
        if "##### BEGIN SECTION landevices" in line:
            in_landevices = True
            continue
        if in_landevices and line.startswith("##### END SECTION"):
            break
        if not in_landevices:
            continue
        if re.match(r"\s*landevice\d+/", line):
            current = {"line": line_no}
            continue
        field_match = re.match(r"\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if field_match and current is not None:
            key, value = field_match.groups()
            value = value.strip()
            if key in {
                "ip",
                "mac",
                "name",
                "interface",
                "ethernetport",
                "vendorname",
                "flags",
                "active",
                "online",
            }:
                current[key] = value
            if key == "lastused" and value.isdigit():
                observed = datetime.fromtimestamp(int(value), tz=start.tzinfo)
                if start <= observed < end:
                    mac = normalize_mac(str(current.get("mac", ""))) if current.get("mac") else ""
                    events.append(
                        Evidence(
                            device=str(current.get("name", "")),
                            mac=mac,
                            ip=str(current.get("ip", "")),
                            evidence_type="landevice_lastused",
                            observed_at=observed.isoformat(),
                            confidence="high",
                            source="support_data_txt_landevices",
                            line=line_no,
                            detail=(
                                f"lastused epoch={value}; interface={current.get('interface', '')}; "
                                f"port={current.get('ethernetport', '')}; active_at_collection={current.get('active', '')}; "
                                f"online_at_collection={current.get('online', '')}"
                            ),
                        )
                    )
    return events


def parse_dhcp_leases(
    lines: list[str],
    support_now: datetime,
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    lease_duration = 864000
    for line_no, line in enumerate(lines, 1):
        match = re.search(
            rf"^w?lease\s+({MAC_RE})\s+({IP_RE})\s+(\d+)\s+\"([^\"]*)\"",
            line.strip(),
            re.IGNORECASE,
        )
        if not match:
            continue
        mac = normalize_mac(match.group(1))
        ip = match.group(2)
        remaining = int(match.group(3))
        lease_name = match.group(4)
        if remaining <= 0:
            continue
        acquired = support_now - timedelta(seconds=lease_duration - remaining)
        expires = support_now + timedelta(seconds=remaining)
        meta = host_names.get(mac, {})
        device = meta.get("name") or lease_name
        if start <= acquired < end:
            events.append(
                Evidence(
                    device=device,
                    mac=mac,
                    ip=ip,
                    evidence_type="dhcp_lease_start_in_window",
                    observed_at=acquired.isoformat(),
                    confidence="medium",
                    source="support_data_txt_dhcpd",
                    line=line_no,
                    detail=(
                        f"Lease start inferred from remaining={remaining}s, "
                        f"default lease={lease_duration}s, expires={expires.isoformat()}"
                    ),
                )
            )
        if acquired < end and expires > start:
            midpoint = max(acquired, start)
            events.append(
                Evidence(
                    device=device,
                    mac=mac,
                    ip=ip,
                    evidence_type="dhcp_lease_valid_during_window",
                    observed_at=midpoint.isoformat(),
                    confidence="low",
                    source="support_data_txt_dhcpd",
                    line=line_no,
                    detail=(
                        "Lease interval overlaps requested window; this is not proof of "
                        f"active traffic. lease_start={acquired.isoformat()}, "
                        f"lease_end={expires.isoformat()}"
                    ),
                )
            )
    return events


def parse_neighbours(
    lines: list[str],
    support_now: datetime,
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    begin, finish = line_window(lines, "##### BEGIN SECTION neighbours", "##### END SECTION neighbours")
    current: dict[str, str | int] | None = None
    header_pattern = re.compile(rf"^\[(?P<mac>{MAC_RE})\](?P<rest>.*)$", re.IGNORECASE)
    duration_pattern = r"(?:\d+\s+days?\s+)?\s*\d{1,2}:\d{2}(?::\d{2})?\s+" r"(?:hours?|minutes?)|\d+\s+seconds?"
    ip_pattern = re.compile(
        rf"^\s+(?P<ip>{IP_RE})\s+(?P<age>{duration_pattern})\b.*?\b(?P<mac>{MAC_RE})\b"
        rf"(?:\s+(?P<age2>{duration_pattern}))?",
        re.IGNORECASE,
    )

    def add_age_event(
        *,
        mac: str,
        ip: str,
        device: str,
        age_text: str,
        line_no: int,
        detail: str,
    ) -> None:
        seconds = parse_duration_to_seconds(age_text)
        if seconds is None:
            return
        observed = support_now - timedelta(seconds=seconds)
        if start <= observed < end:
            events.append(
                Evidence(
                    device=device,
                    mac=normalize_mac(mac),
                    ip=ip,
                    evidence_type="neighbor_last_seen_in_window",
                    observed_at=observed.isoformat(),
                    confidence="medium",
                    source="support_data_txt_neighbours",
                    line=line_no,
                    detail=f"{detail}; raw_age={age_text}",
                )
            )

    for offset, line in enumerate(lines[begin:finish], begin + 1):
        header = header_pattern.match(line)
        if header:
            mac = normalize_mac(header.group("mac"))
            meta = host_names.get(mac, {})
            name_match = re.search(r"\]\s+\([^)]*\)\s+([dDSI ]+)\s+(.+?)\s+\(", line)
            simple_name = ""
            if name_match:
                simple_name = name_match.group(2).strip()
            current = {
                "mac": mac,
                "device": meta.get("name") or simple_name,
                "line": offset,
            }
            age_match = re.search(
                r"\]\s+(?:\([^)]*\)\s+)?[dDSI ]*\s*(?P<age>(?:\d+\s+days?\s+)?\s*\d{1,2}:\d{2}(?::\d{2})?\s+(?:hours?|minutes?)|\d+\s+seconds?)",
                line,
            )
            if age_match:
                add_age_event(
                    mac=mac,
                    ip=meta.get("ip", ""),
                    device=str(current["device"]),
                    age_text=age_match.group("age"),
                    line_no=offset,
                    detail="Neighbor device-level last-seen age",
                )
            continue
        ip_match = ip_pattern.match(line)
        if ip_match:
            mac = normalize_mac(ip_match.group("mac"))
            meta = host_names.get(mac, {})
            add_age_event(
                mac=mac,
                ip=ip_match.group("ip"),
                device=meta.get("name") or (str(current["device"]) if current else ""),
                age_text=ip_match.group("age"),
                line_no=offset,
                detail="Neighbor IP-level last-seen age",
            )
            if ip_match.group("age2"):
                add_age_event(
                    mac=mac,
                    ip=ip_match.group("ip"),
                    device=meta.get("name") or (str(current["device"]) if current else ""),
                    age_text=ip_match.group("age2"),
                    line_no=offset,
                    detail="Neighbor IP-level secondary last-seen age",
                )
    return events


def parse_media_discovery(
    lines: list[str],
    start: datetime,
    end: datetime,
    host_names: dict[str, dict[str, str]],
) -> list[Evidence]:
    events: list[Evidence] = []
    pattern = re.compile(
        rf"(?P<ts>\d{{4}}-\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d+).*"
        rf"upnp_device_new\s+(?P<ip>{IP_RE}).*?\(name=(?P<name>[^)]+)\)",
        re.IGNORECASE,
    )
    mac_by_ip = {meta.get("ip"): mac for mac, meta in host_names.items() if meta.get("ip")}
    for line_no, line in enumerate(lines, 1):
        match = pattern.search(line)
        if not match:
            continue
        observed = datetime.fromisoformat(match.group("ts").replace(" ", "T")).replace(tzinfo=start.tzinfo)
        if start <= observed < end:
            ip = match.group("ip")
            mac = mac_by_ip.get(ip, "")
            events.append(
                Evidence(
                    device=match.group("name"),
                    mac=mac,
                    ip=ip,
                    evidence_type="upnp_media_discovery",
                    observed_at=observed.isoformat(),
                    confidence="medium",
                    source="support_data_txt_upnp",
                    line=line_no,
                    detail=line.strip(),
                )
            )
    return events


def dedupe(events: Iterable[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str, str, str, str]] = set()
    output: list[Evidence] = []
    for event in sorted(events, key=lambda item: (item.observed_at, item.mac, item.evidence_type)):
        key = (event.mac, event.ip, event.evidence_type, event.observed_at, event.source)
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    support_path = args.raw_dir / "support_data_txt.txt"
    lines = support_path.read_text(errors="replace").splitlines()
    start = parse_dt(args.start)
    end = parse_dt(args.end)
    host_names = load_host_names(args.raw_dir)
    support_now = load_support_now(args.raw_dir, lines)
    support_uptime_seconds = load_support_uptime_seconds(lines)

    events = dedupe(
        [
            *parse_exact_connection_events(lines, start, end),
            *parse_station_histories(lines, start, end, host_names),
            *parse_station_last_seen(
                lines,
                support_now,
                support_uptime_seconds,
                start,
                end,
                host_names,
            ),
            *parse_security_notifications(lines, start, end, host_names),
            *parse_landevice_lastused(lines, start, end),
            *parse_dhcp_leases(lines, support_now, start, end, host_names),
            *parse_neighbours(lines, support_now, start, end, host_names),
            *parse_media_discovery(lines, start, end, host_names),
        ]
    )

    payload = {
        "raw_dir": str(args.raw_dir),
        "support_now": support_now.isoformat(),
        "support_uptime_seconds": support_uptime_seconds,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "events": [asdict(event) for event in events],
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    print(f"raw_dir: {args.raw_dir}")
    print(f"support_now: {support_now.isoformat()}")
    print(f"window: {start.isoformat()} -> {end.isoformat()}")
    print(f"events: {len(events)}")
    for event in events:
        print(
            "\t".join(
                [
                    event.observed_at,
                    event.confidence,
                    event.evidence_type,
                    event.device or "-",
                    event.mac or "-",
                    event.ip or "-",
                    f"line={event.line}" if event.line else "line=-",
                    event.detail,
                ]
            )
        )


if __name__ == "__main__":
    main()
