from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
STATION_KEY_VALUE_RE = re.compile(r"^\s+(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$")
UPTIME_SECONDS_RE = re.compile(r"\buptime\s*=\s*(?P<seconds>\d+)\b")
HOSTAPD_LIFECYCLE_RE = re.compile(
    r"(?P<iface>ath\d+):\s+STA\s+(?P<mac>[0-9a-fA-F:]{17})\s+IEEE\s+802\.11:\s+"
    r"(?P<lifecycle>authenticated|associated|reassociated|disassociated|deauthenticated)\b(?P<detail>.*)",
    re.I,
)
REASON_RE = re.compile(r"\breason(?:\s+code)?[=:\s]+(?P<reason>\d+)\b", re.I)
STATUS_RE = re.compile(r"\bstatus(?:[_\s]+code)?[=:\s]+(?P<status>\d+)\b", re.I)
AID_RE = re.compile(r"\baid\s+(?P<aid>\d+)\b", re.I)

IEEE80211_REASON_CODES = {
    0: "reserved_or_success",
    1: "unspecified",
    2: "previous_authentication_no_longer_valid",
    3: "deauthenticated_leaving",
    4: "disassociated_due_to_inactivity",
    5: "ap_unable_to_handle_station",
    6: "class_2_frame_from_nonauthenticated_station",
    7: "class_3_frame_from_nonassociated_station",
    8: "disassociated_leaving",
    9: "station_requesting_association_without_authentication",
    10: "power_capability_unacceptable",
    11: "supported_channels_unacceptable",
    13: "invalid_information_element",
    14: "mic_failure",
    15: "four_way_handshake_timeout",
    16: "group_key_handshake_timeout",
    17: "information_element_different",
    18: "invalid_group_cipher",
    19: "invalid_pairwise_cipher",
    20: "invalid_akmp",
    21: "unsupported_rsn_information_element_version",
    22: "invalid_rsn_information_element_capabilities",
    23: "ieee8021x_authentication_failed",
    24: "cipher_suite_rejected",
    34: "disassociated_due_to_low_ack",
}


@dataclass(slots=True)
class WlanEventDetails:
    timestamp: str | None
    mac: str | None
    interface: str | None
    event_id: int
    band: int
    rate: int
    channel: int
    previous_channel: int
    details_hex: str
    details_int: int | None
    line_number: int


@dataclass(slots=True)
class StationStateSnapshot:
    timestamp: str | None
    mac: str
    line_number: int | None
    observed_at: str | None
    last_seen: str | None
    station_last_seen_uptime_seconds: int | None
    networking_last_seen_age_seconds: int | None
    is_active: bool | None
    is_guest: bool | None
    station_visible: bool | None
    rssi: int | None
    quality: int | None
    bssid: str | None
    role_id: int | None
    if_name: str | None
    connect_state: str | None
    connect_state_id: int | None
    station_type: str | None
    hostname: str | None
    ip: str | None
    speed: str | None
    cnt_connect_success: int | None
    cnt_connect_fail: int | None
    cnt_disconnect_forced: int | None
    time_mean_connect: int | None


@dataclass(slots=True)
class HostapdClientEvent:
    event: str
    hostapd_event: str
    hostapd_action: str
    mac: str
    interface: str
    reason_code: int | None
    reason_name: str | None
    status_code: int | None
    detail: str | None
    aid: int | None


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    match = MAC_RE.search(value)
    return match.group(0).lower() if match else None


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_bool(value: Any) -> bool | None:
    text = str(value or "").strip().casefold()
    if text in {"1", "true", "yes", "ja", "on", "active", "connected"}:
        return True
    if text in {"0", "false", "no", "nein", "off", "inactive", "disconnected"}:
        return False
    return None


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def parse_compact_support_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y%m%d-%H%M%S").astimezone()
    except ValueError:
        return None


def support_uptime_seconds(content: str) -> int | None:
    for line in content.splitlines():
        match = UPTIME_SECONDS_RE.search(line)
        if match:
            return int(match.group("seconds"))
    return None


def wlan_event_row_to_dict(match: re.Match[str], line_number: int) -> dict[str, Any]:
    timestamp = parse_compact_support_timestamp(match.group("timestamp"))
    details_hex = match.group("details")
    details_int = parse_int(details_hex)
    row = WlanEventDetails(
        timestamp=timestamp.isoformat() if timestamp else None,
        mac=normalize_mac(match.group("mac")),
        interface=clean_dash(match.group("iface")),
        event_id=int(match.group("event_id")),
        band=int(match.group("band")),
        rate=int(match.group("rate")),
        channel=int(match.group("channel")),
        previous_channel=int(match.group("prev_channel")),
        details_hex=details_hex,
        details_int=details_int,
        line_number=line_number,
    )
    return asdict(row)


def parse_station_key_value(line: str) -> tuple[str, str] | None:
    match = STATION_KEY_VALUE_RE.match(line)
    if not match:
        return None
    return match.group("key"), match.group("value").strip().strip("'\"")


def station_state_snapshot_to_dict(
    state: dict[str, Any],
    *,
    observed_at: str | None,
    uptime_seconds: int | None,
) -> dict[str, Any] | None:
    mac = normalize_mac(str(state.get("mac") or ""))
    if not mac:
        return None

    observed = parse_iso_datetime(observed_at)
    station_last_seen_uptime = parse_int(state.get("station_last_seen"))
    networking_last_seen_age = parse_int(state.get("networking_last_seen"))
    station_last_seen = None
    networking_last_seen = None
    if observed and station_last_seen_uptime is not None and uptime_seconds is not None:
        station_last_seen = observed - timedelta(seconds=max(0, uptime_seconds - station_last_seen_uptime))
    if observed and networking_last_seen_age is not None:
        networking_last_seen = observed - timedelta(seconds=networking_last_seen_age)

    last_seen = max((dt for dt in (station_last_seen, networking_last_seen) if dt is not None), default=None)
    timestamp = last_seen.isoformat() if last_seen else observed_at
    row = StationStateSnapshot(
        timestamp=timestamp,
        mac=mac,
        line_number=parse_int(state.get("block_line") or state.get("mac_line")),
        observed_at=observed_at,
        last_seen=last_seen.isoformat() if last_seen else None,
        station_last_seen_uptime_seconds=station_last_seen_uptime,
        networking_last_seen_age_seconds=networking_last_seen_age,
        is_active=parse_bool(state.get("is_active")),
        is_guest=parse_bool(state.get("is_guest")),
        station_visible=parse_bool(state.get("station_visible")),
        rssi=parse_int(state.get("rssi")),
        quality=parse_int(state.get("quality")),
        bssid=normalize_mac(str(state.get("bssid") or "")),
        role_id=parse_int(state.get("role_id")),
        if_name=none_if_empty(state.get("if_name")),
        connect_state=none_if_empty(state.get("connect_state")),
        connect_state_id=parse_int(state.get("connect_state")),
        station_type=none_if_empty(state.get("type")),
        hostname=first_present(state, "hostname", "host_name", "name", "devname"),
        ip=first_present(state, "ip", "ipv4", "ip_addr", "ip_address"),
        speed=first_present(state, "speed", "rxrate", "txrate", "rate"),
        cnt_connect_success=parse_int(state.get("cnt_connect_success") or state.get("count_connect_success")),
        cnt_connect_fail=parse_int(state.get("cnt_connect_fail") or state.get("count_connect_fail")),
        cnt_disconnect_forced=parse_int(state.get("cnt_disconnect_forced")),
        time_mean_connect=parse_int(state.get("time_mean_connect")),
    )
    parsed = asdict(row)
    if not any(
        parsed.get(key) is not None
        for key in (
            "last_seen",
            "is_active",
            "is_guest",
            "station_visible",
            "rssi",
            "quality",
            "bssid",
            "role_id",
            "if_name",
            "connect_state",
            "station_type",
            "hostname",
            "ip",
            "speed",
        )
    ):
        return None
    return parsed


def parse_hostapd_lifecycle_event(message: str) -> dict[str, Any] | None:
    match = HOSTAPD_LIFECYCLE_RE.search(message)
    if not match:
        return None
    lifecycle = match.group("lifecycle").casefold()
    detail = " ".join((match.group("detail") or "").strip(" ()").split()) or None
    reason_match = REASON_RE.search(match.group("detail") or "")
    reason_code = int(reason_match.group("reason")) if reason_match else None
    status_match = STATUS_RE.search(match.group("detail") or "")
    status_code = int(status_match.group("status")) if status_match else None
    aid_match = AID_RE.search(match.group("detail") or "")
    event_map = {
        "authenticated": ("authenticated", "auth"),
        "associated": ("connected", "assoc"),
        "reassociated": ("connected", "reassoc"),
        "disassociated": ("disconnected", "disassoc"),
        "deauthenticated": ("disconnected", "deauth"),
    }
    event, action = event_map[lifecycle]
    parsed = HostapdClientEvent(
        event=event,
        hostapd_event=lifecycle,
        hostapd_action=action,
        mac=normalize_mac(match.group("mac")) or match.group("mac").lower(),
        interface=match.group("iface"),
        reason_code=reason_code,
        reason_name=IEEE80211_REASON_CODES.get(reason_code) if reason_code is not None else None,
        status_code=status_code,
        detail=detail,
        aid=int(aid_match.group("aid")) if aid_match else None,
    )
    return asdict(parsed)


def reason_name(reason_code: int | None) -> str | None:
    return IEEE80211_REASON_CODES.get(reason_code) if reason_code is not None else None


def none_if_empty(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def first_present(state: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = none_if_empty(state.get(key))
        if value is not None:
            return value
    return None


def clean_dash(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in {"", "---", "----"} else stripped
