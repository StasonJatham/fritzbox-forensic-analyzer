from __future__ import annotations

import re
import struct
import threading
import time
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fritzbox_collectors import get_webui_sid

CAPTURE_INTERFACE_RE = re.compile(
    r"<th>(?P<label>[^<]+)</th>.*?<button[^>]+name=\"start\"[^>]+value=\"(?P<value>[^\"]+)\"",
    re.I | re.S,
)
LINKTYPE_IEEE802_11 = 105
LINKTYPE_RADIOTAP = 127
MAX_CAPTURE_SECONDS = 30
MAX_CAPTURE_BYTES = 8_000_000


@dataclass(slots=True)
class CaptureInterface:
    label: str
    value: str

    @property
    def stop_params(self) -> dict[str, str]:
        capture_type, minor = self.value.split("-", 1)
        return {
            "type": capture_type,
            "minor": minor,
            "iface": self.label,
        }


def list_capture_interfaces(fc: Any) -> dict[str, Any]:
    page = fetch_capture_page(fc)
    interfaces = parse_capture_interfaces(page)
    preferred = preferred_capture_interface(interfaces)
    return {
        "available": bool(interfaces),
        "interfaces": [{"label": item.label, "value": item.value} for item in interfaces],
        "preferred": preferred.value if preferred else "",
        "note": (
            "Realtime capture uses the hidden FRITZ!Box capture endpoint. It is live packet evidence only; "
            "it is not historical router log evidence."
        ),
    }


def run_wlan_management_capture(fc: Any, duration_seconds: int = 10, iface_value: str = "") -> dict[str, Any]:
    duration = max(3, min(MAX_CAPTURE_SECONDS, int(duration_seconds or 10)))
    page = fetch_capture_page(fc)
    interfaces = parse_capture_interfaces(page)
    selected = interface_by_value(interfaces, iface_value) or preferred_capture_interface(interfaces)
    if selected is None:
        return {
            "ok": False,
            "error": "FRITZ!Box capture page did not expose WLAN capture interfaces.",
            "frames": [],
        }

    http = getattr(fc, "http_interface", None)
    session = getattr(getattr(http, "fc", None), "session", None)
    sid = get_webui_sid(http) if http is not None else None
    if http is None or session is None or not sid:
        return {"ok": False, "error": "Could not obtain authenticated FRITZ!Box Web UI session.", "frames": []}

    base = str(getattr(http, "router_url", "")).rstrip("/")
    capture_url = f"{base}/cgi-bin/capture_notimeout"
    capture_bytes = bytearray()
    capture_lock = threading.Lock()
    error: str | None = None

    def read_capture() -> None:
        nonlocal error
        params = {
            "sid": sid,
            "capture": "Start",
            "snaplen": "2048",
            "filter": "",
            "ifaceorminor": selected.value,
        }
        try:
            with session.get(capture_url, params=params, stream=True, timeout=duration + 45) as response:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    with capture_lock:
                        capture_bytes.extend(chunk)
                        reached_limit = len(capture_bytes) >= MAX_CAPTURE_BYTES
                    if reached_limit:
                        break
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

    started_at = datetime.now().astimezone().isoformat()
    thread = threading.Thread(target=read_capture, daemon=True)
    thread.start()
    time.sleep(duration)
    stop_capture(session, capture_url, sid, selected)
    thread.join(timeout=20)
    stopped_at = datetime.now().astimezone().isoformat()
    if thread.is_alive():
        return {
            "ok": False,
            "started_at": started_at,
            "stopped_at": stopped_at,
            "duration_seconds": duration,
            "interface": {"label": selected.label, "value": selected.value},
            "pcap_bytes": 0,
            "pcap_base64": "",
            "frames": [],
            "error": "Capture stream did not stop before the timeout; discarded partial capture.",
            "note": (
                "Realtime capture timed out after requesting stop. No partial packet data is returned because the "
                "capture worker may still be closing."
            ),
        }

    with capture_lock:
        pcap = bytes(capture_bytes)
    parsed = parse_pcap(pcap, started_at)
    ok = bool(pcap) and (error is None or parsed.get("packet_count", 0) > 0)
    return {
        "ok": ok,
        "started_at": started_at,
        "stopped_at": stopped_at,
        "duration_seconds": duration,
        "interface": {"label": selected.label, "value": selected.value},
        "pcap_bytes": len(pcap),
        "pcap_base64": b64encode(pcap).decode("ascii") if pcap else "",
        "pcap_filename": f"fritzbox-80211-live-{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}.pcap",
        "parse": parsed,
        "frames": parsed.get("frames", []),
        "error": error,
        "note": (
            "These rows come from a realtime capture. They are separate from retained FRITZ!Box history and only "
            "cover the capture window."
        ),
    }


def fetch_capture_page(fc: Any) -> str:
    http = getattr(fc, "http_interface", None)
    session = getattr(getattr(http, "fc", None), "session", None)
    if http is None or session is None:
        return ""
    sid = get_webui_sid(http)
    params = {"sid": sid} if sid else {}
    try:
        response = session.get(f"{str(http.router_url).rstrip('/')}/capture.lua", params=params, timeout=20)
    except TypeError:
        response = session.get(f"{str(http.router_url).rstrip('/')}/capture.lua", params=params)
    except Exception:
        return ""
    if getattr(response, "status_code", None) != 200:
        return ""
    return getattr(response, "text", "") or response.content.decode("utf-8", errors="replace")


def parse_capture_interfaces(page: str) -> list[CaptureInterface]:
    interfaces: list[CaptureInterface] = []
    for match in CAPTURE_INTERFACE_RE.finditer(page or ""):
        label = strip_html(match.group("label")).strip()
        value = match.group("value").strip()
        if not label or not value:
            continue
        interfaces.append(CaptureInterface(label=label, value=value))
    return interfaces


def preferred_capture_interface(interfaces: list[CaptureInterface]) -> CaptureInterface | None:
    for item in interfaces:
        if "management traffic" in item.label.casefold():
            return item
    for item in interfaces:
        if item.label.casefold().startswith("wifi"):
            return item
    return interfaces[0] if interfaces else None


def interface_by_value(interfaces: list[CaptureInterface], value: str) -> CaptureInterface | None:
    for item in interfaces:
        if item.value == value:
            return item
    return None


def stop_capture(session: Any, capture_url: str, sid: str, interface: CaptureInterface) -> None:
    params = {"sid": sid, "capture": "Stop", **interface.stop_params}
    try:
        session.get(capture_url, params=params, timeout=10)
    except TypeError:
        session.get(capture_url, params=params)
    except Exception:
        pass


def parse_pcap(data: bytes, observed_at: str) -> dict[str, Any]:
    if len(data) < 24:
        return {"available": False, "packet_count": 0, "frames": [], "error": "No PCAP data captured."}
    endian = "<"
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic not in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return {"available": False, "packet_count": 0, "frames": [], "error": "Capture is not a classic PCAP file."}
    try:
        _version_major, _version_minor, _tz, _sigfigs, _snaplen, linktype = struct.unpack(f"{endian}HHIIII", data[4:24])
    except struct.error:
        return {"available": False, "packet_count": 0, "frames": [], "error": "PCAP header is truncated."}
    offset = 24
    packets = 0
    frames: list[dict[str, Any]] = []
    while offset + 16 <= len(data):
        try:
            ts_sec, ts_usec, included_len, original_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        except struct.error:
            break
        offset += 16
        payload = data[offset : offset + included_len]
        offset += included_len
        if len(payload) < min(included_len, 10):
            continue
        packets += 1
        frame = parse_80211_payload(payload, linktype, ts_sec, ts_usec, observed_at, original_len)
        if frame:
            frames.append(frame)
    return {
        "available": True,
        "linktype": linktype,
        "packet_count": packets,
        "frames": frames[:300],
        "probe_request_count": sum(1 for frame in frames if frame.get("event") == "probe_request"),
    }


def parse_80211_payload(
    payload: bytes, linktype: int, ts_sec: int, ts_usec: int, observed_at: str, original_len: int
) -> dict[str, Any] | None:
    header_offset = 0
    if linktype == LINKTYPE_RADIOTAP:
        if len(payload) < 8:
            return None
        header_offset = int.from_bytes(payload[2:4], "little", signed=False)
    elif linktype != LINKTYPE_IEEE802_11:
        return None
    if len(payload) < header_offset + 24:
        return None
    frame_control = int.from_bytes(payload[header_offset : header_offset + 2], "little", signed=False)
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    if frame_type != 0:
        return None
    event = {
        0: "association_request",
        1: "association_response",
        4: "probe_request",
        5: "probe_response",
        10: "disassociation",
        11: "authentication",
        12: "deauthentication",
    }.get(subtype)
    if not event:
        return None
    body = payload[header_offset + 24 :]
    tags = parse_80211_tags(body)
    return {
        "time": (
            datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000).astimezone().isoformat() if ts_sec else observed_at
        ),
        "event": event,
        "source_mac": mac_from_bytes(payload[header_offset + 10 : header_offset + 16]),
        "destination_mac": mac_from_bytes(payload[header_offset + 4 : header_offset + 10]),
        "bssid": mac_from_bytes(payload[header_offset + 16 : header_offset + 22]),
        "ssid": tags.get("ssid", ""),
        "channel": tags.get("channel", ""),
        "frame_subtype": subtype,
        "packet_bytes": original_len,
    }


def parse_80211_tags(body: bytes) -> dict[str, str]:
    tags: dict[str, str] = {}
    offset = 0
    while offset + 2 <= len(body):
        tag_id = body[offset]
        length = body[offset + 1]
        offset += 2
        value = body[offset : offset + length]
        offset += length
        if len(value) != length:
            break
        if tag_id == 0:
            tags["ssid"] = value.decode("utf-8", errors="replace")
        elif tag_id == 3 and value:
            tags["channel"] = str(value[0])
    return tags


def mac_from_bytes(value: bytes) -> str:
    if len(value) != 6:
        return ""
    return ":".join(f"{part:02x}" for part in value)


def strip_html(value: str) -> str:
    return re.sub(r"<[^>]*>", "", value).replace("&nbsp;", " ")
