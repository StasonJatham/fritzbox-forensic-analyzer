from __future__ import annotations

import struct

from fritzbox_live_capture import parse_capture_interfaces, parse_pcap


def test_parse_capture_interfaces_finds_wlan_management() -> None:
    html = """
    <tr><th>wifi0</th><td><button type="submit" name="start" value="1-wifi0">Start</button></td></tr>
    <tr><th>WLAN Management Traffic - Schnittstelle 0</th><td><button type="submit" name="start" value="4-128">Start</button></td></tr>
    """

    rows = parse_capture_interfaces(html)

    assert rows[0].label == "wifi0"
    assert rows[1].label.startswith("WLAN Management Traffic")
    assert rows[1].stop_params == {"type": "4", "minor": "128", "iface": rows[1].label}


def test_parse_pcap_extracts_probe_request() -> None:
    frame = bytes.fromhex(
        "4000"  # probe request frame control
        "0000"  # duration
        "ffffffffffff"  # destination
        "aabbccddeeff"  # source/transmitter
        "ffffffffffff"  # bssid
        "0000"  # seq
        "000454657374"  # SSID tag: Test
        "030106"  # DS channel 6
    )
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    packet_header = struct.pack("<IIII", 1_779_305_200, 123000, len(frame), len(frame))
    pcap = global_header + packet_header + frame

    parsed = parse_pcap(pcap, "2026-05-20T22:00:00+02:00")

    assert parsed["packet_count"] == 1
    assert parsed["probe_request_count"] == 1
    assert parsed["frames"][0]["event"] == "probe_request"
    assert parsed["frames"][0]["source_mac"] == "aa:bb:cc:dd:ee:ff"
    assert parsed["frames"][0]["ssid"] == "Test"
    assert parsed["frames"][0]["channel"] == "6"
