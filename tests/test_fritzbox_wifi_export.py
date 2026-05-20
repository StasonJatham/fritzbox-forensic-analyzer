import importlib.util
import sys
from datetime import datetime
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "fritzbox_wifi_export.py"
SPEC = importlib.util.spec_from_file_location("fritzbox_wifi_export", MODULE_PATH)
fritzbox_wifi_export = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules["fritzbox_wifi_export"] = fritzbox_wifi_export
SPEC.loader.exec_module(fritzbox_wifi_export)


def test_parse_connected_wifi_event() -> None:
    entry = fritzbox_wifi_export.FritzLogEntry(
        timestamp=datetime(2026, 5, 20, 14, 0, 0).astimezone(),
        message="WLAN-Gerät angemeldet: phone, 192.0.2.30, aa:bb:cc:dd:ee:ff",
        raw="20.05.2026 14:00:00 WLAN-Gerät angemeldet: phone, 192.0.2.30, aa:bb:cc:dd:ee:ff",
    )

    event = fritzbox_wifi_export.parse_wifi_event(entry, {})

    assert event["event"] == "connected"
    assert event["mac"] == "aa:bb:cc:dd:ee:ff"
    assert event["ip"] == "192.0.2.30"


def test_parse_device_log_timestamp() -> None:
    entries = fritzbox_wifi_export.parse_device_log(
        "20.05.2026 14:00:00 WLAN-Gerät angemeldet: phone, 192.0.2.30, aa:bb:cc:dd:ee:ff"
    )

    assert entries[0].timestamp is not None
    assert entries[0].message.startswith("WLAN-Gerät angemeldet")


def test_entry_to_dict_classifies_router_log() -> None:
    entry = fritzbox_wifi_export.FritzLogEntry(
        timestamp=datetime(2026, 5, 20, 14, 0, 0).astimezone(),
        message="Internetverbindung wurde erfolgreich hergestellt.",
        raw="20.05.2026 14:00:00 Internetverbindung wurde erfolgreich hergestellt.",
    )

    data = fritzbox_wifi_export.entry_to_dict(entry)

    assert data["category"] == "internet"
    assert data["timestamp"].startswith("2026-05-20T14:00:00")


def test_host_seen_index_derives_first_last_and_connection_time() -> None:
    hosts = [
        {
            "NewHostName": "phone",
            "NewMACAddress": "AA:BB:CC:DD:EE:FF",
            "NewIPAddress": "192.0.2.30",
            "NewInterfaceType": "802.11",
            "NewActive": "1",
        }
    ]
    event_log = [
        {
            "timestamp": "2026-05-20T13:00:00+02:00",
            "message": "DHCP assigned 192.0.2.30 to phone",
            "mac": None,
            "ip": "192.0.2.30",
        }
    ]
    wifi_events = [
        {
            "timestamp": "2026-05-20T14:00:00+02:00",
            "event": "connected",
            "hostname": "phone",
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.0.2.30",
        }
    ]

    seen = fritzbox_wifi_export.build_host_seen_index(hosts, event_log, wifi_events)
    host = fritzbox_wifi_export.host_to_dict(hosts[0], seen[fritzbox_wifi_export.host_identity(hosts[0])])

    assert host["first_seen"] == "2026-05-20T13:00:00+02:00"
    assert host["last_seen"] == "2026-05-20T14:00:00+02:00"
    assert host["last_connected"] == "2026-05-20T14:00:00+02:00"


def test_landevice_query_derives_ui_last_connected_time() -> None:
    hosts = [
        {
            "NewHostName": "tablet",
            "NewMACAddress": "AA:BB:CC:DD:EE:FF",
            "NewIPAddress": "192.0.2.44",
            "NewInterfaceType": "802.11",
            "NewActive": "0",
        }
    ]
    records = fritzbox_wifi_export.parse_landevice_query(
        '{"mq_landevices":[{"UID":"landevice1","ip":"192.0.2.44","mac":"AA:BB:CC:DD:EE:FF",'
        '"name":"tablet","active":"0","firstused":1777272000,"lastused":1777725960}]}'
    )

    seen = fritzbox_wifi_export.build_host_seen_index(hosts, [], [], landevice_records=records)
    host = fritzbox_wifi_export.host_to_dict(hosts[0], seen[fritzbox_wifi_export.host_identity(hosts[0])])

    assert host["first_seen"].startswith("2026-04-27T")
    assert host["last_seen"].startswith("2026-05-02T")
    assert host["last_connected"].startswith("2026-05-02T")
    assert host["last_activity_source"] == "fritzbox_landevice_lastused"
