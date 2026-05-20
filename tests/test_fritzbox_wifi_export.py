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
    assert records[0]["firstused_raw"] == 1777272000
    assert records[0]["lastused_raw"] == 1777725960


def test_landevice_query_falls_back_to_query_lua_artifacts() -> None:
    records = fritzbox_wifi_export.parse_landevice_query(
        """
        {
          "landevice_all": {
            "ok": true,
            "data": {
              "mq_landevices": [
                {
                  "UID": "landevice2",
                  "ip": "192.0.2.45",
                  "mac": "AA:BB:CC:DD:EE:45",
                  "name": "fallback-phone",
                  "lastused": 1777725960
                }
              ]
            }
          }
        }
        """
    )

    assert records[0]["hostname"] == "fallback-phone"
    assert records[0]["last_connected"].startswith("2026-05-02T")


def test_wlan_device_list_xml_creates_current_association_rows() -> None:
    records = fritzbox_wifi_export.parse_wlan_device_lists(
        {
            "wlan_device_list_xml_2": """
            <List>
              <TotalAssociations>1</TotalAssociations>
              <Item>
                <AssociatedDeviceIndex>1</AssociatedDeviceIndex>
                <AssociatedDeviceMACAddress>AA:BB:CC:DD:EE:FF</AssociatedDeviceMACAddress>
                <AssociatedDeviceIPAddress>192.0.2.50</AssociatedDeviceIPAddress>
                <AssociatedDeviceAuthState>1</AssociatedDeviceAuthState>
                <X_AVM-DE_Speed>866</X_AVM-DE_Speed>
                <X_AVM-DE_SignalStrength>91</X_AVM-DE_SignalStrength>
                <AssociatedDeviceChannel>6</AssociatedDeviceChannel>
                <X_AVM-DE_ChannelWidth>80</X_AVM-DE_ChannelWidth>
                <AssociatedDeviceGuest>1</AssociatedDeviceGuest>
              </Item>
            </List>
            """
        },
        "2026-05-20T12:00:00+02:00",
    )
    wifi = fritzbox_wifi_export.build_available_wifi_connections([], [], records)

    assert records[0]["radio_index"] == "2"
    assert records[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert records[0]["guest"] is True
    assert wifi[0]["derived_time_type"] == "wlan_association_snapshot"
    assert wifi[0]["source"] == "wlan_device_list_xml_2"


def test_data_lua_log_json_can_be_used_as_log_fallback() -> None:
    raw = fritzbox_wifi_export.parse_data_lua_log(
        '{"log":{"ok":true,"data":{"log":[{"date":"20.05.26","time":"12:00:00","msg":"WLAN-Gerät angemeldet: phone"}]}}}'
    )

    entries = fritzbox_wifi_export.parse_device_log(raw)

    assert entries[0].message == "WLAN-Gerät angemeldet: phone"
    assert entries[0].timestamp is not None


def test_support_data_parser_extracts_sections_key_values_and_signals() -> None:
    findings = fritzbox_wifi_export.parse_support_data(
        """
##### WLAN diagnostics
SSID: Restaurant WiFi
FirmwareVersion=8.20
client aa:bb:cc:dd:ee:ff has ip 192.0.2.44 via wlan
""",
        "2026-05-20T12:00:00+02:00",
    )

    assert any(row["finding_type"] == "section" and row["section"] == "WLAN diagnostics" for row in findings)
    assert any(row["finding_type"] == "key_value" and row["key"] == "SSID" for row in findings)
    assert any(row["finding_type"] == "signal_line" and "192.0.2.44" in row["value"] for row in findings)


def test_landevice_records_add_hosts_missing_from_official_host_list() -> None:
    records = fritzbox_wifi_export.parse_landevice_query(
        '{"mq_landevices":[{"UID":"landevice42","ip":"192.0.2.77","mac":"AA:BB:CC:DD:EE:77",'
        '"name":"stale-phone","friendly_name":"Stale Phone","interface":"802.11","online":"0",'
        '"vendorname":"ExampleVendor","firstused":1777272000,"lastused":1777725960}]}'
    )

    rows = fritzbox_wifi_export.lan_device_host_rows(records, [])

    assert rows[0]["hostname"] == "stale-phone"
    assert rows[0]["friendly_name"] == "Stale Phone"
    assert rows[0]["vendor"] == "ExampleVendor"
    assert rows[0]["last_connected"].startswith("2026-05-02T")
    assert rows[0]["last_activity_source"] == "fritzbox_landevice_lastused"
