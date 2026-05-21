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


def test_parse_support_log_80211_station_events() -> None:
    entries = fritzbox_wifi_export.parse_device_log(
        "2026-05-19 19:42:02.446 - ath1: STA ca:04:95:b2:4c:5b IEEE 802.11: associated (aid 1)\n"
        "2026-05-19 19:59:52.227 - ath1: STA ca:04:95:b2:4c:5b IEEE 802.11: disassociated"
    )
    associated = fritzbox_wifi_export.parse_wifi_event(entries[0], {})
    disassociated = fritzbox_wifi_export.parse_wifi_event(entries[1], {})

    assert entries[0].timestamp is not None
    assert associated["event"] == "connected"
    assert associated["mac"] == "ca:04:95:b2:4c:5b"
    assert disassociated["event"] == "disconnected"


def test_parse_support_log_80211_authentication_event() -> None:
    entries = fritzbox_wifi_export.parse_device_log(
        "2026-05-19 19:42:02.357 - ath1: STA ca:04:95:b2:4c:5b IEEE 802.11: authenticated"
    )
    event = fritzbox_wifi_export.parse_wifi_event(entries[0], {})
    wifi = fritzbox_wifi_export.build_available_wifi_connections([event], [], [])

    assert event["event"] == "authenticated"
    assert wifi[0]["derived_time_type"] == "80211_authentication_event"
    assert wifi[0]["exact_connection_time_available"] is False


def test_parse_support_steering_history_event() -> None:
    entries = fritzbox_wifi_export.parse_device_log(
        "(f) OPTIMISATION RCPI STA CA:04:95:B2:4C:5B from 34:E1:A9:4D:58:EE "
        "(RX -50 dBm) start 2026-03-24 21:48:46 (2485084402) mode BTM "
        "to 34:E1:A9:4D:58:EF (RX -63 dBm) moved 2026-03-24 21:48:47 (2485084500) "
        "ended with SUCCESS at 2026-03-24 21:48:48 (2485084600) in state DONE"
    )
    event = fritzbox_wifi_export.parse_wifi_event(entries[0], {})
    wifi = fritzbox_wifi_export.build_available_wifi_connections([event], [], [])

    assert event["event"] == "steering_observation"
    assert event["timestamp"] == "2026-03-24T21:48:46+01:00"
    assert event["mac"] == "CA:04:95:B2:4C:5B".lower()
    assert event["source_rssi"] == "-50 dBm"
    assert event["result"] == "SUCCESS"
    assert wifi[0]["derived_time_type"] == "80211_steering_history"
    assert wifi[0]["derived_connected_at"] == "2026-03-24T21:48:46+01:00"


def test_parse_support_station_history_intervals() -> None:
    observations = fritzbox_wifi_export.parse_support_wifi_observations(
        """
##### BEGIN SECTION STATION_LIST WLAN client list
  Station management: (is remote station = no)
    mac                     = 2E:3D:37:89:BA:3A
  Connect history:
    (role /         if / connect (status initiator IEEE802.11ReasonCode) / disconnect (status initiator IEEE802.11ReasonCode) / wlan_mode / quality)
      301 /       ath0 /        20260516-111506 (0x00000001 0x09 0x0001) /           20260516-123809 (0x0000001F 0x01 0x0000) /      0x0E /      71
##### END SECTION STATION_LIST
"""
    )
    wifi = fritzbox_wifi_export.build_available_wifi_connections(observations, [], [])

    assert observations[0]["event"] == "station_history_interval"
    assert observations[0]["mac"] == "2e:3d:37:89:ba:3a"
    assert observations[0]["timestamp"] == "2026-05-16T11:15:06+02:00"
    assert observations[0]["disconnected_at"] == "2026-05-16T12:38:09+02:00"
    assert wifi[0]["derived_time_type"] == "80211_station_history_interval"
    assert wifi[0]["exact_connection_time_available"] is True


def test_parse_support_wlan_events_table_rows() -> None:
    observations = fritzbox_wifi_export.parse_support_wifi_observations(
        "     20260516-111501 /              --- / CA:04:95:B2:4C:5B /  30005 /    1 /  286 /  --  /    ----    /    ----    /         0 /         0 / 0x00000601"
    )
    wifi = fritzbox_wifi_export.build_available_wifi_connections(observations, [], [])

    assert observations[0]["event"] == "wlan_event_table_row"
    assert observations[0]["mac"] == "ca:04:95:b2:4c:5b"
    assert observations[0]["timestamp"] == "2026-05-16T11:15:01+02:00"
    assert wifi[0]["derived_time_type"] == "80211_wlan_events_table"


def test_parse_support_wlan_environment_scan_and_station_counters() -> None:
    hints, status = fritzbox_wifi_export.parse_support_wlan_environment(
        """
##### BEGIN SECTION WLAN_SCAN_RESULTS WLAN scan results
Scan results for radio '101':
Scan time: 20.05.2026 22:15:54/[7407912.562]
Scan table:
[BSSID|CHANNEL_INFO|SSID|RSSI|WLAN MODE|CAPS]
[ 0]: '1C:0B:8B:44:F0:98' 2412/2412/ 20/0000/  1-  3 'Karl HQ' (len=7)                            -17 dBm [ 11N 11AX ] [ WPA2_PSK WPA3_PSK PMF PRIVACY ]
##### END SECTION WLAN_SCAN_RESULTS
##### BEGIN SECTION SCAN_EVENTS History of scan requests and finished events
[00] t=20.05.2026 10:31:56/[7365674.807]: SCAN_REQUEST  , radio '101' "ACS-6h", "", HAL returned SUCCESS
##### END SECTION SCAN_EVENTS
##### BEGIN SECTION ENV_INTERFERENCE_HISTORY History of radar and interference events
[00] t=24.02.2026 06:19:48/[10146.150]: INTERFERENCE        , radio '101', primary freq 2437 MHz, active, channel change.
##### END SECTION ENV_INTERFERENCE_HISTORY
##### BEGIN SECTION STATION_LIST WLAN client list
  Station management: (is remote station = no)
    mac                     = 2E:3D:37:89:BA:3A
    cnt_connect_success     = 578
    cnt_connect_fail        = 14
    cnt_disconnect_forced   = 99
    time_mean_connect       = 1029
##### END SECTION STATION_LIST
""",
        "2026-05-20T22:16:00+02:00",
    )

    assert hints[0]["hint_type"] == "wlan_environment_scan_bssid"
    assert hints[0]["mac"] == "1c:0b:8b:44:f0:98"
    assert hints[0]["observed_at"] == "2026-05-20T22:15:54+02:00"
    assert "RSSI -17 dBm" in hints[0]["summary"]
    assert {row["area"] for row in status} == {
        "wlan_scan_event",
        "wlan_interference",
        "wlan_station_counters",
    }
    assert any(row["metric"] == "cnt_connect_fail" and row["value"] == "14" for row in status)


def test_parse_support_ap_handshake_and_association_request() -> None:
    entries = fritzbox_wifi_export.parse_device_log(
        "2026-05-19 19:34:07.235 - HT: Forty MHz Intolerant is set by STA ca:04:95:b2:4c:5b in Association Request\n"
        "2026-05-19 19:34:07.273 - ath0: AP-STA-CONNECTED ca:04:95:b2:4c:5b\n"
        "2026-05-19 19:34:07.431 - ath0: STA ca:04:95:b2:4c:5b WPA: pairwise key handshake completed (RSN)"
    )
    events = [fritzbox_wifi_export.parse_wifi_event(entry, {}) for entry in entries]

    assert [event["event"] for event in events] == [
        "association_request_observed",
        "ap_sta_connected",
        "wpa_pairwise_handshake",
    ]


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
