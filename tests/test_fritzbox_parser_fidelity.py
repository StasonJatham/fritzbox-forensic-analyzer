from __future__ import annotations

import json

from fritzbox_artifact_normalizers import (
    extract_data_lua_wlan_associations,
    extract_query_lua_wlan_associations,
)
from fritzbox_parsers import (
    parse_support_wifi_details,
    parse_webui_typed_artifacts,
)

OBSERVED_AT = "2026-05-20T12:00:00+02:00"


def test_support_station_list_snapshot_retains_identity_and_radio_fields() -> None:
    details = parse_support_wifi_details(
        """
uptime = 100000
##### BEGIN SECTION STATION_LIST WLAN client list
  Station management: (is remote station = no)
    mac                     = AA:BB:CC:DD:EE:21
    hostname                = Lab Phone
    ip                      = 192.0.2.21
    station_visible         = 1
    is_active               = true
    is_guest                = no
    role_id                 = 301
    if_name                 = ath1
    connect_state           = 0x05
    speed                   = 866
    last_seen               = 99940
  Station connection:
    bssid                   = AA:BB:CC:00:00:01
    rssi                    = -51
    quality                 = 78
##### END SECTION STATION_LIST
""",
        OBSERVED_AT,
    )

    row = details["wlan_station_state_snapshots"][0]

    assert row["mac"] == "aa:bb:cc:dd:ee:21"
    assert row["hostname"] == "Lab Phone"
    assert row["ip"] == "192.0.2.21"
    assert row["interface"] == "ath1"
    assert row["bssid"] == "aa:bb:cc:00:00:01"
    assert row["active"] is True
    assert row["guest"] is False
    assert row["last_seen"] == "2026-05-20T11:59:00+02:00"
    assert row["rssi"] == -51
    assert row["quality"] == 78
    assert row["speed"] == "866"


def test_support_hostapd_client_events_include_reason_and_status_codes() -> None:
    details = parse_support_wifi_details(
        """
2026-05-19 19:42:02.446 - ath0: STA AA:BB:CC:DD:EE:22 IEEE 802.11: associated (aid 7 status_code=0)
2026-05-19 19:59:52.227 - ath0: AP-STA-DISCONNECTED AA:BB:CC:DD:EE:22 reason=8 status code=2
""",
        OBSERVED_AT,
    )

    events = details["wlan_ap_client_events"]

    assert events[0]["event_kind"] == "connected"
    assert events[0]["status_code"] == 0
    assert events[1]["event_kind"] == "ap_sta_disconnected"
    assert events[1]["reason_code"] == 8
    assert events[1]["status_code"] == 2


def test_webui_wlan_and_dhcp_camelcase_fields_are_promoted() -> None:
    exports = {
        "query_lua_artifacts_json": json.dumps(
            {
                "wlan_known_devices": {
                    "ok": True,
                    "data": {
                        "devices": [
                            {
                                "macAddress": "AA:BB:CC:DD:EE:23",
                                "hostName": "KnownLaptop",
                                "ipAddress": "198.51.100.23",
                                "isGuest": "1",
                                "lastConnected": "1779271200",
                                "rssiDbm": "-64",
                                "linkRate": "573",
                                "apId": "2",
                            }
                        ]
                    },
                }
            }
        ),
        "data_lua_pages_json": json.dumps(
            {
                "wlanSta": {
                    "ok": True,
                    "data": {
                        "stations": [
                            {
                                "macAddr": "AA:BB:CC:DD:EE:24",
                                "hostName": "UiTablet",
                                "ipAddress": "203.0.113.24",
                                "signalStrength": "-58",
                                "qualityPercent": "72",
                                "ifName": "ath1",
                                "apBssid": "AA:BB:CC:00:00:02",
                                "isActive": "1",
                            }
                        ]
                    },
                },
                "netDhcp": {
                    "ok": True,
                    "data": {
                        "leases": [
                            {
                                "hostName": "LeaseClient",
                                "macAddress": "AA:BB:CC:DD:EE:25",
                                "ipAddress": "192.0.2.25",
                                "leaseEnd": "1779274800",
                                "isActive": "true",
                            }
                        ]
                    },
                },
            }
        ),
    }

    typed = parse_webui_typed_artifacts(exports, OBSERVED_AT)

    known = next(row for row in typed["wlan_station_state_snapshots"] if row["mac"] == "aa:bb:cc:dd:ee:23")
    ui = next(row for row in typed["wlan_station_state_snapshots"] if row["mac"] == "aa:bb:cc:dd:ee:24")
    lease = typed["dhcp_leases"][0]

    assert known["hostname"] == "KnownLaptop"
    assert known["ip"] == "198.51.100.23"
    assert known["guest"] == "1"
    assert known["last_seen"].startswith("2026-05-20T")
    assert known["rssi"] == "-64"
    assert known["speed"] == "573"
    assert known["interface"] == "2"
    assert ui["hostname"] == "UiTablet"
    assert ui["ip"] == "203.0.113.24"
    assert ui["bssid"] == "aa:bb:cc:00:00:02"
    assert ui["rssi"] == "-58"
    assert ui["quality"] == "72"
    assert lease["hostname"] == "LeaseClient"
    assert lease["mac"] == "aa:bb:cc:dd:ee:25"
    assert lease["ip"] == "192.0.2.25"
    assert lease["lease_expires"].startswith("2026-05-20T")
    assert lease["active"] == "true"


def test_webui_association_normalizers_accept_fritzbox_aliases() -> None:
    query_rows = extract_query_lua_wlan_associations(
        {
            "wlan_stations": {
                "ok": True,
                "data": [{"macAddress": "AA:BB:CC:DD:EE:26", "hostName": "Phone", "ipAddress": "192.0.2.26"}],
            }
        },
        OBSERVED_AT,
    )
    data_rows = extract_data_lua_wlan_associations(
        {
            "wlanSta": {
                "ok": True,
                "data": {"stations": [{"macAddr": "AA:BB:CC:DD:EE:27", "hostName": "Watch", "isGuest": "0"}]},
            }
        },
        OBSERVED_AT,
    )

    assert query_rows[0]["mac"] == "aa:bb:cc:dd:ee:26"
    assert query_rows[0]["hostname"] == "Phone"
    assert query_rows[0]["ip"] == "192.0.2.26"
    assert data_rows[0]["mac"] == "aa:bb:cc:dd:ee:27"
    assert data_rows[0]["hostname"] == "Watch"
    assert data_rows[0]["guest"] == "0"
