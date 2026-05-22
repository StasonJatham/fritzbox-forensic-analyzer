from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fritzbox_log_store import ingest_dataset, init_db


def test_fritzbox_siem_typed_rows_get_specific_semantics_and_correlations(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "443",
                    "internal_client": "192.168.178.50",
                    "internal_port": "8443",
                    "description": "admin ui",
                    "enabled": "1",
                    "source": "WANIPConn:GetGenericPortMappingEntry",
                }
            ],
            "wlan_ap_client_events": [
                {
                    "event_time": "2026-05-20T12:01:00+02:00",
                    "event_kind": "ap_sta_connected",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "interface": "ath0",
                    "source": "support_data_hostapd",
                    "message": "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:01",
                },
                {
                    "event_time": "2026-05-20T12:05:00+02:00",
                    "event_kind": "ap_sta_disconnected",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "interface": "ath0",
                    "reason_code": "8",
                    "source": "support_data_hostapd",
                    "message": "ath0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01 reason=8",
                },
            ],
            "wlan_station_intervals": [
                {
                    "connected_at": "2026-05-20T11:00:00+02:00",
                    "disconnected_at": "2026-05-20T11:10:00+02:00",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "interface": "ath1",
                    "source": "support_data_station_list",
                }
            ],
            "dhcp_leases": [
                {
                    "observed_at": "2026-05-20T12:00:00+02:00",
                    "hostname": "laptop",
                    "mac": "aa:bb:cc:dd:ee:03",
                    "ip": "192.168.178.30",
                    "active": "1",
                    "source": "data_lua_netDhcp",
                },
                {
                    "observed_at": "2026-05-20T12:10:00+02:00",
                    "hostname": "laptop",
                    "mac": "aa:bb:cc:dd:ee:03",
                    "ip": "192.168.178.31",
                    "active": "1",
                    "source": "data_lua_netDhcp",
                },
            ],
            "security_advisories": [
                {
                    "advisory_id": "query_lua_user_remote_rights",
                    "severity": "medium",
                    "category": "User rights",
                    "title": "FRITZ!Box user has internet or VPN rights",
                    "subject": "analyst",
                    "status": "review",
                    "recommendation": "Verify remote rights.",
                    "source": "query_lua_user_rights",
                    "confidence": "medium",
                    "evidence_json": {"rights": {"frominternet": "1", "vpn_access": "1"}},
                }
            ],
        },
        db,
    )

    conn = init_db(db)
    try:
        events = fetch_events(conn)
        correlations = fetch_correlations(conn)
    finally:
        conn.close()

    assert events["security.wan_port_mapping_enabled"]["severity"] == "critical"
    assert events["security.wan_port_mapping_enabled"]["confidence"] == "high"
    assert events["wifi.ap_sta_connected"]["action"] == "connect"
    assert events["wifi.ap_sta_disconnected"]["outcome"] == "disconnected"
    assert events["wifi.station_history_interval"]["confidence"] == "high"
    assert json.loads(events["wifi.station_history_interval"]["fields_json"])["duration_seconds"] == 600
    assert events["network.dhcp_lease_observed"]["protocol"] == "DHCP"
    assert events["security.user_remote_rights"]["action"] == "review_user_rights"
    assert events["security.user_remote_rights"]["evidence_level"] == "inferred"

    rule_ids = {row["rule_id"] for row in correlations}
    assert "wifi.session_fragment" in rule_ids
    assert "wifi.station_history_interval" in rule_ids
    assert "network.dhcp_lease_change" in rule_ids
    assert "security.exposure_indicator" in rule_ids


def test_deauthentication_burst_creates_siem_alert(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    station_mac = "aa:bb:cc:dd:ee:10"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "wlan_ap_client_events": [
                {
                    "event_time": "2026-05-20T12:01:00+02:00",
                    "event_kind": "deauthenticated",
                    "mac": station_mac,
                    "client_mac": station_mac,
                    "source_bssid": "34:e1:a9:4d:58:ee",
                    "channel": "6",
                    "interface": "ath0",
                    "reason_code": "3",
                    "source": "support_data_hostapd",
                    "message": f"ath0: STA {station_mac} IEEE 802.11: deauthenticated reason=3",
                },
                {
                    "event_time": "2026-05-20T12:04:00+02:00",
                    "event_kind": "disassociated",
                    "mac": station_mac,
                    "client_mac": station_mac,
                    "source_bssid": "34:e1:a9:4d:58:ee",
                    "channel": "6",
                    "interface": "ath0",
                    "reason_code": "8",
                    "source": "support_data_hostapd",
                    "message": f"ath0: STA {station_mac} IEEE 802.11: disassociated reason=8",
                },
                {
                    "event_time": "2026-05-20T12:08:00+02:00",
                    "event_kind": "ap_sta_disconnected",
                    "mac": station_mac,
                    "interface": "ath0",
                    "reason_code": "8",
                    "source": "support_data_hostapd",
                    "message": f"ath0: AP-STA-DISCONNECTED {station_mac} reason=8",
                },
            ],
        },
        db,
    )

    conn = init_db(db)
    try:
        events = fetch_events(conn)
        deauth = conn.execute("""
            SELECT event_time, mac, fields_json
            FROM siem_events
            WHERE event_kind = 'wifi.deauth_seen'
            """).fetchone()
        disassoc = conn.execute("""
            SELECT fields_json
            FROM siem_events
            WHERE event_kind = 'wifi.disassoc_seen'
            """).fetchone()
        alert = conn.execute("""
            SELECT correlation_type, event_count, severity, summary, fields_json
            FROM siem_correlations
            WHERE rule_id = 'possible_deauth_attack'
            """).fetchone()
    finally:
        conn.close()

    assert events["wifi.deauth_seen"]["action"] == "deauth_seen"
    assert events["wifi.disassoc_seen"]["action"] == "disassoc_seen"
    assert deauth is not None
    assert deauth["event_time"] == "2026-05-20T12:01:00+02:00"
    assert deauth["mac"] == station_mac
    assert disassoc is not None
    deauth_fields = json.loads(deauth["fields_json"])
    disassoc_fields = json.loads(disassoc["fields_json"])
    assert deauth_fields["timestamp"] == "2026-05-20T12:01:00+02:00"
    assert deauth_fields["client_mac"] == station_mac
    assert deauth_fields["source_bssid"] == "34:e1:a9:4d:58:ee"
    assert deauth_fields["channel"] == "6"
    assert disassoc_fields["client_mac"] == station_mac
    assert alert is not None
    assert alert["correlation_type"] == "alert"
    assert alert["event_count"] == 3
    assert alert["severity"] == "high"
    assert "deauthentication" in alert["summary"]
    fields = json.loads(alert["fields_json"])
    assert fields["threshold"] == 3
    assert fields["window_seconds"] == 600
    assert fields["burst_count"] == 3


def test_fritzbox_specific_wan_and_dhcp_alerts(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "443",
                    "internal_client": "192.168.178.50",
                    "internal_port": "8443",
                    "description": "admin ui",
                    "enabled": "1",
                    "source": "WANIPConn:GetGenericPortMappingEntry",
                },
                {
                    "protocol": "TCP",
                    "external_port": "12345",
                    "internal_client": "192.168.178.51",
                    "internal_port": "12345",
                    "description": "custom service",
                    "enabled": "1",
                    "source": "WANIPConn:GetGenericPortMappingEntry",
                },
            ],
            "dhcp_leases": [
                {
                    "observed_at": "2026-05-20T12:00:00+02:00",
                    "hostname": "laptop",
                    "mac": "aa:bb:cc:dd:ee:30",
                    "ip": "192.168.178.30",
                    "active": "1",
                    "source": "data_lua_netDhcp",
                },
                {
                    "observed_at": "2026-05-20T12:05:00+02:00",
                    "hostname": "phone",
                    "mac": "aa:bb:cc:dd:ee:31",
                    "ip": "192.168.178.30",
                    "active": "1",
                    "source": "data_lua_netDhcp",
                },
            ],
        },
        db,
    )

    conn = init_db(db)
    try:
        wan_alert = conn.execute("""
            SELECT correlation_type, entity_key, event_count, severity, fields_json
            FROM siem_correlations
            WHERE rule_id = 'security.high_risk_wan_exposure'
            """).fetchone()
        dhcp_alert = conn.execute("""
            SELECT correlation_type, entity_key, event_count, severity, fields_json
            FROM siem_correlations
            WHERE rule_id = 'network.dhcp_ip_conflict'
            """).fetchone()
    finally:
        conn.close()

    assert wan_alert is not None
    assert wan_alert["correlation_type"] == "alert"
    assert wan_alert["entity_key"] == "ip:192.168.178.50"
    assert wan_alert["event_count"] == 1
    assert wan_alert["severity"] == "critical"
    wan_fields = json.loads(wan_alert["fields_json"])
    assert wan_fields["ports"] == ["443"]
    assert wan_fields["protocols"] == ["TCP"]

    assert dhcp_alert is not None
    assert dhcp_alert["correlation_type"] == "alert"
    assert dhcp_alert["entity_key"] == "ip:192.168.178.30"
    assert dhcp_alert["event_count"] == 2
    assert dhcp_alert["severity"] == "medium"
    dhcp_fields = json.loads(dhcp_alert["fields_json"])
    assert dhcp_fields["macs"] == ["aa:bb:cc:dd:ee:30", "aa:bb:cc:dd:ee:31"]


def test_fritzbox_auth_dns_and_wlan_counter_alerts(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    dns_events = [
        {
            "timestamp": f"2026-05-20T12:{minute:02d}:00+02:00",
            "category": "support data",
            "source": "support_data_txt",
            "message": (
                "probe triggered, loose best server 217.237.151.51:53 - " f"timeout on IN A test-{minute}.example"
            ),
        }
        for minute in (0, 10, 20, 30, 40)
    ]
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "router",
                    "ip": "192.168.178.44",
                    "source": "device_log",
                    "message": (
                        "Anmeldung an der FRITZ!Box-Benutzeroberfläche von IP-Adresse "
                        "192.168.178.44 gescheitert (falsches Kennwort)."
                    ),
                },
                {
                    "timestamp": "2026-05-20T12:03:00+02:00",
                    "category": "router",
                    "ip": "192.168.178.44",
                    "source": "device_log",
                    "message": (
                        "Anmeldung an der FRITZ!Box-Benutzeroberfläche von IP-Adresse "
                        "192.168.178.44 gescheitert (falsches Kennwort)."
                    ),
                },
                {
                    "timestamp": "2026-05-20T12:05:00+02:00",
                    "category": "auth",
                    "ip": "192.168.178.44",
                    "source": "support_data_txt",
                    "message": "validate_user: login success from 192.168.178.44",
                },
                *dns_events,
            ],
            "network_status_snapshots": [
                {
                    "observed_at": "2026-05-20T12:00:00+02:00",
                    "area": "wlan_station_counters",
                    "metric": "cnt_connect_fail",
                    "value": "125",
                    "unit": "count",
                    "source": "support_station_list",
                    "confidence": "medium",
                    "mac": "aa:bb:cc:dd:ee:40",
                }
            ],
            "security_advisories": [
                {
                    "advisory_id": "query_lua_user_remote_rights",
                    "severity": "medium",
                    "category": "User rights",
                    "title": "FRITZ!Box user has internet rights",
                    "subject": "analyst",
                    "status": "review",
                    "recommendation": "Verify remote rights.",
                    "source": "query_lua_user_rights",
                    "confidence": "medium",
                }
            ],
        },
        db,
    )

    conn = init_db(db)
    try:
        rule_ids = {row["rule_id"] for row in conn.execute("SELECT rule_id FROM siem_correlations")}
        auth_alert = conn.execute("""
            SELECT severity, entity_key, event_count, fields_json
            FROM siem_correlations
            WHERE rule_id = 'auth.login_success_after_failures'
            """).fetchone()
        dns_alert = conn.execute("""
            SELECT severity, entity_key, event_count, fields_json
            FROM siem_correlations
            WHERE rule_id = 'network.dns_probe_timeout_burst'
            """).fetchone()
        wlan_alert = conn.execute("""
            SELECT severity, entity_key, event_count, fields_json
            FROM siem_correlations
            WHERE rule_id = 'wifi.station_high_connect_failures'
            """).fetchone()
    finally:
        conn.close()

    assert "security.exposure_with_auth_failures" in rule_ids
    assert auth_alert is not None
    assert auth_alert["severity"] == "medium"
    assert auth_alert["entity_key"] == "ip:192.168.178.44"
    assert auth_alert["event_count"] == 3
    assert json.loads(auth_alert["fields_json"])["failure_count"] == 2

    assert dns_alert is not None
    assert dns_alert["severity"] == "medium"
    assert dns_alert["entity_key"] == "dns_server:217.237.151.51"
    assert dns_alert["event_count"] == 5
    assert json.loads(dns_alert["fields_json"])["threshold"] == 5

    assert wlan_alert is not None
    assert wlan_alert["severity"] == "high"
    assert wlan_alert["entity_key"] == "mac:aa:bb:cc:dd:ee:40"
    assert json.loads(wlan_alert["fields_json"])["value"] == 125


def fetch_events(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    return {row["event_kind"]: row for row in conn.execute("""
            SELECT event_kind, action, outcome, severity, confidence, evidence_level, protocol, fields_json
            FROM siem_events
            ORDER BY id
            """)}


def fetch_correlations(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT rule_id FROM siem_correlations ORDER BY id"))
