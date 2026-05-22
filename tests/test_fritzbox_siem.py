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


def fetch_events(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    return {row["event_kind"]: row for row in conn.execute("""
            SELECT event_kind, action, outcome, severity, confidence, evidence_level, protocol, fields_json
            FROM siem_events
            ORDER BY id
            """)}


def fetch_correlations(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT rule_id FROM siem_correlations ORDER BY id"))
