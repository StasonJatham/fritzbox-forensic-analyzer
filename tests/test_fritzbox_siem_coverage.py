from __future__ import annotations

from pathlib import Path

from fritzbox_log_store import ingest_dataset, init_db
from fritzbox_siem_coverage import audit_database


def test_coverage_audit_reports_raw_parser_and_correlation_state(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {
                "support_data_txt": (
                    "2026-05-20 12:01:00.000 - ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:51\n"
                    "2026-05-20 12:02:00.000 - soap:check_async_auth failed from 192.0.2.20:1234\n"
                ),
                "acquisition_manifest_json": (
                    '{"attempts":[{"artifact":"support_data_txt","surface":"support_data","ok":true},'
                    '{"artifact":"data_lua_page_wlanSta","surface":"webui_data_lua","ok":false,'
                    '"error":"timeout"}]}'
                ),
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:01:00+02:00",
                    "category": "wifi",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "source": "support_data_txt",
                    "message": "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:51",
                },
                {
                    "timestamp": "2026-05-20T12:02:00+02:00",
                    "category": "system",
                    "source": "support_data_txt",
                    "message": "soap:check_async_auth failed from 192.0.2.20:1234",
                },
            ],
            "wlan_station_state_snapshots": [
                {
                    "observed_at": "2026-05-20T12:03:00+02:00",
                    "mac": "aa:bb:cc:dd:ee:51",
                    "hostname": "phone",
                    "source": "query_lua_wlan_stations",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    audit = audit_database(db)
    raw_rules = {row["label"] for row in audit["parser"]["raw_artifact_rule_hits"]["rule_hits"]}
    event_rules = {row["label"] for row in audit["parser"]["event_log_rules"]}

    assert audit["status"] == "ok"
    assert audit["tables"]["raw_artifacts"] == 2
    assert audit["tables"]["siem_events"] > 0
    assert "wifi.ap_sta_connected" in raw_rules
    assert "auth.soap_failure" in raw_rules
    assert "wifi.ap_sta_connected" in event_rules
    assert "auth.soap_failure" in event_rules
    assert audit["parser"]["raw_artifact_rule_hits"]["high_value_hits_not_in_event_log"] == []
    assert audit["raw_artifacts"]["failed_attempt_count"] == 1
    assert audit["raw_artifacts"]["attempts_by_artifact"]["data_lua_page_wlanSta"]["last_error"] == "timeout"
    assert "wlan_station_state_snapshots" in audit["typed_artifacts"]["tables_with_rows"]
    typed_row = next(
        row for row in audit["typed_artifacts"]["tables"] if row["table"] == "wlan_station_state_snapshots"
    )
    assert typed_row["sources"] == [{"label": "query_lua_wlan_stations", "count": 1}]


def test_coverage_audit_can_rebuild_missing_siem_views(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
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
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "message": "Anmeldung fehlgeschlagen von 192.0.2.23",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    conn = init_db(db)
    with conn:
        conn.execute("DELETE FROM records_fts WHERE record_type IN ('siem_events', 'siem_correlations')")
        conn.execute("DELETE FROM siem_correlation_events")
        conn.execute("DELETE FROM siem_correlations")
        conn.execute("DELETE FROM siem_events")
    conn.close()

    audit = audit_database(db, refresh_siem=True)

    assert audit["repairs"]["siem_refreshed"]["siem_events"] > 0
    assert audit["status"] in {"ok", "raw_parser_gaps"}
    assert audit["tables"]["siem_events"] > 0


def test_coverage_audit_can_promote_stored_support_logs_for_legacy_runs(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": "2026-05-20 12:04:00.000 - ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:51"},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    audit = audit_database(db, promote_raw_logs=True, refresh_siem=True)

    assert audit["repairs"]["raw_logs_promoted"]["inserted"] == 1
    assert audit["tables"]["event_log"] == 1
    assert audit["tables"]["siem_events"] > 0
    assert audit["parser"]["raw_artifact_rule_hits"]["high_value_hits_not_in_event_log"] == []


def test_coverage_audit_can_reclassify_legacy_event_log_categories(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
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
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "message": "Anmeldung fehlgeschlagen von 192.0.2.23",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    conn = init_db(db)
    with conn:
        conn.execute("UPDATE event_log SET category = 'system', ip = NULL")
    conn.close()

    audit = audit_database(db, reclassify_event_log=True, refresh_siem=True)

    assert audit["repairs"]["event_log_reclassified"]["updated"] == 1
    assert audit["parser"]["stored_category_mismatches"] == []
