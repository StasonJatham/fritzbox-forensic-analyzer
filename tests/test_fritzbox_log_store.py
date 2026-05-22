import json
from pathlib import Path

from fritzbox_log_store import (
    analysis_snapshot,
    evidence_for_record,
    get_settings,
    ingest_dataset,
    init_db,
    investigation_snapshot,
    latest_snapshot,
    list_runs,
    query_records,
    query_timeline,
    reparse_support_wlan_environment,
    save_settings,
    siem_search_facets,
)


def test_query_records_uses_backend_fts_and_pagination(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {
                "device_log_xml": "<DeviceLog />",
                "support_data_txt": "FRITZ!Box support data\nsupport device system wlan dsl mesh kernel\n",
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "mac": None,
                    "message": "Anmeldung falsches Kennwort",
                }
            ],
            "available_wifi_connections": [
                {
                    "derived_connected_at": "2026-05-20T11:00:00+02:00",
                    "derived_time_type": "mesh_last_observed",
                    "derived_time_confidence": "low",
                    "exact_connection_time_available": False,
                    "event": "known_wifi_device",
                    "hostname": "iPhone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.21",
                    "source": "mesh_list",
                    "confidence": "known_wifi_device_no_connection_timestamp",
                    "message": "Known WLAN device",
                }
            ],
            "known_hosts": [],
        },
        db,
    )

    wifi = query_records(db, "iphone", "wifi", limit=10, offset=0)
    log = query_records(db, "falsches kennwort", "log", limit=1, offset=0, category="auth")

    assert wifi["total"] == 1
    assert wifi["rows"][0]["hostname"] == "iPhone"
    assert log["total"] == 1
    assert log["rows"][0]["ip"] == "192.0.2.23"


def test_ui_queries_preserve_parsed_artifact_sources(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {
                "device_log_xml_wlan": "<DeviceLog />",
                "wlan_device_list_xml_2": "<List />",
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "wifi",
                    "ip": "192.0.2.51",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "source": "device_log_xml",
                    "message": "WLAN-Gerät angemeldet: phone",
                },
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "wifi",
                    "ip": "192.0.2.51",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "source": "device_log_xml_wlan",
                    "message": "WLAN-Gerät angemeldet: phone",
                },
            ],
            "wlan_associations": [
                {
                    "observed_at": "2026-05-20T12:01:00+02:00",
                    "radio_index": "2",
                    "association_index": "1",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "ip": "192.0.2.51",
                    "hostname": "phone",
                    "source": "wlan_device_list_xml_2",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    log_rows = query_records(db, "phone", "log", limit=10, offset=0)
    timeline = query_timeline(db, "phone", limit=10)
    wlan_rows = query_records(db, "phone", "wlan_associations", limit=10, offset=0)

    assert log_rows["total"] == 2
    assert {row["source"] for row in log_rows["rows"]} == {"device_log_xml", "device_log_xml_wlan"}
    assert {row["source"] for row in timeline["rows"]} >= {"device_log_xml", "device_log_xml_wlan"}
    assert wlan_rows["rows"][0]["source"] == "wlan_device_list_xml_2"


def test_ingest_reclassifies_imported_event_log_rows_with_shared_parser(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "system",
                    "message": "soap:check_async_auth failed with -1 from 192.168.178.23:54587",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    rows = query_records(db, "check_async_auth", "log", limit=10, offset=0, category="auth")

    assert rows["total"] == 1
    assert rows["rows"][0]["category"] == "auth"
    assert rows["rows"][0]["ip"] == "192.168.178.23"


def test_siem_events_and_correlations_normalize_parsed_evidence(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml_wlan": "<DeviceLog />"},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "wifi",
                    "ip": "192.0.2.51",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "source": "device_log_xml_wlan",
                    "message": "WLAN-Anmeldung ist fehlgeschlagen: phone, 192.0.2.51, AA:BB:CC:DD:EE:51",
                }
            ],
            "available_wifi_connections": [
                {
                    "derived_connected_at": "2026-05-20T12:01:00+02:00",
                    "derived_time_type": "wlan_association_snapshot",
                    "derived_time_confidence": "high",
                    "exact_connection_time_available": False,
                    "event": "associated_snapshot",
                    "hostname": "phone",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "ip": "192.0.2.51",
                    "source": "wlan_device_list_xml_2",
                    "confidence": "high",
                    "message": "WLAN association snapshot phone",
                }
            ],
            "known_hosts": [],
        },
        db,
    )

    events = query_records(db, "phone", "events", limit=10, offset=0)
    correlations = query_records(db, "phone", "correlations", limit=10, offset=0)

    assert events["total"] >= 2
    failed = next(row for row in events["rows"] if row["event_kind"] == "wifi.connection_failed")
    assert failed["event_category"] == "wifi"
    assert failed["outcome"] == "failure"
    assert failed["source"] == "device_log_xml_wlan"
    assert '"wifi"' in failed["tags_json"]
    assert '"raw_message"' in failed["fields_json"]
    assert correlations["total"] >= 1
    assert correlations["rows"][0]["event_count"] >= 2
    assert query_records(db, "wifi.connection_failed", "all", limit=10, offset=0)["total"] >= 1


def test_siem_correlations_do_not_promote_diagnostic_fragments_to_hosts(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": "wan:0 0 secs, refcnt 4"},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "system",
                    "ip": "192.0.2.51",
                    "mac": "AA:BB:CC:DD:EE:51",
                    "source": "support_data_txt",
                    "message": "AA:BB:CC:DD:EE:51 wan:0 0 secs, refcnt 4",
                },
                {
                    "timestamp": "2026-05-20T12:01:00+02:00",
                    "category": "system",
                    "ip": "0.0.0.0",
                    "mac": "00:00:00:00:00:00",
                    "source": "support_data_txt",
                    "message": "00:00:00:00:00:00 ignored placeholder",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    conn = init_db(db)
    try:
        keys = {row["entity_key"] for row in conn.execute("SELECT entity_key FROM siem_correlations")}
    finally:
        conn.close()

    assert "host:0 0 secs" not in keys
    assert "ip:0.0.0.0" not in keys
    assert "mac:00:00:00:00:00:00" not in keys
    assert "mac:aa:bb:cc:dd:ee:51" in keys
    assert "ip:192.0.2.51" in keys


def test_siem_correlation_rules_link_evidence_events(tmp_path: Path) -> None:
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
                    "timestamp": f"2026-05-20T12:0{minute}:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "mac": None,
                    "source": "device_log_xml",
                    "message": f"Anmeldung fehlgeschlagen von 192.0.2.23 Versuch {minute}",
                }
                for minute in range(3)
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    rule_hits = query_records(db, "auth.failed_login_burst", "correlations", limit=10, offset=0)

    assert rule_hits["total"] == 1
    hit = rule_hits["rows"][0]
    assert hit["rule_id"] == "auth.failed_login_burst"
    assert hit["correlation_type"] == "rule_match"
    assert hit["event_count"] == 3
    assert hit["window_start"] == "2026-05-20T12:00:00+02:00"
    assert hit["window_end"] == "2026-05-20T12:02:00+02:00"
    evidence = evidence_for_record(db, "correlations", hit["id"])
    assert len(evidence["record"]["linked_events"]) == 3
    assert {event["event_kind"] for event in evidence["record"]["linked_events"]} == {"auth.login_failure"}


def test_siem_wifi_session_fragments_pair_hostapd_markers(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": "hostapd log"},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "wifi",
                    "source": "support_data_txt",
                    "message": "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:99",
                },
                {
                    "timestamp": "2026-05-20T12:45:00+02:00",
                    "category": "wifi",
                    "source": "support_data_txt",
                    "message": "ath0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:99",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    rule_hits = query_records(db, "wifi.session_fragment", "correlations", limit=10, offset=0)

    assert rule_hits["total"] == 1
    hit = rule_hits["rows"][0]
    assert hit["entity_key"] == "mac:aa:bb:cc:dd:ee:99"
    assert hit["first_seen"] == "2026-05-20T12:00:00+02:00"
    assert hit["last_seen"] == "2026-05-20T12:45:00+02:00"
    fields = json.loads(hit["fields_json"])
    assert fields["duration_seconds"] == 2700


def test_siem_timeline_and_facets_use_normalized_events(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:45"},
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "wifi",
                    "source": "support_data_txt",
                    "message": "ath0: AP-STA-CONNECTED aa:bb:cc:dd:ee:45",
                }
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    timeline = query_timeline(db, "AP-STA-CONNECTED", category="wifi", limit=10, offset=0)
    facets = siem_search_facets(db, "aa:bb:cc:dd:ee:45", category="wifi")

    assert timeline["total"] == 1
    assert timeline["rows"][0]["record_type"] == "siem_events"
    assert timeline["rows"][0]["event_class"] == "wifi"
    assert any(item["value"] == "wifi.ap_sta_connected" for item in facets["facets"]["kind"])
    assert any(item["value"] == "wifi.ap_sta_connected" for item in facets["facets"]["parser_rule"])


def test_siem_burst_rules_use_canonical_key_and_emit_separate_windows(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    event_log = []
    for hour in ("12", "13"):
        for minute in range(3):
            event_log.append(
                {
                    "timestamp": f"2026-05-20T{hour}:0{minute}:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "mac": "AA:BB:CC:DD:EE:23",
                    "source": "device_log_xml",
                    "message": f"Anmeldung fehlgeschlagen von 192.0.2.23 Versuch {hour}:{minute}",
                }
            )
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
            "event_log": event_log,
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    rule_hits = query_records(db, "auth.failed_login_burst", "correlations", limit=10, offset=0)
    ip_pivot = query_records(db, "192.0.2.23", "correlations", limit=10, offset=0)

    assert rule_hits["total"] == 2
    assert {row["entity_key"] for row in rule_hits["rows"]} == {"mac:aa:bb:cc:dd:ee:23"}
    assert {row["event_count"] for row in rule_hits["rows"]} == {3}
    assert ip_pivot["total"] >= 2


def test_siem_burst_windows_sort_by_absolute_time(tmp_path: Path) -> None:
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
                    "ip": "192.0.2.24",
                    "source": "device_log_xml",
                    "message": "Anmeldung fehlgeschlagen von 192.0.2.24 Versuch 1",
                },
                {
                    "timestamp": "2026-05-20T10:01:00+00:00",
                    "category": "auth",
                    "ip": "192.0.2.24",
                    "source": "device_log_xml",
                    "message": "Anmeldung fehlgeschlagen von 192.0.2.24 Versuch 2",
                },
                {
                    "timestamp": "2026-05-20T12:02:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.24",
                    "source": "device_log_xml",
                    "message": "Anmeldung fehlgeschlagen von 192.0.2.24 Versuch 3",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    rule_hits = query_records(db, "auth.failed_login_burst", "correlations", limit=10, offset=0)

    assert rule_hits["total"] == 1
    assert rule_hits["rows"][0]["window_start"] == "2026-05-20T12:00:00+02:00"
    assert rule_hits["rows"][0]["window_end"] == "2026-05-20T12:02:00+02:00"


def test_disabled_wan_mapping_does_not_create_exposure_correlation(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "443",
                    "internal_client": "192.0.2.10",
                    "internal_port": "443",
                    "enabled": "0",
                    "source": "test_fixture",
                }
            ],
        },
        db,
    )

    assert query_records(db, "security.exposure_indicator", "correlations", limit=10, offset=0)["total"] == 0
    assert query_records(db, "443", "wan_port_mappings", limit=10, offset=0)["total"] == 1


def test_correlation_time_filter_uses_window_overlap(tmp_path: Path) -> None:
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
                    "timestamp": f"2026-05-20T12:0{minute}:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.25",
                    "source": "device_log_xml",
                    "message": f"Anmeldung fehlgeschlagen von 192.0.2.25 Versuch {minute}",
                }
                for minute in range(3)
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    overlaps = query_records(
        db,
        "auth.failed_login_burst",
        "correlations",
        limit=10,
        offset=0,
        start="2026-05-20T12:01:00+02:00",
        end="2026-05-20T12:01:30+02:00",
    )

    assert overlaps["total"] == 1


def test_all_evidence_search_returns_ranked_parsed_rows_and_filters(tmp_path: Path) -> None:
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
                    "mac": "AA:BB:CC:DD:EE:01",
                    "message": "needle-login needle-login password failure",
                }
            ],
            "available_wifi_connections": [
                {
                    "derived_connected_at": "2026-05-20T11:00:00+02:00",
                    "derived_time_type": "mesh_last_observed",
                    "derived_time_confidence": "low",
                    "exact_connection_time_available": False,
                    "event": "known_wifi_device",
                    "hostname": "needle-login-phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.21",
                    "source": "mesh_list",
                    "confidence": "known_wifi_device_no_connection_timestamp",
                    "message": "Known WLAN device",
                }
            ],
            "known_hosts": [],
        },
        db,
    )

    results = query_records(db, "needle-login", "all", limit=10, offset=0)
    ranks = [row["match_rank"] for row in results["rows"]]

    assert results["total"] >= 2
    assert ranks == sorted(ranks)
    assert results["rows"][0]["record_type"] == "event_log"
    assert results["rows"][0]["record_title"] == "needle-login needle-login password failure"
    assert results["rows"][0]["record_time"] == "2026-05-20T12:00:00+02:00"
    assert results["rows"][0]["evidence_level"] == "parsed_from_raw"
    assert results["rows"][0]["rank_position"] == 1

    inferred = query_records(db, "needle-login", "all", limit=10, offset=0, evidence_level="inferred")

    assert inferred["total"] == 1
    assert inferred["rows"][0]["record_type"] == "wifi_connections"
    assert inferred["rows"][0]["record_entity"].startswith("needle-login-phone")


def test_investigation_snapshot_combines_window_evidence_and_discovery_hints(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {
                "device_log_xml": "<DeviceLog />",
                "support_data_txt": "allow_pcp_and_upnp igd_fw_cnt_upnp dhcp multicast",
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T10:30:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "mac": None,
                    "message": "Anmeldung falsches Kennwort",
                }
            ],
            "available_wifi_connections": [
                {
                    "derived_connected_at": "2026-05-20T10:35:00+02:00",
                    "derived_time_type": "connection_event",
                    "derived_time_confidence": "high",
                    "exact_connection_time_available": True,
                    "event": "connected",
                    "hostname": "Phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.24",
                    "source": "device_log",
                    "confidence": "high",
                    "message": "Phone connected",
                }
            ],
            "known_hosts": [
                {
                    "hostname": "Phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.24",
                    "last_connected": "2026-05-20T10:35:00+02:00",
                    "last_activity": "2026-05-20T10:35:00+02:00",
                    "last_activity_source": "fritzbox_landevice_lastused",
                    "last_activity_confidence": "medium",
                }
            ],
        },
        db,
    )

    snapshot = investigation_snapshot(db, "2026-05-20T10:00:00+02:00", "2026-05-20T11:00:00+02:00")

    assert snapshot["counts"]["exact_events"] == 1
    assert snapshot["counts"]["auth_events"] == 1
    assert snapshot["counts"]["wifi_points"] == 1
    assert snapshot["counts"]["presence_points"] == 1
    assert snapshot["counts"]["discovery_hints_total"] >= 1
    assert snapshot["verdict"]["level"] == "high"


def test_investigation_snapshot_uses_presence_overlap_for_device_candidates(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "restaurant-phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.24",
                    "interface": "WLAN",
                    "first_seen": "2026-05-16T00:15:00+02:00",
                    "last_connected": "2026-05-16T12:15:00+02:00",
                    "last_activity": "2026-05-16T12:15:00+02:00",
                    "last_activity_source": "fritzbox_landevice_lastused",
                    "last_activity_confidence": "medium",
                },
                {
                    "hostname": "office-printer",
                    "mac": "AA:BB:CC:DD:EE:00",
                    "ip": "192.0.2.25",
                    "interface": "LAN",
                    "first_seen": "2026-05-15T00:15:00+02:00",
                    "last_connected": "2026-05-15T12:15:00+02:00",
                    "last_activity": "2026-05-15T12:15:00+02:00",
                    "last_activity_source": "fritzbox_landevice_lastused",
                    "last_activity_confidence": "medium",
                },
            ],
        },
        db,
    )

    snapshot = investigation_snapshot(
        db,
        "2026-05-16T02:00:00+02:00",
        "2026-05-16T11:30:00+02:00",
        interface="wifi",
    )
    point_snapshot = investigation_snapshot(
        db,
        "2026-05-16T02:00:00+02:00",
        "2026-05-16T11:30:00+02:00",
        presence_mode="points",
    )

    assert snapshot["counts"]["device_candidates"] == 1
    assert snapshot["devices"]["rows"][0]["hostname"] == "restaurant-phone"
    assert snapshot["devices"]["rows"][0]["window_match"] == "interval_overlap"
    assert point_snapshot["counts"]["device_candidates"] == 0


def test_settings_store_preserves_password_when_blank(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    saved = save_settings(
        {
            "address": "192.168.178.1",
            "user": "analyst",
            "password": "secret",
            "port": 49000,
            "tls": False,
        },
        db,
    )
    save_settings({"address": "192.168.178.2", "user": "", "password": "", "port": 49443, "tls": True}, db)
    public = get_settings(db)
    private = get_settings(db, include_secret=True)

    assert saved["has_password"] is True
    assert public["address"] == "192.168.178.2"
    assert public["user"] == ""
    assert public["has_password"] is True
    assert "password" not in public
    assert private["password"] == "secret"
    assert private["tls"] is True


def test_query_records_sorts_and_pages(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.168.178.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [
                {
                    "timestamp": "2026-05-20T10:00:00+02:00",
                    "category": "system",
                    "ip": None,
                    "mac": None,
                    "message": "older",
                },
                {
                    "timestamp": "2026-05-20T11:00:00+02:00",
                    "category": "system",
                    "ip": None,
                    "mac": None,
                    "message": "newer",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    first = query_records(db, "", "log", limit=1, offset=0, sort_by="timestamp", sort_dir="asc")
    second = query_records(db, "", "log", limit=1, offset=1, sort_by="timestamp", sort_dir="asc")

    assert first["total"] == 2
    assert first["rows"][0]["message"] == "older"
    assert second["rows"][0]["message"] == "newer"


def test_ingest_preserves_repeated_observations_per_run(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    dataset = {
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
                "mac": None,
                "message": "Anmeldung falsches Kennwort",
            }
        ],
        "available_wifi_connections": [],
        "known_hosts": [],
    }

    ingest_dataset(dataset, db)
    ingest_dataset(dataset, db)

    conn = init_db(db)
    try:
        canonical_events = conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
        observations = conn.execute(
            "SELECT COUNT(*) FROM record_observations WHERE record_type = 'event_log'"
        ).fetchone()[0]
        evidence = conn.execute("SELECT evidence_level FROM event_log LIMIT 1").fetchone()[0]
    finally:
        conn.close()

    assert canonical_events == 1
    assert observations == 2
    assert evidence == "parsed_from_raw"


def test_queries_can_scope_to_latest_or_specific_acquisition_run(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    base = {
        "window_hours": 100,
        "router": {"address": "192.0.2.1"},
        "summary": {},
        "raw_exports": {},
        "available_wifi_connections": [
            {
                "derived_connected_at": "2026-05-20T11:00:00+02:00",
                "derived_time_type": "mesh_last_observed",
                "derived_time_confidence": "low",
                "exact_connection_time_available": False,
                "event": "known_wifi_device",
                "hostname": "shared-phone",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "192.0.2.21",
                "source": "mesh_list",
                "confidence": "known_wifi_device_no_connection_timestamp",
                "message": "Known WLAN device",
            }
        ],
        "known_hosts": [],
    }
    run_one = ingest_dataset(
        {
            **base,
            "generated_at": "2026-05-20T12:00:00+02:00",
            "event_log": [{"timestamp": "2026-05-20T12:00:00+02:00", "category": "system", "message": "old run"}],
        },
        db,
    )
    run_two = ingest_dataset(
        {
            **base,
            "generated_at": "2026-05-20T13:00:00+02:00",
            "event_log": [{"timestamp": "2026-05-20T13:00:00+02:00", "category": "system", "message": "new run"}],
        },
        db,
    )

    assert [run["id"] for run in list_runs(db)] == [run_two, run_one]
    assert query_records(db, "", "log")["rows"][0]["message"] == "new run"
    assert query_records(db, "", "log", run_id=run_one)["rows"][0]["message"] == "old run"
    assert query_records(db, "shared-phone", "wifi", run_id=run_two)["total"] == 1
    assert latest_snapshot(db, run_id=run_one)["latest_run"]["id"] == run_one
    assert query_timeline(db, run_id=run_two)["total"] == 2


def test_active_host_rows_get_inferred_last_activity(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "active-phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.21",
                    "interface": "WLAN",
                    "active_now": True,
                    "first_seen": None,
                    "last_seen": None,
                    "last_connected": None,
                },
                {
                    "hostname": "returned-phone",
                    "mac": "AA:BB:CC:DD:EE:00",
                    "ip": "192.0.2.22",
                    "interface": "WLAN",
                    "active_now": True,
                    "first_seen": "2026-05-01T12:00:00+02:00",
                    "last_seen": "2026-05-15T12:00:00+02:00",
                    "last_connected": "2026-05-15T12:00:00+02:00",
                },
            ],
        },
        db,
    )

    hosts = query_records(db, "active-phone", "hosts")
    presence = query_records(db, "active-phone", "presence")
    snapshot = latest_snapshot(db)

    assert hosts["total"] == 1
    assert hosts["rows"][0]["last_connected"] is None
    assert hosts["rows"][0]["last_activity"]
    assert hosts["rows"][0]["last_activity_source"] == "active_host_snapshot"
    assert hosts["rows"][0]["last_activity_confidence"] == "medium"
    assert presence["total"] == 1
    assert presence["rows"][0]["hostname"] == "active-phone"
    assert snapshot["presence_summary"]["active_snapshot"] == 2
    assert snapshot["presence_summary"]["last_connected"] == 1
    assert (
        query_records(db, "", "hosts", start="2026-05-20T00:00:00+02:00", end="2026-05-21T00:00:00+02:00")["total"] == 2
    )
    friday_hosts = query_records(db, "", "hosts", start="2026-05-15T00:00:00+02:00", end="2026-05-16T00:00:00+02:00")
    assert friday_hosts["total"] == 1
    assert friday_hosts["rows"][0]["hostname"] == "returned-phone"


def test_all_evidence_time_filter_excludes_untimestamped_records(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "tr064_snapshot": {
                "actions": {
                    "wlan_radio": {
                        "ok": True,
                        "service": "WLANConfiguration:1",
                        "action": "GetInfo",
                        "response": {"NewSSID": "Lab", "NewEnable": "1"},
                    }
                }
            },
        },
        db,
    )

    result = query_records(
        db,
        "",
        "all",
        start="2026-05-16T02:00:00+02:00",
        end="2026-05-16T11:30:00+02:00",
    )

    assert result["total"] == 0


def test_analysis_snapshot_exposes_forensic_visualization_data(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    tr064 = {
        "actions": {
            "wan_ip_external": {"ok": True, "response": {"NewExternalIPAddress": "198.51.100.10"}},
            "wan_ip_status": {"ok": True, "response": {"NewConnectionStatus": "Connected"}},
        },
        "indexed_results": {
            "wan_ip_port_mappings": {
                "items": [
                    {
                        "ok": True,
                        "response": {
                            "NewEnabled": "1",
                            "NewExternalPort": "8443",
                            "NewProtocol": "TCP",
                            "NewInternalPort": "443",
                            "NewInternalClient": "192.0.2.21",
                            "NewPortMappingDescription": "camera",
                        },
                    }
                ]
            }
        },
        "wlan": [],
    }
    mesh = {
        "nodes": [
            {
                "device_name": "Repeater",
                "node_interfaces": [
                    {
                        "name": "5 GHz",
                        "type": "wifi",
                        "node_links": [{"type": "wifi", "state": "connected", "cur_data_rate_rx": 866}],
                    }
                ],
            }
        ]
    }
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "tr064_snapshot_json": json.dumps(tr064),
                "mesh_list": json.dumps(mesh),
                "landevice_query_json": "{}",
            },
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "camera",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.21",
                    "interface": "LAN",
                    "active_now": True,
                    "last_connected": "2026-05-20T10:00:00+02:00",
                    "allow_pcp_and_upnp": "1",
                    "upnp_count": "1",
                }
            ],
        },
        db,
    )

    snapshot = analysis_snapshot(db)

    assert snapshot["mesh_summary"]["nodes"] == 1
    assert snapshot["mesh_summary"]["links"][0]["device"] == "Repeater"
    assert snapshot["tr064_summary"]["wan"]["port_mapping_count"] == 1
    assert snapshot["tr064_summary"]["wan"]["port_mappings"][0]["internal_client"] == "192.0.2.21"
    assert snapshot["host_risk_summary"]["devices"][0]["level"] == "high"
    assert snapshot["last_used_histogram"] == [{"label": "2026-05-20", "count": 1}]
    assert any(row["area"] == "Network exposure" for row in snapshot["source_coverage"]["matrix"])


def test_latest_snapshot_and_evidence_filters(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "device_log_xml": "<DeviceLog />",
                "support_data_txt": "FRITZ!Box support data\nsupport device system wlan dsl mesh kernel\n",
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T12:00:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.23",
                    "mac": None,
                    "message": "Successful login",
                }
            ],
            "available_wifi_connections": [
                {
                    "derived_connected_at": "2026-05-20T11:00:00+02:00",
                    "derived_time_type": "mesh_last_observed",
                    "derived_time_confidence": "low",
                    "exact_connection_time_available": False,
                    "event": "known_wifi_device",
                    "hostname": "phone",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.21",
                    "source": "mesh_list",
                    "confidence": "known_wifi_device_no_connection_timestamp",
                    "message": "Known WLAN device",
                }
            ],
            "known_hosts": [],
        },
        db,
    )

    snapshot = latest_snapshot(db)
    inferred = query_records(db, "", "wifi", evidence_level="inferred")
    exact_timeline = query_timeline(db, time_type="exact")

    assert snapshot["has_data"] is True
    assert snapshot["counts"]["event_log"] == 1
    assert snapshot["counts"]["wifi_connections"] == 1
    assert snapshot["latest_run"]["router_address"] == "192.0.2.1"
    assert "support_data_txt" not in snapshot["source_coverage"]["missing_raw_artifacts"]
    assert inferred["total"] == 1
    assert exact_timeline["total"] == 1
    assert exact_timeline["rows"][0]["record_type"] == "siem_events"


def test_support_findings_are_searchable_and_observed_per_run(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    dataset = {
        "generated_at": "2026-05-20T12:00:00+02:00",
        "window_hours": 100,
        "router": {"address": "192.0.2.1"},
        "summary": {},
        "raw_exports": {
            "support_data_txt": "##### WLAN diagnostics\nSSID: Restaurant WiFi\nclient aa:bb:cc:dd:ee:ff\n",
        },
        "event_log": [],
        "available_wifi_connections": [],
        "known_hosts": [],
        "support_findings": [
            {
                "finding_type": "key_value",
                "section": "WLAN diagnostics",
                "key": "SSID",
                "value": "Restaurant WiFi",
                "line_number": 2,
                "observed_at": "2026-05-20T12:00:00+02:00",
                "raw_text": "SSID: Restaurant WiFi",
                "evidence_level": "parsed_from_raw",
                "evidence_note": "Key/value parsed from support data.",
            }
        ],
    }

    ingest_dataset(dataset, db)
    ingest_dataset(dataset, db)

    support = query_records(db, "Restaurant", "support", run_id="all")
    conn = init_db(db)
    try:
        canonical = conn.execute("SELECT COUNT(*) FROM support_findings").fetchone()[0]
        observations = conn.execute(
            "SELECT COUNT(*) FROM record_observations WHERE record_type = 'support_finding'"
        ).fetchone()[0]
    finally:
        conn.close()

    assert support["total"] == 2
    assert support["rows"][0]["key"] == "SSID"
    assert canonical == 2
    assert observations == 2


def test_ingest_additional_forensic_evidence_tables_and_queries(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
            "host_filter_profiles": [
                {"profile_id": "standard", "name": "Standard", "access_mode": "unlimited", "devices": ["phone"]}
            ],
            "mesh_topology_links": [
                {
                    "node": "FRITZ!Box",
                    "node_mac": "AA:BB:CC:00:00:01",
                    "interface": "wifi0",
                    "peer": "Repeater",
                    "peer_mac": "AA:BB:CC:00:00:02",
                    "link_type": "wifi",
                    "state": "active",
                    "last_connected": "2026-05-20T11:59:00+02:00",
                }
            ],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "8443",
                    "internal_client": "192.0.2.44",
                    "internal_port": "443",
                    "description": "camera https",
                    "enabled": "1",
                }
            ],
            "wlan_radios": [
                {
                    "radio_index": "1",
                    "ssid": "ForensicNet",
                    "enabled": "1",
                    "status": "Up",
                    "standard": "ax",
                    "channel": "11",
                    "total_associations": "1",
                }
            ],
            "wlan_associations": [
                {
                    "observed_at": "2026-05-20T12:00:00+02:00",
                    "radio_index": "1",
                    "association_index": "0",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.44",
                    "hostname": "camera",
                    "speed": "866",
                    "signal_strength": "-45",
                }
            ],
            "device_risk_summaries": [
                {
                    "device_key": "AA:BB:CC:DD:EE:FF",
                    "hostname": "camera",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.44",
                    "risk_level": "high",
                    "risk_score": "80",
                    "reasons": ["WAN mapping"],
                    "summary": "WAN mapping exposes camera",
                }
            ],
        },
        db,
    )

    snapshot = latest_snapshot(db)
    host_filter = query_records(db, "Standard", "host_filter")
    mesh = query_records(db, "Repeater", "mesh")
    wan = query_records(db, "camera", "wan_exposure")
    radio = query_records(db, "ForensicNet", "wlan_radios")
    association = query_records(db, "camera", "wlan_associations")
    risk = query_records(db, "WAN mapping", "device_risks", evidence_level="inferred")
    evidence = evidence_for_record(db, "wan_exposure", wan["rows"][0]["id"])

    assert snapshot["counts"]["host_filter_profiles"] == 1
    assert snapshot["counts"]["mesh_topology_links"] == 1
    assert snapshot["counts"]["wan_port_mappings"] == 1
    assert snapshot["counts"]["wlan_radios"] == 1
    assert snapshot["counts"]["wlan_associations"] == 1
    assert snapshot["counts"]["device_risk_summaries"] == 1
    assert snapshot["counts"]["security_advisories"] >= 1
    assert host_filter["rows"][0]["name"] == "Standard"
    assert mesh["rows"][0]["peer"] == "Repeater"
    assert wan["rows"][0]["external_port"] == "8443"
    assert radio["rows"][0]["ssid"] == "ForensicNet"
    assert association["rows"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert risk["rows"][0]["risk_level"] == "high"
    assert evidence["record"]["description"] == "camera https"


def test_security_advisories_are_derived_from_router_settings(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "support_data_txt": "remote access from internet enabled via MyFRITZ",
                "webui_readonly_artifacts_json": """
                {
                  "endpoints": {
                    "juis_boxinfo_xml": {
                      "ok": true,
                      "raw": "<e:BoxInfo><q:Flag>2nd_factor_disabled</q:Flag><q:Flag>remote_login_service</q:Flag></e:BoxInfo>"
                    }
                  }
                }
                """,
            },
            "event_log": [
                {
                    "timestamp": "2026-05-20T11:00:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.50",
                    "message": "Anmeldung fehlgeschlagen falsches Kennwort",
                },
                {
                    "timestamp": "2026-05-20T11:01:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.50",
                    "message": "Anmeldung fehlgeschlagen falsches Kennwort",
                },
                {
                    "timestamp": "2026-05-20T11:02:00+02:00",
                    "category": "auth",
                    "ip": "192.0.2.50",
                    "message": "Anmeldung fehlgeschlagen falsches Kennwort",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "camera",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.44",
                    "allow_pcp_and_upnp": "1",
                    "upnp_count": "2",
                }
            ],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "443",
                    "internal_client": "192.0.2.44",
                    "internal_port": "443",
                    "description": "camera https",
                    "enabled": "1",
                }
            ],
        },
        db,
    )

    advisories = query_records(db, "", "security_advisories")
    wan = query_records(db, "WAN port", "security")
    analysis = analysis_snapshot(db)

    assert advisories["total"] >= 5
    assert advisories["rows"][0]["severity"] in {"critical", "high"}
    assert wan["rows"][0]["advisory_id"] == "wan_port_mapping_enabled"
    assert analysis["security_advisories"]["total"] >= 5
    assert analysis["security_advisories"]["high_or_critical"] >= 1
    assert query_records(db, "second factor", "security_advisories")["total"] == 1
    assert query_records(db, "remote login service", "security_advisories")["total"] == 1


def test_additional_evidence_extracts_from_raw_artifacts(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    tr064_snapshot = {
        "actions": {
            "host_filter_profiles": {
                "ok": True,
                "response": {"NewProfileList": [{"id": "guest", "name": "Guest", "access_mode": "limited"}]},
            },
            "wan_common_bytes_sent": {"ok": True, "response": {"NewTotalBytesSent": "123456"}},
            "wan_dsl_stats": {"ok": True, "response": {"NewFECErrors": "7"}},
        },
        "wlan": [
            {
                "index": 1,
                "info": {"ok": True, "response": {"NewSSID": "LabNet", "NewEnable": "1", "NewStatus": "Up"}},
                "total_associations": {"ok": True, "response": {"NewTotalAssociations": "1"}},
                "channel_info": {"ok": True, "response": {"NewChannel": "6"}},
                "statistics": {"ok": True, "response": {"NewTotalBytesSent": "123", "NewTotalBytesReceived": "456"}},
            }
        ],
        "indexed_results": {
            "wan_ip_port_mappings": {
                "items": [
                    {
                        "ok": True,
                        "response": {
                            "NewProtocol": "UDP",
                            "NewExternalPort": "51820",
                            "NewInternalClient": "192.0.2.99",
                            "NewInternalPort": "51820",
                            "NewPortMappingDescription": "wireguard",
                            "NewEnabled": "1",
                        },
                    }
                ]
            },
            "wlan_1_associations": {
                "items": [
                    {
                        "ok": True,
                        "response": {
                            "NewAssociatedDeviceMACAddress": "AA:BB:CC:DD:EE:99",
                            "NewAssociatedDeviceIPAddress": "192.0.2.99",
                            "NewAssociatedDeviceAuthState": "1",
                        },
                    }
                ]
            },
        },
    }
    mesh_list = {
        "nodes": [
            {
                "device_name": "Router",
                "device_mac_address": "AA:BB:CC:00:00:01",
                "node_interfaces": [
                    {
                        "name": "lan",
                        "type": "ethernet",
                        "node_links": [
                            {
                                "type": "ethernet",
                                "state": "active",
                                "remote_name": "Switch",
                                "remote_mac": "AA:BB:CC:00:00:03",
                                "last_connected": 1779271200,
                            }
                        ],
                    }
                ],
            }
        ]
    }

    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "tr064_snapshot_json": json.dumps(tr064_snapshot),
                "mesh_list": json.dumps(mesh_list),
                "acquisition_manifest_json": json.dumps(
                    {
                        "attempt_count": 2,
                        "successful_count": 1,
                        "failed_count": 1,
                        "attempts": [
                            {
                                "artifact": "support_data_txt",
                                "surface": "support_data",
                                "ok": False,
                                "error": "HTTP 403",
                            },
                            {"artifact": "tr064_snapshot_json", "surface": "tr064_snapshot", "ok": True},
                        ],
                    }
                ),
            },
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "wireguard",
                    "mac": "AA:BB:CC:DD:EE:99",
                    "ip": "192.0.2.99",
                    "interface": "WLAN",
                    "active_now": True,
                    "allow_pcp_and_upnp": "1",
                    "upnp_count": "2",
                }
            ],
        },
        db,
    )

    assert query_records(db, "Guest", "host_filter_profiles")["total"] == 1
    assert query_records(db, "Switch", "mesh_topology_links")["rows"][0]["link_type"] == "ethernet"
    assert query_records(db, "51820", "wan_port_mappings")["rows"][0]["internal_client"] == "192.0.2.99"
    assert query_records(db, "LabNet", "wlan_radio")["rows"][0]["total_associations"] == "1"
    assert query_records(db, "AA:BB:CC:DD:EE:99", "wlan_association")["total"] == 1
    assert query_records(db, "NewTotalBytesSent", "network_status")["rows"][0]["unit"] == "bytes"
    assert query_records(db, "NewFECErrors", "dsl_stats")["rows"][0]["area"] == "dsl"
    coverage = latest_snapshot(db)["source_coverage"]
    assert coverage["attempted_artifacts"]["support_data_txt"]["failed"] == 1
    assert coverage["attempted_artifacts"]["tr064_snapshot_json"]["successful"] == 1
    risk = query_records(db, "UPnP", "device_risk")
    assert risk["total"] == 1
    assert risk["rows"][0]["risk_level"] == "medium"


def test_webui_aha_and_telephony_artifacts_are_typed_from_raw_exports(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    query_lua = {
        "wlan_stations": {
            "ok": True,
            "data": {
                "wlan_stations": [
                    {
                        "mac": "AA:BB:CC:DD:EE:10",
                        "ip": "192.0.2.10",
                        "name": "StationPhone",
                        "active": "1",
                        "guest": "0",
                        "ap": "1",
                        "ssid": "LabNet",
                        "rssi": "-51",
                        "speed": "866",
                    }
                ]
            },
        },
        "wlan_known_devices": {
            "ok": True,
            "data": {
                "wlan_known_devices": [
                    {
                        "mac": "AA:BB:CC:DD:EE:11",
                        "name": "KnownTablet",
                        "active": "0",
                        "guest": "1",
                        "ssid": "GuestNet",
                        "last_connected": "1779271200",
                        "rssi": "-70",
                    }
                ]
            },
        },
        "user_rights": {
            "ok": True,
            "data": {
                "user_rights": [
                    {
                        "name": "admin",
                        "enabled": "1",
                        "box_admin": "1",
                        "vpn_access": "1",
                        "frominternet": "1",
                    }
                ]
            },
        },
    }
    data_lua = {
        "wlanSta": {
            "ok": True,
            "data": {
                "stations": [
                    {
                        "mac": "AA:BB:CC:DD:EE:12",
                        "ip": "192.0.2.12",
                        "name": "UiStation",
                        "ssid": "LabNet",
                        "rssi": "-48",
                    }
                ]
            },
        },
        "netDhcp": {
            "ok": True,
            "data": {"leases": [{"hostname": "leasebox", "mac": "AA:BB:CC:DD:EE:13", "ip": "192.0.2.77"}]},
        },
        "wlanRadar": {"ok": True, "data": {"radar": {"channel": "52", "state": "active"}}},
    }
    phonebooks = {"0": """
        <phonebooks><phonebook><contact><uniqueid>7</uniqueid><person><realName>Alice Example</realName></person>
        <telephony><number type="home">+491234</number></telephony></contact></phonebook></phonebooks>
        """}

    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "query_lua_artifacts_json": json.dumps(query_lua),
                "data_lua_pages_json": json.dumps(data_lua),
                "aha_device_stats_json": json.dumps(
                    {"AIN123": "<devicestats><temperature><celsius>225</celsius></temperature></devicestats>"}
                ),
                "call_list_xml": """
                <root><Call><Id>1</Id><Type>1</Type><Caller>+491111</Caller><Called>**1</Called>
                <Name>Alice Example</Name><Date>20.05.26 12:00</Date><Duration>0:01</Duration></Call></root>
                """,
                "phonebooks_xml_json": json.dumps(phonebooks),
            },
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    station = query_records(db, "StationPhone", "wlan_associations")
    known = query_records(db, "KnownTablet", "wlan_associations")
    ui_station = query_records(db, "UiStation", "wlan_association")
    dhcp = query_records(db, "leasebox", "network_status")
    dhcp_typed = query_records(db, "leasebox", "dhcp")
    radar = query_records(db, "wlanRadar.radar.channel", "network_status")
    aha = query_records(db, "AIN123 celsius 225", "network_status")
    telephony = query_records(db, "Alice Example", "network_status")
    telephony_typed = query_records(db, "Alice Example", "telephony")
    rights = query_records(db, "admin", "security_advisories")

    assert station["rows"][0]["signal_strength"] == "-51"
    assert known["rows"][0]["guest"] == "1"
    assert ui_station["rows"][0]["source"] == "data_lua_page_wlanSta"
    assert dhcp["rows"][0]["area"] == "dhcp"
    assert dhcp_typed["rows"][0]["ip"] == "192.0.2.77"
    assert radar["rows"][0]["value"] == "52"
    assert aha["rows"][0]["value"] == "225"
    assert telephony["total"] >= 2
    assert telephony_typed["total"] >= 2
    assert rights["rows"][0]["advisory_id"] == "query_lua_user_remote_rights"


def test_advertisement_hints_are_extracted_and_searchable(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "support_data_txt": ("wlan debug: SSDP multicast 239.255.255.250 from 192.0.2.44 aa:bb:cc:dd:ee:ff\n")
            },
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [
                {
                    "hostname": "camera",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.0.2.44",
                    "interface": "WLAN",
                    "allow_pcp_and_upnp": "1",
                    "upnp_count": "2",
                }
            ],
            "wan_port_mappings": [
                {
                    "protocol": "TCP",
                    "external_port": "8443",
                    "internal_client": "192.0.2.44",
                    "internal_port": "443",
                    "description": "camera",
                    "enabled": "1",
                }
            ],
        },
        db,
    )

    ssdp = query_records(db, "SSDP", "advertisement_hints")
    upnp = query_records(db, "UPnP", "advertisements")
    snapshot = analysis_snapshot(db)

    assert ssdp["total"] >= 1
    assert ssdp["rows"][0]["protocol"] == "SSDP"
    assert ssdp["rows"][0]["confidence"] == "low"
    assert upnp["total"] >= 2
    assert snapshot["advertisement_hints"]["total"] >= 3
    assert any(row["label"] == "SSDP" for row in snapshot["advertisement_hints"]["by_protocol"])


def test_investigation_probe_telemetry_filters_kernel_probe_false_positive(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": "0x80890570 q6v5_wcss_probe+0x18c/0x5e8 phys=0x0cb50000 ioremap"},
            "support_findings": [
                {
                    "finding_type": "key_value",
                    "source": "support_data_txt",
                    "raw_text": "0x80890570 q6v5_wcss_probe+0x18c/0x5e8 phys=0x0cb50000 ioremap",
                    "observed_at": "2026-05-20T12:00:00+02:00",
                }
            ],
            "event_log": [
                {
                    "timestamp": "2026-05-20T10:10:00+02:00",
                    "category": "wifi",
                    "message": "[7407881.173308][  T926] wlan: ol_ath_wifi_ssr: Waiting for probe lock",
                },
                {
                    "timestamp": "2026-05-20T10:20:00+02:00",
                    "category": "wlan",
                    "message": "802.11 Probe Request from AA:BB:CC:DD:EE:FF near radio 1",
                },
            ],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    snapshot = investigation_snapshot(db, "2026-05-20T10:00:00+02:00", "2026-05-20T11:00:00+02:00")

    assert snapshot["probe_telemetry"]["total"] == 1
    assert snapshot["probe_telemetry"]["false_positive_count"] == 1
    assert snapshot["probe_telemetry"]["rows"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert snapshot["discovery_devices"]["rows"][0]["kind"] == "nearby_probe"


def test_investigation_reports_probe_telemetry_absence(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {
                "support_data_txt": "dhcp multicast ssdp 239.255.255.250 from 192.0.2.44 aa:bb:cc:dd:ee:ff"
            },
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    snapshot = investigation_snapshot(db)

    assert snapshot["probe_telemetry"]["available"] is False
    assert snapshot["probe_telemetry"]["total"] == 0
    assert "No 802.11 probe-request" in snapshot["probe_telemetry"]["note"]
    assert snapshot["counts"]["discovery_hints_total"] >= 1


def test_reparse_support_wlan_environment_promotes_stored_raw_artifact(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    support = """
##### BEGIN SECTION WLAN_SCAN_RESULTS WLAN scan results
Scan results for radio '101':
Scan time: 20.05.2026 22:15:54/[7407912.562]
Scan table:
[BSSID|CHANNEL_INFO|SSID|RSSI|WLAN MODE|CAPS]
[ 0]: 'AA:BB:CC:DD:EE:01' 2437/2437/ 20/0000/  6-  8 'CafeNet' (len=7) -72 dBm [ 11N ] [ WPA2_PSK ]
##### END SECTION WLAN_SCAN_RESULTS

##### BEGIN SECTION SCAN_EVENTS History of scan requests and finished events
[00] t=20.05.2026 12:00:01/[7365674.807]: SCAN_REQUEST  , radio '101' "ACS-6h", "", HAL returned SUCCESS
##### END SECTION SCAN_EVENTS

##### BEGIN SECTION ENV_INTERFERENCE_HISTORY History of radar and interference events
[00] t=20.05.2026 12:01:02/[10146.150]: INTERFERENCE        , radio '101', primary freq 2437 MHz, active, channel change.
##### END SECTION ENV_INTERFERENCE_HISTORY

##### BEGIN SECTION WLAN_CHANNEL_INFO WLAN channel load
2437 MHz ( 6) | 34 %
##### END SECTION WLAN_CHANNEL_INFO
"""
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {"support_data_txt": support},
            "event_log": [],
            "available_wifi_connections": [],
            "known_hosts": [],
        },
        db,
    )

    assert query_records(db, "CafeNet", "advertisement_hints")["total"] == 0

    result = reparse_support_wlan_environment(db)

    assert result["parsed"]["advertisement_hints"] == 1
    assert result["parsed"]["network_status_snapshots"] == 3
    assert query_records(db, "CafeNet", "advertisement_hints")["rows"][0]["mac"] == "aa:bb:cc:dd:ee:01"
    assert query_records(db, "wlan_scan_event", "network_status")["total"] == 1
