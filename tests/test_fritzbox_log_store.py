import json
from pathlib import Path

from fritzbox_log_store import (
    analysis_snapshot,
    evidence_for_record,
    get_settings,
    ingest_dataset,
    init_db,
    latest_snapshot,
    list_runs,
    query_records,
    query_timeline,
    save_settings,
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
    assert exact_timeline["rows"][0]["record_type"] == "event_log"


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
    assert host_filter["rows"][0]["name"] == "Standard"
    assert mesh["rows"][0]["peer"] == "Repeater"
    assert wan["rows"][0]["external_port"] == "8443"
    assert radio["rows"][0]["ssid"] == "ForensicNet"
    assert association["rows"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert risk["rows"][0]["risk_level"] == "high"
    assert evidence["record"]["description"] == "camera https"


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
