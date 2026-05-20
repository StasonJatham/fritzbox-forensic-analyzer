from pathlib import Path

from fritzbox_log_store import get_settings, ingest_dataset, init_db, latest_snapshot, list_runs, query_records, query_timeline, save_settings


def test_query_records_uses_backend_fts_and_pagination(tmp_path: Path) -> None:
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
                {"timestamp": "2026-05-20T10:00:00+02:00", "category": "system", "ip": None, "mac": None, "message": "older"},
                {"timestamp": "2026-05-20T11:00:00+02:00", "category": "system", "ip": None, "mac": None, "message": "newer"},
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
        observations = conn.execute("SELECT COUNT(*) FROM record_observations WHERE record_type = 'event_log'").fetchone()[0]
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
                }
            ],
        },
        db,
    )

    hosts = query_records(db, "active-phone", "hosts")

    assert hosts["total"] == 1
    assert hosts["rows"][0]["last_connected"] is None
    assert hosts["rows"][0]["last_activity"]
    assert hosts["rows"][0]["last_activity_source"] == "active_host_snapshot"
    assert hosts["rows"][0]["last_activity_confidence"] == "medium"
    assert query_records(db, "", "hosts", start="2026-05-20T00:00:00+02:00", end="2026-05-21T00:00:00+02:00")["total"] == 1
    assert query_records(db, "", "hosts", start="2026-05-15T00:00:00+02:00", end="2026-05-16T00:00:00+02:00")["total"] == 0


def test_latest_snapshot_and_evidence_filters(tmp_path: Path) -> None:
    db = tmp_path / "analysis.sqlite3"
    ingest_dataset(
        {
            "generated_at": "2026-05-20T12:00:00+02:00",
            "window_hours": 100,
            "router": {"address": "192.0.2.1"},
            "summary": {},
            "raw_exports": {"device_log_xml": "<DeviceLog />"},
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
    assert inferred["total"] == 1
    assert exact_timeline["total"] == 1
    assert exact_timeline["rows"][0]["record_type"] == "event_log"
