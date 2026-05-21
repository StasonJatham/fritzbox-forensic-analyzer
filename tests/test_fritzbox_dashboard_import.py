import io
import json
import time
from types import SimpleNamespace
from pathlib import Path
import zipfile

import pytest

from fritzbox_api_models import LiveCaptureRequest, SettingsRequest
import fritzbox_wifi_dashboard as dashboard
from fritzbox_log_store import ingest_dataset, latest_snapshot


def sample_dataset(router: str) -> dict:
    return {
        "generated_at": "2026-05-20T12:00:00+02:00",
        "window_hours": 24,
        "router": {"address": router},
        "summary": {},
        "raw_exports": {"device_log_xml": f"<DeviceLog>{router}</DeviceLog>"},
        "event_log": [
            {
                "timestamp": "2026-05-20T12:00:00+02:00",
                "category": "auth",
                "ip": "192.0.2.23",
                "mac": None,
                "message": f"Successful login on {router}",
            }
        ],
        "available_wifi_connections": [],
        "known_hosts": [],
    }


def test_import_acquisition_package_creates_switchable_profile(tmp_path: Path, monkeypatch) -> None:
    source_db = tmp_path / "source.sqlite3"
    target_db = tmp_path / "target.sqlite3"
    ingest_dataset(sample_dataset("192.0.2.1"), source_db)

    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("database/fritzbox-analysis.sqlite3", source_db.read_bytes())

    monkeypatch.setattr(dashboard, "DEFAULT_DB", target_db)
    imported = dashboard.import_acquisition_package_bytes(package.getvalue(), "router-one.zip")
    profiles = dashboard.list_profiles()
    imported_db = dashboard.db_for_profile(imported["profile"]["id"])

    assert imported["imported"] is True
    assert imported["profile"]["router_address"] == "192.0.2.1"
    assert any(profile["id"] == imported["profile"]["id"] for profile in profiles)
    assert latest_snapshot(imported_db)["counts"]["event_log"] == 1


def test_import_json_dataset_creates_switchable_profile(tmp_path: Path, monkeypatch) -> None:
    target_db = tmp_path / "target.sqlite3"
    payload = json.dumps(sample_dataset("192.0.2.55")).encode("utf-8")

    monkeypatch.setattr(dashboard, "DEFAULT_DB", target_db)
    imported = dashboard.import_acquisition_package_bytes(payload, "router-two.json")
    imported_db = dashboard.db_for_profile(imported["profile"]["id"])
    snapshot = latest_snapshot(imported_db)

    assert imported["imported"] is True
    assert imported["profile"]["router_address"] == "192.0.2.55"
    assert snapshot["counts"]["event_log"] == 1
    assert snapshot["source_coverage"]["missing_raw_artifacts"]


def test_import_zip_rejects_oversized_embedded_database(tmp_path: Path, monkeypatch) -> None:
    target_db = tmp_path / "target.sqlite3"
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("database/fritzbox-analysis.sqlite3", b"too-large")

    monkeypatch.setattr(dashboard, "DEFAULT_DB", target_db)
    monkeypatch.setattr(dashboard, "MAX_IMPORT_BYTES", 4)

    with pytest.raises(dashboard.HTTPException) as exc_info:
        dashboard.import_acquisition_package_bytes(package.getvalue(), "oversized.zip")

    assert exc_info.value.status_code == 413


def test_clear_imported_profile_removes_stored_evidence(tmp_path: Path, monkeypatch) -> None:
    target_db = tmp_path / "target.sqlite3"
    payload = json.dumps(sample_dataset("192.0.2.88")).encode("utf-8")

    monkeypatch.setattr(dashboard, "DEFAULT_DB", target_db)
    imported = dashboard.import_acquisition_package_bytes(payload, "router-clear.json")
    profile_id = imported["profile"]["id"]
    imported_db = dashboard.db_for_profile(profile_id)

    assert latest_snapshot(imported_db)["counts"]["event_log"] == 1

    cleared = dashboard.clear_profile(profile_id)

    assert cleared["cleared"] is True
    assert cleared["profile"] == profile_id
    assert latest_snapshot(imported_db)["has_data"] is False


def test_api_docs_are_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("FRITZBOX_ENABLE_API_DOCS", raising=False)
    app = dashboard.create_app()

    assert app.openapi_url is None
    assert not any(route.path == "/docs" for route in app.routes)


def test_parser_rules_endpoint_exposes_registry(monkeypatch) -> None:
    monkeypatch.delenv("FRITZBOX_ALLOW_PUBLIC_BIND", raising=False)
    app = dashboard.create_app()
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "") == "/api/parser-rules")

    payload = json.loads(endpoint().body)

    assert payload["total"] >= 1
    assert {rule["rule_id"] for rule in payload["rules"]} >= {"wifi.ap_sta_connected", "auth.soap_failure"}


def test_live_80211_status_degrades_when_router_is_unreachable(monkeypatch) -> None:
    app = dashboard.create_app()
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "") == "/api/live-80211/status")
    monkeypatch.setattr(
        dashboard,
        "fritz_connection_from_stored_settings",
        lambda: (_ for _ in ()).throw(RuntimeError("sid=0123456789abcdef&password=hunter2")),
    )

    payload = json.loads(endpoint().body)

    assert payload["interfaces"] == []
    assert "hunter2" not in payload["note"]
    assert "<redacted>" in payload["note"]


def test_live_80211_capture_degrades_when_router_is_unreachable(monkeypatch) -> None:
    app = dashboard.create_app()
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "") == "/api/live-80211/capture")
    monkeypatch.setattr(
        dashboard,
        "fritz_connection_from_stored_settings",
        lambda: (_ for _ in ()).throw(RuntimeError("sid=0123456789abcdef&password=hunter2")),
    )

    payload = json.loads(endpoint(LiveCaptureRequest(duration_seconds=5)).body)

    assert payload["frames"] == []
    assert payload["parse"]["packet_count"] == 0
    assert "hunter2" not in payload["note"]


def test_settings_request_validates_port() -> None:
    with pytest.raises(ValueError):
        SettingsRequest(address="192.0.2.1", port=70000)

    assert SettingsRequest(address="192.0.2.1", port=65535).port == 65535


def test_public_bind_requires_explicit_opt_in(monkeypatch) -> None:
    monkeypatch.delenv("FRITZBOX_ALLOW_PUBLIC_BIND", raising=False)

    assert dashboard.is_loopback_bind("127.0.0.1")
    assert not dashboard.is_loopback_bind("0.0.0.0")
    assert not dashboard.public_bind_allowed()


def test_http_error_redacts_router_secrets() -> None:
    error = dashboard.http_error(500, "failed", RuntimeError("sid=0123456789abcdef&password=hunter2"))

    assert "0123456789abcdef" not in error.detail
    assert "hunter2" not in error.detail
    assert "<redacted>" in error.detail


def test_api_auth_is_not_required_for_local_default(monkeypatch) -> None:
    monkeypatch.delenv("FRITZBOX_ALLOW_PUBLIC_BIND", raising=False)
    monkeypatch.delenv("FRITZBOX_API_TOKEN", raising=False)

    assert not dashboard.api_auth_required()


def test_public_bind_requires_api_token_for_api(monkeypatch) -> None:
    monkeypatch.setenv("FRITZBOX_ALLOW_PUBLIC_BIND", "1")
    monkeypatch.delenv("FRITZBOX_API_TOKEN", raising=False)

    assert dashboard.api_auth_required()
    assert not dashboard.request_has_api_token(SimpleNamespace(headers={}))


def test_configured_api_token_allows_api_access(monkeypatch) -> None:
    monkeypatch.setenv("FRITZBOX_ALLOW_PUBLIC_BIND", "1")
    monkeypatch.setenv("FRITZBOX_API_TOKEN", "test-token")

    assert not dashboard.request_has_api_token(SimpleNamespace(headers={}))
    assert dashboard.request_has_api_token(SimpleNamespace(headers={"authorization": "Bearer test-token"}))
    assert dashboard.request_has_api_token(SimpleNamespace(headers={"x-api-token": "test-token"}))


def test_acquisition_job_manager_runs_pipeline_in_background(monkeypatch) -> None:
    manager = dashboard.AcquisitionJobManager()

    def fake_export(hours: int, include_disconnects: bool, progress_callback=None):
        assert hours == 24
        assert include_disconnects is True
        if progress_callback:
            progress_callback("core_tr064", "running", {})
            progress_callback("core_tr064", "completed", {"elapsed_seconds": 0.01})
        return {
            "generated_at": "2026-05-21T08:00:00+02:00",
            "router": {"address": "192.0.2.1"},
            "summary": {"raw_acquisition_dir": "/tmp/raw"},
            "known_hosts": [],
            "event_log": [],
            "raw_exports": {},
        }

    monkeypatch.setattr(dashboard, "stored_connection_args", lambda: SimpleNamespace(address="192.0.2.1"))
    monkeypatch.setattr(dashboard, "export_from_stored_settings", fake_export)
    monkeypatch.setattr(dashboard, "ingest_dataset", lambda dataset, path: 42)

    started = manager.start(24, True)
    deadline = time.monotonic() + 2
    status = started
    while time.monotonic() < deadline:
        status = manager.status(started["job_id"])
        if status["status"] == "completed":
            break
        time.sleep(0.01)

    assert status["status"] == "completed"
    assert status["run_id"] == 42
    assert status["raw_acquisition_dir"] == "/tmp/raw"
    assert status["stages"]["raw_core_tr064"]["status"] == "completed"
