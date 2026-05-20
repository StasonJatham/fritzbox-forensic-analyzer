import io
import json
from pathlib import Path
import zipfile

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
