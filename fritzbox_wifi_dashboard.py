#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import threading
from types import SimpleNamespace
from typing import Any
import zipfile

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

import fritzbox_wifi_export as exporter
from fritzbox_log_store import (
    DEFAULT_DB,
    analysis_snapshot,
    entity_pivot,
    evidence_for_record,
    get_settings,
    ingest_dataset,
    init_db,
    latest_snapshot,
    list_runs,
    query_entities,
    query_records,
    query_timeline,
    save_settings,
)


def load_app_html() -> str:
    for path in (
        Path(__file__).resolve().parent / "static" / "dashboard.html",
        Path.cwd() / "static" / "dashboard.html",
    ):
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise RuntimeError("static/dashboard.html was not found")


PROFILE_LOCAL = "local"


def profile_dir() -> Path:
    root = DEFAULT_DB.parent if DEFAULT_DB.parent != Path("") else Path(".")
    path = root / "imports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_profile_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._").lower()
    return cleaned or "imported-fritzbox"


def db_for_profile(profile: str = PROFILE_LOCAL) -> Path:
    profile = safe_profile_id(profile or PROFILE_LOCAL)
    if profile == PROFILE_LOCAL:
        return DEFAULT_DB
    path = profile_dir() / f"{profile}.sqlite3"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Analysis profile not found: {profile}")
    return path


def profile_summary(profile: str, path: Path, label: str | None = None) -> dict[str, Any]:
    snapshot = latest_snapshot(path)
    run = snapshot.get("latest_run") or {}
    router = run.get("router_address") or "unknown"
    return {
        "id": profile,
        "label": label or (f"{router} ({profile})" if profile != PROFILE_LOCAL else f"Local workspace ({router})"),
        "router_address": router,
        "has_data": snapshot.get("has_data", False),
        "latest_run": run.get("generated_at"),
        "counts": snapshot.get("counts") or {},
    }


def list_profiles() -> list[dict[str, Any]]:
    profiles = [profile_summary(PROFILE_LOCAL, DEFAULT_DB, "Local workspace")]
    for path in sorted(profile_dir().glob("*.sqlite3")):
        profile = safe_profile_id(path.stem)
        try:
            profiles.append(profile_summary(profile, path))
        except sqlite3.DatabaseError:
            profiles.append(
                {
                    "id": profile,
                    "label": f"{profile} (unreadable)",
                    "router_address": "unknown",
                    "has_data": False,
                    "latest_run": "",
                    "counts": {},
                }
            )
    return profiles


def import_acquisition_package_bytes(payload: bytes, filename: str = "import.zip") -> dict[str, Any]:
    if not payload:
        raise HTTPException(status_code=400, detail="Import file is empty.")
    if filename.lower().endswith(".json") or payload.lstrip().startswith(b"{"):
        try:
            dataset = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Import JSON is not a valid FRITZ!Box dataset.") from exc
        if not isinstance(dataset, dict) or not {"generated_at", "known_hosts", "event_log"}.intersection(dataset):
            raise HTTPException(
                status_code=400, detail="Import JSON does not look like a FRITZ!Box acquisition dataset."
            )
        return import_dataset_profile(dataset, filename)

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            db_members = [name for name in archive.namelist() if name == "database/fritzbox-analysis.sqlite3"]
            if not db_members:
                raise HTTPException(
                    status_code=400,
                    detail="Unsupported import. Upload a FRITZ!Box forensic package ZIP exported by this tool.",
                )
            with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
                tmp.write(archive.read(db_members[0]))
                temp_path = Path(tmp.name)
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Import file is not a valid ZIP package.") from exc

    try:
        init_db(temp_path).close()
        snapshot = latest_snapshot(temp_path)
        run = snapshot.get("latest_run") or {}
        router = safe_profile_id(str(run.get("router_address") or Path(filename).stem or "imported-fritzbox"))
        generated = safe_profile_id(str(run.get("generated_at") or datetime.now().astimezone().isoformat()))
        digest = hashlib.sha256(payload).hexdigest()[:10]
        profile = safe_profile_id(f"{router}-{generated}-{digest}")
        target = profile_dir() / f"{profile}.sqlite3"
        shutil.copyfile(temp_path, target)
        summary = profile_summary(profile, target)
        return {"imported": True, "profile": summary}
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=400, detail="Import package database is unreadable.") from exc
    finally:
        temp_path.unlink(missing_ok=True)


def import_dataset_profile(dataset: dict[str, Any], filename: str) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
        temp_path = Path(tmp.name)
    try:
        ingest_dataset(dataset, temp_path)
        snapshot = latest_snapshot(temp_path)
        run = snapshot.get("latest_run") or {}
        router = safe_profile_id(
            str((dataset.get("router") or {}).get("address") or run.get("router_address") or Path(filename).stem)
        )
        generated = safe_profile_id(
            str(dataset.get("generated_at") or run.get("generated_at") or datetime.now().astimezone().isoformat())
        )
        digest = hashlib.sha256(json.dumps(dataset, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:10]
        profile = safe_profile_id(f"{router}-{generated}-{digest}")
        target = profile_dir() / f"{profile}.sqlite3"
        shutil.copyfile(temp_path, target)
        summary = profile_summary(profile, target)
        return {"imported": True, "profile": summary}
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=400, detail="Import JSON could not be stored as an analysis profile.") from exc
    finally:
        temp_path.unlink(missing_ok=True)


class Poller:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.interval_minutes = 15
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_run_id: int | None = None

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "interval_minutes": self.interval_minutes,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
            "last_run_id": self.last_run_id,
        }

    def start(self, interval_minutes: int) -> dict[str, Any]:
        with self._lock:
            self.interval_minutes = max(5, min(15, int(interval_minutes or 15)))
            if self.active:
                return self.snapshot()
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            return self.snapshot()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._stop.set()
            return self.snapshot()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                dataset = export_from_stored_settings(hours=10000, include_disconnects=True)
                self.last_run_id = ingest_dataset(dataset, DEFAULT_DB)
                self.last_error = None
                self.last_run_at = datetime.now().astimezone().isoformat()
            except Exception as exc:  # pragma: no cover - depends on router availability
                self.last_error = str(exc)
                self.last_run_at = datetime.now().astimezone().isoformat()
            self._stop.wait(self.interval_minutes * 60)


poller = Poller()


def export_from_stored_settings(hours: int, include_disconnects: bool) -> dict[str, Any]:
    exporter.load_env_file(Path(".env"))
    exporter.load_env_file(Path(".fritzbox.env"))
    stored = get_settings(DEFAULT_DB, include_secret=True)
    args = SimpleNamespace(
        address=stored.get("address")
        or exporter.os.getenv("FRITZBOX_ADDRESS")
        or exporter.os.getenv("FRITZBOX_IP")
        or "192.168.178.1",
        user=None,
        password=stored.get("password")
        or exporter.os.getenv("FRITZBOX_PASSWORD")
        or exporter.os.getenv("FRITZBOX_ADMIN_PASS"),
        port=49000,
        tls=False,
        hours=hours,
        include_disconnects=include_disconnects,
    )
    if not args.password:
        raise HTTPException(status_code=401, detail="Set the FRITZ!Box admin password in the UI or .env.")
    return exporter.export_dataset(args)


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def build_raw_artifacts_zip(path: Path = DEFAULT_DB) -> bytes:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, run_id, name, sha256, content, created_at
            FROM raw_artifacts
            ORDER BY created_at DESC, id DESC
            """
        )
    ]
    conn.close()
    if not rows:
        raise HTTPException(status_code=404, detail="No raw FRITZ!Box artifacts are stored yet. Run a fetch first.")

    manifest: list[dict[str, Any]] = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            name = safe_artifact_name(str(row["name"] or "artifact"))
            extension = guess_artifact_extension(name, str(row["content"] or ""))
            created = safe_artifact_name(str(row["created_at"] or "unknown")).replace("T", "_")
            filename = f"raw_artifacts/run-{row['run_id']}/{row['id']:06d}_{created}_{name}{extension}"
            archive.writestr(filename, str(row["content"] or ""))
            manifest.append(
                {
                    "id": row["id"],
                    "run_id": row["run_id"],
                    "name": row["name"],
                    "sha256": row["sha256"],
                    "created_at": row["created_at"],
                    "path": filename,
                    "bytes": len(str(row["content"] or "").encode("utf-8")),
                }
            )
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return buffer.getvalue()


def build_forensic_acquisition_zip(path: Path = DEFAULT_DB) -> bytes:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    tables = {
        "export_runs": "SELECT * FROM export_runs ORDER BY id",
        "raw_artifacts": "SELECT id, run_id, name, sha256, created_at FROM raw_artifacts ORDER BY id",
        "event_log": "SELECT * FROM event_log ORDER BY COALESCE(timestamp, ''), id",
        "wifi_connections": "SELECT * FROM wifi_connections ORDER BY COALESCE(derived_connected_at, ''), id",
        "hosts": "SELECT * FROM hosts ORDER BY hostname, mac, ip, id",
        "support_findings": "SELECT * FROM support_findings ORDER BY line_number, id",
        "record_observations": "SELECT * FROM record_observations ORDER BY observed_at, id",
    }
    table_rows = {name: rows_for_query(conn, sql) for name, sql in tables.items()}
    raw_rows = rows_for_query(
        conn,
        """
        SELECT id, run_id, name, sha256, content, created_at
        FROM raw_artifacts
        ORDER BY created_at DESC, id DESC
        """,
    )
    package_manifest = forensic_manifest(conn, table_rows, raw_rows)
    conn.close()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(package_manifest, indent=2, sort_keys=True))
        archive.writestr("limitations.md", forensic_limitations_text())
        for name, rows in table_rows.items():
            archive.writestr(f"parsed/{name}.json", json.dumps(rows, indent=2, sort_keys=True, default=str))
        for row in raw_rows:
            artifact_name = safe_artifact_name(str(row["name"] or "artifact"))
            extension = guess_artifact_extension(artifact_name, str(row["content"] or ""))
            created = safe_artifact_name(str(row["created_at"] or "unknown")).replace("T", "_")
            filename = f"raw_artifacts/run-{row['run_id']}/{row['id']:06d}_{created}_{artifact_name}{extension}"
            archive.writestr(filename, str(row["content"] or ""))
        archive.writestr("database/fritzbox-analysis.sqlite3", sqlite_backup_bytes(path))
    return buffer.getvalue()


def rows_for_query(conn: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql)]


def forensic_manifest(
    conn: sqlite3.Connection,
    table_rows: dict[str, list[dict[str, Any]]],
    raw_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    latest_run = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    retained = conn.execute(
        "SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event, COUNT(*) AS event_count FROM event_log"
    ).fetchone()
    generated_at = datetime.now().astimezone().isoformat()
    raw_manifest = [
        {
            "id": row["id"],
            "run_id": row["run_id"],
            "name": row["name"],
            "sha256": row["sha256"],
            "created_at": row["created_at"],
            "bytes": len(str(row["content"] or "").encode("utf-8")),
        }
        for row in raw_rows
    ]
    return {
        "package_type": "fritzbox_forensic_acquisition_package",
        "generated_at": generated_at,
        "latest_run": dict(latest_run) if latest_run else None,
        "retained_event_window": dict(retained) if retained else None,
        "source_coverage": source_coverage_for_package(conn, latest_run),
        "record_counts": {name: len(rows) for name, rows in table_rows.items()},
        "raw_artifacts": raw_manifest,
        "hashes": {
            "raw_artifacts": [{"id": row["id"], "sha256": row["sha256"]} for row in raw_rows],
        },
        "evidence_levels": {
            "raw": "Raw artifact exposed by FRITZ!Box during acquisition.",
            "parsed_from_raw": "Field or event parsed from retained raw FRITZ!Box data.",
            "enriched_from_current_host_table": "Context from current/known host table at acquisition time; not proof of historical ownership.",
            "inferred": "Derived context, such as mesh last-observed WLAN rows; not an exact association timestamp.",
        },
        "timestamp_assumptions": {
            "router_event_timestamps": "Parsed from retained FRITZ!Box log text and interpreted in collector local time unless a source includes an offset.",
            "router_clock_status": "Not independently validated by this package.",
        },
        "contamination_notice": {
            "tool_login_may_create_router_log_entries": True,
            "polling_may_create_repeated_observations": True,
            "initial_acquisition_should_be_distinguished_from_monitoring": True,
        },
    }


def source_coverage_for_package(conn: sqlite3.Connection, latest_run: sqlite3.Row | None) -> dict[str, Any]:
    from fritzbox_log_store import acquisition_source_coverage

    run_id = int(latest_run["id"]) if latest_run else None
    return acquisition_source_coverage(conn, run_id)


def sqlite_backup_bytes(path: Path) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp:
        source = sqlite3.connect(path)
        target = sqlite3.connect(tmp.name)
        try:
            source.backup(target)
            target.execute("UPDATE settings SET value = '[redacted from forensic package]' WHERE key = 'password'")
            target.commit()
        finally:
            target.close()
            source.close()
        return Path(tmp.name).read_bytes()


def forensic_limitations_text() -> str:
    return """# FRITZ!Box Forensic Package Limitations

This package preserves what the FRITZ!Box exposed through the local collection tool at acquisition time.

- Retained router log entries are not a full historical record.
- Absence of a log row means only that it was not observed in retained/exported data.
- Mesh `last_observed` values are low-confidence context and are not exact WiFi join times.
- Current host table enrichment can be stale or reassigned.
- Parsed support-data findings are best-effort extraction from an undocumented diagnostic bundle; always validate against the raw `support_data_txt` artifact.
- Router timestamps are not independently validated unless separately documented.
- Tool login and polling may create router log entries and repeated observations.
"""


def safe_artifact_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned or "artifact"


def guess_artifact_extension(name: str, content: str) -> str:
    if Path(name).suffix:
        return ""
    stripped = content.lstrip()
    if stripped.startswith("<"):
        return ".xml"
    if stripped.startswith("{") or stripped.startswith("["):
        return ".json"
    return ".txt"


def create_app() -> FastAPI:
    app = FastAPI(title="FRITZ!Box Forensic Analyzer")
    static_dir = next(
        path for path in (Path(__file__).resolve().parent / "static", Path.cwd() / "static") if path.exists()
    )
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return load_app_html()

    @app.get("/api/latest")
    def api_latest(profile: str = PROFILE_LOCAL, run_id: str = "latest") -> JSONResponse:
        return JSONResponse(json_safe(latest_snapshot(db_for_profile(profile), run_id)))

    @app.get("/api/profiles")
    def api_profiles() -> JSONResponse:
        return JSONResponse(json_safe({"profiles": list_profiles()}))

    @app.get("/api/runs")
    def api_runs(profile: str = PROFILE_LOCAL) -> JSONResponse:
        return JSONResponse(json_safe({"runs": list_runs(db_for_profile(profile))}))

    @app.post("/api/import/package")
    async def api_import_package(request: Request, filename: str = "import.zip") -> JSONResponse:
        payload = await request.body()
        return JSONResponse(json_safe(import_acquisition_package_bytes(payload, filename)))

    @app.get("/api/export")
    def api_export(
        hours: int = Query(default=24, ge=1, le=10000),
        include_disconnects: bool = True,
    ) -> JSONResponse:
        try:
            dataset = export_from_stored_settings(hours, include_disconnects)
            ingest_dataset(dataset, DEFAULT_DB)
            return JSONResponse(json_safe(dataset))
        except SystemExit as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail=f"FRITZ!Box export failed: {type(exc).__name__}: {exc}"
            ) from exc

    @app.get("/api/raw-artifacts/download")
    def api_download_raw_artifacts(profile: str = PROFILE_LOCAL) -> Response:
        payload = build_raw_artifacts_zip(db_for_profile(profile))
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="fritzbox-raw-artifacts-{stamp}.zip"'},
        )

    @app.get("/api/acquisition-package/download")
    def api_download_acquisition_package(profile: str = PROFILE_LOCAL) -> Response:
        payload = build_forensic_acquisition_zip(db_for_profile(profile))
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="fritzbox-forensic-package-{stamp}.zip"'},
        )

    @app.get("/api/search")
    def api_search(
        q: str = "",
        view: str = Query(default="all", pattern="^(all|wifi|hosts|log|support)$"),
        category: str = Query(default="all"),
        limit: int = Query(default=50, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        sort_by: str = "",
        sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
        evidence_level: str = Query(default="all"),
        time_type: str = Query(default="all"),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
        start: str = "",
        end: str = "",
    ) -> JSONResponse:
        return JSONResponse(
            json_safe(
                query_records(
                    db_for_profile(profile),
                    q,
                    view,
                    limit,
                    offset,
                    category,
                    sort_by,
                    sort_dir,
                    evidence_level,
                    time_type,
                    run_id,
                    start,
                    end,
                )
            )
        )

    @app.get("/api/timeline")
    def api_timeline(
        q: str = "",
        category: str = Query(default="all"),
        start: str = "",
        end: str = "",
        limit: int = Query(default=50, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        evidence_level: str = Query(default="all"),
        time_type: str = Query(default="all"),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
    ) -> JSONResponse:
        return JSONResponse(
            json_safe(
                query_timeline(
                    db_for_profile(profile), q, category, start, end, limit, offset, evidence_level, time_type, run_id
                )
            )
        )

    @app.get("/api/analysis")
    def api_analysis(
        start: str = "", end: str = "", profile: str = PROFILE_LOCAL, run_id: str = "latest"
    ) -> JSONResponse:
        return JSONResponse(json_safe(analysis_snapshot(db_for_profile(profile), start, end, run_id)))

    @app.get("/api/entities")
    def api_entities(
        q: str = "",
        limit: int = Query(default=100, ge=1, le=500),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
    ) -> JSONResponse:
        return JSONResponse(json_safe(query_entities(db_for_profile(profile), q, limit, run_id)))

    @app.get("/api/entity")
    def api_entity(value: str = "", profile: str = PROFILE_LOCAL, run_id: str = "latest") -> JSONResponse:
        return JSONResponse(json_safe(entity_pivot(db_for_profile(profile), value, run_id=run_id)))

    @app.get("/api/evidence")
    def api_evidence(
        record_type: str = Query(default=""),
        record_id: int = Query(default=0, ge=0),
        profile: str = PROFILE_LOCAL,
    ) -> JSONResponse:
        return JSONResponse(json_safe(evidence_for_record(db_for_profile(profile), record_type, record_id)))

    @app.get("/api/polling")
    def api_get_polling() -> JSONResponse:
        return JSONResponse(json_safe(poller.snapshot()))

    @app.post("/api/polling")
    async def api_set_polling(request: Request) -> JSONResponse:
        payload = await request.json()
        if payload.get("active"):
            return JSONResponse(json_safe(poller.start(int(payload.get("interval_minutes") or 15))))
        return JSONResponse(json_safe(poller.stop()))

    @app.get("/api/settings")
    def api_get_settings() -> JSONResponse:
        settings = get_settings(DEFAULT_DB)
        if not settings.get("address"):
            settings["address"] = (
                exporter.os.getenv("FRITZBOX_ADDRESS") or exporter.os.getenv("FRITZBOX_IP") or "192.168.178.1"
            )
        return JSONResponse(settings)

    @app.post("/api/settings")
    async def api_save_settings(request: Request) -> JSONResponse:
        payload = await request.json()
        if not payload.get("address"):
            raise HTTPException(status_code=400, detail="FRITZ!Box IP/address is required.")
        return JSONResponse(save_settings(payload, DEFAULT_DB))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(prog="fritzbox-wifi-dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(), host=args.host, port=args.port)


app = create_app()


if __name__ == "__main__":
    main()
