#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

import fritzbox_wifi_export as exporter
from fritzbox_alerts import get_alert_webhook_settings, mark_alert_state, save_alert_webhook_settings
from fritzbox_api_models import (
    AlertStateRequest,
    AlertWebhookSettingsRequest,
    LiveCaptureRequest,
    PollingRequest,
    SettingsRequest,
    VpnProvisionPlanRequest,
    model_payload,
)
from fritzbox_live_capture import list_capture_interfaces, run_wlan_management_capture
from fritzbox_log_store import (
    ADDITIONAL_EVIDENCE_TABLES,
    DEFAULT_DB,
    analysis_snapshot,
    entity_pivot,
    evidence_for_record,
    get_settings,
    ingest_dataset,
    init_db,
    investigation_snapshot,
    latest_snapshot,
    list_runs,
    query_entities,
    query_records,
    query_timeline,
    save_settings,
    siem_search_facets,
)
from fritzbox_logging import get_logger
from fritzbox_siem_parser import list_parser_rules
from fritzbox_vpn_provision import (
    DynDnsIntent,
    ProvisionIntent,
    WireGuardIntent,
    discover_router_vpn_state_from_connection,
)
from fritzbox_vpn_provision import (
    build_plan as build_vpn_provision_plan,
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
MAX_IMPORT_BYTES = 250 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(r"(?i)(sid=)[0-9a-f]{16}"),
    re.compile(r"(?i)((?:password|passwd|pass|pwd|secret|token|key)=)[^&\\s]+"),
)
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
API_TOKEN_ENV = "FRITZBOX_API_TOKEN"
logger = get_logger("dashboard")


def api_docs_enabled() -> bool:
    return os.getenv("FRITZBOX_ENABLE_API_DOCS", "").casefold() in {"1", "true", "yes", "on"}


def public_bind_allowed() -> bool:
    return os.getenv("FRITZBOX_ALLOW_PUBLIC_BIND", "").casefold() in {"1", "true", "yes", "on"}


def configured_api_token() -> str:
    return os.getenv(API_TOKEN_ENV, "").strip()


def api_auth_required() -> bool:
    return public_bind_allowed() or bool(configured_api_token())


def request_has_api_token(request: Request) -> bool:
    expected = configured_api_token()
    if not expected:
        return False
    provided = request.headers.get("x-api-token", "").strip()
    authorization = request.headers.get("authorization", "").strip()
    if authorization.casefold().startswith("bearer "):
        provided = authorization[7:].strip()
    return hmac.compare_digest(provided, expected)


def is_loopback_bind(host: str) -> bool:
    value = host.strip().casefold()
    return value in LOOPBACK_HOSTS


def sanitized_error(exc: BaseException) -> str:
    message = str(exc)
    for pattern in SECRET_PATTERNS:
        message = pattern.sub(r"\1<redacted>", message)
    return message[:500]


def http_error(status_code: int, prefix: str, exc: BaseException) -> HTTPException:
    detail = f"{prefix}: {type(exc).__name__}"
    message = sanitized_error(exc)
    if message:
        detail = f"{detail}: {message}"
    if exc.__traceback__:
        logger.error("%s", detail, exc_info=(type(exc), exc, exc.__traceback__))
    else:
        logger.error("%s", detail)
    return HTTPException(status_code=status_code, detail=detail)


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


def clear_profile(profile: str = PROFILE_LOCAL) -> dict[str, Any]:
    profile = safe_profile_id(profile or PROFILE_LOCAL)
    path = DEFAULT_DB if profile == PROFILE_LOCAL else profile_dir() / f"{profile}.sqlite3"
    if profile != PROFILE_LOCAL and not path.exists():
        raise HTTPException(status_code=404, detail=f"Analysis profile not found: {profile}")
    for suffix in ("", "-wal", "-shm"):
        target = Path(f"{path}{suffix}")
        target.unlink(missing_ok=True)
    init_db(path).close()
    return {"cleared": True, "profile": profile, "summary": profile_summary(profile, path)}


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
            db_info = archive.getinfo(db_members[0])
            if db_info.flag_bits & 0x1:
                raise HTTPException(status_code=400, detail="Encrypted ZIP imports are not supported.")
            if db_info.file_size > MAX_IMPORT_BYTES:
                raise HTTPException(status_code=413, detail="Imported database is too large.")
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
                logger.exception("polling acquisition failed")
            self._stop.wait(self.interval_minutes * 60)


poller = Poller()


@dataclass
class AcquisitionJob:
    job_id: str
    hours: int
    include_disconnects: bool
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    started_at: str | None = None
    finished_at: str | None = None
    active_stage: str | None = None
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    error: str | None = None
    run_id: int | None = None
    raw_acquisition_dir: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)

    def snapshot(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "hours": self.hours,
            "include_disconnects": self.include_disconnects,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "active_stage": self.active_stage,
            "stages": self.stages,
            "error": self.error,
            "run_id": self.run_id,
            "raw_acquisition_dir": self.raw_acquisition_dir,
            "summary": self.summary,
        }


class AcquisitionJobManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, AcquisitionJob] = {}
        self._active_job_id: str | None = None
        self._latest_job_id: str | None = None

    def start(self, hours: int, include_disconnects: bool) -> dict[str, Any]:
        with self._lock:
            active = self._active_job()
            if active is not None:
                snapshot = active.snapshot()
                snapshot["already_running"] = True
                return snapshot
            job = AcquisitionJob(str(uuid4()), hours, include_disconnects)
            self._jobs[job.job_id] = job
            self._active_job_id = job.job_id
            self._latest_job_id = job.job_id
            thread = threading.Thread(
                target=self._run, args=(job.job_id,), name=f"acquisition-{job.job_id[:8]}", daemon=True
            )
            thread.start()
            logger.info("acquisition job queued job_id=%s hours=%s", job.job_id, hours)
            return job.snapshot()

    def status(self, job_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            resolved = job_id or self._latest_job_id
            if not resolved or resolved not in self._jobs:
                return {"status": "idle", "job_id": None}
            return self._jobs[resolved].snapshot()

    def update_stage(self, job_id: str, stage: str, status: str, details: dict[str, Any] | None = None) -> None:
        now = datetime.now().astimezone().isoformat()
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            current = job.stages.setdefault(stage, {"stage": stage, "started_at": now})
            current["status"] = status
            current["updated_at"] = now
            if details:
                current.update(details)
            if status == "running":
                job.active_stage = stage
            elif job.active_stage == stage and status in {"completed", "failed"}:
                job.active_stage = None

    def _run(self, job_id: str) -> None:
        self._mark_running(job_id)
        try:
            self.update_stage(job_id, "settings", "running")
            # Fail fast on missing saved credentials before opening the collector pipeline.
            stored_connection_args()
            self.update_stage(job_id, "settings", "completed")

            self.update_stage(job_id, "raw_and_parse", "running")
            dataset = export_from_stored_settings(
                self._jobs[job_id].hours,
                self._jobs[job_id].include_disconnects,
                progress_callback=lambda stage, status, details: self.update_stage(
                    job_id, f"raw_{stage}", status, details
                ),
            )
            self.update_stage(job_id, "raw_and_parse", "completed")

            self.update_stage(job_id, "sqlite_ingest", "running")
            run_id = ingest_dataset(dataset, DEFAULT_DB)
            self.update_stage(job_id, "sqlite_ingest", "completed", {"run_id": run_id})
            self._mark_completed(job_id, run_id, dataset)
        except Exception as exc:
            self._mark_failed(job_id, exc)

    def _active_job(self) -> AcquisitionJob | None:
        if not self._active_job_id:
            return None
        job = self._jobs.get(self._active_job_id)
        if job and job.status in {"queued", "running"}:
            return job
        return None

    def _mark_running(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "running"
            job.started_at = datetime.now().astimezone().isoformat()
        logger.info("acquisition job started job_id=%s", job_id)

    def _mark_completed(self, job_id: str, run_id: int, dataset: dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "completed"
            job.finished_at = datetime.now().astimezone().isoformat()
            job.run_id = run_id
            job.raw_acquisition_dir = str((dataset.get("summary") or {}).get("raw_acquisition_dir") or "")
            job.summary = dataset.get("summary") or {}
            job.active_stage = None
            if self._active_job_id == job_id:
                self._active_job_id = None
        logger.info("acquisition job completed job_id=%s run_id=%s raw_dir=%s", job_id, run_id, job.raw_acquisition_dir)

    def _mark_failed(self, job_id: str, exc: BaseException) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "failed"
            job.finished_at = datetime.now().astimezone().isoformat()
            job.error = sanitized_error(exc)
            job.active_stage = None
            if self._active_job_id == job_id:
                self._active_job_id = None
        logger.error(
            "acquisition job failed job_id=%s error=%s",
            job_id,
            sanitized_error(exc),
            exc_info=(type(exc), exc, exc.__traceback__),
        )


acquisition_jobs = AcquisitionJobManager()


def export_from_stored_settings(
    hours: int,
    include_disconnects: bool,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    args = stored_connection_args()
    return exporter.export_dataset(
        argparse.Namespace(
            **vars(args),
            hours=hours,
            include_disconnects=include_disconnects,
            progress_callback=progress_callback,
        )
    )


def stored_connection_args() -> argparse.Namespace:
    exporter.load_env_file(Path(".env"))
    exporter.load_env_file(Path(".fritzbox.env"))
    stored = get_settings(DEFAULT_DB, include_secret=True)
    args = argparse.Namespace(
        address=stored.get("address") or os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1",
        user=None,
        password=stored.get("password") or os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS"),
        port=49000,
        tls=False,
    )
    if not args.password:
        raise HTTPException(status_code=401, detail="Set the FRITZ!Box admin password in the UI or .env.")
    return args


def fritz_connection_from_stored_settings() -> Any:
    try:
        from fritzconnection import FritzConnection
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="Missing dependency: fritzconnection") from exc
    args = stored_connection_args()
    return FritzConnection(
        address=args.address,
        user=args.user,
        password=args.password,
        port=args.port,
        use_tls=args.tls,
        use_cache=True,
        timeout=30,
    )


def vpn_provision_intent_from_payload(payload: dict[str, Any]) -> ProvisionIntent:
    dyndns = payload.get("dyndns") or {}
    wireguard = payload.get("wireguard") or {}
    return ProvisionIntent(
        dyndns=DynDnsIntent(
            enabled=bool(dyndns.get("enabled", True)),
            provider=str(dyndns.get("provider") or "user-defined"),
            domain=str(dyndns.get("domain") or ""),
            username=str(dyndns.get("username") or ""),
            password=str(dyndns.get("password") or ""),
            update_url=str(dyndns.get("update_url") or ""),
            replace_existing=bool(dyndns.get("replace_existing", False)),
        ),
        wireguard=WireGuardIntent(
            client_name=str(wireguard.get("client_name") or ""),
            client_public_key=str(wireguard.get("client_public_key") or ""),
            allowed_ips=str(wireguard.get("allowed_ips") or "192.168.178.0/24"),
            dns=str(wireguard.get("dns") or "192.168.178.1"),
            endpoint_port=int(wireguard.get("endpoint_port") or 51820),
            route_all_traffic=bool(wireguard.get("route_all_traffic", False)),
            replace_existing=bool(wireguard.get("replace_existing", False)),
        ),
    )


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def build_raw_artifacts_zip(path: Path = DEFAULT_DB) -> bytes:
    init_db(path).close()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = [dict(row) for row in conn.execute("""
            SELECT id, run_id, name, sha256, content, created_at
            FROM raw_artifacts
            ORDER BY created_at DESC, id DESC
            """)]
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
    init_db(path).close()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    tables = {
        "export_runs": "SELECT * FROM export_runs ORDER BY id",
        "raw_artifacts": "SELECT id, run_id, name, sha256, created_at FROM raw_artifacts ORDER BY id",
        "event_log": "SELECT * FROM event_log ORDER BY COALESCE(timestamp, ''), id",
        "wifi_connections": "SELECT * FROM wifi_connections ORDER BY COALESCE(derived_connected_at, ''), id",
        "hosts": "SELECT * FROM hosts ORDER BY hostname, mac, ip, id",
        "support_findings": "SELECT * FROM support_findings ORDER BY line_number, id",
        "siem_events": "SELECT * FROM siem_events ORDER BY COALESCE(event_time, ''), id",
        "siem_correlations": "SELECT * FROM siem_correlations ORDER BY COALESCE(last_seen, ''), id",
        "record_observations": "SELECT * FROM record_observations ORDER BY observed_at, id",
        **{table: f"SELECT * FROM {table} ORDER BY id" for table in ADDITIONAL_EVIDENCE_TABLES},
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
    source = sqlite3.connect(path, timeout=30.0)
    target = sqlite3.connect(":memory:")
    try:
        source.execute("PRAGMA busy_timeout = 30000")
        source.backup(target)
        target.execute("UPDATE settings SET value = '[redacted from forensic package]' WHERE key = 'password'")
        target.execute("UPDATE settings SET value = '[redacted from forensic package]' WHERE key = 'alert_webhook_url'")
        target.commit()
        return target.serialize()
    finally:
        target.close()
        source.close()


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
    docs_url = "/docs" if api_docs_enabled() else None
    redoc_url = "/redoc" if api_docs_enabled() else None
    openapi_url = "/openapi.json" if api_docs_enabled() else None
    app = FastAPI(
        title="FRITZ!Box Forensik SIEM",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )
    static_dir = next(
        path for path in (Path(__file__).resolve().parent / "static", Path.cwd() / "static") if path.exists()
    )
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.middleware("http")
    async def require_api_token_for_public_api(request: Request, call_next):
        if request.url.path.startswith("/api/") and api_auth_required() and not request_has_api_token(request):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": f"API token required. Send X-API-Token or Authorization: Bearer from {API_TOKEN_ENV}."
                },
            )
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return load_app_html()

    @app.get("/api/latest")
    def api_latest(profile: str = PROFILE_LOCAL, run_id: str = "latest") -> JSONResponse:
        return JSONResponse(json_safe(latest_snapshot(db_for_profile(profile), run_id)))

    @app.get("/api/profiles")
    def api_profiles() -> JSONResponse:
        return JSONResponse(json_safe({"profiles": list_profiles()}))

    @app.delete("/api/profile")
    def api_clear_profile(profile: str = PROFILE_LOCAL, confirm: str = "") -> JSONResponse:
        if confirm != "DELETE":
            raise HTTPException(status_code=400, detail="Type DELETE to clear the selected analysis profile.")
        return JSONResponse(json_safe(clear_profile(profile)))

    @app.get("/api/runs")
    def api_runs(profile: str = PROFILE_LOCAL) -> JSONResponse:
        return JSONResponse(json_safe({"runs": list_runs(db_for_profile(profile))}))

    @app.post("/api/import/package")
    async def api_import_package(request: Request, filename: str = "import.zip") -> JSONResponse:
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > MAX_IMPORT_BYTES:
                    raise HTTPException(status_code=413, detail="Import file is too large.")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from None
        payload = await request.body()
        if len(payload) > MAX_IMPORT_BYTES:
            raise HTTPException(status_code=413, detail="Import file is too large.")
        return JSONResponse(json_safe(import_acquisition_package_bytes(payload, filename)))

    @app.post("/api/acquisition/start")
    def api_acquisition_start(
        hours: int = Query(default=10000, ge=1, le=10000),
        include_disconnects: bool = True,
    ) -> JSONResponse:
        return JSONResponse(json_safe(acquisition_jobs.start(hours, include_disconnects)), status_code=202)

    @app.get("/api/acquisition/status")
    def api_acquisition_status(job_id: str = "") -> JSONResponse:
        return JSONResponse(json_safe(acquisition_jobs.status(job_id or None)))

    @app.get("/api/export")
    def api_export(
        hours: int = Query(default=24, ge=1, le=10000),
        include_disconnects: bool = True,
    ) -> JSONResponse:
        logger.info(
            "api export requested as background job hours=%s include_disconnects=%s", hours, include_disconnects
        )
        return JSONResponse(json_safe(acquisition_jobs.start(hours, include_disconnects)), status_code=202)

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
        view: str = Query(
            default="events",
            pattern=(
                "^(all|timeline|events|siem|siem_events|normalized_events|correlations|siem_correlations|"
                "wifi|hosts|presence|log|support|raw|host_filter|host_filters|host_filter_profiles|"
                "mesh|mesh_links|mesh_topology|mesh_topology_links|wan|wan_exposure|port_mappings|wan_port_mappings|"
                "wlan_radios|wlan_radio|wlan_associations|wlan_association|"
                "advertisements|advertisement|advertisement_hints|advertising|broadcasts|broadcast_hints|"
                "network_status|network_counters|network_status_snapshots|wan_stats|dsl_stats|lan_stats|"
                "device_risks|device_risk|device_risk_summaries|"
                "security|security_advisory|security_advisories|security_audit|security_audit_findings)$"
            ),
        ),
        category: str = Query(default="all"),
        limit: int = Query(default=50, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        sort_by: str = "",
        sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
        evidence_level: str = Query(default="all"),
        time_type: str = Query(default="all"),
        kind: str = Query(default="all"),
        severity: str = Query(default="all"),
        source: str = Query(default="all"),
        parser_rule: str = Query(default="all"),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
        start: str = "",
        end: str = "",
    ) -> JSONResponse:
        if view == "timeline":
            return JSONResponse(
                json_safe(
                    query_timeline(
                        db_for_profile(profile),
                        q,
                        category,
                        start,
                        end,
                        limit,
                        offset,
                        evidence_level,
                        time_type,
                        run_id,
                        kind,
                        severity,
                        source,
                        parser_rule,
                    )
                )
            )
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
                    kind,
                    severity,
                    source,
                    parser_rule,
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
        kind: str = Query(default="all"),
        severity: str = Query(default="all"),
        source: str = Query(default="all"),
        parser_rule: str = Query(default="all"),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
    ) -> JSONResponse:
        return JSONResponse(
            json_safe(
                query_timeline(
                    db_for_profile(profile),
                    q,
                    category,
                    start,
                    end,
                    limit,
                    offset,
                    evidence_level,
                    time_type,
                    run_id,
                    kind,
                    severity,
                    source,
                    parser_rule,
                )
            )
        )

    @app.get("/api/siem/facets")
    def api_siem_facets(
        q: str = "",
        category: str = Query(default="all"),
        start: str = "",
        end: str = "",
        evidence_level: str = Query(default="all"),
        time_type: str = Query(default="all"),
        kind: str = Query(default="all"),
        severity: str = Query(default="all"),
        source: str = Query(default="all"),
        parser_rule: str = Query(default="all"),
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
    ) -> JSONResponse:
        return JSONResponse(
            json_safe(
                siem_search_facets(
                    db_for_profile(profile),
                    q,
                    category,
                    start,
                    end,
                    evidence_level,
                    time_type,
                    run_id,
                    kind,
                    severity,
                    source,
                    parser_rule,
                )
            )
        )

    @app.get("/api/analysis")
    def api_analysis(
        start: str = "", end: str = "", profile: str = PROFILE_LOCAL, run_id: str = "latest"
    ) -> JSONResponse:
        return JSONResponse(json_safe(analysis_snapshot(db_for_profile(profile), start, end, run_id)))

    @app.get("/api/parser-rules")
    def api_parser_rules() -> JSONResponse:
        rules = list_parser_rules()
        return JSONResponse({"rules": rules, "total": len(rules)})

    @app.get("/api/investigation")
    def api_investigation(
        start: str = "",
        end: str = "",
        q: str = "",
        interface: str = "all",
        presence_mode: str = "overlap",
        confidence: str = "all",
        profile: str = PROFILE_LOCAL,
        run_id: str = "latest",
    ) -> JSONResponse:
        return JSONResponse(
            json_safe(
                investigation_snapshot(
                    db_for_profile(profile),
                    start,
                    end,
                    run_id,
                    query=q,
                    interface=interface,
                    presence_mode=presence_mode,
                    confidence=confidence,
                )
            )
        )

    @app.get("/api/live-80211/status")
    def api_live_80211_status() -> JSONResponse:
        try:
            fc = fritz_connection_from_stored_settings()
            return JSONResponse(json_safe(list_capture_interfaces(fc)))
        except Exception as exc:
            detail = sanitized_error(exc)
            logger.warning("Live 802.11 interface discovery failed: %s", detail)
            return JSONResponse(
                {
                    "interfaces": [],
                    "preferred": "",
                    "note": f"FRITZ!Box live capture unavailable: {type(exc).__name__}: {detail}",
                    "error": detail,
                }
            )

    @app.post("/api/live-80211/capture")
    def api_live_80211_capture(payload: LiveCaptureRequest) -> JSONResponse:
        try:
            fc = fritz_connection_from_stored_settings()
            return JSONResponse(json_safe(run_wlan_management_capture(fc, payload.duration_seconds, payload.interface)))
        except Exception as exc:
            detail = sanitized_error(exc)
            logger.warning("Live 802.11 capture failed: %s", detail)
            return JSONResponse(
                {
                    "duration_seconds": payload.duration_seconds,
                    "interface": payload.interface,
                    "frames": [],
                    "parse": {"error": detail, "packet_count": 0, "probe_request_count": 0},
                    "note": f"FRITZ!Box live capture unavailable: {type(exc).__name__}: {detail}",
                    "error": detail,
                    "pcap_base64": "",
                }
            )

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
    def api_set_polling(payload: PollingRequest) -> JSONResponse:
        if payload.active:
            return JSONResponse(json_safe(poller.start(payload.interval_minutes)))
        return JSONResponse(json_safe(poller.stop()))

    @app.get("/api/settings")
    def api_get_settings() -> JSONResponse:
        settings = get_settings(DEFAULT_DB)
        if not settings.get("address"):
            settings["address"] = os.getenv("FRITZBOX_ADDRESS") or os.getenv("FRITZBOX_IP") or "192.168.178.1"
        env_has_password = bool(os.getenv("FRITZBOX_PASSWORD") or os.getenv("FRITZBOX_ADMIN_PASS"))
        settings["has_password"] = bool(settings.get("has_password") or env_has_password)
        settings["password_source"] = (
            "saved"
            if get_settings(DEFAULT_DB, include_secret=True).get("password")
            else ("env" if env_has_password else "")
        )
        return JSONResponse(settings)

    @app.post("/api/settings")
    def api_save_settings(payload: SettingsRequest) -> JSONResponse:
        return JSONResponse(save_settings(model_payload(payload), DEFAULT_DB))

    @app.get("/api/alert-webhook")
    def api_get_alert_webhook() -> JSONResponse:
        return JSONResponse(get_alert_webhook_settings(DEFAULT_DB))

    @app.post("/api/alert-webhook")
    def api_save_alert_webhook(payload: AlertWebhookSettingsRequest) -> JSONResponse:
        try:
            return JSONResponse(save_alert_webhook_settings(model_payload(payload), DEFAULT_DB))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/alerts/{correlation_id}/state")
    def api_set_alert_state(
        correlation_id: int, payload: AlertStateRequest, profile: str = PROFILE_LOCAL
    ) -> JSONResponse:
        try:
            state = mark_alert_state(
                correlation_id=correlation_id,
                status=payload.status,
                note=payload.note,
                resolved_by=payload.resolved_by,
                path=db_for_profile(profile),
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(json_safe(state))

    @app.post("/api/vpn-provision/plan")
    def api_vpn_provision_plan(payload: VpnProvisionPlanRequest) -> JSONResponse:
        try:
            fc = fritz_connection_from_stored_settings()
            state = discover_router_vpn_state_from_connection(fc, stored_connection_args().address)
            plan = build_vpn_provision_plan(
                state,
                vpn_provision_intent_from_payload(model_payload(payload)),
                dry_run=True,
            )
            return JSONResponse(json_safe(plan.to_dict()))
        except SystemExit as exc:
            raise http_error(401, "VPN provision planning failed", exc) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise http_error(500, "VPN provision planning failed", exc) from exc

    return app


def main() -> None:
    parser = argparse.ArgumentParser(prog="fritzbox-wifi-dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not is_loopback_bind(args.host) and not public_bind_allowed():
        raise SystemExit(
            "Refusing to bind the forensic dashboard outside localhost. "
            "Set FRITZBOX_ALLOW_PUBLIC_BIND=1 only on a trusted network."
        )

    import uvicorn

    uvicorn.run(create_app(), host=args.host, port=args.port)


app = create_app()


if __name__ == "__main__":
    main()
