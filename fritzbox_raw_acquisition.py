from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import traceback
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import get_context
from pathlib import Path
from typing import Any

from fritzbox_collectors import (
    DATA_LUA_PAGES,
    LANDEVICE_FALLBACK_FIELDS,
    LANDEVICE_RICH_FIELDS,
    MAX_WEBUI_ARTIFACT_BYTES,
    QUERY_LUA_QUERIES,
    WEBUI_READONLY_ENDPOINTS,
    action_input_arguments,
    append_query_params,
    fetch_aha_artifacts,
    fetch_avm_path,
    fetch_config_export,
    fetch_support_data,
    fetch_support_lua_page,
    fetch_telephony_exports,
    fetch_webui_text,
    get_device_info,
    get_device_log,
    get_router_time,
    get_webui_sid,
    is_html_response,
    is_read_only_action,
    is_support_data_response,
    safe_call_action,
    tr064_service_inventory,
)
from fritzbox_logging import get_logger, redact

RAW_OUTPUT_ROOT = Path("output")
RAW_SCHEMA_VERSION = 1
DEFAULT_DELAY_SECONDS = 0.75
DEFAULT_HARD_TIMEOUT_SECONDS = 30
DEFAULT_SUPPORT_HARD_TIMEOUT_SECONDS = 180
logger = get_logger("raw_acquisition")


AVM_EXPORT_PATH_SPECS = (
    ("device_log_xml", "DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath", "NewDeviceLogPath", None),
    (
        "device_log_xml_wlan",
        "DeviceInfo:1",
        "X_AVM-DE_GetDeviceLogPath",
        "NewDeviceLogPath",
        {"filter": "wlan"},
    ),
    ("mesh_list", "Hosts:1", "X_AVM-DE_GetMeshListPath", "NewX_AVM-DE_MeshListPath", None),
    ("host_list_xml", "Hosts:1", "X_AVM-DE_GetHostListPath", "NewX_AVM-DE_HostListPath", None),
)


@dataclass(frozen=True)
class RawAcquisitionResult:
    directory: Path
    manifest_path: Path
    generated_at: str


def restrict_path_permissions(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        logger.debug("could not restrict raw acquisition permissions path=%s", path)


class RawAcquisitionWriter:
    """Append-only raw evidence writer.

    Every endpoint attempt gets a manifest row and successful payloads are
    written immediately. The parser can fail later without losing the raw
    acquisition evidence.
    """

    def __init__(self, directory: Path, generated_at: str) -> None:
        self.directory = directory
        self.generated_at = generated_at
        self.manifest_path = directory / "manifest.jsonl"
        self.attempts: list[dict[str, Any]] = []
        self.artifacts: dict[str, str] = {}
        directory.mkdir(parents=True, exist_ok=True)
        restrict_path_permissions(directory, 0o700)

    def write_text(self, name: str, content: str, surface: str, **details: Any) -> None:
        safe_name = safe_file_stem(name)
        path = self.directory / f"{safe_name}{extension_for_artifact(name, content)}"
        path.write_text(content, encoding="utf-8")
        restrict_path_permissions(path, 0o600)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.artifacts[name] = path.name
        self.add_attempt(
            name, surface, True, path=path.name, bytes=len(content.encode("utf-8")), sha256=digest, **details
        )
        logger.debug("raw artifact written artifact=%s surface=%s path=%s bytes=%s", name, surface, path, len(content))

    def write_json(self, name: str, payload: Any, surface: str, **details: Any) -> None:
        self.write_text(name, json.dumps(payload, indent=2, sort_keys=True, default=str), surface, **details)

    def write_existing_file(self, name: str, source_path: Path, surface: str, **details: Any) -> None:
        safe_name = safe_file_stem(name)
        target = self.directory / f"{safe_name}{extension_for_artifact(name, source_path.name)}"
        if source_path.resolve() != target.resolve():
            shutil.move(str(source_path), target)
        restrict_path_permissions(target, 0o600)
        digest = file_sha256(target)
        self.artifacts[name] = target.name
        self.add_attempt(name, surface, True, path=target.name, bytes=target.stat().st_size, sha256=digest, **details)
        logger.debug(
            "raw artifact file written artifact=%s surface=%s path=%s bytes=%s",
            name,
            surface,
            target,
            target.stat().st_size,
        )

    def write_error(self, name: str, surface: str, error: Any, **details: Any) -> None:
        message = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
        safe_name = safe_file_stem(name)
        path = self.directory / f"{safe_name}.error.txt"
        path.write_text(str(message) + "\n", encoding="utf-8")
        restrict_path_permissions(path, 0o600)
        self.add_attempt(name, surface, False, path=path.name, error=str(message), **details)
        logger.warning("raw artifact failed artifact=%s surface=%s error=%s", name, surface, redact(message))

    def add_attempt(self, artifact: str, surface: str, ok: bool, **details: Any) -> None:
        row = {
            "schema_version": RAW_SCHEMA_VERSION,
            "artifact": artifact,
            "surface": surface,
            "ok": bool(ok),
            "attempted_at": datetime.now().astimezone().isoformat(),
        }
        row.update(redact_manifest_details(details))
        self.attempts.append(row)
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        restrict_path_permissions(self.manifest_path, 0o600)

    def write_summary(self) -> None:
        summary = {
            "schema_version": RAW_SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "artifact_count": len(self.artifacts),
            "attempt_count": len(self.attempts),
            "successful_count": sum(1 for item in self.attempts if item.get("ok")),
            "failed_count": sum(1 for item in self.attempts if not item.get("ok")),
            "artifacts": self.artifacts,
            "attempts": self.attempts,
        }
        (self.directory / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        restrict_path_permissions(self.directory / "summary.json", 0o600)


ProgressCallback = Callable[[str, str, dict[str, Any]], None]


def acquire_raw_bundle(
    args: Any,
    output_dir: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> RawAcquisitionResult:
    """Acquire raw FRITZ!Box artifacts to local files before parsing.

    This intentionally runs mostly sequentially with small pauses. FRITZ!Box
    Web UI endpoints are firmware-dependent and fragile; a slow or failed
    endpoint must not abort the acquisition.
    """

    generated_at = datetime.now().astimezone().isoformat()
    directory = output_dir or RAW_OUTPUT_ROOT / f"raw-acquisition-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    writer = RawAcquisitionWriter(directory, generated_at)
    writer.write_json(
        "00_metadata",
        {
            "schema_version": RAW_SCHEMA_VERSION,
            "generated_at": generated_at,
            "router": {
                "address": getattr(args, "address", None),
                "port": getattr(args, "port", None),
                "tls": bool(getattr(args, "tls", False)),
                "user_provided": bool(getattr(args, "user", None)),
            },
            "mode": "raw_first_best_effort",
        },
        "metadata",
    )
    logger.info(
        "raw acquisition started dir=%s address=%s port=%s tls=%s",
        directory,
        getattr(args, "address", None),
        getattr(args, "port", None),
        bool(getattr(args, "tls", False)),
    )

    try:
        from fritzconnection import FritzConnection
    except ImportError as exc:
        writer.write_error("fritzconnection_import", "local_dependency", exc)
        writer.write_summary()
        logger.exception("raw acquisition aborted: missing fritzconnection")
        return RawAcquisitionResult(directory, writer.manifest_path, generated_at)

    try:
        fc = FritzConnection(
            address=args.address,
            user=getattr(args, "user", None),
            password=getattr(args, "password", None),
            port=getattr(args, "port", 49000),
            use_tls=bool(getattr(args, "tls", False)),
            use_cache=True,
            timeout=int(os.getenv("FRITZBOX_REQUEST_TIMEOUT", "20") or "20"),
            pool_connections=1,
            pool_maxsize=1,
        )
    except Exception as exc:
        writer.write_error("fritz_connection", "tr064_connect", exc)
        writer.write_summary()
        logger.exception("raw acquisition could not create FritzConnection")
        return RawAcquisitionResult(directory, writer.manifest_path, generated_at)

    delay = acquisition_delay()
    run_stage(writer, "core_tr064", lambda: collect_core_tr064(writer, fc, delay), progress_callback)
    run_stage(writer, "avm_export_paths", lambda: collect_avm_export_paths(writer, fc, args, delay), progress_callback)
    run_stage(writer, "data_lua_pages", lambda: collect_webui_pages(writer, fc, delay), progress_callback)
    run_stage(writer, "query_lua", lambda: collect_query_lua(writer, fc, delay), progress_callback)
    run_stage(writer, "webui_readonly", lambda: collect_webui_readonly(writer, fc, delay), progress_callback)
    run_stage(writer, "tr064_snapshot", lambda: collect_tr064_snapshot_raw(writer, fc, delay), progress_callback)
    run_stage(
        writer, "optional_surfaces", lambda: collect_optional_surfaces(writer, fc, args, delay), progress_callback
    )
    writer.write_summary()
    logger.info(
        "raw acquisition finished dir=%s attempts=%s successful=%s failed=%s",
        directory,
        len(writer.attempts),
        sum(1 for item in writer.attempts if item.get("ok")),
        sum(1 for item in writer.attempts if not item.get("ok")),
    )
    return RawAcquisitionResult(directory, writer.manifest_path, generated_at)


def acquire_hard_timeout_bundle(
    args: Any,
    output_dir: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> RawAcquisitionResult:
    """Conservative acquisition mode using one child process per router call.

    Some FRITZ!Box models/firmwares can hang below the HTTP timeout layer. This
    mode gives every artifact an OS-level timeout and tears down the child
    process if it stalls, while preserving all successful raw artifacts.
    """

    generated_at = datetime.now().astimezone().isoformat()
    directory = output_dir or RAW_OUTPUT_ROOT / f"raw-acquisition-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    writer = RawAcquisitionWriter(directory, generated_at)
    writer.write_json(
        "00_metadata",
        {
            "schema_version": RAW_SCHEMA_VERSION,
            "generated_at": generated_at,
            "router": {
                "address": getattr(args, "address", None),
                "port": getattr(args, "port", None),
                "tls": bool(getattr(args, "tls", False)),
                "user_provided": bool(getattr(args, "user", None)),
            },
            "mode": "hard_timeout_best_effort",
        },
        "metadata",
    )
    logger.info("hard-timeout acquisition started dir=%s address=%s", directory, getattr(args, "address", None))

    base = {
        "address": getattr(args, "address", None),
        "user": getattr(args, "user", None),
        "password": getattr(args, "password", None),
        "port": getattr(args, "port", 49000),
        "tls": bool(getattr(args, "tls", False)),
    }
    jobs = [
        (
            "core_tr064",
            "device_info_json",
            "call",
            {**base, "service": "DeviceInfo:1", "action": "GetInfo"},
            hard_timeout(),
        ),
        ("core_tr064", "router_time_json", "call", {**base, "service": "Time:1", "action": "GetInfo"}, hard_timeout()),
        ("core_tr064", "hosts_tr064_generic_json", "hosts", base, hard_timeout(90)),
        (
            "core_tr064",
            "device_log_text_json",
            "call",
            {**base, "service": "DeviceInfo:1", "action": "GetDeviceLog"},
            hard_timeout(45),
        ),
        *avm_export_path_jobs(base, timeout=hard_timeout(60)),
        ("webui_query_lua", "landevice_query_json", "landevice_query", base, hard_timeout(45)),
        *[
            (
                "webui_query_lua",
                f"query_lua_{name}",
                "query_lua",
                {**base, "query_name": name, "query": query},
                hard_timeout(45),
            )
            for name, query in QUERY_LUA_QUERIES.items()
        ],
        ("support_bundle", "support_lua_page_html", "support_lua", base, hard_timeout(45)),
        ("support_bundle", "support_data_txt", "support", base, support_hard_timeout()),
        (
            "network_state",
            "wan_ip_info_json",
            "call",
            {**base, "service": "WANIPConn:1", "action": "GetInfo"},
            hard_timeout(),
        ),
        (
            "network_state",
            "wan_external_ip_json",
            "call",
            {**base, "service": "WANIPConn:1", "action": "GetExternalIPAddress"},
            hard_timeout(),
        ),
        (
            "network_state",
            "lan_host_config_json",
            "call",
            {**base, "service": "LANHostConfigManagement:1", "action": "GetInfo"},
            hard_timeout(),
        ),
        *[
            (
                "webui_data_lua",
                f"data_lua_page_{page}",
                "data_lua",
                {**base, "page": page},
                hard_timeout(45),
            )
            for page in DATA_LUA_PAGES
        ],
        ("webui_readonly", "webui_readonly_artifacts_json", "webui_readonly", base, hard_timeout(45)),
    ]
    run_artifact_jobs(writer, jobs, progress_callback)
    writer.write_summary()
    logger.info(
        "hard-timeout acquisition finished dir=%s attempts=%s successful=%s failed=%s",
        directory,
        len(writer.attempts),
        sum(1 for item in writer.attempts if item.get("ok")),
        sum(1 for item in writer.attempts if not item.get("ok")),
    )
    return RawAcquisitionResult(directory, writer.manifest_path, generated_at)


def acquire_critical_bundle(
    args: Any,
    output_dir: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> RawAcquisitionResult:
    """Acquire only the high-value forensic artifacts needed in the field.

    This mode is intentionally narrow and slow: support data and FRITZ!Box
    internal device-history queries are attempted before broad optional scans.
    """

    generated_at = datetime.now().astimezone().isoformat()
    directory = output_dir or RAW_OUTPUT_ROOT / f"raw-critical-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    writer = RawAcquisitionWriter(directory, generated_at)
    writer.write_json(
        "00_metadata",
        {
            "schema_version": RAW_SCHEMA_VERSION,
            "generated_at": generated_at,
            "router": {
                "address": getattr(args, "address", None),
                "port": getattr(args, "port", None),
                "tls": bool(getattr(args, "tls", False)),
                "user_provided": bool(getattr(args, "user", None)),
            },
            "mode": "critical_forensic_raw_first",
        },
        "metadata",
    )
    base = {
        "address": getattr(args, "address", None),
        "user": getattr(args, "user", None),
        "password": getattr(args, "password", None),
        "port": getattr(args, "port", 49000),
        "tls": bool(getattr(args, "tls", False)),
    }
    critical_queries = {
        "landevice_all": QUERY_LUA_QUERIES["landevice_all"],
        "landevice_topology": QUERY_LUA_QUERIES["landevice_topology"],
        "wlan_known_devices": QUERY_LUA_QUERIES["wlan_known_devices"],
        "wlan_stations": QUERY_LUA_QUERIES["wlan_stations"],
        "net_dhcp": QUERY_LUA_QUERIES["net_dhcp"],
    }
    critical_pages = ("log", "homeNet", "netDev", "wlan", "wlanSta", "wlanMonitor", "wlanRadar", "mesh")
    jobs = [
        ("support_bundle", "support_lua_page_html", "support_lua", base, hard_timeout(45)),
        (
            "core_tr064",
            "device_log_text_json",
            "call",
            {**base, "service": "DeviceInfo:1", "action": "GetDeviceLog"},
            hard_timeout(60),
        ),
        ("core_tr064", "hosts_tr064_generic_json", "hosts", base, hard_timeout(120)),
        *avm_export_path_jobs(base, timeout=hard_timeout(75)),
        ("webui_query_lua", "landevice_query_json", "landevice_query", base, hard_timeout(60)),
        *[
            (
                "webui_query_lua",
                f"query_lua_{name}",
                "query_lua",
                {**base, "query_name": name, "query": query},
                hard_timeout(60),
            )
            for name, query in critical_queries.items()
        ],
        *[
            (
                "webui_data_lua",
                f"data_lua_page_{page}",
                "data_lua",
                {**base, "page": page},
                hard_timeout(60),
            )
            for page in critical_pages
        ],
        (
            "core_tr064",
            "device_info_json",
            "call",
            {**base, "service": "DeviceInfo:1", "action": "GetInfo"},
            hard_timeout(),
        ),
        ("core_tr064", "router_time_json", "call", {**base, "service": "Time:1", "action": "GetInfo"}, hard_timeout()),
        ("support_bundle", "support_data_txt", "support", base, support_hard_timeout()),
    ]
    run_artifact_jobs(writer, jobs, progress_callback)
    writer.write_summary()
    logger.info(
        "critical acquisition finished dir=%s attempts=%s successful=%s failed=%s",
        directory,
        len(writer.attempts),
        sum(1 for item in writer.attempts if item.get("ok")),
        sum(1 for item in writer.attempts if not item.get("ok")),
    )
    return RawAcquisitionResult(directory, writer.manifest_path, generated_at)


def run_artifact_jobs(
    writer: RawAcquisitionWriter,
    jobs: list[tuple[str, str, str, dict[str, Any], int]],
    progress_callback: ProgressCallback | None,
) -> None:
    delay = acquisition_delay()
    active_stage = ""
    for stage, name, kind, payload, timeout in jobs:
        if stage != active_stage:
            if active_stage:
                notify_progress(progress_callback, active_stage, "completed", {})
            active_stage = stage
            notify_progress(progress_callback, stage, "running", {})
        child_payload = {**payload, "__artifact_path": str(writer.directory / f".{safe_file_stem(name)}.child")}
        run_child_artifact(writer, name, stage, kind, child_payload, timeout)
        pause(delay)
    if active_stage:
        notify_progress(progress_callback, active_stage, "completed", {})


def avm_export_path_jobs(base: dict[str, Any], timeout: int) -> list[tuple[str, str, str, dict[str, Any], int]]:
    jobs: list[tuple[str, str, str, dict[str, Any], int]] = []
    for name, service, action, field, query_params in AVM_EXPORT_PATH_SPECS:
        jobs.append(
            (
                "avm_export_paths",
                name,
                "avm_path",
                {
                    **base,
                    "service": service,
                    "action": action,
                    "field": field,
                    "query_params": query_params or {},
                },
                timeout,
            )
        )
    for index in range(1, 5):
        jobs.append(
            (
                "avm_export_paths",
                f"wlan_device_list_xml_{index}",
                "avm_path",
                {
                    **base,
                    "service": f"WLANConfiguration:{index}",
                    "action": "X_AVM-DE_GetWLANDeviceListPath",
                    "field": "NewX_AVM-DE_WLANDeviceListPath",
                },
                timeout,
            )
        )
    return jobs


def run_child_artifact(
    writer: RawAcquisitionWriter,
    name: str,
    surface: str,
    kind: str,
    payload: dict[str, Any],
    timeout: int,
) -> None:
    context: Any = get_context(os.getenv("FRITZBOX_CHILD_START_METHOD", "spawn"))
    queue = context.Queue()
    process = context.Process(target=child_artifact_worker, args=(kind, payload, queue))
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(2)
        writer.write_error(name, surface, f"hard timeout after {timeout}s")
        return
    try:
        status, content = queue.get_nowait()
    except Exception as exc:
        writer.write_error(
            name, surface, f"missing child result: exitcode={process.exitcode} {type(exc).__name__}: {exc}"
        )
        return
    if status == "ok":
        writer.write_text(name, content, surface)
    elif status == "file":
        try:
            result = json.loads(content)
            writer.write_existing_file(name, Path(result["path"]), surface, **(result.get("details") or {}))
        except Exception as exc:
            writer.write_error(name, surface, f"invalid child file result: {type(exc).__name__}: {exc}")
    else:
        writer.write_error(name, surface, content)


def child_artifact_worker(kind: str, payload: dict[str, Any], queue: Any) -> None:
    try:
        from fritzconnection import FritzConnection

        fc = FritzConnection(
            address=payload["address"],
            user=payload.get("user"),
            password=payload.get("password"),
            port=payload.get("port", 49000),
            use_tls=bool(payload.get("tls", False)),
            use_cache=True,
            timeout=int(os.getenv("FRITZBOX_REQUEST_TIMEOUT", "20") or "20"),
            pool_connections=1,
            pool_maxsize=1,
        )
        if kind == "call":
            result = fc.call_action(payload["service"], payload["action"], **payload.get("kwargs", {}))
            queue.put(("ok", json.dumps(result, indent=2, sort_keys=True, default=str)))
        elif kind == "avm_path":
            result = fc.call_action(payload["service"], payload["action"], **payload.get("kwargs", {}))
            path = result.get(payload["field"])
            if not path:
                queue.put(("err", "empty export path"))
                return
            path = append_query_params(str(path), payload.get("query_params"))
            content = fetch_avm_path(payload["address"], payload.get("port", 49000), path, fc=fc)
            if content:
                queue.put(("ok", content))
            else:
                queue.put(("err", f"empty export response for {path}"))
        elif kind == "hosts":
            rows = collect_hosts_paced(fc, min(acquisition_delay(), 0.5))
            queue.put(("ok", json.dumps(rows, indent=2, sort_keys=True, default=str)))
        elif kind == "landevice_query":
            sid = get_webui_sid(getattr(fc, "http_interface", None))
            for fields in (LANDEVICE_RICH_FIELDS, LANDEVICE_FALLBACK_FIELDS):
                query = f"landevice:settings/landevice/list({','.join(fields)})"
                params = {"mq_landevices": query}
                if sid:
                    params["sid"] = sid
                raw, error = fetch_webui_payload(fc, "query.lua", params)
                if not error:
                    queue.put(("ok", raw))
                    break
            else:
                queue.put(("err", "landevice query failed for rich and fallback field sets"))
        elif kind == "query_lua":
            sid = get_webui_sid(getattr(fc, "http_interface", None))
            params = {payload["query_name"]: payload["query"]}
            if sid:
                params["sid"] = sid
            raw, error = fetch_webui_payload(fc, "query.lua", params)
            if error:
                queue.put(("err", error))
            else:
                queue.put(("ok", raw))
        elif kind == "data_lua":
            sid = get_webui_sid(getattr(fc, "http_interface", None))
            params = {"page": payload["page"]}
            if sid:
                params["sid"] = sid
            raw, error = fetch_webui_payload(fc, "data.lua", params)
            if error:
                queue.put(("err", error))
            else:
                queue.put(("ok", raw))
        elif kind == "webui_readonly":
            from fritzbox_collectors import fetch_webui_readonly_artifacts

            queue.put(("ok", json.dumps(fetch_webui_readonly_artifacts(fc), indent=2, sort_keys=True, default=str)))
        elif kind == "support":
            support_target = Path(str(payload.get("__artifact_path") or "")) if payload.get("__artifact_path") else None
            support_data = ""
            streamed_path = None
            if support_target:
                streamed_path = fetch_support_data_to_file(fc, support_target.with_suffix(".support.txt"))
            if streamed_path is None:
                support_data = fetch_support_data(fc) or ""
            if streamed_path is not None:
                queue.put(("file", json.dumps({"path": str(streamed_path), "details": {"streamed": True}})))
                return
            if support_data:
                queue.put(("ok", support_data))
            else:
                queue.put(("err", "empty support data response"))
        elif kind == "support_lua":
            support_lua = fetch_support_lua_page(fc) or ""
            if support_lua:
                queue.put(("ok", support_lua))
            else:
                queue.put(("err", "empty support.lua response"))
        else:
            queue.put(("err", f"unknown child artifact kind: {kind}"))
    except BaseException as exc:
        queue.put(("err", f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}"))


def fetch_support_data_to_file(fc: Any, target: Path) -> Path | None:
    """Stream support-data output directly to disk.

    The support dump is the one artifact most likely to be large or slow on
    older FRITZ!Box hardware. This helper avoids holding the response body in
    memory and lets the child-process hard timeout kill only this one request.
    """

    http = getattr(fc, "http_interface", None)
    if http is None:
        return None
    session = getattr(getattr(http, "fc", None), "session", None)
    if session is None:
        return None
    try:
        sid = next(http._get_sid())
    except Exception:
        return None
    if not sid or sid == "0000000000000000":
        return None

    target.parent.mkdir(parents=True, exist_ok=True)
    url = f"{str(http.router_url).rstrip('/')}/cgi-bin/firmwarecfg"
    timeout = (support_connect_timeout(), support_read_timeout())
    for field in ("SupportDataEnhanced", "SupportData"):
        part = target.with_name(f"{target.name}.{field}.part")
        try:
            response = session.post(
                url,
                files={"sid": (None, sid), field: (None, "")},
                stream=True,
                timeout=timeout,
            )
        except TypeError:
            try:
                response = session.post(
                    url,
                    files={"sid": (None, sid), field: (None, "")},
                    timeout=timeout,
                )
            except Exception as exc:
                logger.debug("support stream request failed field=%s error=%s", field, redact(exc))
                continue
        except Exception as exc:
            logger.debug("support stream request failed field=%s error=%s", field, redact(exc))
            continue

        try:
            if getattr(response, "status_code", None) != 200:
                logger.debug("support stream non-200 field=%s status=%s", field, getattr(response, "status_code", None))
                continue
            with part.open("wb") as handle:
                iter_content = getattr(response, "iter_content", None)
                if callable(iter_content):
                    chunks = iter_content(chunk_size=64 * 1024)
                    if not isinstance(chunks, Iterable):
                        continue
                    for chunk in chunks:
                        if chunk:
                            handle.write(chunk)
                else:
                    handle.write(getattr(response, "content", b"") or b"")
            if part.stat().st_size == 0:
                part.unlink(missing_ok=True)
                continue
            if not is_support_data_response(read_text_head(part)):
                logger.debug("support stream invalid response field=%s bytes=%s", field, part.stat().st_size)
                part.unlink(missing_ok=True)
                continue
            part.replace(target)
            restrict_path_permissions(target, 0o600)
            return target
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
    return None


def run_stage(
    writer: RawAcquisitionWriter,
    stage: str,
    call: Callable[[], None],
    progress_callback: ProgressCallback | None = None,
) -> None:
    started = time.monotonic()
    logger.info("raw acquisition stage started stage=%s", stage)
    notify_progress(progress_callback, stage, "running", {})
    try:
        call()
    except Exception as exc:
        writer.write_error(f"stage_{stage}", "collector_stage", exc)
        logger.exception("raw acquisition stage failed stage=%s", stage)
        notify_progress(progress_callback, stage, "failed", {"error": f"{type(exc).__name__}: {exc}"})
    else:
        elapsed = time.monotonic() - started
        logger.info("raw acquisition stage finished stage=%s elapsed=%.2fs", stage, elapsed)
        notify_progress(progress_callback, stage, "completed", {"elapsed_seconds": round(elapsed, 2)})


def notify_progress(
    progress_callback: ProgressCallback | None,
    stage: str,
    status: str,
    details: dict[str, Any],
) -> None:
    if progress_callback is None:
        return
    try:
        progress_callback(stage, status, details)
    except Exception:
        logger.exception("raw acquisition progress callback failed stage=%s status=%s", stage, status)


def collect_core_tr064(writer: RawAcquisitionWriter, fc: Any, delay: float) -> None:
    safe_write_call(writer, "device_info_json", "tr064_core", lambda: get_device_info(fc), as_json=True)
    pause(delay)
    safe_write_call(writer, "router_time_json", "tr064_core", lambda: get_router_time(fc), as_json=True)
    pause(delay)
    safe_write_call(
        writer, "hosts_tr064_generic_json", "tr064_core", lambda: collect_hosts_paced(fc, delay), as_json=True
    )
    pause(delay)
    safe_write_call(writer, "device_log_text", "tr064_core", lambda: get_device_log(fc), as_json=False)
    pause(delay)


def collect_avm_export_paths(writer: RawAcquisitionWriter, fc: Any, args: Any, delay: float) -> None:
    wlan_lists: dict[str, str] = {}
    for name, service, action, field, query_params in AVM_EXPORT_PATH_SPECS:
        fetch_and_write_avm_path(writer, fc, args, name, service, action, field, query_params=query_params)
        pause(delay)

    for index in range(1, 5):
        name = f"wlan_device_list_xml_{index}"
        content = fetch_and_write_avm_path(
            writer,
            fc,
            args,
            name,
            f"WLANConfiguration:{index}",
            "X_AVM-DE_GetWLANDeviceListPath",
            "NewX_AVM-DE_WLANDeviceListPath",
        )
        if content:
            wlan_lists[str(index)] = content
        pause(delay)
    if wlan_lists:
        writer.write_json("wlan_device_list_xml", wlan_lists, "tr064_export_path", count=len(wlan_lists))


def fetch_and_write_avm_path(
    writer: RawAcquisitionWriter,
    fc: Any,
    args: Any,
    name: str,
    service: str,
    action: str,
    field: str,
    query_params: dict[str, Any] | None = None,
) -> str | None:
    try:
        response = fc.call_action(service, action)
        path = response.get(field)
    except Exception as exc:
        writer.write_error(name, "tr064_export_path", exc, service=service, action=action)
        return None
    if not path:
        writer.write_error(name, "tr064_export_path", "empty export path", service=service, action=action)
        return None
    path = append_query_params(str(path), query_params)
    try:
        content = fetch_avm_path(args.address, args.port, path, fc=fc)
    except Exception as exc:
        writer.write_error(name, "tr064_export_path", exc, service=service, action=action, path=str(path))
        return None
    if not content:
        writer.write_error(
            name, "tr064_export_path", "empty export response", service=service, action=action, path=str(path)
        )
        return None
    writer.write_text(name, content, "tr064_export_path", service=service, action=action, path=str(path))
    return content


def collect_webui_pages(writer: RawAcquisitionWriter, fc: Any, delay: float) -> None:
    sid = get_valid_webui_sid(fc)
    pages: dict[str, Any] = {}
    if sid is None:
        for page in DATA_LUA_PAGES:
            writer.write_error(f"data_lua_page_{page}", "webui_data_lua", "no valid Web UI SID; skipped", page=page)
            pages[page] = {"ok": False, "error": "no valid Web UI SID; skipped", "page": page}
        writer.write_json("data_lua_pages_json", pages, "webui_data_lua", count=0, failed=len(pages))
        return
    for page in DATA_LUA_PAGES:
        raw, error = fetch_webui_payload(fc, "data.lua", {"page": page, "sid": sid})
        name = f"data_lua_page_{page}"
        if error:
            writer.write_error(name, "webui_data_lua", error, page=page)
            pages[page] = {"ok": False, "error": error, "page": page}
        else:
            writer.write_text(name, raw, "webui_data_lua", page=page)
            pages[page] = decode_webui_payload(raw)
        pause(delay)
    if pages:
        writer.write_json(
            "data_lua_pages_json",
            pages,
            "webui_data_lua",
            count=sum(1 for item in pages.values() if item.get("ok") is not False),
            failed=sum(1 for item in pages.values() if item.get("ok") is False),
        )


def collect_query_lua(writer: RawAcquisitionWriter, fc: Any, delay: float) -> None:
    sid = get_valid_webui_sid(fc)
    artifacts: dict[str, Any] = {}
    if sid is None:
        for name, query in QUERY_LUA_QUERIES.items():
            writer.write_error(f"query_lua_{name}", "webui_query_lua", "no valid Web UI SID; skipped", query=query)
            artifacts[name] = {"ok": False, "error": "no valid Web UI SID; skipped", "query": query}
        writer.write_error("landevice_query_json", "webui_query_lua", "no valid Web UI SID; skipped")
        writer.write_json("query_lua_artifacts_json", artifacts, "webui_query_lua", count=0, failed=len(artifacts))
        return

    for fields in (LANDEVICE_RICH_FIELDS, LANDEVICE_FALLBACK_FIELDS):
        query = f"landevice:settings/landevice/list({','.join(fields)})"
        raw, error = fetch_webui_payload(fc, "query.lua", {"mq_landevices": query, "sid": sid})
        if error:
            writer.write_error("landevice_query_json", "webui_query_lua", error, query=query)
        else:
            writer.write_text("landevice_query_json", raw, "webui_query_lua", query=query)
            break
        pause(delay)

    for name, query in QUERY_LUA_QUERIES.items():
        raw, error = fetch_webui_payload(fc, "query.lua", {name: query, "sid": sid})
        artifact_name = f"query_lua_{name}"
        if error:
            writer.write_error(artifact_name, "webui_query_lua", error, query=query)
            artifacts[name] = {"ok": False, "error": error, "query": query}
        else:
            writer.write_text(artifact_name, raw, "webui_query_lua", query=query)
            artifacts[name] = {"ok": True, **decode_query_payload(raw), "query": query}
        pause(delay)
    if artifacts:
        writer.write_json(
            "query_lua_artifacts_json",
            artifacts,
            "webui_query_lua",
            count=sum(1 for item in artifacts.values() if item.get("ok") is not False),
            failed=sum(1 for item in artifacts.values() if item.get("ok") is False),
        )


def collect_webui_readonly(writer: RawAcquisitionWriter, fc: Any, delay: float) -> None:
    sid = get_valid_webui_sid(fc)
    endpoints: dict[str, Any] = {}
    for name, path, params in WEBUI_READONLY_ENDPOINTS:
        request_params = dict(params)
        if sid and path.endswith(".lua"):
            request_params.setdefault("sid", sid)
        raw, error = fetch_webui_payload(fc, path, request_params)
        artifact_name = f"webui_readonly_{name}"
        if error:
            writer.write_error(artifact_name, "webui_readonly_get", error, path=path)
            endpoints[name] = {"ok": False, "error": error, "path": path}
        else:
            writer.write_text(artifact_name, raw[:MAX_WEBUI_ARTIFACT_BYTES], "webui_readonly_get", path=path)
            endpoints[name] = {
                "ok": True,
                "raw": raw[:MAX_WEBUI_ARTIFACT_BYTES],
                "path": path,
                "truncated": len(raw.encode("utf-8")) > MAX_WEBUI_ARTIFACT_BYTES,
            }
        pause(delay)
    writer.write_json(
        "webui_readonly_artifacts_json",
        {"schema_version": 1, "max_body_bytes": MAX_WEBUI_ARTIFACT_BYTES, "endpoints": endpoints},
        "webui_readonly_get",
    )


def collect_tr064_snapshot_raw(writer: RawAcquisitionWriter, fc: Any, delay: float) -> None:
    snapshot: dict[str, Any] = {
        "actions": {},
        "wlan": [],
        "service_inventory": [],
        "dynamic_readonly": {},
        "indexed_results": {},
    }
    try:
        service_inventory = tr064_service_inventory(fc)
        snapshot["service_inventory"] = service_inventory
        writer.write_json("tr064_service_inventory_json", service_inventory, "tr064_snapshot")
    except Exception as exc:
        writer.write_error("tr064_service_inventory_json", "tr064_snapshot", exc)

    core_actions: list[tuple[str, str, str, dict[str, Any]]] = [
        ("device_info", "DeviceInfo:1", "GetInfo", {}),
        ("time_info", "Time:1", "GetInfo", {}),
        ("user_interface", "UserInterface:1", "GetInfo", {}),
        ("lan_host_config", "LANHostConfigManagement:1", "GetInfo", {}),
        ("wan_ip_info", "WANIPConn:1", "GetInfo", {}),
        ("wan_ip_external", "WANIPConn:1", "GetExternalIPAddress", {}),
    ]
    for key, service, action, arguments in core_actions:
        result = safe_call_action(fc, service, action, arguments)
        snapshot["actions"][key] = result
        writer.write_json(f"tr064_action_{key}", result, "tr064_snapshot", service=service, action=action)
        pause(delay)

    max_actions = int(os.getenv("FRITZBOX_DYNAMIC_TR064_MAX_ACTIONS", "220") or "220")
    called = 0
    for service_name, service in sorted((getattr(fc, "services", {}) or {}).items()):
        for action_name, action in sorted(getattr(service, "actions", {}).items()):
            if called >= max_actions:
                break
            if not is_read_only_action(action_name) or action_input_arguments(action):
                continue
            result = safe_call_action(fc, service_name, action_name, {})
            key = f"{service_name}:{action_name}"
            snapshot["dynamic_readonly"][key] = result
            writer.write_json(f"tr064_dynamic_{called:03d}_{key}", result, "tr064_dynamic_readonly", key=key)
            called += 1
            pause(delay)
        if called >= max_actions:
            break

    try:
        indexed_results = collect_indexed_results_paced(fc, delay)
        snapshot["indexed_results"] = indexed_results
        writer.write_json("tr064_indexed_results_json", indexed_results, "tr064_snapshot")
    except Exception as exc:
        snapshot["indexed_results"] = {}
        writer.write_error("tr064_indexed_results_json", "tr064_snapshot", exc)
    writer.write_json("tr064_snapshot_json", snapshot, "tr064_snapshot", dynamic_count=called)


def collect_optional_surfaces(writer: RawAcquisitionWriter, fc: Any, args: Any, delay: float) -> None:
    safe_write_mapping(writer, "telephony_export", lambda: fetch_telephony_exports(fc, args.address, args.port))
    pause(delay)
    safe_write_mapping(writer, "aha_http", lambda: fetch_aha_artifacts(fc))
    pause(delay)
    export_password = os.getenv("FRITZBOX_EXPORT_PASSWORD") or getattr(args, "password", None)
    if export_password:
        safe_write_call(
            writer,
            "config_export_file",
            "device_config_export",
            lambda: fetch_config_export(fc, args.address, args.port, export_password),
            as_json=False,
            allow_empty=False,
        )
    else:
        writer.write_error("config_export_file", "device_config_export", "no export password")
    pause(delay)
    safe_write_call(
        writer,
        "support_lua_page_html",
        "webui_support_lua",
        lambda: fetch_support_lua_page(fc),
        as_json=False,
        allow_empty=False,
    )
    pause(delay)
    safe_write_call(
        writer,
        "support_data_txt",
        "support_data",
        lambda: fetch_support_data(fc),
        as_json=False,
        allow_empty=False,
    )


def safe_write_call(
    writer: RawAcquisitionWriter,
    name: str,
    surface: str,
    call: Callable[[], Any],
    *,
    as_json: bool,
    allow_empty: bool = True,
) -> Any:
    try:
        value = call()
    except BaseException as exc:
        writer.write_error(name, surface, exc)
        return None
    if value in (None, "") and not allow_empty:
        writer.write_error(name, surface, "empty response")
        return None
    if as_json:
        writer.write_json(name, value, surface)
    else:
        writer.write_text(name, str(value or ""), surface)
    return value


def safe_write_mapping(writer: RawAcquisitionWriter, surface: str, call: Callable[[], dict[str, str]]) -> None:
    try:
        mapping = call()
    except Exception as exc:
        writer.write_error(surface, surface, exc)
        return
    if not mapping:
        writer.write_error(surface, surface, "empty response")
        return
    for name, content in mapping.items():
        writer.write_text(name, str(content), surface)


def collect_hosts_paced(fc: Any, delay: float) -> list[dict[str, Any]]:
    count_result = safe_call_action(fc, "Hosts:1", "GetHostNumberOfEntries", {})
    if not count_result.get("ok"):
        return []
    try:
        count = int((count_result.get("response") or {}).get("NewHostNumberOfEntries") or 0)
    except (TypeError, ValueError):
        return []

    hosts: list[dict[str, Any]] = []
    for index in range(min(count, max_indexed_items("FRITZBOX_MAX_HOSTS", 512))):
        generic = safe_call_action(fc, "Hosts:1", "GetGenericHostEntry", {"NewIndex": index})
        response = dict(generic.get("response") or {})
        pause(delay)
        mac = response.get("NewMACAddress")
        if mac:
            specific = safe_call_action(fc, "Hosts:1", "GetSpecificHostEntry", {"NewMACAddress": mac})
            if specific.get("ok") and specific.get("response"):
                response.update(specific["response"])
            pause(delay)
        if response:
            hosts.append(response)
    return hosts


def collect_indexed_results_paced(fc: Any, delay: float) -> dict[str, Any]:
    specs = [
        (
            "Hosts:1",
            "GetHostNumberOfEntries",
            "NewHostNumberOfEntries",
            "GetGenericHostEntry",
            "NewIndex",
            "hosts_generic",
            "FRITZBOX_MAX_HOSTS",
            512,
        ),
        (
            "WANIPConn:1",
            "GetPortMappingNumberOfEntries",
            "NewPortMappingNumberOfEntries",
            "GetGenericPortMappingEntry",
            "NewPortMappingIndex",
            "wan_ip_port_mappings",
            "FRITZBOX_MAX_PORT_MAPPINGS",
            512,
        ),
        (
            "WANPPPConn:1",
            "GetPortMappingNumberOfEntries",
            "NewPortMappingNumberOfEntries",
            "GetGenericPortMappingEntry",
            "NewPortMappingIndex",
            "wan_ppp_port_mappings",
            "FRITZBOX_MAX_PORT_MAPPINGS",
            512,
        ),
    ]
    indexed: dict[str, Any] = {}
    for service, count_action, count_field, item_action, index_arg, key, env_name, default_limit in specs:
        count_result = safe_call_action(fc, service, count_action, {})
        indexed[key] = {"count": count_result, "items": []}
        pause(delay)
        if not count_result.get("ok"):
            continue
        try:
            count = int((count_result.get("response") or {}).get(count_field) or 0)
        except (TypeError, ValueError):
            continue
        for index in range(min(count, max_indexed_items(env_name, default_limit))):
            indexed[key]["items"].append(safe_call_action(fc, service, item_action, {index_arg: index}))
            pause(delay)

    association_limit = max_indexed_items("FRITZBOX_MAX_WLAN_ASSOCIATIONS", 256)
    for radio_index in range(1, 5):
        service = f"WLANConfiguration:{radio_index}"
        count_result = safe_call_action(fc, service, "GetTotalAssociations", {})
        key = f"wlan_{radio_index}_associations"
        indexed[key] = {"count": count_result, "items": []}
        pause(delay)
        if not count_result.get("ok"):
            continue
        try:
            count = int((count_result.get("response") or {}).get("NewTotalAssociations") or 0)
        except (TypeError, ValueError):
            continue
        for index in range(min(count, association_limit)):
            indexed[key]["items"].append(
                safe_call_action(fc, service, "GetGenericAssociatedDeviceInfo", {"NewAssociatedDeviceIndex": index})
            )
            pause(delay)
    return indexed


def max_indexed_items(env_name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(env_name, str(default)) or default))
    except ValueError:
        return default


def get_valid_webui_sid(fc: Any) -> str | None:
    sid = get_webui_sid(getattr(fc, "http_interface", None))
    if not sid:
        return None
    return sid


def fetch_webui_payload(fc: Any, path: str, params: dict[str, Any]) -> tuple[str, str | None]:
    raw, error = fetch_webui_text(fc, path, params, timeout=webui_timeout())
    if error:
        return "", error
    if not raw:
        return "", "empty response"
    if is_html_response(raw, None):
        return "", "HTML login/UI response instead of raw API payload"
    return raw[:MAX_WEBUI_ARTIFACT_BYTES], None


def decode_webui_payload(raw: str) -> dict[str, Any]:
    try:
        return {"ok": True, "data": json.loads(raw)}
    except json.JSONDecodeError:
        return {"ok": True, "raw": raw}


def decode_query_payload(raw: str) -> dict[str, Any]:
    try:
        return {"data": json.loads(raw)}
    except json.JSONDecodeError:
        return {"raw": raw}


def load_raw_bundle(directory: Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        name = artifact_name_from_path(path)
        artifacts[name] = path.read_text(encoding="utf-8", errors="replace")
    normalize_hard_timeout_artifacts(artifacts)
    normalize_manifest_artifacts(artifacts)
    reconstruct_combined_artifacts(artifacts)
    return artifacts


def normalize_hard_timeout_artifacts(artifacts: dict[str, str]) -> None:
    if "device_log_text" not in artifacts and "device_log_text_json" in artifacts:
        with suppress(json.JSONDecodeError, AttributeError):
            artifacts["device_log_text"] = json.loads(artifacts["device_log_text_json"]).get("NewDeviceLog", "")
    if "support_bundle_json" in artifacts:
        try:
            support_bundle = json.loads(artifacts["support_bundle_json"])
        except json.JSONDecodeError:
            support_bundle = {}
        if isinstance(support_bundle, dict):
            for key in ("support_lua_page_html", "support_data_txt"):
                value = support_bundle.get(key)
                if value and key not in artifacts:
                    artifacts[key] = str(value)


def normalize_manifest_artifacts(artifacts: dict[str, str]) -> None:
    if "summary" in artifacts and "acquisition_summary_json" not in artifacts:
        artifacts["acquisition_summary_json"] = artifacts["summary"]
    if "acquisition_manifest_json" not in artifacts:
        if "manifest" in artifacts:
            artifacts["acquisition_manifest_json"] = artifacts["manifest"]
        elif "summary" in artifacts:
            artifacts["acquisition_manifest_json"] = artifacts["summary"]
    if "manifest_jsonl" in artifacts and "acquisition_manifest_jsonl" not in artifacts:
        artifacts["acquisition_manifest_jsonl"] = artifacts["manifest_jsonl"]


def reconstruct_combined_artifacts(artifacts: dict[str, str]) -> None:
    if "wlan_device_list_xml" not in artifacts:
        wlan_lists = {}
        for name, raw in artifacts.items():
            match = re.fullmatch(r"wlan_device_list_xml_(\d+)", name)
            if match:
                wlan_lists[match.group(1)] = raw
        if wlan_lists:
            artifacts["wlan_device_list_xml"] = json.dumps(wlan_lists, sort_keys=True, default=str)
    if "data_lua_pages_json" not in artifacts:
        pages = {}
        for name, raw in artifacts.items():
            if name.startswith("data_lua_page_"):
                if name.endswith("_error"):
                    page = name.removeprefix("data_lua_page_").removesuffix("_error")
                    pages[page] = {"ok": False, "error": raw.strip(), "page": page}
                else:
                    pages[name.removeprefix("data_lua_page_")] = decode_webui_payload(raw)
        if pages:
            artifacts["data_lua_pages_json"] = json.dumps(pages, sort_keys=True, default=str)
    if "query_lua_artifacts_json" not in artifacts:
        queries = {}
        for name, raw in artifacts.items():
            if name.startswith("query_lua_"):
                if name.endswith("_error"):
                    query_name = name.removeprefix("query_lua_").removesuffix("_error")
                    queries[query_name] = {
                        "ok": False,
                        "error": raw.strip(),
                        "query": QUERY_LUA_QUERIES.get(query_name),
                    }
                else:
                    query_name = name.removeprefix("query_lua_")
                    queries[query_name] = {
                        "ok": True,
                        **decode_query_payload(raw),
                        "query": QUERY_LUA_QUERIES.get(query_name),
                    }
        if queries:
            artifacts["query_lua_artifacts_json"] = json.dumps(queries, sort_keys=True, default=str)


def artifact_name_from_path(path: Path) -> str:
    if path.name.endswith(".error.txt"):
        return f"{path.name[: -len('.error.txt')]}_error"
    if path.name == "manifest.jsonl":
        return "manifest_jsonl"
    stem = path.name
    for suffix in (".json", ".xml", ".txt", ".html", ".raw"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def safe_file_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")[:180] or "artifact"


def extension_for_artifact(name: str, content: str) -> str:
    lowered = name.casefold()
    if lowered.endswith("_json") or content.lstrip().startswith(("{", "[")):
        return ".json"
    if lowered.endswith("_xml") or content.lstrip().startswith("<"):
        return ".xml"
    if lowered.endswith("_html"):
        return ".html"
    if lowered.endswith("_txt") or "log" in lowered or "support_data" in lowered:
        return ".txt"
    return ".raw"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text_head(path: Path, limit: int = 1024 * 1024) -> str:
    with path.open("rb") as handle:
        return handle.read(limit).decode("utf-8", errors="replace")


def redact_manifest_details(details: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in details.items():
        if key.casefold() in {"password", "sid", "token", "secret"}:
            redacted[key] = "<redacted>"
        else:
            redacted[key] = value
    return redacted


def acquisition_delay() -> float:
    try:
        return max(0.0, float(os.getenv("FRITZBOX_ACQUISITION_DELAY", str(DEFAULT_DELAY_SECONDS))))
    except ValueError:
        return DEFAULT_DELAY_SECONDS


def webui_timeout() -> int:
    try:
        return max(2, int(os.getenv("FRITZBOX_WEBUI_TIMEOUT", "12") or "12"))
    except ValueError:
        return 12


def hard_timeout(default: int = DEFAULT_HARD_TIMEOUT_SECONDS) -> int:
    try:
        return max(5, int(os.getenv("FRITZBOX_HARD_TIMEOUT", str(default)) or default))
    except ValueError:
        return default


def support_hard_timeout() -> int:
    try:
        return max(30, int(os.getenv("FRITZBOX_SUPPORT_HARD_TIMEOUT", str(DEFAULT_SUPPORT_HARD_TIMEOUT_SECONDS))))
    except ValueError:
        return DEFAULT_SUPPORT_HARD_TIMEOUT_SECONDS


def support_connect_timeout() -> int:
    try:
        return max(5, int(os.getenv("FRITZBOX_SUPPORT_CONNECT_TIMEOUT", "15") or "15"))
    except ValueError:
        return 15


def support_read_timeout() -> int:
    try:
        return max(30, int(os.getenv("FRITZBOX_SUPPORT_READ_TIMEOUT", "240") or "240"))
    except ValueError:
        return 240


def pause(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)
