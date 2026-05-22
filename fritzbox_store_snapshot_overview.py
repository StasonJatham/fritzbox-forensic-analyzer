from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES
from fritzbox_store_constants import EXPECTED_RAW_ARTIFACTS, WIFI_DEDUPE_SQL
from fritzbox_store_ingest import init_db
from fritzbox_store_query_helpers import (
    _combine_filter,
    _run_observation_count,
    _run_observation_sql,
    _run_record_count,
    resolve_run_id,
)
from fritzbox_store_schema import DEFAULT_DB
from fritzbox_store_snapshot_summaries import (
    _count_like,
    _event_gaps,
    _host_count,
    _hourly_counts,
    _time_range_sql,
    advertisement_hint_summary,
    host_risk_summary,
    last_used_histogram,
    mesh_summary,
    raw_artifact_summaries,
    security_advisory_summary,
    tr064_summary,
)


def _decode_json(value: Any) -> Any:
    if value in (None, ""):
        return None
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return value


def latest_snapshot(path: Path = DEFAULT_DB, run_id: str | int = "latest") -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    latest_run = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    if scoped_run_id is None:
        selected_run = latest_run
        retained = dict(conn.execute("""
                SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN timestamp IS NOT NULL AND timestamp != '' THEN 1 ELSE 0 END) AS timestamped_event_count
                FROM event_log
                """).fetchone())
        counts = {
            "runs": int(conn.execute("SELECT COUNT(*) FROM export_runs").fetchone()[0]),
            "raw_artifacts": int(conn.execute("SELECT COUNT(*) FROM raw_artifacts").fetchone()[0]),
            "event_log": int(conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]),
            "wifi_connections": int(
                conn.execute("SELECT COUNT(*) FROM wifi_connections WHERE " + WIFI_DEDUPE_SQL).fetchone()[0]
            ),
            "hosts": int(conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]),
            "support_findings": int(conn.execute("SELECT COUNT(*) FROM support_findings").fetchone()[0]),
            "siem_events": int(conn.execute("SELECT COUNT(*) FROM siem_events").fetchone()[0]),
            "siem_correlations": int(conn.execute("SELECT COUNT(*) FROM siem_correlations").fetchone()[0]),
            "active_hosts": int(conn.execute("SELECT COUNT(*) FROM hosts WHERE active_now = 1").fetchone()[0]),
            "hosts_with_last_connected": int(
                conn.execute(
                    "SELECT COUNT(*) FROM hosts WHERE last_connected IS NOT NULL AND last_connected != ''"
                ).fetchone()[0]
            ),
            "hosts_with_first_seen": int(
                conn.execute("SELECT COUNT(*) FROM hosts WHERE first_seen IS NOT NULL AND first_seen != ''").fetchone()[
                    0
                ]
            ),
            **{
                table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ADDITIONAL_EVIDENCE_TABLES
            },
        }
        last_exact_wifi = conn.execute(
            "SELECT MAX(derived_connected_at) FROM wifi_connections WHERE exact_connection_time_available = 1 AND "
            + WIFI_DEDUPE_SQL
        ).fetchone()[0]
        last_device_connected = conn.execute("SELECT MAX(last_connected) FROM hosts").fetchone()[0]
    else:
        selected_run = conn.execute("SELECT * FROM export_runs WHERE id = ?", [scoped_run_id]).fetchone()
        retained = dict(
            conn.execute(
                """
                SELECT MIN(event_time) AS oldest_event, MAX(event_time) AS newest_event,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN event_time IS NOT NULL AND event_time != '' THEN 1 ELSE 0 END) AS timestamped_event_count
                FROM record_observations
                WHERE run_id = ? AND record_type = 'event_log'
                """,
                [scoped_run_id],
            ).fetchone()
        )
        counts = {
            "runs": int(conn.execute("SELECT COUNT(*) FROM export_runs").fetchone()[0]),
            "raw_artifacts": _run_observation_count(conn, scoped_run_id, "raw_artifact"),
            "event_log": _run_observation_count(conn, scoped_run_id, "event_log"),
            "wifi_connections": _run_record_count(conn, scoped_run_id, "wifi_connection", "wifi_connections"),
            "hosts": _run_record_count(conn, scoped_run_id, "host", "hosts"),
            "support_findings": _run_record_count(conn, scoped_run_id, "support_finding", "support_findings"),
            "siem_events": int(
                conn.execute("SELECT COUNT(*) FROM siem_events WHERE run_id = ?", [scoped_run_id]).fetchone()[0]
            ),
            "siem_correlations": int(
                conn.execute("SELECT COUNT(*) FROM siem_correlations WHERE run_id = ?", [scoped_run_id]).fetchone()[0]
            ),
            "active_hosts": _run_record_count(conn, scoped_run_id, "host", "hosts", "t.active_now = 1"),
            "hosts_with_last_connected": _run_record_count(
                conn, scoped_run_id, "host", "hosts", "t.last_connected IS NOT NULL AND t.last_connected != ''"
            ),
            "hosts_with_first_seen": _run_record_count(
                conn, scoped_run_id, "host", "hosts", "t.first_seen IS NOT NULL AND t.first_seen != ''"
            ),
            **{
                table: _run_record_count(conn, scoped_run_id, spec["record_type"], table)
                for table, spec in ADDITIONAL_EVIDENCE_TABLES.items()
            },
        }
        last_exact_wifi = conn.execute(
            """
            SELECT MAX(t.derived_connected_at)
            FROM wifi_connections t
            WHERE t.exact_connection_time_available = 1
              AND t.id IN (
                SELECT record_table_id FROM record_observations
                WHERE run_id = ? AND record_type = 'wifi_connection' AND record_table_id IS NOT NULL
              )
            """,
            [scoped_run_id],
        ).fetchone()[0]
        last_device_connected = conn.execute(
            """
            SELECT MAX(t.last_connected)
            FROM hosts t
            WHERE t.id IN (
                SELECT record_table_id FROM record_observations
                WHERE run_id = ? AND record_type = 'host' AND record_table_id IS NOT NULL
            )
            """,
            [scoped_run_id],
        ).fetchone()[0]
    latest = dict(selected_run) if selected_run else None
    if latest:
        for key in (
            "summary_json",
            "router_metadata_json",
            "timestamp_assumptions_json",
            "contamination_json",
            "source_endpoints_json",
        ):
            latest[key.removesuffix("_json")] = _decode_json(latest.pop(key, None))
    source_coverage = acquisition_source_coverage(conn, scoped_run_id)
    presence = presence_summary(conn, scoped_run_id)
    conn.close()
    return {
        "has_data": (
            counts["runs"] > 0
            or counts["event_log"] > 0
            or counts["wifi_connections"] > 0
            or counts["hosts"] > 0
            or counts["support_findings"] > 0
            or any(counts.get(table, 0) > 0 for table in ADDITIONAL_EVIDENCE_TABLES)
        ),
        "latest_run": latest,
        "selected_run_id": scoped_run_id,
        "run_scope": "all" if scoped_run_id is None else str(scoped_run_id),
        "retained": retained,
        "counts": counts,
        "last_exact_wifi": last_exact_wifi,
        "last_device_connected": last_device_connected,
        "presence_summary": presence,
        "source_coverage": source_coverage,
    }


def presence_summary(conn: sqlite3.Connection, run_id: int | None) -> dict[str, Any]:
    run_sql, run_params = _run_observation_sql("host", run_id)
    where = f"WHERE {run_sql}" if run_sql else ""
    params = run_params
    row = dict(
        conn.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN active_now = 1 THEN 1 ELSE 0 END) AS active_now,
                SUM(CASE WHEN first_seen IS NOT NULL AND first_seen != '' THEN 1 ELSE 0 END) AS first_seen,
                SUM(CASE WHEN last_connected IS NOT NULL AND last_connected != '' THEN 1 ELSE 0 END) AS last_connected,
                SUM(CASE WHEN last_activity IS NOT NULL AND last_activity != '' THEN 1 ELSE 0 END) AS last_activity,
                SUM(CASE WHEN last_activity_source = 'exact_wifi_connection' THEN 1 ELSE 0 END) AS exact_wifi,
                SUM(CASE WHEN last_activity_source = 'fritzbox_landevice_lastused' THEN 1 ELSE 0 END) AS device_state,
                SUM(CASE WHEN active_now = 1 THEN 1 ELSE 0 END) AS active_snapshot,
                MAX(last_activity) AS newest_activity,
                MIN(first_seen) AS oldest_first_seen
            FROM hosts t
            {where}
            """,
            params,
        ).fetchone()
    )
    return {
        key: (value or 0 if key not in {"newest_activity", "oldest_first_seen"} else value)
        for key, value in row.items()
    }


def acquisition_source_coverage(conn: sqlite3.Connection, run_id: int | None) -> dict[str, Any]:
    expected = EXPECTED_RAW_ARTIFACTS
    params: list[Any] = []
    if run_id is None:
        where = "WHERE record_type = 'raw_artifact'"
    else:
        where = "WHERE record_type = 'raw_artifact' AND run_id = ?"
        params.append(run_id)
    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT json_extract(content_json, '$.name') AS name, COUNT(*) AS observations,
                   MAX(observed_at) AS last_observed
            FROM record_observations
            {where}
            GROUP BY name
            ORDER BY name
            """,
            params,
        )
    ]
    present = {str(row["name"]): row for row in rows if row.get("name")}
    manifest = acquisition_manifest(conn, run_id)
    attempts_by_artifact = manifest_attempts_by_artifact(manifest)
    warnings = []
    if "landevice_query_json" not in present:
        warnings.append(
            "FRITZ!Box web UI LAN-device state was not collected; Host Table last-connected values may be unavailable."
        )
    if "device_log_xml" not in present:
        warnings.append("Retained device log XML was not collected; timeline completeness is reduced.")
    if "device_log_xml_wlan" not in present:
        warnings.append("WLAN-filtered retained device log XML was not collected; WLAN event coverage is reduced.")
    if "host_list_xml" not in present:
        warnings.append("Host list XML was not collected; device attribution is reduced.")
    if "tr064_snapshot_json" not in present:
        warnings.append(
            "TR-064 router/WAN/WLAN status snapshot was not collected; network-state visualizations are reduced."
        )
    if "data_lua_pages_json" not in present:
        warnings.append(
            "Unofficial FRITZ!Box data.lua pages were not collected; UI-only topology/log/counter evidence is reduced."
        )
    if "webui_readonly_artifacts_json" not in present:
        warnings.append(
            "Additional authenticated Web UI read-only probes were not collected; undocumented endpoint coverage is reduced."
        )
    if "support_data_txt" not in present:
        warnings.append(
            "FRITZ!Box support data was not collected; deep diagnostic settings/service-state evidence is unavailable."
        )
    if "support_lua_page_html" not in present:
        warnings.append("support.lua page evidence was not collected; support-workflow coverage is reduced.")
    if "call_list_xml" not in present:
        warnings.append("Telephony call-list XML was not collected; phone/call context is unavailable.")
    if "config_export_file" not in present:
        warnings.append(
            "Encrypted configuration export was not collected; full settings backup evidence is unavailable."
        )
    matrix_groups = [
        {
            "area": "Retained logs",
            "artifacts": [
                "device_log_xml",
                "device_log_xml_wlan",
                "data_lua_pages_json",
                "webui_readonly_artifacts_json",
                "support_lua_page_html",
                "support_data_txt",
            ],
            "detail": "Timeline, event classes, and raw log validation.",
        },
        {
            "area": "Device inventory",
            "artifacts": ["host_list_xml", "landevice_query_json", "wlan_device_list_xml", "mesh_list"],
            "detail": "Host attribution, active state, mesh context, and last-used device state.",
        },
        {
            "area": "Network exposure",
            "artifacts": ["tr064_snapshot_json", "config_export_file"],
            "detail": "WAN state, external address, port mappings, MyFRITZ!/UPnP hints, and settings backup evidence.",
        },
        {
            "area": "Peripheral context",
            "artifacts": [
                "call_list_xml",
                "phonebooks_xml_json",
                "aha_device_list_xml",
                "aha_switch_list_txt",
                "aha_device_stats_json",
            ],
            "detail": "Telephony and smart-home context where supported by the router.",
        },
    ]
    matrix = []
    for group in matrix_groups:
        artifacts = group["artifacts"]
        found = [name for name in artifacts if name in present]
        matrix.append(
            {
                "area": group["area"],
                "present": len(found),
                "expected": len(artifacts),
                "state": "complete" if len(found) == len(artifacts) else "partial" if found else "missing",
                "artifacts": [
                    {
                        "name": name,
                        "present": name in present,
                        "attempted": name in attempts_by_artifact,
                        "attempts": attempts_by_artifact.get(name, {}).get("attempts", 0),
                        "successful_attempts": attempts_by_artifact.get(name, {}).get("successful", 0),
                        "failed_attempts": attempts_by_artifact.get(name, {}).get("failed", 0),
                        "last_error": attempts_by_artifact.get(name, {}).get("last_error"),
                        "observations": int((present.get(name) or {}).get("observations") or 0),
                        "last_observed": (present.get(name) or {}).get("last_observed"),
                    }
                    for name in artifacts
                ],
                "detail": group["detail"],
            }
        )
    return {
        "expected_raw_artifacts": expected,
        "present_raw_artifacts": rows,
        "missing_raw_artifacts": [name for name in expected if name not in present],
        "attempted_artifacts": attempts_by_artifact,
        "acquisition_manifest": manifest,
        "warnings": warnings,
        "matrix": matrix,
    }


def acquisition_manifest(conn: sqlite3.Connection, run_id: int | None) -> dict[str, Any]:
    params: list[Any] = []
    where = "WHERE json_extract(content_json, '$.name') = 'acquisition_manifest_json'"
    if run_id is not None:
        where += " AND run_id = ?"
        params.append(run_id)
    row = conn.execute(
        f"""
        SELECT json_extract(content_json, '$.content') AS content
        FROM record_observations
        {where}
        ORDER BY id DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if not row or not row["content"]:
        return {"attempt_count": 0, "successful_count": 0, "failed_count": 0, "attempts": []}
    try:
        manifest = json.loads(str(row["content"]))
    except json.JSONDecodeError:
        return {"attempt_count": 0, "successful_count": 0, "failed_count": 0, "attempts": []}
    if not isinstance(manifest, dict):
        return {"attempt_count": 0, "successful_count": 0, "failed_count": 0, "attempts": []}
    manifest.setdefault("attempts", [])
    manifest.setdefault("attempt_count", len(manifest["attempts"]))
    manifest.setdefault("successful_count", sum(1 for item in manifest["attempts"] if item.get("ok")))
    manifest.setdefault("failed_count", sum(1 for item in manifest["attempts"] if not item.get("ok")))
    return manifest


def manifest_attempts_by_artifact(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for attempt in manifest.get("attempts") or []:
        if not isinstance(attempt, dict):
            continue
        artifact = str(attempt.get("artifact") or "")
        if not artifact:
            continue
        entry = grouped.setdefault(
            artifact,
            {"attempts": 0, "successful": 0, "failed": 0, "surfaces": [], "last_error": None},
        )
        entry["attempts"] += 1
        if attempt.get("ok"):
            entry["successful"] += 1
        else:
            entry["failed"] += 1
            entry["last_error"] = attempt.get("error") or entry["last_error"]
        surface = attempt.get("surface")
        if surface and surface not in entry["surfaces"]:
            entry["surfaces"].append(surface)
    return grouped


def analysis_snapshot(
    path: Path = DEFAULT_DB, start: str = "", end: str = "", run_id: str | int = "latest"
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    range_filter, params = _time_range_sql("timestamp", start, end)
    event_run_sql, event_run_params = _run_observation_sql("event_log", scoped_run_id)
    event_filter, event_params = _combine_filter(range_filter, params, event_run_sql, event_run_params)
    category_counts = [
        dict(row)
        for row in conn.execute(
            f"SELECT COALESCE(category, 'unknown') AS label, COUNT(*) AS count FROM event_log t{event_filter} GROUP BY label ORDER BY count DESC",
            event_params,
        )
    ]
    auth_counts = {
        "failed": _count_like(
            conn,
            "event_log",
            "message",
            ["falsches", "fehlgeschlagen", "failed"],
            start,
            end,
            "timestamp",
            scoped_run_id,
        ),
        "successful": _count_like(
            conn, "event_log", "message", ["erfolgreich", "success"], start, end, "timestamp", scoped_run_id
        ),
        "app": _count_like(conn, "event_log", "message", ["app"], start, end, "timestamp", scoped_run_id),
    }
    hourly = _hourly_counts(conn, start, end, scoped_run_id)
    wifi_run_sql, wifi_run_params = _run_observation_sql("wifi_connection", scoped_run_id)
    confidence_filter, confidence_params = _combine_filter(
        " WHERE " + ("1=1" if scoped_run_id is not None else WIFI_DEDUPE_SQL),
        [],
        wifi_run_sql,
        wifi_run_params,
    )
    confidence = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(derived_time_confidence, evidence, 'unknown') AS label, COUNT(*) AS count
            FROM wifi_connections t
            {confidence_filter}
            GROUP BY label
            ORDER BY count DESC
            """,
            confidence_params,
        )
    ]
    host_run_sql, host_run_params = _run_observation_sql("host", scoped_run_id)
    host_filter, host_params = _combine_filter(" WHERE 1=1", [], host_run_sql, host_run_params)
    interface_counts = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.interface, ''), NULLIF(t.interface_detail, ''), 'unknown') AS label,
                   COUNT(*) AS count
            FROM hosts t{host_filter}
            GROUP BY label
            ORDER BY count DESC
            """,
            host_params,
        )
    ]
    vendor_counts = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.vendor, ''), NULLIF(t.model, ''), 'unknown') AS label,
                   COUNT(*) AS count
            FROM hosts t{host_filter}
            GROUP BY label
            ORDER BY count DESC
            LIMIT 8
            """,
            host_params,
        )
    ]
    timestamp_coverage = {
        "first_seen": _host_count(conn, host_filter, host_params, "t.first_seen IS NOT NULL AND t.first_seen != ''"),
        "last_seen": _host_count(conn, host_filter, host_params, "t.last_seen IS NOT NULL AND t.last_seen != ''"),
        "last_connected": _host_count(
            conn, host_filter, host_params, "t.last_connected IS NOT NULL AND t.last_connected != ''"
        ),
        "last_activity": _host_count(
            conn, host_filter, host_params, "t.last_activity IS NOT NULL AND t.last_activity != ''"
        ),
        "active_now": _host_count(conn, host_filter, host_params, "t.active_now = 1"),
        "online": _host_count(conn, host_filter, host_params, "t.online = 1"),
    }
    if scoped_run_id is None:
        retained = dict(conn.execute("""
                SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN timestamp IS NOT NULL AND timestamp != '' THEN 1 ELSE 0 END) AS timestamped_event_count
                FROM event_log
                """).fetchone())
        run = conn.execute(
            "SELECT generated_at, router_address, summary_json FROM export_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    else:
        retained = dict(
            conn.execute(
                """
                SELECT MIN(event_time) AS oldest_event, MAX(event_time) AS newest_event,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN event_time IS NOT NULL AND event_time != '' THEN 1 ELSE 0 END) AS timestamped_event_count
                FROM record_observations
                WHERE run_id = ? AND record_type = 'event_log'
                """,
                [scoped_run_id],
            ).fetchone()
        )
        run = conn.execute(
            "SELECT generated_at, router_address, summary_json FROM export_runs WHERE id = ?",
            [scoped_run_id],
        ).fetchone()
    gaps = _event_gaps(conn, scoped_run_id)
    source_coverage = acquisition_source_coverage(conn, scoped_run_id)
    raw = raw_artifact_summaries(conn, scoped_run_id)
    mesh = mesh_summary(raw.get("mesh_list"))
    tr064 = tr064_summary(raw.get("tr064_snapshot_json"))
    host_risk = host_risk_summary(conn, host_filter, host_params, tr064.get("wan", {}).get("port_mappings") or [])
    last_used = last_used_histogram(conn, host_filter, host_params)
    advertisement_hints = advertisement_hint_summary(conn, scoped_run_id, start, end)
    security_advisories = security_advisory_summary(conn, scoped_run_id)
    conn.close()
    return {
        "category_counts": category_counts,
        "auth_counts": auth_counts,
        "hourly_counts": hourly,
        "confidence_counts": confidence,
        "interface_counts": interface_counts,
        "vendor_counts": vendor_counts,
        "timestamp_coverage": timestamp_coverage,
        "source_coverage": source_coverage,
        "mesh_summary": mesh,
        "tr064_summary": tr064,
        "host_risk_summary": host_risk,
        "security_advisories": security_advisories,
        "last_used_histogram": last_used,
        "advertisement_hints": advertisement_hints,
        "retained": retained,
        "latest_run": dict(run) if run else None,
        "gaps": gaps,
    }
