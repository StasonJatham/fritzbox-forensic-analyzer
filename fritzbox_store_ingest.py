from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from fritzbox_evidence_extractors import (
    extract_additional_evidence,
    json_column_value,
    keyed_record_key,
    normalize_additional_row,
)
from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES
from fritzbox_siem import refresh_siem_views
from fritzbox_store_constants import EXPECTED_RAW_ARTIFACTS
from fritzbox_store_records import (
    add_fts,
    event_evidence,
    event_key,
    host_evidence,
    host_key,
    lookup_event_id,
    lookup_host_id,
    lookup_keyed_record_id,
    lookup_raw_artifact_id,
    lookup_support_finding_id,
    lookup_wifi_id,
    normalize_event_log_row,
    repair_observation_table_ids,
    searchable_text,
    support_finding_key,
    wifi_evidence,
    wifi_key,
)
from fritzbox_store_schema import DEFAULT_DB
from fritzbox_store_schema import init_db as open_store_db


def init_db(path: Path = DEFAULT_DB) -> sqlite3.Connection:
    return open_store_db(path, repair_observation_table_ids)


def ingest_dataset(dataset: dict[str, Any], path: Path = DEFAULT_DB) -> int:
    conn = init_db(path)
    generated_at = str(dataset.get("generated_at") or datetime.now().astimezone().isoformat())
    acquired_at = datetime.now().astimezone().isoformat()
    summary = dataset.get("summary") or {}
    router = dataset.get("router") or {}
    acquisition = acquisition_metadata(dataset, acquired_at)
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO export_runs(
                generated_at, router_address, window_hours, summary_json, acquired_at, collector_time,
                tool_version, tool_git_commit, acquisition_mode, router_metadata_json,
                timestamp_assumptions_json, contamination_json, source_endpoints_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generated_at,
                router.get("address"),
                dataset.get("window_hours"),
                json.dumps(summary, sort_keys=True),
                acquired_at,
                acquisition["collector_time"],
                acquisition["tool_version"],
                acquisition["tool_git_commit"],
                acquisition["acquisition_mode"],
                json.dumps(acquisition["router_metadata"], sort_keys=True),
                json.dumps(acquisition["timestamp_assumptions"], sort_keys=True),
                json.dumps(acquisition["contamination"], sort_keys=True),
                json.dumps(acquisition["source_endpoints"], sort_keys=True),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("export run insert did not return a row id")
        run_id = int(cursor.lastrowid)

        for name, content in (dataset.get("raw_exports") or {}).items():
            if not isinstance(content, str):
                content = json.dumps(content, sort_keys=True)
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO raw_artifacts(run_id, name, sha256, content, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, name, digest, content, generated_at),
            )
            row_id = cursor.lastrowid if cursor.rowcount else lookup_raw_artifact_id(conn, run_id, name, digest)
            if row_id and cursor.rowcount:
                add_fts(conn, "raw_artifacts", int(row_id), f"{name} {digest} {content}")
            add_observation(
                conn,
                run_id=run_id,
                record_type="raw_artifact",
                record_key=f"{name}:{digest}",
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=generated_at,
                evidence_level="raw",
                evidence_note="Raw artifact exposed by FRITZ!Box during this acquisition run.",
                source=name,
                content={"name": name, "sha256": digest, "content": content},
            )

        for finding in dataset.get("support_findings") or []:
            searchable = searchable_text(finding)
            evidence_level = finding.get("evidence_level") or "parsed_from_raw"
            evidence_note = finding.get("evidence_note") or "Parsed from FRITZ!Box support-data raw artifact."
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO support_findings(
                    run_id, finding_type, section, key, value, line_number, observed_at, source,
                    evidence_level, evidence_note, raw_text, raw_json, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding.get("finding_type"),
                    finding.get("section"),
                    finding.get("key"),
                    finding.get("value"),
                    finding.get("line_number"),
                    finding.get("observed_at"),
                    finding.get("source") or "support_data_txt",
                    evidence_level,
                    evidence_note,
                    finding.get("raw_text"),
                    json.dumps(finding, sort_keys=True),
                    searchable,
                ),
            )
            row_id = cursor.lastrowid if cursor.rowcount else lookup_support_finding_id(conn, finding)
            if row_id and cursor.rowcount:
                add_fts(conn, "support_findings", int(row_id), searchable)
            add_observation(
                conn,
                run_id=run_id,
                record_type="support_finding",
                record_key=support_finding_key(finding),
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=finding.get("observed_at") or generated_at,
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source=finding.get("source") or "support_data_txt",
                content=finding,
            )

        for event in dataset.get("event_log") or []:
            event = normalize_event_log_row(event)
            searchable = searchable_text(event)
            evidence_level, evidence_note = event_evidence(event)
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO event_log(
                    run_id, timestamp, category, mac, ip, source, message, evidence_level, evidence_note, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    event.get("timestamp"),
                    event.get("category"),
                    event.get("mac"),
                    event.get("ip"),
                    event.get("source") or "device_log",
                    event.get("message") or "",
                    evidence_level,
                    evidence_note,
                    searchable,
                ),
            )
            row_id = cursor.lastrowid if cursor.rowcount else None
            if row_id:
                add_fts(conn, "event_log", int(row_id), searchable)
            else:
                row_id = lookup_event_id(conn, event)
            add_observation(
                conn,
                run_id=run_id,
                record_type="event_log",
                record_key=event_key(event),
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=event.get("timestamp"),
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source=event.get("source") or "device_log",
                content=event,
            )

        for row in dataset.get("available_wifi_connections") or []:
            searchable = searchable_text(row)
            evidence_level, evidence_note = wifi_evidence(row)
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO wifi_connections(
                    run_id, derived_connected_at, derived_time_type, derived_time_confidence,
                    exact_connection_time_available, event, hostname, mac, ip, source, evidence,
                    evidence_level, evidence_note, message, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    row.get("derived_connected_at") or row.get("timestamp"),
                    row.get("derived_time_type"),
                    row.get("derived_time_confidence"),
                    1 if row.get("exact_connection_time_available") else 0,
                    row.get("event"),
                    row.get("hostname"),
                    row.get("mac"),
                    row.get("ip"),
                    row.get("source"),
                    row.get("confidence"),
                    evidence_level,
                    evidence_note,
                    row.get("message"),
                    searchable,
                ),
            )
            row_id = cursor.lastrowid if cursor.rowcount else None
            if row_id:
                add_fts(conn, "wifi_connections", int(row_id), searchable)
            else:
                row_id = lookup_wifi_id(conn, row)
            add_observation(
                conn,
                run_id=run_id,
                record_type="wifi_connection",
                record_key=wifi_key(row),
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=row.get("derived_connected_at") or row.get("timestamp"),
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source=row.get("source") or row.get("derived_time_type") or "wifi",
                content=row,
            )

        for host in dataset.get("known_hosts") or []:
            searchable = searchable_text(host)
            evidence_level, evidence_note = host_evidence(host)
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO hosts(
                    run_id, hostname, mac, ip, interface, interface_detail, active_now, online,
                    first_seen, last_seen,
                    last_connected, last_activity, last_activity_source, last_activity_confidence,
                    uid, friendly_name, neighbour_name, ip_list, mac_list, wlan_station_type,
                    wlan_uids, plc_uids, ethernet_port, vendor, model, speed, source_flags,
                    parent_uid, flags, modification_flags, dhcp, static_dhcp, blocked,
                    guest, vpn, wan_access, filter_profile_id,
                    allow_pcp_and_upnp, pcp_count, upnp_count, myfritz_enabled,
                    last_activity_note, evidence_level, evidence_note, raw_json, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname, mac, ip) DO UPDATE SET
                    run_id = excluded.run_id,
                    interface = COALESCE(excluded.interface, hosts.interface),
                    interface_detail = COALESCE(excluded.interface_detail, hosts.interface_detail),
                    active_now = excluded.active_now,
                    online = COALESCE(excluded.online, hosts.online),
                    first_seen = COALESCE(MIN(NULLIF(hosts.first_seen, ''), NULLIF(excluded.first_seen, '')), excluded.first_seen, hosts.first_seen),
                    last_seen = MAX(COALESCE(hosts.last_seen, ''), COALESCE(excluded.last_seen, '')),
                    last_connected = MAX(COALESCE(hosts.last_connected, ''), COALESCE(excluded.last_connected, '')),
                    last_activity = MAX(COALESCE(hosts.last_activity, ''), COALESCE(excluded.last_activity, '')),
                    last_activity_source = COALESCE(excluded.last_activity_source, hosts.last_activity_source),
                    last_activity_confidence = COALESCE(excluded.last_activity_confidence, hosts.last_activity_confidence),
                    last_activity_note = COALESCE(excluded.last_activity_note, hosts.last_activity_note),
                    uid = COALESCE(excluded.uid, hosts.uid),
                    friendly_name = COALESCE(excluded.friendly_name, hosts.friendly_name),
                    neighbour_name = COALESCE(excluded.neighbour_name, hosts.neighbour_name),
                    ip_list = COALESCE(excluded.ip_list, hosts.ip_list),
                    mac_list = COALESCE(excluded.mac_list, hosts.mac_list),
                    wlan_station_type = COALESCE(excluded.wlan_station_type, hosts.wlan_station_type),
                    wlan_uids = COALESCE(excluded.wlan_uids, hosts.wlan_uids),
                    plc_uids = COALESCE(excluded.plc_uids, hosts.plc_uids),
                    ethernet_port = COALESCE(excluded.ethernet_port, hosts.ethernet_port),
                    vendor = COALESCE(excluded.vendor, hosts.vendor),
                    model = COALESCE(excluded.model, hosts.model),
                    speed = COALESCE(excluded.speed, hosts.speed),
                    source_flags = COALESCE(excluded.source_flags, hosts.source_flags),
                    parent_uid = COALESCE(excluded.parent_uid, hosts.parent_uid),
                    flags = COALESCE(excluded.flags, hosts.flags),
                    modification_flags = COALESCE(excluded.modification_flags, hosts.modification_flags),
                    dhcp = COALESCE(excluded.dhcp, hosts.dhcp),
                    static_dhcp = COALESCE(excluded.static_dhcp, hosts.static_dhcp),
                    blocked = COALESCE(excluded.blocked, hosts.blocked),
                    guest = COALESCE(excluded.guest, hosts.guest),
                    vpn = COALESCE(excluded.vpn, hosts.vpn),
                    wan_access = COALESCE(excluded.wan_access, hosts.wan_access),
                    filter_profile_id = COALESCE(excluded.filter_profile_id, hosts.filter_profile_id),
                    allow_pcp_and_upnp = COALESCE(excluded.allow_pcp_and_upnp, hosts.allow_pcp_and_upnp),
                    pcp_count = COALESCE(excluded.pcp_count, hosts.pcp_count),
                    upnp_count = COALESCE(excluded.upnp_count, hosts.upnp_count),
                    myfritz_enabled = COALESCE(excluded.myfritz_enabled, hosts.myfritz_enabled),
                    evidence_level = excluded.evidence_level,
                    evidence_note = excluded.evidence_note,
                    raw_json = excluded.raw_json,
                    searchable = excluded.searchable
                """,
                (
                    run_id,
                    host.get("hostname"),
                    host.get("mac"),
                    host.get("ip"),
                    host.get("interface"),
                    host.get("interface_detail"),
                    1 if host.get("active_now") else 0,
                    1 if host.get("online") else 0 if host.get("online") is not None else None,
                    host.get("first_seen"),
                    host.get("last_seen"),
                    host.get("last_connected"),
                    host.get("last_activity"),
                    host.get("last_activity_source"),
                    host.get("last_activity_confidence"),
                    host.get("uid"),
                    host.get("friendly_name"),
                    host.get("neighbour_name"),
                    host.get("ip_list"),
                    host.get("mac_list"),
                    host.get("wlan_station_type"),
                    host.get("wlan_uids"),
                    host.get("plc_uids"),
                    host.get("ethernet_port"),
                    host.get("vendor"),
                    host.get("model"),
                    host.get("speed"),
                    host.get("source_flags"),
                    host.get("parent_uid"),
                    host.get("flags"),
                    host.get("modification_flags"),
                    host.get("dhcp"),
                    host.get("static_dhcp"),
                    host.get("blocked"),
                    host.get("guest"),
                    host.get("vpn"),
                    host.get("wan_access"),
                    host.get("filter_profile_id"),
                    host.get("allow_pcp_and_upnp"),
                    host.get("pcp_count"),
                    host.get("upnp_count"),
                    host.get("myfritz_enabled"),
                    host.get("last_activity_note"),
                    evidence_level,
                    evidence_note,
                    json.dumps(host, sort_keys=True),
                    searchable,
                ),
            )
            row_id = cursor.lastrowid if cursor.rowcount else None
            if row_id:
                add_fts(conn, "hosts", int(row_id), searchable)
            else:
                row_id = lookup_host_id(conn, host)
            add_observation(
                conn,
                run_id=run_id,
                record_type="host",
                record_key=host_key(host),
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=(
                    (generated_at if host.get("active_now") else None)
                    or host.get("last_activity")
                    or host.get("last_connected")
                    or host.get("last_seen")
                    or host.get("first_seen")
                ),
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source="Hosts:GetGenericHostEntry",
                content=host,
            )

        ingest_additional_evidence(conn, dataset, run_id, acquired_at, generated_at)
        siem_counts = refresh_siem_views(conn, run_id)
        summary = {**summary, **siem_counts}
        conn.execute(
            "UPDATE export_runs SET summary_json = ? WHERE id = ?", [json.dumps(summary, sort_keys=True), run_id]
        )
    conn.close()
    return run_id


def acquisition_metadata(dataset: dict[str, Any], acquired_at: str) -> dict[str, Any]:
    router = dataset.get("router") or {}
    collector_now = datetime.now().astimezone()
    collector_tz = collector_now.tzinfo
    return {
        "collector_time": acquired_at,
        "tool_version": "fritzforensik-local",
        "tool_git_commit": git_commit(),
        "acquisition_mode": dataset.get("acquisition_mode") or "manual_or_ui_fetch",
        "router_metadata": {
            **router,
            "device_model": (dataset.get("device_info") or {}).get("model"),
            "firmware": (dataset.get("device_info") or {}).get("firmware"),
            "router_time": (dataset.get("router_time") or {}).get("current_time"),
        },
        "timestamp_assumptions": {
            "router_event_timestamps": "Parsed from retained FRITZ!Box log text and interpreted in the collector local timezone unless the raw entry already contains an offset.",
            "collector_timezone": collector_tz.tzname(None) if collector_tz else None,
            "router_clock_status": "not independently validated",
            "absence_meaning": "Not observed in retained/exported data does not prove the event did not happen.",
        },
        "contamination": {
            "tool_login_may_create_router_log_entries": True,
            "polling_may_create_repeated_observations": True,
            "guidance": "Treat initial acquisition separately from later monitoring runs.",
        },
        "source_endpoints": dataset.get("source_endpoints")
        or {
            "tr064": ["DeviceInfo:GetDeviceLog", "Hosts:GetGenericHostEntry"],
            "avm_exports": EXPECTED_RAW_ARTIFACTS,
        },
    }


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None
    return result.stdout.strip() or None


def add_observation(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    record_type: str,
    record_key: str,
    record_table_id: int | None,
    observed_at: str,
    event_time: str | None,
    evidence_level: str,
    evidence_note: str,
    source: str | None,
    content: dict[str, Any],
) -> None:
    content_json = json.dumps(content, sort_keys=True, default=str)
    digest = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
    conn.execute(
        """
        INSERT INTO record_observations(
            run_id, record_type, record_key, record_table_id, observed_at, event_time,
            evidence_level, evidence_note, source, content_sha256, content_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            record_type,
            record_key,
            record_table_id,
            observed_at,
            event_time,
            evidence_level,
            evidence_note,
            source,
            digest,
            content_json,
        ),
    )


def ingest_additional_evidence(
    conn: sqlite3.Connection,
    dataset: dict[str, Any],
    run_id: int,
    acquired_at: str,
    generated_at: str,
) -> None:
    extracted = extract_additional_evidence(dataset, generated_at)
    for table, spec in ADDITIONAL_EVIDENCE_TABLES.items():
        seen: set[str] = set()
        for row in extracted.get(table, []):
            normalized = normalize_additional_row(table, row)
            record_key = keyed_record_key(normalized, spec["record_key_fields"])
            if record_key in seen:
                continue
            seen.add(record_key)
            searchable = searchable_text(normalized)
            evidence_level = normalized.get("evidence_level") or (
                "inferred" if table == "device_risk_summaries" else "parsed_from_raw"
            )
            evidence_note = normalized.get("evidence_note") or str(spec["note"])
            columns = list(spec["columns"])
            values = [json_column_value(normalized.get(column)) for column in columns]
            column_sql = ", ".join(
                ["run_id", "record_key", *columns, "evidence_level", "evidence_note", "raw_json", "searchable"]
            )
            placeholders = ", ".join("?" for _ in range(len(columns) + 6))
            cursor = conn.execute(
                f"""
                INSERT OR IGNORE INTO {table}({column_sql})
                VALUES ({placeholders})
                """,
                (
                    run_id,
                    record_key,
                    *values,
                    evidence_level,
                    evidence_note,
                    json.dumps(normalized, sort_keys=True, default=str),
                    searchable,
                ),
            )
            row_id = cursor.lastrowid if cursor.rowcount else lookup_keyed_record_id(conn, table, normalized)
            if row_id and cursor.rowcount:
                add_fts(conn, spec["fts_type"], int(row_id), searchable)
            add_observation(
                conn,
                run_id=run_id,
                record_type=spec["record_type"],
                record_key=record_key,
                record_table_id=int(row_id) if row_id else None,
                observed_at=acquired_at,
                event_time=normalized.get(str(spec["time_column"])) if spec["time_column"] else generated_at,
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source=normalized.get("source"),
                content={**normalized, "record_key": record_key},
            )


def reparse_support_wlan_environment(path: Path = DEFAULT_DB, run_id: int | str = "latest") -> dict[str, Any]:
    """Promote newly supported WLAN support-data sections from stored raw artifacts."""
    from fritzbox_parsers import parse_support_wlan_environment

    conn = init_db(path)
    with conn:
        run = resolve_reparse_run(conn, run_id)
        support_rows = conn.execute(
            """
            SELECT content_json
            FROM record_observations
            WHERE run_id = ? AND record_type = 'raw_artifact' AND source = 'support_data_txt'
            ORDER BY id DESC
            """,
            [run["id"]],
        ).fetchall()
        before = {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", [run["id"]]).fetchone()[0])
            for table in ("advertisement_hints", "network_status_snapshots")
        }
        hints: list[dict[str, Any]] = []
        snapshots: list[dict[str, Any]] = []
        for row in support_rows:
            try:
                content = json.loads(row["content_json"] or "{}")
            except json.JSONDecodeError:
                continue
            artifact_content = content.get("content")
            if not isinstance(artifact_content, str) or not artifact_content:
                continue
            parsed_hints, parsed_snapshots = parse_support_wlan_environment(artifact_content, run["generated_at"])
            hints.extend(parsed_hints)
            snapshots.extend(parsed_snapshots)
        if hints or snapshots:
            ingest_additional_evidence(
                conn,
                {
                    "generated_at": run["generated_at"],
                    "advertisement_hints": hints,
                    "network_status_snapshots": snapshots,
                },
                int(run["id"]),
                str(run["acquired_at"] or run["generated_at"]),
                str(run["generated_at"]),
            )
        after = {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", [run["id"]]).fetchone()[0])
            for table in ("advertisement_hints", "network_status_snapshots")
        }
    conn.close()
    return {
        "run_id": int(run["id"]),
        "generated_at": run["generated_at"],
        "raw_support_artifacts": len(support_rows),
        "parsed": {"advertisement_hints": len(hints), "network_status_snapshots": len(snapshots)},
        "inserted": {table: after[table] - before[table] for table in before},
        "totals": after,
    }


def resolve_reparse_run(conn: sqlite3.Connection, run_id: int | str) -> sqlite3.Row:
    if str(run_id).casefold() == "latest":
        row = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    else:
        row = conn.execute("SELECT * FROM export_runs WHERE id = ?", [int(run_id)]).fetchone()
    if row is None:
        raise ValueError(f"Export run not found: {run_id}")
    return row
