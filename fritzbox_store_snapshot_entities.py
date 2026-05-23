from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fritzbox_evidence_tables import ADDITIONAL_RECORD_TYPE_ALIASES
from fritzbox_store_constants import WIFI_DEDUPE_SQL
from fritzbox_store_ingest import init_db
from fritzbox_store_query_helpers import _combine_filter, _run_observation_sql, enrich_host_activity, resolve_run_id
from fritzbox_store_schema import DEFAULT_DB


def query_entities(
    path: Path = DEFAULT_DB, query: str = "", limit: int = 100, run_id: str | int = "latest"
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    q = f"%{query.casefold()}%" if query else ""
    where_parts: list[str] = []
    params: list[Any] = []
    if q:
        where_parts.append("lower(t.searchable) LIKE ?")
        params.append(q)
    run_sql, run_params = _run_observation_sql("host", scoped_run_id)
    if run_sql:
        where_parts.append(run_sql)
        params.extend(run_params)
    where = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    hosts = [
        dict(row)
        for row in conn.execute(
            f"SELECT t.* FROM hosts t {where} ORDER BY COALESCE(t.last_seen, '') DESC LIMIT ?",
            [*params, limit],
        )
    ]
    enrich_host_activity(conn, hosts, scoped_run_id)
    entities: dict[str, dict[str, Any]] = {}
    for host in hosts:
        key = host.get("mac") or host.get("ip") or host.get("hostname") or f"host-{host['id']}"
        entities[key] = {
            "key": key,
            "hostname": host.get("hostname"),
            "mac": host.get("mac"),
            "ip": host.get("ip"),
            "interface": host.get("interface"),
            "active_now": host.get("active_now"),
            "first_seen": host.get("first_seen"),
            "last_seen": host.get("last_seen"),
            "last_connected": host.get("last_connected"),
            "host_record": host,
            "event_count": _entity_event_count(conn, host, scoped_run_id),
            "wifi_count": _entity_wifi_count(conn, host, scoped_run_id),
        }
    conn.close()
    return {"rows": list(entities.values()), "total": len(entities)}


def entity_pivot(
    path: Path = DEFAULT_DB, value: str = "", limit: int = 200, run_id: str | int = "latest"
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    needle = value.strip()
    if not needle:
        conn.close()
        return {"entity": {}, "timeline": [], "hosts": [], "wifi": [], "logs": []}
    like = f"%{needle}%"
    host_run_sql, host_run_params = _run_observation_sql("host", scoped_run_id)
    host_where, host_params = _combine_filter(" WHERE t.searchable LIKE ?", [like], host_run_sql, host_run_params)
    hosts = [
        dict(row)
        for row in conn.execute(
            f"SELECT t.* FROM hosts t{host_where} ORDER BY COALESCE(t.last_seen, '') DESC LIMIT 10",
            host_params,
        )
    ]
    wifi_run_sql, wifi_run_params = _run_observation_sql("wifi_connection", scoped_run_id)
    wifi_where, wifi_params = _combine_filter(
        " WHERE t.searchable LIKE ? AND " + ("1=1" if scoped_run_id is not None else "t." + WIFI_DEDUPE_SQL.strip()),
        [like],
        wifi_run_sql,
        wifi_run_params,
    )
    wifi = [
        dict(row)
        for row in conn.execute(
            f"SELECT t.* FROM wifi_connections t{wifi_where} ORDER BY COALESCE(t.derived_connected_at, '') DESC LIMIT ?",
            [*wifi_params, limit],
        )
    ]
    event_run_sql, event_run_params = _run_observation_sql("event_log", scoped_run_id)
    event_where, event_params = _combine_filter(" WHERE t.searchable LIKE ?", [like], event_run_sql, event_run_params)
    logs = [
        dict(row)
        for row in conn.execute(
            f"SELECT t.* FROM event_log t{event_where} ORDER BY COALESCE(t.timestamp, '') DESC LIMIT ?",
            [*event_params, limit],
        )
    ]
    timeline = [
        {
            "record_type": "event_log",
            "record_id": row["id"],
            "event_time": row["timestamp"],
            "event_class": row["category"],
            "message": row["message"],
            "ip": row["ip"],
            "mac": row["mac"],
            "confidence": "high",
            "time_type": "exact",
            "evidence_level": row["evidence_level"],
            "evidence_note": row["evidence_note"],
            "source": row["source"],
        }
        for row in logs
    ] + [
        {
            "record_type": "wifi_connections",
            "record_id": row["id"],
            "event_time": row["derived_connected_at"],
            "event_class": "wifi",
            "message": row["message"] or row["event"],
            "ip": row["ip"],
            "mac": row["mac"],
            "hostname": row["hostname"],
            "confidence": row["derived_time_confidence"] or row["evidence"],
            "time_type": row["derived_time_type"],
            "evidence_level": row["evidence_level"],
            "evidence_note": row["evidence_note"],
            "source": row["source"],
        }
        for row in wifi
    ]
    timeline.sort(key=lambda row: row.get("event_time") or "", reverse=True)
    conn.close()
    return {"entity": {"value": needle}, "timeline": timeline[:limit], "hosts": hosts, "wifi": wifi, "logs": logs}


def evidence_for_record(path: Path = DEFAULT_DB, record_type: str = "", record_id: int = 0) -> dict[str, Any]:
    conn = init_db(path)
    table_map = {
        "log": "event_log",
        "event_log": "event_log",
        "wifi": "wifi_connections",
        "wifi_connections": "wifi_connections",
        "hosts": "hosts",
        "support": "support_findings",
        "support_findings": "support_findings",
        "events": "siem_events",
        "siem": "siem_events",
        "siem_events": "siem_events",
        "normalized_events": "siem_events",
        "correlations": "siem_correlations",
        "siem_correlations": "siem_correlations",
        "raw": "raw_artifacts",
        "raw_artifacts": "raw_artifacts",
        **ADDITIONAL_RECORD_TYPE_ALIASES,
    }
    table = table_map.get(record_type)
    if not table:
        conn.close()
        return {"record": None, "artifacts": []}
    record = conn.execute(f"SELECT * FROM {table} WHERE id = ?", [record_id]).fetchone()
    if not record:
        conn.close()
        return {"record": None, "artifacts": []}
    row = dict(record)
    if table == "raw_artifacts":
        conn.close()
        return {
            "record": row,
            "artifacts": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "created_at": row["created_at"],
                    "snippet": _snippet(row["content"], row["content"][:80]),
                }
            ],
        }
    if table == "siem_correlations":
        linked = [
            dict(item)
            for item in conn.execute(
                """
                SELECT
                    l.role, l.reason, l.weight,
                    e.id, e.event_time, e.event_category, e.event_kind, e.severity,
                    e.entity, e.hostname, e.mac, e.ip, e.source, e.record_type,
                    e.record_id, e.message
                FROM siem_correlation_events l
                JOIN siem_events e ON e.id = l.event_id
                WHERE l.correlation_id = ?
                ORDER BY COALESCE(e.event_time, ''), e.id
                LIMIT 200
                """,
                [record_id],
            )
        ]
        row["linked_events"] = linked
        state = conn.execute(
            """
            SELECT status, resolved_at, resolved_by, note, updated_at
            FROM siem_alert_states
            WHERE run_id = ?
              AND rule_id = ?
              AND entity_key = ?
              AND window_start = ?
              AND window_end = ?
            """,
            [
                row.get("run_id"),
                row.get("rule_id") or "",
                row.get("entity_key") or "",
                row.get("window_start") or "",
                row.get("window_end") or "",
            ],
        ).fetchone()
        row["alert_status"] = state["status"] if state else ("open" if row.get("correlation_type") == "alert" else "")
        row["resolved_at"] = state["resolved_at"] if state else ""
        row["resolved_by"] = state["resolved_by"] if state else ""
        row["resolution_note"] = state["note"] if state else ""
    if table == "event_log":
        linked = [
            dict(item)
            for item in conn.execute(
                """
                SELECT id, event_time, event_category, event_kind, action, outcome, severity,
                       entity, hostname, mac, ip, source, confidence, evidence_level,
                       record_type, record_id, message, tags_json, fields_json
                FROM siem_events
                WHERE record_type = 'event_log'
                  AND record_id = ?
                ORDER BY id DESC
                LIMIT 20
                """,
                [record_id],
            )
        ]
        row["linked_events"] = linked
    needles = [
        row.get("message"),
        row.get("mac"),
        row.get("ip"),
        row.get("hostname"),
        row.get("raw_text"),
        row.get("value"),
        row.get("key"),
        row.get("section"),
        row.get("name"),
        row.get("content"),
        row.get("raw_json"),
        row.get("summary"),
        row.get("description"),
        row.get("ssid"),
        row.get("internal_client"),
    ]
    artifacts: list[dict[str, Any]] = []
    for needle in [item for item in needles if item]:
        found = conn.execute(
            "SELECT id, name, created_at, content FROM raw_artifacts WHERE content LIKE ? ORDER BY id DESC LIMIT 3",
            [f"%{needle}%"],
        ).fetchall()
        for artifact in found:
            content = artifact["content"]
            artifacts.append(
                {
                    "id": artifact["id"],
                    "name": artifact["name"],
                    "created_at": artifact["created_at"],
                    "snippet": _snippet(content, str(needle)),
                }
            )
        if artifacts:
            break
    conn.close()
    return {"record": row, "artifacts": artifacts}


def _entity_event_count(conn: sqlite3.Connection, host: dict[str, Any], run_id: int | None = None) -> int:
    terms = [host.get("hostname"), host.get("mac"), host.get("ip")]
    terms = [term for term in terms if term]
    if not terms:
        return 0
    where = " OR ".join("searchable LIKE ?" for _ in terms)
    run_sql, run_params = _run_observation_sql("event_log", run_id)
    filter_sql, params = _combine_filter(f" WHERE ({where})", [f"%{term}%" for term in terms], run_sql, run_params)
    return int(conn.execute(f"SELECT COUNT(*) FROM event_log t{filter_sql}", params).fetchone()[0])


def _entity_wifi_count(conn: sqlite3.Connection, host: dict[str, Any], run_id: int | None = None) -> int:
    terms = [host.get("hostname"), host.get("mac"), host.get("ip")]
    terms = [term for term in terms if term]
    if not terms:
        return 0
    where = " OR ".join("searchable LIKE ?" for _ in terms)
    run_sql, run_params = _run_observation_sql("wifi_connection", run_id)
    filter_sql, params = _combine_filter(
        f" WHERE ({where}) AND " + ("1=1" if run_id is not None else "t." + WIFI_DEDUPE_SQL.strip()),
        [f"%{term}%" for term in terms],
        run_sql,
        run_params,
    )
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM wifi_connections t{filter_sql}",
            params,
        ).fetchone()[0]
    )


def _snippet(content: str, needle: str, width: int = 360) -> str:
    index = content.casefold().find(needle.casefold())
    if index < 0:
        return content[:width]
    start = max(index - width // 2, 0)
    end = min(index + len(needle) + width // 2, len(content))
    return content[start:end]
