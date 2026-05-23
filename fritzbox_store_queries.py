from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES, ADDITIONAL_RECORD_TYPE_ALIASES
from fritzbox_store_constants import WIFI_DEDUPE_SQL
from fritzbox_store_ingest import init_db
from fritzbox_store_query_helpers import (
    _run_observation_sql,
    enrich_host_activity,
    make_fts_query,
    resolve_run_id,
)
from fritzbox_store_schema import DEFAULT_DB


def _all_evidence_sources() -> list[dict[str, str]]:
    sources = [
        {
            "table": "siem_events",
            "fts_type": "siem_events",
            "record_label": "SIEM Event",
            "observation_type": "siem_event",
            "time_expr": "COALESCE(t.event_time, '')",
            "title_expr": "COALESCE(NULLIF(t.message, ''), t.event_kind, '')",
            "entity_expr": "TRIM(COALESCE(t.entity, '') || ' ' || COALESCE(t.hostname, '') || ' ' || COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, ''))",
            "class_expr": "COALESCE(t.event_category, '')",
            "evidence_expr": "'normalized'",
            "evidence_note_expr": "'Normalized SIEM event derived from retained FRITZ!Box evidence rows.'",
            "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
            "rank_penalty": "5.0",
        },
        {
            "table": "siem_correlations",
            "fts_type": "siem_correlations",
            "record_label": "Correlation",
            "observation_type": "siem_correlation",
            "time_expr": "COALESCE(t.last_seen, t.first_seen, '')",
            "title_expr": "COALESCE(NULLIF(t.summary, ''), t.entity_label, t.entity_key, '')",
            "entity_expr": "COALESCE(t.entity_label, t.entity_key, '')",
            "class_expr": "'correlation'",
            "evidence_expr": "'correlated'",
            "evidence_note_expr": "'Correlation derived from normalized FRITZ!Box evidence rows.'",
            "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
            "rank_penalty": "6.0",
        },
        {
            "table": "event_log",
            "fts_type": "event_log",
            "record_label": "Router Log",
            "observation_type": "event_log",
            "time_expr": "COALESCE(t.timestamp, '')",
            "title_expr": "COALESCE(t.message, '')",
            "entity_expr": "TRIM(COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, ''))",
            "class_expr": "COALESCE(t.category, '')",
            "evidence_expr": "COALESCE(t.evidence_level, '')",
            "evidence_note_expr": "COALESCE(t.evidence_note, '')",
            "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
        },
        {
            "table": "wifi_connections",
            "fts_type": "wifi_connections",
            "record_label": "WiFi Connection",
            "observation_type": "wifi_connection",
            "time_expr": "COALESCE(t.derived_connected_at, '')",
            "title_expr": "COALESCE(NULLIF(t.message, ''), t.event, '')",
            "entity_expr": "TRIM(COALESCE(t.hostname, '') || ' ' || COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, ''))",
            "class_expr": "COALESCE(t.derived_time_type, '')",
            "evidence_expr": "COALESCE(t.evidence_level, '')",
            "evidence_note_expr": "COALESCE(t.evidence_note, '')",
            "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
        },
        {
            "table": "hosts",
            "fts_type": "hosts",
            "record_label": "Host",
            "observation_type": "host",
            "time_expr": "COALESCE(t.last_activity, t.last_seen, t.last_connected, t.first_seen, '')",
            "title_expr": "COALESCE(NULLIF(t.hostname, ''), t.friendly_name, t.mac, t.ip, '')",
            "entity_expr": "TRIM(COALESCE(t.hostname, '') || ' ' || COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, ''))",
            "class_expr": "COALESCE(t.interface, '')",
            "evidence_expr": "COALESCE(t.evidence_level, '')",
            "evidence_note_expr": "COALESCE(t.evidence_note, '')",
            "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
        },
        {
            "table": "support_findings",
            "fts_type": "support_findings",
            "record_label": "Support Finding",
            "observation_type": "support_finding",
            "time_expr": "COALESCE(t.observed_at, '')",
            "title_expr": "COALESCE(NULLIF(t.key, ''), t.finding_type, t.section, '')",
            "entity_expr": "COALESCE(t.section, '')",
            "class_expr": "COALESCE(t.finding_type, '')",
            "evidence_expr": "COALESCE(t.evidence_level, '')",
            "evidence_note_expr": "COALESCE(t.evidence_note, '')",
            "match_expr": "COALESCE(NULLIF(t.raw_text, ''), t.searchable, records_fts.content, '')",
            "extra_filter": "1=1",
        },
        {
            "table": "raw_artifacts",
            "fts_type": "raw_artifacts",
            "record_label": "Raw Artifact",
            "observation_type": "raw_artifact",
            "time_expr": "COALESCE(t.created_at, '')",
            "title_expr": "COALESCE(t.name, '')",
            "entity_expr": "COALESCE(t.sha256, '')",
            "class_expr": "'raw'",
            "evidence_expr": "'raw'",
            "evidence_note_expr": "'Raw artifact exposed by FRITZ!Box during this acquisition run.'",
            "match_expr": "COALESCE(t.content, records_fts.content, '')",
            "extra_filter": "1=1",
        },
    ]
    for table, spec in ADDITIONAL_EVIDENCE_TABLES.items():
        columns = [str(column) for column in spec["columns"]]
        title_column = next(
            (
                column
                for column in (
                    "summary",
                    "description",
                    "hostname",
                    "name",
                    "ssid",
                    "metric",
                    "protocol",
                    "node",
                    "external_port",
                )
                if column in columns
            ),
            "record_key",
        )
        entity_columns = [
            column for column in ("hostname", "mac", "ip", "internal_client", "node", "peer") if column in columns
        ]
        entity_expr = (
            "TRIM(" + " || ' ' || ".join(f"COALESCE(t.{column}, '')" for column in entity_columns) + ")"
            if entity_columns
            else "COALESCE(t.record_key, '')"
        )
        time_column = str(spec["time_column"])
        sources.append(
            {
                "table": table,
                "fts_type": str(spec["fts_type"]),
                "record_label": str(spec["record_type"]).replace("_", " ").title(),
                "observation_type": str(spec["record_type"]),
                "time_expr": f"COALESCE(t.{time_column}, '')" if time_column else "''",
                "title_expr": f"COALESCE(t.{title_column}, t.record_key, '')",
                "entity_expr": entity_expr,
                "class_expr": f"'{table}'",
                "evidence_expr": "COALESCE(t.evidence_level, '')",
                "evidence_note_expr": "COALESCE(t.evidence_note, '')",
                "match_expr": "COALESCE(t.searchable, records_fts.content, '')",
                "extra_filter": "1=1",
            }
        )
    return sources


def _all_evidence_records(
    conn: sqlite3.Connection,
    fts_query: str,
    limit: int,
    offset: int,
    sort_by: str,
    sort_dir: str,
    category: str,
    evidence_level: str,
    time_type: str,
    scoped_run_id: int | None,
    start: str,
    end: str,
    kind: str,
    severity: str,
    source_filter: str,
    parser_rule: str,
) -> tuple[list[dict[str, Any]], int]:
    select_parts: list[str] = []
    params: list[Any] = []
    for source in _all_evidence_sources():
        rank_penalty = source.get("rank_penalty", "0.0")
        rank_expr = f"(bm25(records_fts) + {rank_penalty})" if fts_query else "0.0"
        evidence_expr = source["evidence_expr"]
        time_expr = source["time_expr"]
        where = [
            "records_fts.record_type = ?",
            "records_fts.record_id = t.id",
            source["extra_filter"],
        ]
        source_params: list[Any] = [source["fts_type"]]
        if fts_query:
            where.append("records_fts.content MATCH ?")
            source_params.append(fts_query)
        if source["table"] in {"siem_events", "siem_correlations"}:
            if scoped_run_id is not None:
                where.append("t.run_id = ?")
                source_params.append(scoped_run_id)
        else:
            run_sql, run_params = _run_observation_sql(source["observation_type"], scoped_run_id)
            if run_sql:
                where.append(run_sql)
                source_params.extend(run_params)
        if category != "all":
            if source["table"] == "siem_events":
                where.append("COALESCE(NULLIF(t.event_category, ''), 'unknown') = ?")
                source_params.append(category)
            elif source["table"] == "siem_correlations":
                where.append("t.categories_json LIKE ?")
                source_params.append(f"%{category}%")
            elif source["table"] == "event_log":
                where.append("t.category = ?")
                source_params.append(category)
            elif source["table"] == "wifi_connections":
                where.append("1=1" if category == "wifi" else "1=0")
            elif (
                category == "network"
                and source["table"]
                in {
                    "hosts",
                    "mesh_topology_links",
                    "wlan_associations",
                    "wlan_radios",
                    "advertisement_hints",
                    "network_status_snapshots",
                }
            ) or (category == "internet" and source["table"] in {"wan_port_mappings", "network_status_snapshots"}):
                where.append("1=1")
            else:
                where.append("1=0")
        if evidence_level != "all":
            where.append(f"COALESCE({evidence_expr}, '') = ?")
            source_params.append(evidence_level)
        if kind != "all":
            if source["table"] == "siem_events":
                where.append("COALESCE(NULLIF(t.event_kind, ''), 'unknown') = ?")
                source_params.append(kind)
            elif source["table"] == "siem_correlations":
                where.append("(t.rule_id = ? OR t.correlation_type = ?)")
                source_params.extend([kind, kind])
            else:
                where.append("1=0")
        if severity != "all":
            if source["table"] in {"siem_events", "siem_correlations"}:
                where.append("COALESCE(NULLIF(t.severity, ''), 'unknown') = ?")
                source_params.append(severity)
            else:
                where.append("1=0")
        if source_filter != "all":
            if source["table"] == "siem_events":
                where.append("COALESCE(NULLIF(t.source, ''), 'unknown') = ?")
                source_params.append(source_filter)
            else:
                where.append("1=0")
        if parser_rule != "all":
            if source["table"] == "siem_events":
                where.append("COALESCE(NULLIF(json_extract(t.fields_json, '$.parser_rule_id'), ''), 'unparsed') = ?")
                source_params.append(parser_rule)
            else:
                where.append("1=0")
        if time_type != "all":
            if source["table"] == "siem_events":
                if time_type == "exact":
                    where.append("COALESCE(t.confidence, '') IN ('high', 'exact')")
                elif time_type == "derived":
                    where.append("COALESCE(t.confidence, '') NOT IN ('high', 'exact')")
                else:
                    where.append("(COALESCE(t.event_kind, '') = ? OR COALESCE(t.source, '') = ?)")
                    source_params.extend([time_type, time_type])
            elif source["table"] == "event_log":
                where.append("1=1" if time_type == "exact" else "1=0")
            elif source["table"] == "wifi_connections":
                if time_type == "exact":
                    where.append("t.exact_connection_time_available = 1")
                elif time_type == "derived":
                    where.append("t.exact_connection_time_available = 0")
                else:
                    where.append("COALESCE(t.derived_time_type, '') = ?")
                    source_params.append(time_type)
            elif source["table"] == "hosts":
                if time_type == "exact":
                    where.append("COALESCE(t.last_activity_source, '') = 'exact_wifi_connection'")
                elif time_type == "derived":
                    where.append("COALESCE(t.last_activity_source, '') != 'exact_wifi_connection'")
                else:
                    where.append("COALESCE(t.last_activity_source, '') = ?")
                    source_params.append(time_type)
            else:
                where.append("1=0")
        if (start or end) and time_expr == "''":
            where.append("1=0")
        if start and time_expr != "''":
            where.append(f"COALESCE({time_expr}, '') >= ?")
            source_params.append(start)
        if end and time_expr != "''":
            where.append(f"COALESCE({time_expr}, '') <= ?")
            source_params.append(end)
        select_parts.append(f"""
            SELECT
                ? AS record_type,
                ? AS record_label,
                t.id AS record_id,
                {time_expr} AS record_time,
                {source["title_expr"]} AS record_title,
                {source["entity_expr"]} AS record_entity,
                {source["class_expr"]} AS record_class,
                {evidence_expr} AS evidence_level,
                {source["evidence_note_expr"]} AS evidence_note,
                records_fts.content AS content,
                {source["match_expr"]} AS match_text,
                {rank_expr} AS match_rank,
                CASE
                    WHEN {evidence_expr} IN ('raw', 'parsed_from_raw') THEN 0
                    WHEN {evidence_expr} = 'enriched_from_current_host_table' THEN 1
                    WHEN {evidence_expr} = 'inferred' THEN 2
                    ELSE 3
                END AS evidence_weight
            FROM {source["table"]} t
            JOIN records_fts
            WHERE {" AND ".join(where)}
            """)
        params.extend([source["fts_type"], source["record_label"], *source_params])
    union_sql = " UNION ALL ".join(select_parts)
    total = int(conn.execute(f"SELECT COUNT(*) FROM ({union_sql}) all_evidence", params).fetchone()[0])
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    order_map = {
        "record_type": "record_type COLLATE NOCASE",
        "record_id": "record_id",
        "record_time": "record_time",
        "evidence_level": "evidence_level COLLATE NOCASE",
        "rank": "match_rank",
    }
    if fts_query and sort_by not in order_map:
        order = "match_rank ASC, evidence_weight ASC, record_time DESC, record_id DESC"
    elif sort_by in order_map:
        if sort_by == "rank":
            order = f"match_rank {'ASC' if fts_query else direction}, record_time DESC, record_id DESC"
        else:
            order = f"{order_map[sort_by]} {direction}, record_time DESC, record_id DESC"
    else:
        order = "record_time DESC, evidence_weight ASC, record_id DESC"
    rows = [
        dict(row)
        for row in conn.execute(
            f"SELECT * FROM ({union_sql}) all_evidence ORDER BY {order} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
    ]
    for index, row in enumerate(rows, start=offset + 1):
        row["rank_position"] = index
    return rows, total


def query_records(
    path: Path = DEFAULT_DB,
    query: str = "",
    record_type: str = "all",
    limit: int = 200,
    offset: int = 0,
    category: str = "all",
    sort_by: str = "",
    sort_dir: str = "desc",
    evidence_level: str = "all",
    time_type: str = "all",
    run_id: str | int = "latest",
    start: str = "",
    end: str = "",
    kind: str = "all",
    severity: str = "all",
    source: str = "all",
    parser_rule: str = "all",
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    fts_query = make_fts_query(query)
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    table: str | None = None
    fts_type: str | None = None
    dedupe = "1=1"
    order = "t.id DESC"
    if record_type in {"events", "siem", "siem_events", "normalized_events"}:
        table = "siem_events"
        sort_map = {
            "event_time": "COALESCE(t.event_time, '')",
            "timestamp": "COALESCE(t.event_time, '')",
            "event_category": "COALESCE(t.event_category, '')",
            "category": "COALESCE(t.event_category, '')",
            "event_kind": "COALESCE(t.event_kind, '')",
            "kind": "COALESCE(t.event_kind, '')",
            "severity": (
                "CASE t.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
            ),
            "entity": "COALESCE(t.entity, '')",
            "hostname": "COALESCE(t.hostname, '')",
            "mac": "COALESCE(t.mac, '')",
            "ip": "COALESCE(t.ip, '')",
            "source": "COALESCE(t.source, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['event_time'])} {direction}"
        fts_type = "siem_events"
        dedupe = "1=1"
    elif record_type in {"correlations", "siem_correlations"}:
        table = "siem_correlations"
        sort_map = {
            "entity": "COALESCE(t.entity_label, '')",
            "entity_label": "COALESCE(t.entity_label, '')",
            "first_seen": "COALESCE(t.first_seen, '')",
            "last_seen": "COALESCE(t.last_seen, '')",
            "event_count": "t.event_count",
            "severity": (
                "CASE t.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
            ),
        }
        order = f"{sort_map.get(sort_by, sort_map['last_seen'])} {direction}"
        fts_type = "siem_correlations"
        dedupe = "1=1"
    elif record_type == "wifi":
        table = "wifi_connections"
        sort_map = {
            "derived_connected_at": "COALESCE(t.derived_connected_at, '')",
            "type": "COALESCE(t.derived_time_type, '')",
            "hostname": "COALESCE(t.hostname, '')",
            "mac": "COALESCE(t.mac, '')",
            "ip": "COALESCE(t.ip, '')",
            "exact": "t.exact_connection_time_available",
            "source": "COALESCE(t.source, '')",
            "evidence": "COALESCE(t.evidence, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['derived_connected_at'])} {direction}"
        fts_type = "wifi_connections"
        dedupe = "1=1" if scoped_run_id is not None else "t." + WIFI_DEDUPE_SQL.strip()
    elif record_type in ("hosts", "presence"):
        table = "hosts"
        sort_map = {
            "hostname": "COALESCE(t.hostname, '')",
            "mac": "COALESCE(t.mac, '')",
            "ip": "COALESCE(t.ip, '')",
            "interface": "COALESCE(t.interface, '')",
            "active_now": "t.active_now",
            "first_seen": "COALESCE(t.first_seen, '')",
            "last_seen": "COALESCE(t.last_seen, '')",
            "last_connected": "COALESCE(t.last_connected, '')",
            "last_activity": "COALESCE(t.last_activity, t.last_seen, t.last_connected, '')",
            "presence_source": "COALESCE(t.last_activity_source, '')",
            "presence_confidence": "COALESCE(t.last_activity_confidence, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['last_activity'])} {direction}"
        fts_type = "hosts"
        dedupe = "1=1"
    elif record_type == "log":
        table = "event_log"
        sort_map = {
            "timestamp": "COALESCE(t.timestamp, '')",
            "category": "COALESCE(t.category, '')",
            "mac": "COALESCE(t.mac, '')",
            "ip": "COALESCE(t.ip, '')",
            "source": "COALESCE(t.source, '')",
            "message": "COALESCE(t.message, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['timestamp'])} {direction}"
        fts_type = "event_log"
        dedupe = "1=1"
    elif record_type == "support":
        table = "support_findings"
        sort_map = {
            "line_number": "COALESCE(t.line_number, 0)",
            "finding_type": "COALESCE(t.finding_type, '')",
            "section": "COALESCE(t.section, '')",
            "key": "COALESCE(t.key, '')",
            "value": "COALESCE(t.value, '')",
            "observed_at": "COALESCE(t.observed_at, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['line_number'])} {direction}"
        fts_type = "support_findings"
        dedupe = "1=1"
    elif record_type in ADDITIONAL_RECORD_TYPE_ALIASES:
        table = ADDITIONAL_RECORD_TYPE_ALIASES[record_type]
        spec = ADDITIONAL_EVIDENCE_TABLES[table]
        sort_map = {column: f"COALESCE(t.{column}, '')" for column in spec["columns"]}
        sort_map["record_key"] = "COALESCE(t.record_key, '')"
        if table == "security_advisories":
            sort_map["severity"] = (
                "CASE t.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
            )
        order = f"{sort_map.get(sort_by, spec['sort'])} {direction}"
        fts_type = spec["fts_type"]
        dedupe = "1=1"
    elif record_type == "raw":
        table = "raw_artifacts"
        sort_map = {
            "created_at": "COALESCE(t.created_at, '')",
            "name": "COALESCE(t.name, '')",
            "sha256": "COALESCE(t.sha256, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['created_at'])} {direction}"
        fts_type = "raw_artifacts"
        dedupe = "1=1"
    else:
        table = None
        fts_type = None

    if table:
        params: list[Any] = []
        where: list[str] = [dedupe]
        join = ""
        observation_type = {
            "event_log": "event_log",
            "wifi_connections": "wifi_connection",
            "hosts": "host",
            "support_findings": "support_finding",
            "raw_artifacts": "raw_artifact",
            **{table_name: spec["record_type"] for table_name, spec in ADDITIONAL_EVIDENCE_TABLES.items()},
        }.get(table)
        if fts_query:
            join = " JOIN records_fts f ON f.record_id = t.id AND f.record_type = ?"
            params.append(fts_type)
            where.append("f.content MATCH ?")
            params.append(fts_query)
        if table in {"siem_events", "siem_correlations"}:
            if scoped_run_id is not None:
                where.append("t.run_id = ?")
                params.append(scoped_run_id)
        elif observation_type:
            run_sql, run_params = _run_observation_sql(observation_type, scoped_run_id)
            if run_sql:
                where.append(run_sql)
                params.extend(run_params)
        if table == "siem_events" and category != "all":
            where.append("COALESCE(NULLIF(t.event_category, ''), 'unknown') = ?")
            params.append(category)
        elif table == "siem_correlations" and category != "all":
            where.append("t.categories_json LIKE ?")
            params.append(f"%{category}%")
        elif table == "event_log" and category != "all":
            where.append("t.category = ?")
            params.append(category)
        if table == "siem_events":
            if kind != "all":
                where.append("COALESCE(NULLIF(t.event_kind, ''), 'unknown') = ?")
                params.append(kind)
            if severity != "all":
                where.append("COALESCE(NULLIF(t.severity, ''), 'unknown') = ?")
                params.append(severity)
            if source != "all":
                where.append("COALESCE(NULLIF(t.source, ''), 'unknown') = ?")
                params.append(source)
            if parser_rule != "all":
                where.append("COALESCE(NULLIF(json_extract(t.fields_json, '$.parser_rule_id'), ''), 'unparsed') = ?")
                params.append(parser_rule)
        elif table == "siem_correlations":
            if kind != "all":
                where.append("(t.rule_id = ? OR t.correlation_type = ?)")
                params.extend([kind, kind])
            if severity != "all":
                where.append("t.severity = ?")
                params.append(severity)
        time_column = ""
        host_time_columns: list[str] = []
        if table == "event_log":
            time_column = "timestamp"
        elif table == "siem_events":
            time_column = "event_time"
        elif table == "siem_correlations":
            time_column = ""
        elif table == "wifi_connections":
            time_column = "derived_connected_at"
        elif table == "support_findings":
            time_column = "observed_at"
        elif table == "raw_artifacts":
            time_column = "created_at"
        elif table == "hosts":
            active_run_filter = f" AND run_id = {scoped_run_id}" if scoped_run_id is not None else ""
            host_time_columns = [
                "t.last_activity",
                "t.last_seen",
                "t.last_connected",
                "t.first_seen",
                f"""CASE WHEN t.active_now = 1 THEN (
                    SELECT MAX(COALESCE(event_time, observed_at))
                    FROM record_observations
                    WHERE record_type = 'host' AND record_table_id = t.id
                    {active_run_filter}
                ) END""",
            ]
        elif table in ADDITIONAL_EVIDENCE_TABLES:
            time_column = str(ADDITIONAL_EVIDENCE_TABLES[table]["time_column"])
        if table == "siem_correlations" and (start or end):
            window_start = "COALESCE(t.window_start, t.first_seen, t.last_seen, '')"
            window_end = "COALESCE(t.window_end, t.last_seen, t.first_seen, '')"
            if start:
                where.append(f"{window_end} >= ?")
                params.append(start)
            if end:
                where.append(f"{window_start} <= ?")
                params.append(end)
        elif table == "hosts" and (start or end):
            range_clauses = []
            for column in host_time_columns:
                column_checks = []
                if start:
                    column_checks.append(f"COALESCE({column}, '') >= ?")
                    params.append(start)
                if end:
                    column_checks.append(f"COALESCE({column}, '') <= ?")
                    params.append(end)
                range_clauses.append("(" + " AND ".join(column_checks) + ")")
            where.append("(" + " OR ".join(range_clauses) + ")")
        else:
            if start and time_column:
                where.append(f"COALESCE(t.{time_column}, '') >= ?")
                params.append(start)
            if end and time_column:
                where.append(f"COALESCE(t.{time_column}, '') <= ?")
                params.append(end)
        if table == "raw_artifacts" or table == "siem_correlations":
            pass
        elif evidence_level != "all":
            where.append("COALESCE(t.evidence_level, '') = ?")
            params.append(evidence_level)
        if table == "raw_artifacts":
            pass
        elif time_type != "all":
            if table == "event_log":
                where.append("1=1" if time_type == "exact" else "1=0")
            elif table == "siem_events":
                if time_type == "exact":
                    where.append("COALESCE(t.confidence, '') IN ('high', 'exact')")
                elif time_type == "derived":
                    where.append("COALESCE(t.confidence, '') NOT IN ('high', 'exact')")
                else:
                    where.append("(COALESCE(t.event_kind, '') = ? OR COALESCE(t.source, '') = ?)")
                    params.extend([time_type, time_type])
            elif table == "wifi_connections":
                if time_type == "exact":
                    where.append("t.exact_connection_time_available = 1")
                elif time_type == "derived":
                    where.append("t.exact_connection_time_available = 0")
                else:
                    where.append("COALESCE(t.derived_time_type, '') = ?")
                    params.append(time_type)
        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        count_sql = f"SELECT COUNT(*) FROM {table} t{join}{where_sql}"
        total = int(conn.execute(count_sql, params).fetchone()[0])
        sql = f"SELECT t.* FROM {table} t{join}{where_sql} ORDER BY {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = [dict(row) for row in conn.execute(sql, params)]
        if table == "hosts":
            enrich_host_activity(conn, rows, scoped_run_id)
        if table == "siem_correlations":
            enrich_alert_states(conn, rows)
    else:
        rows, total = _all_evidence_records(
            conn,
            fts_query,
            limit,
            offset,
            sort_by,
            sort_dir,
            category,
            evidence_level,
            time_type,
            scoped_run_id,
            start,
            end,
            kind,
            severity,
            source,
            parser_rule,
        )
    conn.close()
    return {"rows": rows, "total": total, "limit": limit, "offset": offset}


def enrich_alert_states(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        if row.get("correlation_type") != "alert":
            continue
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
        row["alert_status"] = state["status"] if state else "open"
        row["resolved_at"] = state["resolved_at"] if state else ""
        row["resolved_by"] = state["resolved_by"] if state else ""
        row["resolution_note"] = state["note"] if state else ""


def query_timeline(
    path: Path = DEFAULT_DB,
    query: str = "",
    category: str = "all",
    start: str = "",
    end: str = "",
    limit: int = 200,
    offset: int = 0,
    evidence_level: str = "all",
    time_type: str = "all",
    run_id: str | int = "latest",
    kind: str = "all",
    severity: str = "all",
    source: str = "all",
    parser_rule: str = "all",
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    fts_query = make_fts_query(query)
    siem_count_sql = "SELECT COUNT(*) FROM siem_events"
    siem_count_params: list[Any] = []
    if scoped_run_id is not None:
        siem_count_sql += " WHERE run_id = ?"
        siem_count_params.append(scoped_run_id)
    if int(conn.execute(siem_count_sql, siem_count_params).fetchone()[0]):
        result = _query_siem_timeline(
            conn,
            fts_query,
            category,
            start,
            end,
            limit,
            offset,
            evidence_level,
            time_type,
            scoped_run_id,
            kind,
            severity,
            source,
            parser_rule,
        )
        conn.close()
        return result
    rows: list[dict[str, Any]] = []
    event_where, event_params = _timeline_filters(
        "event_log", fts_query, category, start, end, evidence_level, time_type, scoped_run_id
    )
    wifi_where, wifi_params = _timeline_filters(
        "wifi_connections", fts_query, category, start, end, evidence_level, time_type, scoped_run_id
    )

    event_total = int(conn.execute(f"SELECT COUNT(*) FROM event_log t{event_where}", event_params).fetchone()[0])
    wifi_total = int(conn.execute(f"SELECT COUNT(*) FROM wifi_connections t{wifi_where}", wifi_params).fetchone()[0])

    sql = f"""
        SELECT * FROM (
            SELECT 'event_log' AS record_type, t.id AS record_id, t.timestamp AS event_time,
                   t.category AS event_class, t.ip, t.mac, NULL AS hostname, t.message, t.source,
                   'exact' AS time_type, 'high' AS confidence, t.evidence_level, t.evidence_note, 1 AS exact_time
            FROM event_log t{event_where}
            UNION ALL
            SELECT 'wifi_connections' AS record_type, t.id AS record_id, t.derived_connected_at AS event_time,
                   'wifi' AS event_class, t.ip, t.mac, t.hostname,
                   COALESCE(t.message, t.event, 'Known WLAN device') AS message,
                   t.source,
                   COALESCE(t.derived_time_type, 'derived') AS time_type,
                   COALESCE(t.derived_time_confidence, t.evidence, 'low') AS confidence,
                   t.evidence_level, t.evidence_note,
                   t.exact_connection_time_available AS exact_time
            FROM wifi_connections t{wifi_where}
        )
        ORDER BY COALESCE(event_time, '') DESC
        LIMIT ? OFFSET ?
    """
    rows = [dict(row) for row in conn.execute(sql, [*event_params, *wifi_params, limit, offset])]
    conn.close()
    return {"rows": rows, "total": event_total + wifi_total, "limit": limit, "offset": offset}


def _query_siem_timeline(
    conn: sqlite3.Connection,
    fts_query: str,
    category: str,
    start: str,
    end: str,
    limit: int,
    offset: int,
    evidence_level: str,
    time_type: str,
    run_id: int | None,
    kind: str,
    severity: str,
    source: str,
    parser_rule: str,
) -> dict[str, Any]:
    where, params, join = _siem_event_search_sql(
        fts_query,
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
    where.append("COALESCE(t.event_time, '') != ''")
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM siem_events t{join}{where_sql}", params).fetchone()[0])
    sql = f"""
        SELECT
            'siem_events' AS record_type,
            t.id AS record_id,
            t.event_time,
            t.event_category AS event_class,
            t.ip,
            t.mac,
            t.hostname,
            t.message,
            t.source,
            CASE WHEN COALESCE(t.confidence, '') IN ('high', 'exact') THEN 'exact' ELSE 'derived' END AS time_type,
            t.confidence,
            t.evidence_level,
            t.evidence_note,
            CASE WHEN COALESCE(t.confidence, '') IN ('high', 'exact') THEN 1 ELSE 0 END AS exact_time
        FROM siem_events t{join}{where_sql}
        ORDER BY COALESCE(t.event_time, '') DESC, t.id DESC
        LIMIT ? OFFSET ?
    """
    rows = [dict(row) for row in conn.execute(sql, [*params, limit, offset])]
    return {"rows": rows, "total": total, "limit": limit, "offset": offset}


def _siem_event_search_sql(
    fts_query: str,
    category: str,
    start: str,
    end: str,
    evidence_level: str,
    time_type: str,
    run_id: int | None,
    kind: str,
    severity: str,
    source: str,
    parser_rule: str,
) -> tuple[list[str], list[Any], str]:
    params: list[Any] = []
    where: list[str] = []
    join = ""
    if fts_query:
        join = " JOIN records_fts f ON f.record_id = t.id AND f.record_type = ?"
        params.append("siem_events")
        where.append("f.content MATCH ?")
        params.append(fts_query)
    if run_id is not None:
        where.append("t.run_id = ?")
        params.append(run_id)
    if category != "all":
        where.append("COALESCE(NULLIF(t.event_category, ''), 'unknown') = ?")
        params.append(category)
    if kind != "all":
        where.append("COALESCE(NULLIF(t.event_kind, ''), 'unknown') = ?")
        params.append(kind)
    if severity != "all":
        where.append("COALESCE(NULLIF(t.severity, ''), 'unknown') = ?")
        params.append(severity)
    if source != "all":
        where.append("COALESCE(NULLIF(t.source, ''), 'unknown') = ?")
        params.append(source)
    if parser_rule != "all":
        where.append("COALESCE(NULLIF(json_extract(t.fields_json, '$.parser_rule_id'), ''), 'unparsed') = ?")
        params.append(parser_rule)
    if evidence_level != "all":
        where.append("COALESCE(t.evidence_level, '') = ?")
        params.append(evidence_level)
    if time_type != "all":
        if time_type == "exact":
            where.append("COALESCE(t.confidence, '') IN ('high', 'exact')")
        elif time_type == "derived":
            where.append("COALESCE(t.confidence, '') NOT IN ('high', 'exact')")
        else:
            where.append("(COALESCE(t.event_kind, '') = ? OR COALESCE(t.source, '') = ?)")
            params.extend([time_type, time_type])
    if start:
        where.append("COALESCE(t.event_time, '') >= ?")
        params.append(start)
    if end:
        where.append("COALESCE(t.event_time, '') <= ?")
        params.append(end)
    return where, params, join


def siem_search_facets(
    path: Path = DEFAULT_DB,
    query: str = "",
    category: str = "all",
    start: str = "",
    end: str = "",
    evidence_level: str = "all",
    time_type: str = "all",
    run_id: str | int = "latest",
    kind: str = "all",
    severity: str = "all",
    source: str = "all",
    parser_rule: str = "all",
    limit: int = 12,
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    where, params, join = _siem_event_search_sql(
        make_fts_query(query),
        category,
        start,
        end,
        evidence_level,
        time_type,
        scoped_run_id,
        kind,
        severity,
        source,
        parser_rule,
    )
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM siem_events t{join}{where_sql}", params).fetchone()[0])

    facet_specs = {
        "category": "COALESCE(NULLIF(t.event_category, ''), 'unknown')",
        "kind": "COALESCE(NULLIF(t.event_kind, ''), 'unknown')",
        "severity": "COALESCE(NULLIF(t.severity, ''), 'unknown')",
        "source": "COALESCE(NULLIF(t.source, ''), 'unknown')",
        "parser_rule": "COALESCE(NULLIF(json_extract(t.fields_json, '$.parser_rule_id'), ''), 'unparsed')",
        "entity": "COALESCE(NULLIF(t.entity, ''), 'unknown')",
    }
    facets: dict[str, list[dict[str, Any]]] = {}
    for name, expression in facet_specs.items():
        sql = f"""
            SELECT {expression} AS value, COUNT(*) AS count
            FROM siem_events t{join}{where_sql}
            GROUP BY value
            ORDER BY count DESC, value COLLATE NOCASE ASC
            LIMIT ?
        """
        facets[name] = [dict(row) for row in conn.execute(sql, [*params, limit])]
    conn.close()
    return {"total": total, "facets": facets}


def _timeline_filters(
    table: str,
    fts_query: str,
    category: str,
    start: str,
    end: str,
    evidence_level: str = "all",
    time_type: str = "all",
    run_id: int | None = None,
) -> tuple[str, list[Any]]:
    params: list[Any] = []
    where: list[str] = []
    time_column = "timestamp" if table == "event_log" else "derived_connected_at"
    observation_type = "event_log" if table == "event_log" else "wifi_connection"
    run_sql, run_params = _run_observation_sql(observation_type, run_id)
    if run_sql:
        where.append(run_sql)
        params.extend(run_params)
    if fts_query:
        where.append("t.id IN (SELECT record_id FROM records_fts WHERE record_type = ? AND content MATCH ?)")
        params.extend([table, fts_query])
    if table == "event_log" and category != "all":
        where.append("t.category = ?")
        params.append(category)
    elif table == "wifi_connections" and category not in ("all", "wifi"):
        where.append("1=0")
    if evidence_level != "all":
        where.append("COALESCE(t.evidence_level, '') = ?")
        params.append(evidence_level)
    if time_type != "all":
        if table == "event_log":
            where.append("1=1" if time_type == "exact" else "1=0")
        elif table == "wifi_connections":
            if time_type == "exact":
                where.append("t.exact_connection_time_available = 1")
            elif time_type == "derived":
                where.append("t.exact_connection_time_available = 0")
            else:
                where.append("COALESCE(t.derived_time_type, '') = ?")
                params.append(time_type)
    if table == "wifi_connections" and run_id is None:
        where.append("t." + WIFI_DEDUPE_SQL.strip())
    if start:
        where.append(f"COALESCE(t.{time_column}, '') >= ?")
        params.append(start)
    if end:
        where.append(f"COALESCE(t.{time_column}, '') <= ?")
        params.append(end)
    return (f" WHERE {' AND '.join(where)}" if where else "", params)
