from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import re
import subprocess
from typing import Any


DEFAULT_DB = Path(os.getenv("FRITZBOX_ANALYSIS_DB", "fritzbox-analysis.sqlite3"))
WIFI_DEDUPE_SQL = """
    id IN (
        SELECT MAX(id) FROM wifi_connections
        GROUP BY COALESCE(derived_connected_at, ''), COALESCE(event, ''), COALESCE(hostname, ''),
                 COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(source, '')
    )
"""


def init_db(path: Path = DEFAULT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS export_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TEXT NOT NULL,
            router_address TEXT,
            window_hours INTEGER,
            summary_json TEXT NOT NULL,
            acquired_at TEXT,
            collector_time TEXT,
            tool_version TEXT,
            tool_git_commit TEXT,
            acquisition_mode TEXT,
            router_metadata_json TEXT,
            timestamp_assumptions_json TEXT,
            contamination_json TEXT,
            source_endpoints_json TEXT
        );

        CREATE TABLE IF NOT EXISTS raw_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(name, sha256),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            timestamp TEXT,
            category TEXT,
            mac TEXT,
            ip TEXT,
            message TEXT NOT NULL,
            evidence_level TEXT NOT NULL DEFAULT 'parsed_from_raw',
            evidence_note TEXT,
            searchable TEXT NOT NULL,
            UNIQUE(timestamp, message),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS wifi_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            derived_connected_at TEXT,
            derived_time_type TEXT,
            derived_time_confidence TEXT,
            exact_connection_time_available INTEGER NOT NULL,
            event TEXT,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            source TEXT,
            evidence TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'inferred',
            evidence_note TEXT,
            message TEXT,
            searchable TEXT NOT NULL,
            UNIQUE(derived_connected_at, event, hostname, mac, source),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            hostname TEXT,
            mac TEXT,
            ip TEXT,
            interface TEXT,
            active_now INTEGER NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            last_connected TEXT,
            evidence_level TEXT NOT NULL DEFAULT 'enriched_from_current_host_table',
            evidence_note TEXT,
            raw_json TEXT NOT NULL,
            searchable TEXT NOT NULL,
            UNIQUE(hostname, mac, ip),
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            record_type,
            record_id UNINDEXED,
            content
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS record_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            record_key TEXT NOT NULL,
            record_table_id INTEGER,
            observed_at TEXT NOT NULL,
            event_time TEXT,
            evidence_level TEXT NOT NULL,
            evidence_note TEXT,
            source TEXT,
            content_sha256 TEXT NOT NULL,
            content_json TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES export_runs(id)
        );
        """
    )
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    ensure_columns(
        conn,
        "export_runs",
        {
            "acquired_at": "TEXT",
            "collector_time": "TEXT",
            "tool_version": "TEXT",
            "tool_git_commit": "TEXT",
            "acquisition_mode": "TEXT",
            "router_metadata_json": "TEXT",
            "timestamp_assumptions_json": "TEXT",
            "contamination_json": "TEXT",
            "source_endpoints_json": "TEXT",
        },
    )
    ensure_columns(conn, "event_log", {"evidence_level": "TEXT NOT NULL DEFAULT 'parsed_from_raw'", "evidence_note": "TEXT"})
    ensure_columns(conn, "wifi_connections", {"evidence_level": "TEXT NOT NULL DEFAULT 'inferred'", "evidence_note": "TEXT"})
    ensure_columns(
        conn,
        "hosts",
        {"evidence_level": "TEXT NOT NULL DEFAULT 'enriched_from_current_host_table'", "evidence_note": "TEXT"},
    )
    conn.execute(
        """
        UPDATE event_log
        SET evidence_note = 'Parsed from retained FRITZ!Box device log. The timestamp is exact for the retained log entry, not proof of full historical activity.'
        WHERE evidence_note IS NULL
        """
    )
    conn.execute(
        """
        UPDATE wifi_connections
        SET evidence_note = CASE
            WHEN exact_connection_time_available = 1 THEN 'Exact WiFi connection event parsed from a retained FRITZ!Box log entry.'
            WHEN derived_time_type = 'mesh_last_observed' THEN 'Known/current WLAN device observation from mesh data. This is not an exact WiFi association time.'
            ELSE 'Derived WiFi-related row. Treat as contextual unless backed by a retained exact connection log entry.'
        END
        WHERE evidence_note IS NULL
        """
    )
    conn.execute(
        """
        UPDATE hosts
        SET evidence_note = 'Host context from the FRITZ!Box host table at acquisition time; IP/name mappings may be stale or reassigned.'
        WHERE evidence_note IS NULL
        """
    )
    conn.commit()


def ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


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
        run_id = int(cursor.lastrowid)

        for name, content in (dataset.get("raw_exports") or {}).items():
            if not isinstance(content, str):
                content = json.dumps(content, sort_keys=True)
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT OR IGNORE INTO raw_artifacts(run_id, name, sha256, content, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, name, digest, content, generated_at),
            )
            add_observation(
                conn,
                run_id=run_id,
                record_type="raw_artifact",
                record_key=f"{name}:{digest}",
                record_table_id=None,
                observed_at=acquired_at,
                event_time=generated_at,
                evidence_level="raw",
                evidence_note="Raw artifact exposed by FRITZ!Box during this acquisition run.",
                source=name,
                content={"name": name, "sha256": digest, "content": content},
            )

        for event in dataset.get("event_log") or []:
            searchable = searchable_text(event)
            evidence_level, evidence_note = event_evidence(event)
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO event_log(
                    run_id, timestamp, category, mac, ip, message, evidence_level, evidence_note, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    event.get("timestamp"),
                    event.get("category"),
                    event.get("mac"),
                    event.get("ip"),
                    event.get("message") or "",
                    evidence_level,
                    evidence_note,
                    searchable,
                ),
            )
            row_id = cursor.lastrowid
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
                source="device_log_xml",
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
            row_id = cursor.lastrowid
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
                    run_id, hostname, mac, ip, interface, active_now, first_seen, last_seen,
                    last_connected, evidence_level, evidence_note, raw_json, searchable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    host.get("hostname"),
                    host.get("mac"),
                    host.get("ip"),
                    host.get("interface"),
                    1 if host.get("active_now") else 0,
                    host.get("first_seen"),
                    host.get("last_seen"),
                    host.get("last_connected"),
                    evidence_level,
                    evidence_note,
                    json.dumps(host, sort_keys=True),
                    searchable,
                ),
            )
            row_id = cursor.lastrowid
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
                event_time=host.get("last_seen") or host.get("first_seen"),
                evidence_level=evidence_level,
                evidence_note=evidence_note,
                source="Hosts:GetGenericHostEntry",
                content=host,
            )
    conn.close()
    return run_id


def acquisition_metadata(dataset: dict[str, Any], acquired_at: str) -> dict[str, Any]:
    router = dataset.get("router") or {}
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
            "collector_timezone": datetime.now().astimezone().tzinfo.tzname(None) if datetime.now().astimezone().tzinfo else None,
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
            "avm_exports": ["device_log_xml", "mesh_list", "host_list_xml", "wlan_device_list_xml"],
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


def event_evidence(event: dict[str, Any]) -> tuple[str, str]:
    return (
        "parsed_from_raw",
        "Parsed from retained FRITZ!Box device log. The timestamp is exact for the retained log entry, not proof of full historical activity.",
    )


def wifi_evidence(row: dict[str, Any]) -> tuple[str, str]:
    if row.get("exact_connection_time_available"):
        return (
            "parsed_from_raw",
            "Exact WiFi connection event parsed from a retained FRITZ!Box log entry.",
        )
    if row.get("derived_time_type") == "mesh_last_observed":
        return (
            "inferred",
            "Known/current WLAN device observation from mesh data. This is not an exact WiFi association time.",
        )
    return (
        "inferred",
        "Derived WiFi-related row. Treat as contextual unless backed by a retained exact connection log entry.",
    )


def host_evidence(host: dict[str, Any]) -> tuple[str, str]:
    return (
        "enriched_from_current_host_table",
        "Host context from the FRITZ!Box host table at acquisition time; IP/name mappings may be stale or reassigned.",
    )


def event_key(event: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            {"timestamp": event.get("timestamp"), "message": event.get("message")},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def wifi_key(row: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "derived_connected_at": row.get("derived_connected_at") or row.get("timestamp"),
                "event": row.get("event"),
                "hostname": row.get("hostname"),
                "mac": row.get("mac"),
                "ip": row.get("ip"),
                "source": row.get("source"),
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def host_key(host: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            {"hostname": host.get("hostname"), "mac": host.get("mac"), "ip": host.get("ip")},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def lookup_event_id(conn: sqlite3.Connection, event: dict[str, Any]) -> int | None:
    row = conn.execute(
        "SELECT id FROM event_log WHERE timestamp IS ? AND message = ?",
        (event.get("timestamp"), event.get("message") or ""),
    ).fetchone()
    return int(row["id"]) if row else None


def lookup_wifi_id(conn: sqlite3.Connection, row: dict[str, Any]) -> int | None:
    found = conn.execute(
        """
        SELECT id FROM wifi_connections
        WHERE COALESCE(derived_connected_at, '') = COALESCE(?, '')
          AND COALESCE(event, '') = COALESCE(?, '')
          AND COALESCE(hostname, '') = COALESCE(?, '')
          AND COALESCE(mac, '') = COALESCE(?, '')
          AND COALESCE(source, '') = COALESCE(?, '')
        """,
        (
            row.get("derived_connected_at") or row.get("timestamp"),
            row.get("event"),
            row.get("hostname"),
            row.get("mac"),
            row.get("source"),
        ),
    ).fetchone()
    return int(found["id"]) if found else None


def lookup_host_id(conn: sqlite3.Connection, host: dict[str, Any]) -> int | None:
    row = conn.execute(
        """
        SELECT id FROM hosts
        WHERE COALESCE(hostname, '') = COALESCE(?, '')
          AND COALESCE(mac, '') = COALESCE(?, '')
          AND COALESCE(ip, '') = COALESCE(?, '')
        """,
        (host.get("hostname"), host.get("mac"), host.get("ip")),
    ).fetchone()
    return int(row["id"]) if row else None


def add_fts(conn: sqlite3.Connection, record_type: str, record_id: int, content: str) -> None:
    conn.execute(
        "INSERT INTO records_fts(record_type, record_id, content) VALUES (?, ?, ?)",
        (record_type, record_id, content),
    )


def searchable_text(row: dict[str, Any]) -> str:
    values: list[str] = []
    for value in row.values():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            values.append(json.dumps(value, sort_keys=True))
        else:
            values.append(str(value))
    return " ".join(values)


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
) -> dict[str, Any]:
    conn = init_db(path)
    fts_query = make_fts_query(query)
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    if record_type == "wifi":
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
        dedupe = "t." + WIFI_DEDUPE_SQL.strip()
    elif record_type == "hosts":
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
        }
        order = f"{sort_map.get(sort_by, sort_map['last_seen'])} {direction}"
        fts_type = "hosts"
        dedupe = "1=1"
    elif record_type == "log":
        table = "event_log"
        sort_map = {
            "timestamp": "COALESCE(t.timestamp, '')",
            "category": "COALESCE(t.category, '')",
            "mac": "COALESCE(t.mac, '')",
            "ip": "COALESCE(t.ip, '')",
            "message": "COALESCE(t.message, '')",
        }
        order = f"{sort_map.get(sort_by, sort_map['timestamp'])} {direction}"
        fts_type = "event_log"
        dedupe = "1=1"
    else:
        table = None
        fts_type = None

    if table:
        params: list[Any] = []
        where: list[str] = [dedupe]
        join = ""
        if fts_query:
            join = " JOIN records_fts f ON f.record_id = t.id AND f.record_type = ?"
            params.append(fts_type)
            where.append("f.content MATCH ?")
            params.append(fts_query)
        if table == "event_log" and category != "all":
            where.append("t.category = ?")
            params.append(category)
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
        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        count_sql = f"SELECT COUNT(*) FROM {table} t{join}{where_sql}"
        total = int(conn.execute(count_sql, params).fetchone()[0])
        sql = f"SELECT t.* FROM {table} t{join}{where_sql} ORDER BY {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = [dict(row) for row in conn.execute(sql, params)]
    else:
        if fts_query:
            where = " WHERE content MATCH ?"
            params = [fts_query]
        else:
            where = ""
            params = []
        total = int(conn.execute(f"SELECT COUNT(*) FROM records_fts{where}", params).fetchone()[0])
        rows = [
            dict(row)
            for row in conn.execute(
                f"SELECT record_type, record_id, content FROM records_fts{where} LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        ]
    conn.close()
    return {"rows": rows, "total": total, "limit": limit, "offset": offset}


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
) -> dict[str, Any]:
    conn = init_db(path)
    fts_query = make_fts_query(query)
    rows: list[dict[str, Any]] = []
    event_where, event_params = _timeline_filters("event_log", fts_query, category, start, end, evidence_level, time_type)
    wifi_where, wifi_params = _timeline_filters(
        "wifi_connections", fts_query, category, start, end, evidence_level, time_type
    )

    event_total = int(conn.execute(f"SELECT COUNT(*) FROM event_log t{event_where}", event_params).fetchone()[0])
    wifi_total = int(conn.execute(f"SELECT COUNT(*) FROM wifi_connections t{wifi_where}", wifi_params).fetchone()[0])

    sql = f"""
        SELECT * FROM (
            SELECT 'event_log' AS record_type, t.id AS record_id, t.timestamp AS event_time,
                   t.category AS event_class, t.ip, t.mac, NULL AS hostname, t.message,
                   'exact' AS time_type, 'high' AS confidence, t.evidence_level, t.evidence_note, 1 AS exact_time
            FROM event_log t{event_where}
            UNION ALL
            SELECT 'wifi_connections' AS record_type, t.id AS record_id, t.derived_connected_at AS event_time,
                   'wifi' AS event_class, t.ip, t.mac, t.hostname,
                   COALESCE(t.message, t.event, 'Known WLAN device') AS message,
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


def _timeline_filters(
    table: str,
    fts_query: str,
    category: str,
    start: str,
    end: str,
    evidence_level: str = "all",
    time_type: str = "all",
) -> tuple[str, list[Any]]:
    params: list[Any] = []
    where: list[str] = []
    time_column = "timestamp" if table == "event_log" else "derived_connected_at"
    if fts_query:
        where.append(
            "t.id IN (SELECT record_id FROM records_fts WHERE record_type = ? AND content MATCH ?)"
        )
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
    if table == "wifi_connections":
        where.append("t." + WIFI_DEDUPE_SQL.strip())
    if start:
        where.append(f"COALESCE(t.{time_column}, '') >= ?")
        params.append(start)
    if end:
        where.append(f"COALESCE(t.{time_column}, '') <= ?")
        params.append(end)
    return (f" WHERE {' AND '.join(where)}" if where else "", params)


def _decode_json(value: Any) -> Any:
    if value in (None, ""):
        return None
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return value


def latest_snapshot(path: Path = DEFAULT_DB) -> dict[str, Any]:
    conn = init_db(path)
    latest_run = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    retained = dict(
        conn.execute(
            "SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event, COUNT(*) AS event_count FROM event_log"
        ).fetchone()
    )
    counts = {
        "runs": int(conn.execute("SELECT COUNT(*) FROM export_runs").fetchone()[0]),
        "raw_artifacts": int(conn.execute("SELECT COUNT(*) FROM raw_artifacts").fetchone()[0]),
        "event_log": int(conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]),
        "wifi_connections": int(
            conn.execute("SELECT COUNT(*) FROM wifi_connections WHERE " + WIFI_DEDUPE_SQL).fetchone()[0]
        ),
        "hosts": int(conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]),
        "active_hosts": int(conn.execute("SELECT COUNT(*) FROM hosts WHERE active_now = 1").fetchone()[0]),
    }
    last_exact_wifi = conn.execute(
        "SELECT MAX(derived_connected_at) FROM wifi_connections WHERE exact_connection_time_available = 1 AND "
        + WIFI_DEDUPE_SQL
    ).fetchone()[0]
    latest = dict(latest_run) if latest_run else None
    if latest:
        for key in (
            "summary_json",
            "router_metadata_json",
            "timestamp_assumptions_json",
            "contamination_json",
            "source_endpoints_json",
        ):
            latest[key.removesuffix("_json")] = _decode_json(latest.pop(key, None))
    conn.close()
    return {
        "has_data": counts["runs"] > 0 or counts["event_log"] > 0 or counts["wifi_connections"] > 0 or counts["hosts"] > 0,
        "latest_run": latest,
        "retained": retained,
        "counts": counts,
        "last_exact_wifi": last_exact_wifi,
    }


def analysis_snapshot(path: Path = DEFAULT_DB, start: str = "", end: str = "") -> dict[str, Any]:
    conn = init_db(path)
    range_filter, params = _time_range_sql("timestamp", start, end)
    category_counts = [
        dict(row)
        for row in conn.execute(
            f"SELECT COALESCE(category, 'unknown') AS label, COUNT(*) AS count FROM event_log{range_filter} GROUP BY label ORDER BY count DESC",
            params,
        )
    ]
    auth_counts = {
        "failed": _count_like(conn, "event_log", "message", ["falsches", "fehlgeschlagen", "failed"], start, end, "timestamp"),
        "successful": _count_like(conn, "event_log", "message", ["erfolgreich", "success"], start, end, "timestamp"),
        "app": _count_like(conn, "event_log", "message", ["app"], start, end, "timestamp"),
    }
    hourly = _hourly_counts(conn, start, end)
    confidence = [
        dict(row)
        for row in conn.execute(
            """
            SELECT COALESCE(derived_time_confidence, evidence, 'unknown') AS label, COUNT(*) AS count
            FROM wifi_connections
            WHERE """ + WIFI_DEDUPE_SQL + """
            GROUP BY label
            ORDER BY count DESC
            """
        )
    ]
    retained = dict(
        conn.execute(
            "SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event, COUNT(*) AS event_count FROM event_log"
        ).fetchone()
    )
    run = conn.execute(
        "SELECT generated_at, router_address, summary_json FROM export_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    gaps = _event_gaps(conn)
    conn.close()
    return {
        "category_counts": category_counts,
        "auth_counts": auth_counts,
        "hourly_counts": hourly,
        "confidence_counts": confidence,
        "retained": retained,
        "latest_run": dict(run) if run else None,
        "gaps": gaps,
    }


def query_entities(path: Path = DEFAULT_DB, query: str = "", limit: int = 100) -> dict[str, Any]:
    conn = init_db(path)
    q = f"%{query.casefold()}%" if query else ""
    where = ""
    params: list[Any] = []
    if q:
        where = "WHERE lower(searchable) LIKE ?"
        params.append(q)
    hosts = [dict(row) for row in conn.execute(f"SELECT * FROM hosts {where} ORDER BY COALESCE(last_seen, '') DESC LIMIT ?", [*params, limit])]
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
            "event_count": _entity_event_count(conn, host),
            "wifi_count": _entity_wifi_count(conn, host),
        }
    conn.close()
    return {"rows": list(entities.values()), "total": len(entities)}


def entity_pivot(path: Path = DEFAULT_DB, value: str = "", limit: int = 200) -> dict[str, Any]:
    conn = init_db(path)
    needle = value.strip()
    if not needle:
        conn.close()
        return {"entity": {}, "timeline": [], "hosts": [], "wifi": [], "logs": []}
    like = f"%{needle}%"
    hosts = [dict(row) for row in conn.execute("SELECT * FROM hosts WHERE searchable LIKE ? ORDER BY COALESCE(last_seen, '') DESC LIMIT 10", [like])]
    wifi = [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM wifi_connections WHERE searchable LIKE ? AND " + WIFI_DEDUPE_SQL + " ORDER BY COALESCE(derived_connected_at, '') DESC LIMIT ?",
            [like, limit],
        )
    ]
    logs = [dict(row) for row in conn.execute("SELECT * FROM event_log WHERE searchable LIKE ? ORDER BY COALESCE(timestamp, '') DESC LIMIT ?", [like, limit])]
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
        }
        for row in wifi
    ]
    timeline.sort(key=lambda row: row.get("event_time") or "", reverse=True)
    conn.close()
    return {"entity": {"value": needle}, "timeline": timeline[:limit], "hosts": hosts, "wifi": wifi, "logs": logs}


def evidence_for_record(path: Path = DEFAULT_DB, record_type: str = "", record_id: int = 0) -> dict[str, Any]:
    conn = init_db(path)
    table_map = {"log": "event_log", "event_log": "event_log", "wifi": "wifi_connections", "wifi_connections": "wifi_connections", "hosts": "hosts"}
    table = table_map.get(record_type)
    if not table:
        conn.close()
        return {"record": None, "artifacts": []}
    record = conn.execute(f"SELECT * FROM {table} WHERE id = ?", [record_id]).fetchone()
    if not record:
        conn.close()
        return {"record": None, "artifacts": []}
    row = dict(record)
    needles = [row.get("message"), row.get("mac"), row.get("ip"), row.get("hostname")]
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


def _time_range_sql(column: str, start: str, end: str) -> tuple[str, list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    if start:
        where.append(f"COALESCE({column}, '') >= ?")
        params.append(start)
    if end:
        where.append(f"COALESCE({column}, '') <= ?")
        params.append(end)
    return (f" WHERE {' AND '.join(where)}" if where else "", params)


def _count_like(conn: sqlite3.Connection, table: str, column: str, needles: list[str], start: str, end: str, time_column: str) -> int:
    range_sql, params = _time_range_sql(time_column, start, end)
    clause = " OR ".join([f"lower({column}) LIKE ?" for _ in needles])
    if range_sql:
        sql = f"SELECT COUNT(*) FROM {table}{range_sql} AND ({clause})"
    else:
        sql = f"SELECT COUNT(*) FROM {table} WHERE {clause}"
    return int(conn.execute(sql, [*params, *[f"%{needle}%" for needle in needles]]).fetchone()[0])


def _hourly_counts(conn: sqlite3.Connection, start: str, end: str) -> list[dict[str, Any]]:
    event_filter, event_params = _time_range_sql("timestamp", start, end)
    wifi_filter, wifi_params = _time_range_sql("derived_connected_at", start, end)
    sql = f"""
        SELECT hour, SUM(count) AS count FROM (
            SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) AS count FROM event_log{event_filter} GROUP BY hour
            UNION ALL
            SELECT substr(derived_connected_at, 12, 2) AS hour, COUNT(*) AS count FROM wifi_connections{wifi_filter}{' AND ' if wifi_filter else ' WHERE '}""" + WIFI_DEDUPE_SQL + """ GROUP BY hour
        )
        WHERE hour IS NOT NULL AND hour != ''
        GROUP BY hour
        ORDER BY hour
    """
    return [dict(row) for row in conn.execute(sql, [*event_params, *wifi_params])]


def _event_gaps(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [row["timestamp"] for row in conn.execute("SELECT timestamp FROM event_log WHERE timestamp IS NOT NULL ORDER BY timestamp")]
    gaps: list[dict[str, Any]] = []
    previous_dt: datetime | None = None
    previous_raw = ""
    for raw in rows:
        try:
            current = datetime.fromisoformat(raw)
        except ValueError:
            continue
        if previous_dt:
            hours = (current - previous_dt).total_seconds() / 3600
            if hours >= 1:
                gaps.append({"from": previous_raw, "to": raw, "hours": round(hours, 2)})
        previous_dt = current
        previous_raw = raw
    return sorted(gaps, key=lambda row: row["hours"], reverse=True)[:5]


def _entity_event_count(conn: sqlite3.Connection, host: dict[str, Any]) -> int:
    terms = [host.get("hostname"), host.get("mac"), host.get("ip")]
    terms = [term for term in terms if term]
    if not terms:
        return 0
    where = " OR ".join("searchable LIKE ?" for _ in terms)
    return int(conn.execute(f"SELECT COUNT(*) FROM event_log WHERE {where}", [f"%{term}%" for term in terms]).fetchone()[0])


def _entity_wifi_count(conn: sqlite3.Connection, host: dict[str, Any]) -> int:
    terms = [host.get("hostname"), host.get("mac"), host.get("ip")]
    terms = [term for term in terms if term]
    if not terms:
        return 0
    where = " OR ".join("searchable LIKE ?" for _ in terms)
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM wifi_connections WHERE ({where}) AND {WIFI_DEDUPE_SQL}",
            [f"%{term}%" for term in terms],
        ).fetchone()[0]
    )


def _snippet(content: str, needle: str, width: int = 360) -> str:
    index = content.casefold().find(needle.casefold())
    if index < 0:
        return content[:width]
    start = max(index - width // 2, 0)
    end = min(index + len(needle) + width // 2, len(content))
    return content[start:end]


def make_fts_query(query: str) -> str:
    tokens = re.findall(r"[\w]+", query.casefold())
    return " AND ".join(f"{token}*" for token in tokens)


def get_settings(path: Path = DEFAULT_DB, include_secret: bool = False) -> dict[str, Any]:
    conn = init_db(path)
    rows = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM settings")}
    conn.close()
    result: dict[str, Any] = {
        "address": rows.get("address", ""),
        "user": rows.get("user", ""),
        "port": int(rows.get("port", "49000") or "49000"),
        "tls": rows.get("tls", "0") == "1",
        "has_password": bool(rows.get("password")),
    }
    if include_secret:
        result["password"] = rows.get("password", "")
    return result


def save_settings(settings: dict[str, Any], path: Path = DEFAULT_DB) -> dict[str, Any]:
    conn = init_db(path)
    current = get_settings(path, include_secret=True)
    values = {
        "address": str(settings.get("address") or current.get("address") or "192.168.178.1"),
        "user": str(settings["user"] if "user" in settings else current.get("user") or ""),
        "port": str(int(settings.get("port") or current.get("port") or 49000)),
        "tls": "1" if bool(settings.get("tls")) else "0",
        "password": str(settings.get("password") or current.get("password") or ""),
    }
    now = datetime.now().astimezone().isoformat()
    with conn:
        for key, value in values.items():
            conn.execute(
                """
                INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, value, now),
            )
    conn.close()
    return get_settings(path)
