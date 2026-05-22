from __future__ import annotations

import re
import sqlite3
from typing import Any


def make_fts_query(query: str) -> str:
    tokens = re.findall(r"[\w]+", query.casefold())
    return " AND ".join(f"{token}*" for token in tokens)


def resolve_run_id(conn: sqlite3.Connection, run_id: str | int | None = "latest") -> int | None:
    value = str(run_id or "latest").strip().lower()
    if value == "all":
        return None
    if value == "latest":
        row = conn.execute("SELECT id FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None
    try:
        return int(value)
    except ValueError:
        row = conn.execute("SELECT id FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None


def _run_observation_sql(record_type: str, run_id: int | None) -> tuple[str, list[Any]]:
    if run_id is None:
        return "", []
    return (
        """
        t.id IN (
            SELECT record_table_id FROM record_observations
            WHERE run_id = ? AND record_type = ? AND record_table_id IS NOT NULL
        )
        """,
        [run_id, record_type],
    )


def _combine_filter(
    base_sql: str,
    base_params: list[Any],
    extra_sql: str,
    extra_params: list[Any],
) -> tuple[str, list[Any]]:
    if not extra_sql:
        return base_sql, base_params
    if base_sql:
        return f"{base_sql} AND {extra_sql}", [*base_params, *extra_params]
    return f" WHERE {extra_sql}", extra_params


def _run_observation_count(conn: sqlite3.Connection, run_id: int, record_type: str) -> int:
    column = "record_table_id" if record_type != "raw_artifact" else "content_sha256"
    return int(
        conn.execute(
            f"SELECT COUNT(DISTINCT {column}) FROM record_observations WHERE run_id = ? AND record_type = ?",
            [run_id, record_type],
        ).fetchone()[0]
    )


def _run_record_count(
    conn: sqlite3.Connection,
    run_id: int,
    record_type: str,
    table: str,
    extra_where: str = "",
) -> int:
    where = """
        t.id IN (
            SELECT record_table_id FROM record_observations
            WHERE run_id = ? AND record_type = ? AND record_table_id IS NOT NULL
        )
    """
    if extra_where:
        where = f"({where}) AND ({extra_where})"
    return int(conn.execute(f"SELECT COUNT(*) FROM {table} t WHERE {where}", [run_id, record_type]).fetchone()[0])


def enrich_host_activity(conn: sqlite3.Connection, hosts: list[dict[str, Any]], run_id: int | None = None) -> None:
    for host in hosts:
        if host.get("last_activity"):
            continue
        candidates = [
            (
                host.get("last_connected"),
                "exact_wifi_connection",
                "high",
                "Retained WLAN connection log entry matched this host.",
            ),
            (host.get("last_seen"), "retained_or_mesh_evidence", "medium", "Last retained evidence matched this host."),
        ]
        if host.get("active_now"):
            candidates.append(
                (
                    _host_observed_at(conn, int(host["id"]), run_id),
                    "active_host_snapshot",
                    "medium",
                    "Host table reported this client active at acquisition time; this is an observation, not a session start time.",
                )
            )
        candidates = [candidate for candidate in candidates if candidate[0]]
        if not candidates:
            continue
        timestamp, source, confidence, note = max(candidates, key=lambda item: str(item[0]))
        host["last_activity"] = timestamp
        host["last_activity_source"] = source
        host["last_activity_confidence"] = confidence
        host["last_activity_note"] = note


def _host_observed_at(conn: sqlite3.Connection, host_id: int, run_id: int | None = None) -> str | None:
    params: list[Any] = [host_id]
    run_sql = ""
    if run_id is not None:
        run_sql = " AND run_id = ?"
        params.append(run_id)
    row = conn.execute(
        f"""
        SELECT MAX(COALESCE(event_time, observed_at)) AS observed_at
        FROM record_observations
        WHERE record_type = 'host' AND record_table_id = ?{run_sql}
        """,
        params,
    ).fetchone()
    return row["observed_at"] if row else None
