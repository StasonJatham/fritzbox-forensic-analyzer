from __future__ import annotations

import json
import sqlite3
from argparse import ArgumentParser
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from fritzbox_log_store import (
    EXPECTED_RAW_ARTIFACTS,
    add_fts,
    add_observation,
    event_key,
    init_db,
    normalize_event_log_row,
    searchable_text,
)
from fritzbox_parsers import FritzLogEntry, parse_data_lua_log, parse_device_log, parse_device_log_xml
from fritzbox_siem import refresh_siem_views
from fritzbox_siem_parser import list_parser_rules, parse_fritzbox_log_message

EVIDENCE_TABLES = (
    "raw_artifacts",
    "event_log",
    "wifi_connections",
    "hosts",
    "support_findings",
    "host_filter_profiles",
    "mesh_topology_links",
    "wan_port_mappings",
    "wlan_radios",
    "wlan_associations",
    "advertisement_hints",
    "network_status_snapshots",
    "device_risk_summaries",
    "security_advisories",
    "wlan_station_state_snapshots",
    "wlan_station_intervals",
    "wlan_ap_client_events",
    "wlan_event_details",
    "dhcp_leases",
    "aha_device_states",
    "telephony_records",
    "siem_events",
    "siem_correlations",
    "siem_correlation_events",
)

TYPED_ARTIFACT_TABLES = (
    "host_filter_profiles",
    "mesh_topology_links",
    "wan_port_mappings",
    "wlan_radios",
    "wlan_associations",
    "advertisement_hints",
    "network_status_snapshots",
    "device_risk_summaries",
    "security_advisories",
    "wlan_station_state_snapshots",
    "wlan_station_intervals",
    "wlan_ap_client_events",
    "wlan_event_details",
    "dhcp_leases",
    "aha_device_states",
    "telephony_records",
)

HIGH_VALUE_RAW_RULE_PREFIXES = ("wifi.", "auth.", "network.", "security.")
PROMOTABLE_RAW_LOG_ARTIFACTS = {
    "device_log_text",
    "device_log_text_json",
    "device_log_xml",
    "device_log_xml_wlan",
    "data_lua_pages_json",
    "support_data_txt",
}


def audit_database(
    path: Path,
    *,
    run_id: int | str = "latest",
    refresh_siem: bool = False,
    promote_raw_logs: bool = False,
    reclassify_event_log: bool = False,
) -> dict[str, Any]:
    """Audit whether one acquisition run has raw, parsed, and correlated SIEM data."""

    conn = init_db(path)
    try:
        run = resolve_run(conn, run_id)
        selected_run_id = int(run["id"])
        repairs: dict[str, Any] = {}
        promoted = 0
        if promote_raw_logs:
            with conn:
                raw_repair = promote_raw_logs_to_event_log(conn, selected_run_id)
                repairs["raw_logs_promoted"] = raw_repair
                promoted = int(raw_repair["inserted"])
        reclassified = 0
        if reclassify_event_log:
            with conn:
                category_repair = reclassify_event_log_rows(conn, selected_run_id)
                repairs["event_log_reclassified"] = category_repair
                reclassified = int(category_repair["updated"])
        if refresh_siem and (promoted or reclassified or count_table(conn, "siem_events", selected_run_id) == 0):
            with conn:
                repairs["siem_refreshed"] = refresh_siem_for_run(conn, selected_run_id)

        audit = {
            "database": str(path),
            "run": run_summary(run),
            "repairs": repairs,
            "tables": table_counts(conn, selected_run_id),
            "raw_artifacts": raw_artifact_coverage(conn, selected_run_id),
            "typed_artifacts": typed_artifact_coverage(conn, selected_run_id),
            "parser": parser_coverage(conn, selected_run_id),
            "correlation": correlation_coverage(conn, selected_run_id),
            "parser_rules": list_parser_rules(),
        }
        audit["status"] = audit_status(audit)
        audit["findings"] = audit_findings(audit)
        return audit
    finally:
        conn.close()


def refresh_siem_for_run(conn: sqlite3.Connection, run_id: int) -> dict[str, int]:
    counts = refresh_siem_views(conn, run_id)
    row = conn.execute("SELECT summary_json FROM export_runs WHERE id = ?", [run_id]).fetchone()
    summary = load_json(row["summary_json"] if row else None)
    summary.update(counts)
    conn.execute("UPDATE export_runs SET summary_json = ? WHERE id = ?", [json.dumps(summary, sort_keys=True), run_id])
    return counts


def promote_raw_logs_to_event_log(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """Promote retained raw log artifacts into event_log rows for legacy/imported runs."""

    run = conn.execute("SELECT generated_at, acquired_at FROM export_runs WHERE id = ?", [run_id]).fetchone()
    observed_at = str((run["acquired_at"] if run else None) or (run["generated_at"] if run else None) or "")
    existing = {
        (
            str(row["timestamp"] or ""),
            str(row["message"] or ""),
            str(row["source"] or ""),
        )
        for row in conn.execute("SELECT timestamp, message, source FROM event_log WHERE run_id = ?", [run_id])
    }
    inserted = 0
    skipped = 0
    by_source: Counter[str] = Counter()
    for artifact in conn.execute(
        "SELECT name, content FROM raw_artifacts WHERE run_id = ? ORDER BY name",
        [run_id],
    ):
        name = str(artifact["name"])
        if name not in PROMOTABLE_RAW_LOG_ARTIFACTS:
            continue
        for entry in log_entries_from_artifact(name, artifact["content"] or ""):
            message = entry.message.strip()
            if not message:
                continue
            timestamp = entry.timestamp.isoformat() if entry.timestamp else None
            key = (timestamp or "", message, entry.source)
            if key in existing:
                skipped += 1
                continue
            event = normalize_event_log_row(
                {
                    "timestamp": timestamp,
                    "category": "router",
                    "source": entry.source,
                    "message": message,
                }
            )
            searchable = searchable_text(event)
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
                    event.get("source") or entry.source,
                    event.get("message") or "",
                    "parsed_from_raw",
                    f"Promoted from stored raw artifact {name} during SIEM coverage repair.",
                    searchable,
                ),
            )
            row_id = int(cursor.lastrowid) if cursor.rowcount and cursor.lastrowid is not None else None
            if not row_id:
                skipped += 1
                continue
            add_fts(conn, "event_log", row_id, searchable)
            add_observation(
                conn,
                run_id=run_id,
                record_type="event_log",
                record_key=event_key(event),
                record_table_id=row_id,
                observed_at=observed_at,
                event_time=event.get("timestamp"),
                evidence_level="parsed_from_raw",
                evidence_note=f"Promoted from stored raw artifact {name} during SIEM coverage repair.",
                source=event.get("source") or entry.source,
                content=event,
            )
            inserted += 1
            by_source[entry.source] += 1
            existing.add(key)
    return {"inserted": inserted, "skipped": skipped, "by_source": dict(sorted(by_source.items()))}


def reclassify_event_log_rows(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    updated = 0
    by_change: Counter[str] = Counter()
    for row in conn.execute(
        "SELECT id, timestamp, category, mac, ip, source, message FROM event_log WHERE run_id = ?",
        [run_id],
    ).fetchall():
        old_category = row["category"]
        old_mac = row["mac"]
        old_ip = row["ip"]
        normalized = normalize_event_log_row(dict(row))
        new_category = normalized.get("category")
        new_mac = normalized.get("mac")
        new_ip = normalized.get("ip")
        if (old_category, old_mac, old_ip) == (new_category, new_mac, new_ip):
            continue
        searchable = searchable_text(normalized)
        conn.execute(
            """
            UPDATE event_log
            SET category = ?, mac = ?, ip = ?, searchable = ?
            WHERE id = ?
            """,
            [new_category, new_mac, new_ip, searchable, row["id"]],
        )
        conn.execute(
            "DELETE FROM records_fts WHERE record_type = 'event_log' AND record_id = ?",
            [row["id"]],
        )
        add_fts(conn, "event_log", int(row["id"]), searchable)
        updated += 1
        by_change[f"{old_category or 'empty'}->{new_category or 'empty'}"] += 1
    return {"updated": updated, "by_change": dict(sorted(by_change.items()))}


def log_entries_from_artifact(name: str, content: str) -> list[FritzLogEntry]:
    if name == "device_log_text_json":
        text = json_text_field(content, "NewDeviceLog")
        return parse_device_log(text, "device_log_text") if text else []
    if name == "device_log_text":
        return parse_device_log(content, "device_log_text")
    if name in {"device_log_xml", "device_log_xml_wlan"}:
        text = parse_device_log_xml(content)
        return parse_device_log(text, name) if text else []
    if name == "data_lua_pages_json":
        text = parse_data_lua_log(content)
        return parse_device_log(text, name) if text else []
    if name == "support_data_txt":
        return parse_device_log(content, "support_data_txt")
    return []


def json_text_field(content: str, field: str) -> str:
    try:
        payload = json.loads(content or "{}")
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def resolve_run(conn: sqlite3.Connection, run_id: int | str) -> sqlite3.Row:
    if str(run_id).casefold() == "latest":
        row = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    else:
        row = conn.execute("SELECT * FROM export_runs WHERE id = ?", [int(run_id)]).fetchone()
    if row is None:
        raise ValueError(f"Export run not found: {run_id}")
    return row


def run_summary(row: sqlite3.Row) -> dict[str, Any]:
    summary = load_json(row["summary_json"])
    return {
        "id": row["id"],
        "generated_at": row["generated_at"],
        "acquired_at": row["acquired_at"],
        "router_address": row["router_address"],
        "acquisition_mode": row["acquisition_mode"],
        "raw_acquisition_dir": summary.get("raw_acquisition_dir"),
    }


def table_counts(conn: sqlite3.Connection, run_id: int) -> dict[str, int]:
    return {table: count_table(conn, table, run_id) for table in EVIDENCE_TABLES if table_exists(conn, table)}


def count_table(conn: sqlite3.Connection, table: str, run_id: int) -> int:
    if not table_exists(conn, table):
        return 0
    if "run_id" in table_columns(conn, table):
        row = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", [run_id]).fetchone()
    else:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0] if row else 0)


def raw_artifact_coverage(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT name, COUNT(*) AS count, SUM(length(content)) AS bytes
            FROM raw_artifacts
            WHERE run_id = ?
            GROUP BY name
            ORDER BY name
            """,
            [run_id],
        )
    ]
    present = {row["name"] for row in rows}
    error_rows = [row for row in rows if str(row["name"]).endswith("_error")]
    attempts = acquisition_attempts(conn, run_id)
    failed_attempts = [attempt for attempt in attempts if not attempt.get("ok")]
    return {
        "total": sum(int(row["count"]) for row in rows),
        "bytes": sum(int(row["bytes"] or 0) for row in rows),
        "present_names": rows,
        "missing_expected_names": [name for name in EXPECTED_RAW_ARTIFACTS if name not in present],
        "error_names": error_rows,
        "attempt_count": len(attempts),
        "failed_attempt_count": len(failed_attempts),
        "failed_attempts": failed_attempts[:100],
        "attempts_by_artifact": attempts_by_artifact(attempts),
    }


def acquisition_attempts(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT name, content
        FROM raw_artifacts
        WHERE run_id = ? AND name IN ('acquisition_manifest_json', 'manifest_jsonl', 'acquisition_manifest_jsonl')
        ORDER BY id
        """,
        [run_id],
    ):
        name = str(row["name"])
        content = row["content"] or ""
        if name.endswith("_jsonl") or name == "manifest_jsonl":
            attempts.extend(manifest_jsonl_attempts(content))
            continue
        payload = load_json(content)
        raw_attempts = payload.get("attempts") if isinstance(payload, dict) else []
        if isinstance(raw_attempts, list):
            attempts.extend([attempt for attempt in raw_attempts if isinstance(attempt, dict)])
    return attempts


def manifest_jsonl_attempts(content: str) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for line in content.splitlines():
        try:
            attempt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(attempt, dict):
            attempts.append(attempt)
    return attempts


def attempts_by_artifact(attempts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for attempt in attempts:
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


def typed_artifact_coverage(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    for table in TYPED_ARTIFACT_TABLES:
        if not table_exists(conn, table):
            tables.append({"table": table, "exists": False, "count": 0, "sources": [], "evidence_levels": []})
            continue
        columns = table_columns(conn, table)
        count = count_table(conn, table, run_id)
        sources = []
        if "source" in columns:
            sources = counter_query(
                conn,
                f"""
                SELECT COALESCE(source, 'unknown') AS label, COUNT(*) AS count
                FROM {table}
                WHERE run_id = ?
                GROUP BY label
                ORDER BY count DESC, label
                LIMIT 20
                """,
                [run_id],
            )
        evidence_levels = []
        if "evidence_level" in columns:
            evidence_levels = counter_query(
                conn,
                f"""
                SELECT COALESCE(evidence_level, 'unknown') AS label, COUNT(*) AS count
                FROM {table}
                WHERE run_id = ?
                GROUP BY label
                ORDER BY count DESC, label
                """,
                [run_id],
            )
        tables.append(
            {
                "table": table,
                "exists": True,
                "count": count,
                "sources": sources,
                "evidence_levels": evidence_levels,
            }
        )
    return {
        "tables": tables,
        "tables_with_rows": [row["table"] for row in tables if row["count"] > 0],
        "empty_tables": [row["table"] for row in tables if row["exists"] and row["count"] == 0],
        "missing_tables": [row["table"] for row in tables if not row["exists"]],
    }


def parser_coverage(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    event_rules: Counter[str] = Counter()
    event_categories: Counter[str] = Counter()
    stored_parser_mismatches: Counter[str] = Counter()
    event_messages = set()

    for row in conn.execute(
        "SELECT category, message FROM event_log WHERE run_id = ?",
        [run_id],
    ):
        message = row["message"] or ""
        event_messages.add(message)
        parsed = parse_fritzbox_log_message(message, row["category"] or "")
        rule_id = parser_rule_id(parsed)
        event_rules[rule_id] += 1
        event_categories[parsed.get("category") or row["category"] or "unknown"] += 1
        if rule_id != "router.fallback" and row["category"] and row["category"] != parsed.get("category"):
            stored_parser_mismatches[f"{row['category']}->{parsed.get('category')}"] += 1

    raw_hits = scan_raw_parser_hits(conn, run_id, event_messages)

    return {
        "event_log_rules": counter_rows(event_rules),
        "event_log_categories": counter_rows(event_categories),
        "stored_category_mismatches": counter_rows(stored_parser_mismatches),
        "raw_artifact_rule_hits": raw_hits,
    }


def scan_raw_parser_hits(conn: sqlite3.Connection, run_id: int, event_messages: set[str]) -> dict[str, Any]:
    rule_hits: Counter[str] = Counter()
    artifact_hits: dict[str, Counter[str]] = defaultdict(Counter)
    high_value_unpromoted: Counter[str] = Counter()
    scanned_lines = 0

    for artifact in conn.execute(
        "SELECT name, content FROM raw_artifacts WHERE run_id = ?",
        [run_id],
    ):
        name = str(artifact["name"])
        content = artifact["content"] or ""
        if name.endswith("_error"):
            continue
        entries = log_entries_from_artifact(name, content) or parse_device_log(content, name)
        for entry in entries:
            scanned_lines += 1
            parsed = parse_fritzbox_log_message(entry.message, "")
            rule_id = parser_rule_id(parsed)
            if rule_id == "router.fallback":
                continue
            rule_hits[rule_id] += 1
            artifact_hits[name][rule_id] += 1
            if (
                name in PROMOTABLE_RAW_LOG_ARTIFACTS
                and entry.message not in event_messages
                and high_value_rule(rule_id)
            ):
                high_value_unpromoted[rule_id] += 1

    return {
        "scanned_lines": scanned_lines,
        "rule_hits": counter_rows(rule_hits),
        "artifact_rule_hits": {
            artifact: counter_rows(counter)
            for artifact, counter in sorted(artifact_hits.items(), key=lambda item: item[0])
        },
        "high_value_hits_not_in_event_log": counter_rows(high_value_unpromoted),
    }


def correlation_coverage(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    siem_events = count_table(conn, "siem_events", run_id)
    linked_events = int(
        conn.execute(
            "SELECT COUNT(DISTINCT event_id) FROM siem_correlation_events WHERE run_id = ?",
            [run_id],
        ).fetchone()[0]
        or 0
    )
    categories = counter_query(
        conn,
        """
        SELECT event_category AS label, COUNT(*) AS count
        FROM siem_events
        WHERE run_id = ?
        GROUP BY event_category
        ORDER BY count DESC
        """,
        [run_id],
    )
    kinds = counter_query(
        conn,
        """
        SELECT event_kind AS label, COUNT(*) AS count
        FROM siem_events
        WHERE run_id = ?
        GROUP BY event_kind
        ORDER BY count DESC
        LIMIT 40
        """,
        [run_id],
    )
    rules = counter_query(
        conn,
        """
        SELECT COALESCE(rule_id, correlation_type) AS label, COUNT(*) AS count
        FROM siem_correlations
        WHERE run_id = ?
        GROUP BY label
        ORDER BY count DESC
        """,
        [run_id],
    )
    unlinked_high_value = counter_query(
        conn,
        """
        SELECT e.event_category AS label, COUNT(*) AS count
        FROM siem_events e
        LEFT JOIN siem_correlation_events c ON c.run_id = e.run_id AND c.event_id = e.id
        WHERE e.run_id = ?
          AND c.id IS NULL
          AND e.event_category IN ('auth', 'wifi', 'discovery', 'network', 'security')
        GROUP BY e.event_category
        ORDER BY count DESC
        """,
        [run_id],
    )
    return {
        "siem_events": siem_events,
        "linked_events": linked_events,
        "link_ratio": round(linked_events / siem_events, 4) if siem_events else 0,
        "event_categories": categories,
        "top_event_kinds": kinds,
        "correlation_rules": rules,
        "unlinked_high_value_events": unlinked_high_value,
    }


def audit_status(audit: dict[str, Any]) -> str:
    tables = audit["tables"]
    parser = audit["parser"]
    raw = audit["raw_artifacts"]
    if tables.get("raw_artifacts", 0) == 0:
        return "missing_raw"
    if tables.get("event_log", 0) == 0 and raw.get("total", 0) > 0:
        return "raw_only"
    if tables.get("siem_events", 0) == 0 and tables.get("event_log", 0) > 0:
        return "needs_siem_refresh"
    if parser["raw_artifact_rule_hits"]["high_value_hits_not_in_event_log"]:
        return "raw_parser_gaps"
    return "ok"


def audit_findings(audit: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    tables = audit["tables"]
    raw = audit["raw_artifacts"]
    parser = audit["parser"]
    correlation = audit["correlation"]
    typed = audit["typed_artifacts"]

    if tables.get("raw_artifacts", 0) == 0:
        findings.append("No raw artifacts are stored for the selected run.")
    if tables.get("event_log", 0) == 0 and raw.get("total", 0) > 0:
        findings.append("Raw artifacts exist, but no normalized event_log rows exist for this run.")
    if tables.get("siem_events", 0) == 0 and tables.get("event_log", 0) > 0:
        findings.append("Parsed evidence exists, but SIEM events/correlations have not been built for this run.")
    if raw["error_names"]:
        findings.append(f"{len(raw['error_names'])} artifact error row(s) were retained; inspect acquisition logs.")
    if raw["failed_attempt_count"]:
        findings.append(
            f"{raw['failed_attempt_count']} acquisition endpoint attempt(s) failed; successful artifacts remain usable."
        )
    if typed["tables_with_rows"]:
        findings.append(
            f"Typed artifact tables populated: {', '.join(typed['tables_with_rows'][:8])}"
            + ("." if len(typed["tables_with_rows"]) <= 8 else ", ...")
        )
    if parser["stored_category_mismatches"]:
        findings.append("Some stored event categories differ from the shared parser classification.")
    if parser["raw_artifact_rule_hits"]["high_value_hits_not_in_event_log"]:
        findings.append("High-value parser hits still exist only inside raw artifacts and should be reviewed.")
    if correlation["siem_events"] and correlation["link_ratio"] < 0.05:
        findings.append("Very few SIEM events are linked to correlations; entity extraction may need review.")
    if not findings:
        findings.append("Raw artifacts, parsed tables, SIEM events, and correlations are present for this run.")
    return findings


def high_value_rule(rule_id: str) -> bool:
    return rule_id.startswith(HIGH_VALUE_RAW_RULE_PREFIXES)


def parser_rule_id(parsed: dict[str, Any]) -> str:
    fields = parsed.get("fields") if isinstance(parsed, dict) else {}
    if isinstance(fields, dict):
        return str(fields.get("parser_rule_id") or "router.fallback")
    return "router.fallback"


def counter_rows(counter: Counter[str], *, limit: int | None = None) -> list[dict[str, Any]]:
    rows = [{"label": label, "count": count} for label, count in counter.most_common(limit)]
    return rows


def counter_query(conn: sqlite3.Connection, sql: str, params: list[Any]) -> list[dict[str, Any]]:
    return [{"label": row["label"] or "unknown", "count": int(row["count"])} for row in conn.execute(sql, params)]


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", [table]).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}


def load_json(value: str | None) -> dict[str, Any]:
    try:
        decoded = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def format_markdown(audit: dict[str, Any]) -> str:
    lines = [
        f"# SIEM Coverage Audit: run {audit['run']['id']}",
        "",
        f"- Status: `{audit['status']}`",
        f"- Database: `{audit['database']}`",
        f"- Router: `{audit['run'].get('router_address') or 'unknown'}`",
        f"- Generated: `{audit['run'].get('generated_at') or 'unknown'}`",
        f"- Raw acquisition dir: `{audit['run'].get('raw_acquisition_dir') or 'unknown'}`",
        "",
        "## Findings",
        *[f"- {finding}" for finding in audit["findings"]],
        "",
        "## Counts",
        *[f"- `{table}`: {count}" for table, count in sorted(audit["tables"].items())],
        "",
        "## Raw Artifacts",
        f"- Stored artifact rows: {audit['raw_artifacts']['total']}",
        f"- Stored artifact bytes: {audit['raw_artifacts']['bytes']}",
        f"- Missing expected artifact names: {len(audit['raw_artifacts']['missing_expected_names'])}",
        f"- Error artifact names: {len(audit['raw_artifacts']['error_names'])}",
        f"- Failed endpoint attempts in manifest: {audit['raw_artifacts']['failed_attempt_count']}",
        "",
        "## Typed Artifacts",
        f"- Typed tables with rows: {len(audit['typed_artifacts']['tables_with_rows'])}",
        f"- Empty typed tables: {len(audit['typed_artifacts']['empty_tables'])}",
        f"- Missing typed tables: {len(audit['typed_artifacts']['missing_tables'])}",
        "",
        "## Parser Coverage",
        f"- Event-log parser rules hit: {len(audit['parser']['event_log_rules'])}",
        f"- Raw artifact parser rules hit: {len(audit['parser']['raw_artifact_rule_hits']['rule_hits'])}",
        "- High-value raw hits not in event_log: "
        f"{sum(row['count'] for row in audit['parser']['raw_artifact_rule_hits']['high_value_hits_not_in_event_log'])}",
        "",
        "## Correlation Coverage",
        f"- SIEM events: {audit['correlation']['siem_events']}",
        f"- Linked SIEM events: {audit['correlation']['linked_events']}",
        f"- Link ratio: {audit['correlation']['link_ratio']}",
        f"- Correlation rule types: {len(audit['correlation']['correlation_rules'])}",
    ]
    return "\n".join(lines)


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Audit FRITZ!Box Mini-SIEM parser and correlation coverage.")
    parser.add_argument("database", type=Path, help="SQLite database to audit.")
    parser.add_argument("--run-id", default="latest", help="Run id to audit, or 'latest'.")
    parser.add_argument("--refresh-siem", action="store_true", help="Rebuild SIEM events/correlations if missing.")
    parser.add_argument(
        "--promote-raw-logs",
        action="store_true",
        help="Promote stored raw log artifacts into event_log before auditing.",
    )
    parser.add_argument(
        "--reclassify-event-log",
        action="store_true",
        help="Rewrite stored event_log category/MAC/IP fields with the shared parser.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of Markdown.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    audit = audit_database(
        args.database,
        run_id=args.run_id,
        refresh_siem=args.refresh_siem or args.promote_raw_logs or args.reclassify_event_log,
        promote_raw_logs=args.promote_raw_logs,
        reclassify_event_log=args.reclassify_event_log,
    )
    if args.json:
        print(json.dumps(audit, indent=2, sort_keys=True, default=str))
    else:
        print(format_markdown(audit))


if __name__ == "__main__":
    main()
