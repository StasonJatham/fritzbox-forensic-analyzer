from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from fritzbox_evidence_extractors import keyed_record_key
from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES
from fritzbox_siem_parser import parse_fritzbox_log_message


def repair_observation_table_ids(conn: sqlite3.Connection) -> None:
    lookup_map = {
        "event_log": lookup_event_id,
        "wifi_connection": lookup_wifi_id,
        "host": lookup_host_id,
        "support_finding": lookup_support_finding_id,
        "host_filter_profile": lambda conn, row: lookup_keyed_record_id(conn, "host_filter_profiles", row),
        "mesh_topology_link": lambda conn, row: lookup_keyed_record_id(conn, "mesh_topology_links", row),
        "wan_port_mapping": lambda conn, row: lookup_keyed_record_id(conn, "wan_port_mappings", row),
        "wlan_radio": lambda conn, row: lookup_keyed_record_id(conn, "wlan_radios", row),
        "wlan_association": lambda conn, row: lookup_keyed_record_id(conn, "wlan_associations", row),
        "advertisement_hint": lambda conn, row: lookup_keyed_record_id(conn, "advertisement_hints", row),
        "device_risk_summary": lambda conn, row: lookup_keyed_record_id(conn, "device_risk_summaries", row),
        "security_advisory": lambda conn, row: lookup_keyed_record_id(conn, "security_advisories", row),
    }
    rows = conn.execute("""
        SELECT id, record_type, record_table_id, content_json
        FROM record_observations
        """).fetchall()
    for row in rows:
        if str(row["record_type"]) not in lookup_map:
            continue
        record_id = row["record_table_id"]
        try:
            content = json.loads(row["content_json"] or "{}")
        except json.JSONDecodeError:
            continue
        replacement = lookup_map[str(row["record_type"])](conn, content)
        if replacement and replacement != record_id:
            conn.execute("UPDATE record_observations SET record_table_id = ? WHERE id = ?", [replacement, row["id"]])


def normalize_event_log_row(event: dict[str, Any]) -> dict[str, Any]:
    """Apply the shared SIEM parser before storing retained/imported log rows."""

    message = str(event.get("message") or "")
    parsed = parse_fritzbox_log_message(message, str(event.get("category") or ""))
    parser_rule_id = parsed.get("fields", {}).get("parser_rule_id")
    category = event.get("category")
    if parser_rule_id and parser_rule_id != "router.fallback":
        category = parsed.get("category") or category
    return {
        **event,
        "category": category or parsed.get("category") or "router",
        "mac": parsed.get("mac") or event.get("mac"),
        "ip": parsed.get("ip") or event.get("ip"),
        "parser_rule_id": parser_rule_id,
        "parser_fields": parsed.get("fields") or {},
    }


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
    if row.get("derived_time_type") == "80211_steering_history":
        return (
            "parsed_from_raw",
            "Historic 802.11 steering/roaming observation parsed from FRITZ!Box support data. This proves AP-side observation, not full session duration.",
        )
    if str(row.get("derived_time_type") or "").startswith("80211_"):
        return (
            "parsed_from_raw",
            "Historic 802.11/AP-side evidence parsed from FRITZ!Box support data. Interpret event type and confidence before treating it as a full connection session.",
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
            {
                "timestamp": event.get("timestamp"),
                "message": event.get("message"),
                "source": event.get("source") or "device_log",
            },
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


def support_finding_key(finding: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "finding_type": finding.get("finding_type"),
                "section": finding.get("section"),
                "key": finding.get("key"),
                "line_number": finding.get("line_number"),
                "raw_text": finding.get("raw_text"),
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def lookup_event_id(conn: sqlite3.Connection, event: dict[str, Any]) -> int | None:
    row = conn.execute(
        """
        SELECT id FROM event_log
        WHERE timestamp IS ?
          AND message = ?
          AND COALESCE(source, '') = COALESCE(?, '')
        """,
        (event.get("timestamp"), event.get("message") or "", event.get("source") or "device_log"),
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


def lookup_support_finding_id(conn: sqlite3.Connection, finding: dict[str, Any]) -> int | None:
    row = conn.execute(
        """
        SELECT id FROM support_findings
        WHERE COALESCE(line_number, -1) = COALESCE(?, -1)
          AND COALESCE(raw_text, '') = COALESCE(?, '')
        ORDER BY id DESC
        LIMIT 1
        """,
        (finding.get("line_number"), finding.get("raw_text")),
    ).fetchone()
    return int(row["id"]) if row else None


def lookup_raw_artifact_id(conn: sqlite3.Connection, run_id: int, name: str, sha256: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM raw_artifacts WHERE run_id = ? AND name = ? AND sha256 = ? ORDER BY id DESC LIMIT 1",
        (run_id, name, sha256),
    ).fetchone()
    return int(row["id"]) if row else None


def lookup_keyed_record_id(conn: sqlite3.Connection, table: str, row: dict[str, Any]) -> int | None:
    spec = ADDITIONAL_EVIDENCE_TABLES[table]
    record_key = row.get("record_key") or keyed_record_key(row, spec["record_key_fields"])
    found = conn.execute(
        f"SELECT id FROM {table} WHERE record_key = ? ORDER BY id DESC LIMIT 1",
        [record_key],
    ).fetchone()
    return int(found["id"]) if found else None


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
