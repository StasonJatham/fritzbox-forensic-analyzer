from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from fritzbox_evidence_extractors import artifact_snippet, first_regex
from fritzbox_store_constants import WIFI_DEDUPE_SQL
from fritzbox_store_ingest import init_db
from fritzbox_store_queries import query_timeline
from fritzbox_store_query_helpers import _combine_filter, _run_observation_sql, resolve_run_id
from fritzbox_store_schema import DEFAULT_DB
from fritzbox_store_snapshot_overview import acquisition_source_coverage, analysis_snapshot
from fritzbox_store_snapshot_summaries import _time_range_sql, advertisement_hint_summary

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROBE_REQUEST_PATTERNS = [
    re.compile(r"\bprobe[-_\s]?request\b", re.I),
    re.compile(r"\b(probereq|prbreq|prb_req)\b", re.I),
    re.compile(r"\b802\.11\b.{0,120}\bprobe\b", re.I | re.S),
    re.compile(r"\bprobe\b.{0,120}\b802\.11\b", re.I | re.S),
    re.compile(r"\b(wlan|wi-?fi|wireless)\b.{0,120}\bprobe\b", re.I | re.S),
    re.compile(r"\b(mgmt|management frame)\b.{0,120}\bprobe\b", re.I | re.S),
    re.compile(r"\b(sondierungsanfrage|suchanfrage)\b", re.I),
]
PROBE_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"\bq6v5_wcss_probe\b", re.I),
    re.compile(r"\b[a-z0-9_]+_probe\b", re.I),
    re.compile(r"\bprobe\+0x[0-9a-f]+\b", re.I),
    re.compile(r"\bdriver probe\b", re.I),
    re.compile(r"\bprobe failed\b", re.I),
    re.compile(r"\bprobing\b", re.I),
    re.compile(r"\bprobe lock\b", re.I),
]


def investigation_snapshot(
    path: Path = DEFAULT_DB,
    start: str = "",
    end: str = "",
    run_id: str | int = "latest",
    query: str = "",
    interface: str = "all",
    presence_mode: str = "overlap",
    confidence: str = "all",
) -> dict[str, Any]:
    conn = init_db(path)
    scoped_run_id = resolve_run_id(conn, run_id)
    auth_terms = ["anmeldung", "login", "kennwort", "password", "app", "fehlgeschlagen", "failed", "falsches"]
    normalized_interface = interface if interface in {"all", "wifi", "lan", "guest", "active"} else "all"
    normalized_mode = presence_mode if presence_mode in {"overlap", "points", "active"} else "overlap"
    normalized_confidence = confidence if confidence in {"all", "high", "medium", "low", "exact"} else "all"

    event_filter, event_params = _time_range_sql("t.timestamp", start, end)
    event_run_sql, event_run_params = _run_observation_sql("event_log", scoped_run_id)
    event_filter, event_params = _combine_filter(event_filter, event_params, event_run_sql, event_run_params)
    exact_events = int(conn.execute(f"SELECT COUNT(*) FROM event_log t{event_filter}", event_params).fetchone()[0])

    auth_clause = " OR ".join("lower(t.message) LIKE ?" for _ in auth_terms)
    auth_params = [*event_params, *[f"%{term}%" for term in auth_terms]]
    auth_events = int(
        conn.execute(
            f"SELECT COUNT(*) FROM event_log t{event_filter}{' AND' if event_filter else ' WHERE'} ({auth_clause})",
            auth_params,
        ).fetchone()[0]
    )
    auth_samples = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT t.id, t.timestamp, t.category, t.ip, t.mac, t.message, t.evidence_level, t.evidence_note
            FROM event_log t{event_filter}{" AND" if event_filter else " WHERE"} ({auth_clause})
            ORDER BY COALESCE(t.timestamp, '') DESC, t.id DESC
            LIMIT 8
            """,
            auth_params,
        )
    ]

    wifi_filter, wifi_params = _time_range_sql("t.derived_connected_at", start, end)
    wifi_run_sql, wifi_run_params = _run_observation_sql("wifi_connection", scoped_run_id)
    wifi_filter, wifi_params = _combine_filter(wifi_filter, wifi_params, wifi_run_sql, wifi_run_params)
    wifi_dedupe = "1=1" if scoped_run_id is not None else "t." + WIFI_DEDUPE_SQL.strip()
    wifi_filter, wifi_params = _combine_filter(wifi_filter, wifi_params, wifi_dedupe, [])
    wifi_points = int(conn.execute(f"SELECT COUNT(*) FROM wifi_connections t{wifi_filter}", wifi_params).fetchone()[0])
    wifi_exact = int(
        conn.execute(
            f"SELECT COUNT(*) FROM wifi_connections t{wifi_filter} AND t.exact_connection_time_available = 1",
            wifi_params,
        ).fetchone()[0]
    )
    wifi_samples = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT t.id, t.derived_connected_at, t.derived_time_type, t.derived_time_confidence,
                   t.exact_connection_time_available, t.event,
                   t.hostname, t.mac, t.ip, t.source, t.evidence_level, t.evidence_note, t.message
            FROM wifi_connections t{wifi_filter}
            ORDER BY COALESCE(t.derived_connected_at, '') DESC, t.id DESC
            LIMIT 250
            """,
            wifi_params,
        )
    ]
    enrich_device_metadata(conn, wifi_samples, scoped_run_id)

    host_run_sql, host_run_params = _run_observation_sql("host", scoped_run_id)
    host_filter, host_params = _combine_filter(" WHERE 1=1", [], host_run_sql, host_run_params)
    host_point_columns = ["t.last_activity", "t.last_seen", "t.last_connected", "t.first_seen"]
    presence_start_expr = (
        "COALESCE(NULLIF(t.first_seen, ''), NULLIF(t.last_connected, ''), "
        "NULLIF(t.last_seen, ''), NULLIF(t.last_activity, ''))"
    )
    presence_end_expr = (
        "COALESCE(NULLIF(t.last_activity, ''), NULLIF(t.last_connected, ''), "
        "NULLIF(t.last_seen, ''), NULLIF(t.first_seen, ''))"
    )
    host_interface_expr = (
        "COALESCE(NULLIF(t.interface, ''), "
        "CASE WHEN COALESCE(t.wlan_uids, '') != '' THEN 'WLAN' "
        "WHEN COALESCE(t.ethernet_port, '') != '' THEN 'Ethernet' END)"
    )
    host_filter, host_params = _combine_filter(
        host_filter,
        host_params,
        f"({presence_start_expr} != '' OR {presence_end_expr} != '' OR t.active_now = 1 OR t.online = 1)",
        [],
    )
    if query:
        searchable = (
            "LOWER(COALESCE(t.searchable, '') || ' ' || COALESCE(t.hostname, '') || ' ' || "
            "COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, '') || ' ' || COALESCE(t.friendly_name, ''))"
        )
        host_filter, host_params = _combine_filter(
            host_filter, host_params, f"{searchable} LIKE ?", [f"%{query.lower()}%"]
        )
    if normalized_interface == "wifi":
        host_filter, host_params = _combine_filter(
            host_filter,
            host_params,
            "(LOWER(COALESCE(t.interface, '')) LIKE '%wlan%' OR COALESCE(t.wlan_uids, '') != '')",
            [],
        )
    elif normalized_interface == "lan":
        host_filter, host_params = _combine_filter(
            host_filter,
            host_params,
            "(LOWER(COALESCE(t.interface, '')) LIKE '%lan%' OR COALESCE(t.ethernet_port, '') != '')",
            [],
        )
    elif normalized_interface == "guest":
        host_filter, host_params = _combine_filter(
            host_filter,
            host_params,
            "(LOWER(COALESCE(t.guest, '')) IN ('1', 'true', 'yes', 'ja') OR LOWER(COALESCE(t.interface_detail, '')) LIKE '%guest%')",
            [],
        )
    elif normalized_interface == "active":
        host_filter, host_params = _combine_filter(host_filter, host_params, "(t.active_now = 1 OR t.online = 1)", [])
    if normalized_confidence == "exact":
        host_filter, host_params = _combine_filter(
            host_filter, host_params, "COALESCE(t.last_activity_source, '') = 'exact_wifi_connection'", []
        )
    elif normalized_confidence != "all":
        host_filter, host_params = _combine_filter(
            host_filter, host_params, "COALESCE(t.last_activity_confidence, '') = ?", [normalized_confidence]
        )
    if start or end:
        if normalized_mode == "active":
            host_filter, host_params = _combine_filter(
                host_filter, host_params, "(t.active_now = 1 OR t.online = 1)", []
            )
        elif normalized_mode == "points":
            range_clauses: list[str] = []
            range_params: list[Any] = []
            for column in host_point_columns:
                checks: list[str] = []
                if start:
                    checks.append(f"COALESCE({column}, '') >= ?")
                    range_params.append(start)
                if end:
                    checks.append(f"COALESCE({column}, '') <= ?")
                    range_params.append(end)
                range_clauses.append("(" + " AND ".join(checks) + ")")
            host_filter, host_params = _combine_filter(
                host_filter, host_params, "(" + " OR ".join(range_clauses) + ")", range_params
            )
        else:
            overlap_checks: list[str] = []
            overlap_params: list[Any] = []
            if end:
                overlap_checks.append(f"COALESCE({presence_start_expr}, '') <= ?")
                overlap_params.append(end)
            if start:
                overlap_checks.append(f"COALESCE({presence_end_expr}, '') >= ?")
                overlap_params.append(start)
            if overlap_checks:
                host_filter, host_params = _combine_filter(
                    host_filter, host_params, "(" + " AND ".join(overlap_checks) + ")", overlap_params
                )
    presence_points = int(conn.execute(f"SELECT COUNT(*) FROM hosts t{host_filter}", host_params).fetchone()[0])
    presence_samples = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT t.id, t.hostname, t.friendly_name, t.neighbour_name, t.vendor, t.model, t.wlan_station_type,
                   t.interface_detail, t.mac, t.ip, {host_interface_expr} AS interface, t.active_now, t.online,
                   t.first_seen, t.last_connected, t.last_activity, t.last_activity_source,
                   t.last_activity_confidence, t.evidence_level, t.evidence_note,
                   {presence_start_expr} AS presence_start,
                   {presence_end_expr} AS presence_end,
                   CASE
                       WHEN t.active_now = 1 OR t.online = 1 THEN 'active_snapshot'
                       WHEN COALESCE(t.last_activity_source, '') = 'exact_wifi_connection' THEN 'exact_connection'
                       WHEN {presence_start_expr} != '' AND {presence_end_expr} != '' THEN 'interval_overlap'
                       ELSE 'presence_point'
                   END AS window_match
            FROM hosts t{host_filter}
            ORDER BY COALESCE(t.last_activity, t.last_connected, t.last_seen, t.first_seen, '') DESC, t.id DESC
            LIMIT 50
            """,
            host_params,
        )
    ]
    for row in presence_samples:
        row["device_type"] = infer_device_type(row)
        row["device_label"] = device_display_name(row)
    presence_by_interface = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF({host_interface_expr}, ''), 'unknown') AS label, COUNT(*) AS count
            FROM hosts t{host_filter}
            GROUP BY label
            ORDER BY count DESC, label COLLATE NOCASE ASC
            """,
            host_params,
        )
    ]
    presence_by_confidence = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.last_activity_confidence, ''), 'unknown') AS label, COUNT(*) AS count
            FROM hosts t{host_filter}
            GROUP BY label
            ORDER BY count DESC, label COLLATE NOCASE ASC
            """,
            host_params,
        )
    ]

    timeline = query_timeline(path, "", "all", start, end, 8, 0, "all", "all", run_id)
    discovery_in_range = advertisement_hint_summary(conn, scoped_run_id, start, end)
    discovery_total = advertisement_hint_summary(conn, scoped_run_id, "", "")
    probe_telemetry = probe_request_telemetry_summary(conn, scoped_run_id, start, end, query)
    discovery_devices = investigation_discovery_rows(conn, scoped_run_id, start, end, query, probe_telemetry)
    retained = analysis_snapshot(path, "", "", run_id).get("retained", {})
    source_coverage = acquisition_source_coverage(conn, scoped_run_id)
    observed_total = (
        exact_events
        + wifi_points
        + presence_points
        + int(discovery_in_range.get("total") or 0)
        + int(probe_telemetry.get("total") or 0)
    )
    if not start and not end:
        verdict = "Set a start and end time to audit a specific interval."
        verdict_level = "medium"
    elif observed_total == 0:
        verdict = (
            "No retained evidence was observed in this time window. This is not proof that no device was connected."
        )
        verdict_level = "low"
    elif exact_events or wifi_exact or auth_events:
        verdict = (
            "Exact retained evidence exists in this time window. Review exact logs first, then correlate device state."
        )
        verdict_level = "high"
    else:
        verdict = (
            "Only derived or state evidence was observed in this time window. Treat it as best-effort presence context."
        )
        verdict_level = "medium"
    conn.close()
    return {
        "range": {"start": start, "end": end},
        "run_id": scoped_run_id,
        "verdict": {"level": verdict_level, "message": verdict},
        "counts": {
            "exact_events": exact_events,
            "auth_events": auth_events,
            "wifi_points": wifi_points,
            "exact_wifi_points": wifi_exact,
            "presence_points": presence_points,
            "device_candidates": presence_points,
            "probe_requests": int(probe_telemetry.get("total") or 0),
            "discovery_hints_in_range": int(discovery_in_range.get("total") or 0),
            "discovery_hints_total": int(discovery_total.get("total") or 0),
        },
        "filters": {
            "query": query,
            "interface": normalized_interface,
            "presence_mode": normalized_mode,
            "confidence": normalized_confidence,
        },
        "devices": {
            "rows": presence_samples,
            "by_interface": presence_by_interface,
            "by_confidence": presence_by_confidence,
            "note": (
                "Device candidates use best-effort interval overlap by default: first_seen must be before "
                "the window end and last_connected/last_activity must be after the window start."
            ),
        },
        "discovery_devices": discovery_devices,
        "probe_telemetry": probe_telemetry,
        "samples": {
            "timeline": timeline.get("rows", []),
            "auth": auth_samples,
            "wifi": wifi_samples,
            "presence": presence_samples,
            "discovery": discovery_total.get("recent", []),
        },
        "discovery": {
            "in_range": discovery_in_range,
            "all_retained": discovery_total,
            "note": "Discovery/advertisement rows are hints from FRITZ!Box state and raw artifacts. They are not packet captures and often use acquisition time, not the original packet time.",
        },
        "retained": retained,
        "source_coverage": source_coverage,
        "limitations": [
            "No row in a window means no retained/exported evidence was observed, not that no activity happened.",
            "FRITZ!Box lastused/last_connected values are device state points, not complete sessions.",
            "Nearby unassociated-device detection requires retained 802.11 probe-request telemetry; current FRITZ!Box exports often do not preserve it.",
            "Advertisement, broadcast, DHCP, UPnP, PCP, mDNS, SSDP, ARP, and multicast rows are best-effort hints unless backed by exact retained logs.",
            "Packet-level discovery attempts require packet capture or separate network telemetry.",
        ],
    }


def probe_request_telemetry_summary(
    conn: sqlite3.Connection,
    run_id: int | None,
    start: str = "",
    end: str = "",
    query: str = "",
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    false_positive_count = 0
    generic_probe_mentions = 0
    query_value = query.casefold().strip()

    def add_row(row: dict[str, Any]) -> None:
        searchable = " ".join(str(value or "") for value in row.values()).casefold()
        if query_value and query_value not in searchable:
            return
        rows.append(row)

    event_where, event_params = _time_range_sql("t.timestamp", start, end)
    run_sql, run_params = _run_observation_sql("event_log", run_id)
    event_where, event_params = _combine_filter(event_where, event_params, run_sql, run_params)
    event_where, event_params = _combine_filter(
        event_where,
        event_params,
        "(LOWER(t.message) LIKE '%probe%' OR LOWER(t.message) LIKE '%802.11%' OR LOWER(t.message) LIKE '%suchanfrage%')",
        [],
    )
    for row in conn.execute(
        f"""
        SELECT t.id, t.timestamp, t.message, t.mac, t.ip, t.source, t.evidence_level, t.evidence_note
        FROM event_log t{event_where}
        ORDER BY COALESCE(t.timestamp, '') DESC, t.id DESC
        LIMIT 200
        """,
        event_params,
    ):
        message = row["message"] or ""
        match, false_positive = classify_probe_request_text(message)
        false_positive_count += int(false_positive)
        generic_probe_mentions += int(not match and "probe" in message.casefold())
        if not match:
            continue
        mac = row["mac"] or first_regex(MAC_RE, message)
        ip = row["ip"] or first_regex(IPV4_RE, message)
        add_row(
            {
                "id": row["id"],
                "record_type": "event_log",
                "kind": "nearby_probe",
                "title": mac or ip or "802.11 probe request",
                "time": row["timestamp"],
                "mac": mac,
                "ip": ip,
                "source": row["source"] or "event_log",
                "confidence": "high",
                "evidence_level": row["evidence_level"] or "parsed_from_raw",
                "evidence_note": row["evidence_note"]
                or "Exact retained log row that appears to describe 802.11 probe-request telemetry.",
                "summary": message,
            }
        )

    support_where, support_params = _time_range_sql("t.observed_at", start, end)
    run_sql, run_params = _run_observation_sql("support_finding", run_id)
    support_where, support_params = _combine_filter(support_where, support_params, run_sql, run_params)
    support_where, support_params = _combine_filter(
        support_where,
        support_params,
        "(LOWER(t.searchable) LIKE '%probe%' OR LOWER(t.searchable) LIKE '%802.11%' OR LOWER(t.searchable) LIKE '%suchanfrage%')",
        [],
    )
    for row in conn.execute(
        f"""
        SELECT t.id, t.observed_at, t.source, t.raw_text, t.searchable, t.evidence_level, t.evidence_note
        FROM support_findings t{support_where}
        ORDER BY COALESCE(t.observed_at, '') DESC, t.id DESC
        LIMIT 200
        """,
        support_params,
    ):
        text = row["raw_text"] or row["searchable"] or ""
        match, false_positive = classify_probe_request_text(text)
        false_positive_count += int(false_positive)
        generic_probe_mentions += int(not match and "probe" in text.casefold())
        if not match:
            continue
        mac = first_regex(MAC_RE, text)
        ip = first_regex(IPV4_RE, text)
        add_row(
            {
                "id": row["id"],
                "record_type": "support_findings",
                "kind": "nearby_probe",
                "title": mac or ip or "802.11 probe request",
                "time": row["observed_at"],
                "mac": mac,
                "ip": ip,
                "source": row["source"] or "support_data_txt",
                "confidence": "medium" if row["observed_at"] else "low",
                "evidence_level": row["evidence_level"] or "parsed_from_raw",
                "evidence_note": row["evidence_note"]
                or "Support-data row that appears to describe 802.11 probe-request telemetry.",
                "summary": text,
            }
        )

    if not start and not end:
        raw_where: list[str] = []
        raw_params: list[Any] = []
        if run_id is not None:
            raw_where.append("""
                r.sha256 IN (
                    SELECT content_sha256 FROM record_observations
                    WHERE run_id = ? AND record_type = 'raw_artifact'
                )
                """)
            raw_params.append(run_id)
        raw_where.append(
            "(LOWER(r.content) LIKE '%probe%' OR LOWER(r.content) LIKE '%802.11%' OR LOWER(r.content) LIKE '%suchanfrage%')"
        )
        raw_sql = f"WHERE {' AND '.join(raw_where)}"
        for row in conn.execute(
            f"""
            SELECT r.id, r.name, r.created_at, r.content
            FROM raw_artifacts r
            {raw_sql}
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT 40
            """,
            raw_params,
        ):
            content = row["content"] or ""
            for snippet in probe_request_snippets(content):
                match, false_positive = classify_probe_request_text(snippet)
                false_positive_count += int(false_positive)
                generic_probe_mentions += int(not match and "probe" in snippet.casefold())
                if not match:
                    continue
                mac = first_regex(MAC_RE, snippet)
                ip = first_regex(IPV4_RE, snippet)
                add_row(
                    {
                        "id": row["id"],
                        "record_type": "raw_artifacts",
                        "kind": "nearby_probe",
                        "title": mac or ip or "802.11 probe request",
                        "time": row["created_at"],
                        "mac": mac,
                        "ip": ip,
                        "source": row["name"],
                        "confidence": "low",
                        "evidence_level": "parsed_from_raw",
                        "evidence_note": (
                            "Raw artifact contains probe-request wording but no separately retained event timestamp."
                        ),
                        "summary": snippet,
                    }
                )

    rows.sort(key=lambda item: (item.get("time") or "", item.get("id") or 0), reverse=True)
    note = (
        "No 802.11 probe-request management-frame telemetry was retained by this FRITZ!Box export. "
        "Network-layer DHCP, mDNS, SSDP, UPnP, ARP, and multicast hints are not proof that an unassociated "
        "nearby phone was probing for WiFi."
    )
    if rows:
        note = (
            "802.11 probe-request rows were found in retained artifacts. Treat rows without exact timestamps as "
            "artifact evidence, not precise proximity events."
        )
    return {
        "available": bool(rows),
        "total": len(rows),
        "rows": rows[:50],
        "false_positive_count": false_positive_count,
        "generic_probe_mentions": generic_probe_mentions,
        "note": note,
    }


def classify_probe_request_text(text: str) -> tuple[bool, bool]:
    if not text:
        return False, False
    has_probe = "probe" in text.casefold()
    if has_probe and any(pattern.search(text) for pattern in PROBE_FALSE_POSITIVE_PATTERNS):
        return False, True
    return any(pattern.search(text) for pattern in PROBE_REQUEST_PATTERNS), False


def probe_request_snippets(content: str, limit: int = 20) -> list[str]:
    snippets: list[str] = []
    seen: set[str] = set()
    for pattern in (*PROBE_REQUEST_PATTERNS, re.compile(r"\bprobe\b", re.I)):
        for match in pattern.finditer(content):
            snippet = artifact_snippet(content, match.start(), 420)
            if snippet in seen:
                continue
            seen.add(snippet)
            snippets.append(snippet)
            if len(snippets) >= limit:
                return snippets
    return snippets


def enrich_device_metadata(conn: sqlite3.Connection, rows: list[dict[str, Any]], run_id: int | None) -> None:
    if not rows:
        return
    host_run_sql, host_run_params = _run_observation_sql("host", run_id)
    where = f"WHERE 1=1{(' AND ' + host_run_sql) if host_run_sql else ''}"
    hosts = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT hostname, friendly_name, neighbour_name, vendor, model, wlan_station_type,
                   interface, interface_detail, mac, ip, ip_list, mac_list
            FROM hosts t
            {where}
            ORDER BY t.run_id DESC, t.id DESC
            """,
            host_run_params,
        )
    ]
    by_mac: dict[str, dict[str, Any]] = {}
    by_ip: dict[str, dict[str, Any]] = {}
    for host in hosts:
        for value in (host.get("mac"), host.get("mac_list")):
            for token in MAC_RE.findall(str(value or "")):
                by_mac.setdefault(normalize_mac(token), host)
        for value in (host.get("ip"), host.get("ip_list")):
            for token in IPV4_RE.findall(str(value or "")):
                by_ip.setdefault(token, host)

    for row in rows:
        mac = first_present(row, "mac", "source_mac", "node_mac", "peer_mac", "bssid")
        ip = first_present(row, "ip", "source_ip")
        matched_host = by_mac.get(normalize_mac(mac)) if mac else None
        if not matched_host and ip:
            matched_host = by_ip.get(str(ip))
        if not matched_host:
            continue
        for key in (
            "hostname",
            "friendly_name",
            "neighbour_name",
            "vendor",
            "model",
            "wlan_station_type",
            "interface_detail",
        ):
            row[key] = row.get(key) or matched_host.get(key)
        row["device_type"] = row.get("device_type") or infer_device_type(matched_host)
        row["device_label"] = row.get("device_label") or device_display_name(row)


def first_present(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return value
    return None


def normalize_mac(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def device_display_name(row: dict[str, Any]) -> str:
    for key in ("friendly_name", "hostname", "neighbour_name", "title", "mac", "ip"):
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def infer_device_type(row: dict[str, Any]) -> str:
    haystack = " ".join(
        str(row.get(key) or "")
        for key in ("friendly_name", "hostname", "neighbour_name", "vendor", "model", "wlan_station_type")
    ).lower()
    rules = (
        ("iPhone", ("iphone",)),
        ("iPad", ("ipad",)),
        ("Apple Watch", ("watch",)),
        ("Mac", ("macbook", "mac ", "imac")),
        ("Android", ("android", "pixel", "galaxy", "samsung", "xiaomi", "huawei", "oneplus")),
        ("Router/AP", ("router", "dreamrouter", "fritz.box", "repeater", "access point")),
        ("TV", ("tv", "chromecast", "fire tv", "appletv")),
        ("IoT", ("thermostat", "camera", "speaker", "echo", "homepod", "sonos")),
    )
    for label, needles in rules:
        if any(needle in haystack for needle in needles):
            return label
    for key in ("model", "vendor", "wlan_station_type"):
        value = str(row.get(key) or "").strip()
        if value and value.casefold() not in {"0", "false", "none", "null", "unknown"}:
            return value
    return ""


def investigation_discovery_rows(
    conn: sqlite3.Connection,
    run_id: int | None,
    start: str = "",
    end: str = "",
    query: str = "",
    probe_telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    query_like = f"%{query.lower()}%" if query else ""
    if probe_telemetry is None:
        probe_telemetry = probe_request_telemetry_summary(conn, run_id, start, end, query)
    rows.extend(probe_telemetry.get("rows") or [])
    enrich_device_metadata(conn, rows, run_id)

    def add_time_filters(where: list[str], params: list[Any], column: str) -> None:
        if start:
            where.append(f"COALESCE({column}, '') >= ?")
            params.append(start)
        if end:
            where.append(f"COALESCE({column}, '') <= ?")
            params.append(end)

    wlan_where: list[str] = []
    wlan_params: list[Any] = []
    run_sql, run_params = _run_observation_sql("wlan_association", run_id)
    if run_sql:
        wlan_where.append(run_sql)
        wlan_params.extend(run_params)
    add_time_filters(wlan_where, wlan_params, "t.observed_at")
    if query:
        wlan_where.append(
            "LOWER(COALESCE(t.searchable, '') || ' ' || COALESCE(t.hostname, '') || ' ' || "
            "COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, '')) LIKE ?"
        )
        wlan_params.append(query_like)
    wlan_sql = f"WHERE {' AND '.join(wlan_where)}" if wlan_where else ""
    for row in conn.execute(
        f"""
        SELECT t.id, t.observed_at, t.hostname, t.mac, t.ip, t.radio_index,
               t.auth_state, t.speed, t.signal_strength, t.channel, t.guest,
               t.source, t.evidence_level, t.evidence_note
        FROM wlan_associations t
        {wlan_sql}
        ORDER BY COALESCE(t.observed_at, '') DESC, t.id DESC
        LIMIT 50
        """,
        wlan_params,
    ):
        item = dict(row)
        enrich_device_metadata(conn, [item], run_id)
        rows.append(
            {
                **item,
                "record_type": "wlan_associations",
                "kind": "connected_now",
                "title": device_display_name(item) or "WLAN associated device",
                "time": item.get("observed_at"),
                "signal": item.get("signal_strength") or item.get("speed") or item.get("channel"),
                "summary": "Currently associated WiFi client snapshot retained during acquisition.",
            }
        )

    mesh_where: list[str] = []
    mesh_params: list[Any] = []
    run_sql, run_params = _run_observation_sql("mesh_topology_link", run_id)
    if run_sql:
        mesh_where.append(run_sql)
        mesh_params.extend(run_params)
    add_time_filters(mesh_where, mesh_params, "t.last_connected")
    if query:
        mesh_where.append(
            "LOWER(COALESCE(t.searchable, '') || ' ' || COALESCE(t.node, '') || ' ' || "
            "COALESCE(t.node_mac, '') || ' ' || COALESCE(t.peer, '') || ' ' || COALESCE(t.peer_mac, '')) LIKE ?"
        )
        mesh_params.append(query_like)
    mesh_sql = f"WHERE {' AND '.join(mesh_where)}" if mesh_where else ""
    for row in conn.execute(
        f"""
        SELECT t.id, t.last_connected, t.node, t.node_mac, t.peer, t.peer_mac,
               t.interface, t.link_type, t.state, t.rx, t.tx, t.source,
               t.evidence_level, t.evidence_note
        FROM mesh_topology_links t
        {mesh_sql}
        ORDER BY COALESCE(t.last_connected, '') DESC, t.id DESC
        LIMIT 50
        """,
        mesh_params,
    ):
        item = dict(row)
        enrich_device_metadata(conn, [item], run_id)
        rows.append(
            {
                **item,
                "record_type": "mesh_topology_links",
                "kind": "mesh_roaming_link",
                "title": device_display_name(item)
                or item.get("node")
                or item.get("node_mac")
                or item.get("peer")
                or "Mesh/AP link",
                "time": item.get("last_connected"),
                "mac": item.get("node_mac") or item.get("peer_mac"),
                "signal": " / ".join(part for part in [item.get("rx"), item.get("tx")] if part),
                "summary": "Mesh/topology link evidence; useful for roaming or AP path context.",
            }
        )

    hint_where: list[str] = []
    hint_params: list[Any] = []
    run_sql, run_params = _run_observation_sql("advertisement_hint", run_id)
    if run_sql:
        hint_where.append(run_sql)
        hint_params.extend(run_params)
    add_time_filters(hint_where, hint_params, "t.observed_at")
    if query:
        hint_where.append(
            "LOWER(COALESCE(t.searchable, '') || ' ' || COALESCE(t.hostname, '') || ' ' || "
            "COALESCE(t.mac, '') || ' ' || COALESCE(t.ip, '') || ' ' || COALESCE(t.protocol, '')) LIKE ?"
        )
        hint_params.append(query_like)
    hint_sql = f"WHERE {' AND '.join(hint_where)}" if hint_where else ""
    for row in conn.execute(
        f"""
        SELECT t.id, t.observed_at, t.hint_type, t.protocol, t.hostname, t.mac, t.ip,
               t.direction, t.confidence, t.summary, t.source, t.evidence_level, t.evidence_note
        FROM advertisement_hints t
        {hint_sql}
        ORDER BY COALESCE(t.observed_at, '') DESC, t.id DESC
        LIMIT 50
        """,
        hint_params,
    ):
        item = dict(row)
        enrich_device_metadata(conn, [item], run_id)
        rows.append(
            {
                **item,
                "record_type": "advertisement_hints",
                "kind": "network_discovery_hint",
                "title": device_display_name(item) or item.get("protocol") or "Broadcast hint",
                "time": item.get("observed_at"),
                "signal": item.get("protocol"),
                "summary": item.get("summary") or "Broadcast/discovery keyword retained in FRITZ!Box artifacts.",
            }
        )

    rows.sort(key=lambda row: (row.get("time") or "", row.get("id") or 0), reverse=True)
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("kind") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return {
        "rows": rows[:80],
        "total": len(rows),
        "by_kind": [{"label": key, "count": value} for key, value in sorted(counts.items())],
        "note": (
            "This combines true retained 802.11 probe-request rows when present, current WLAN association "
            "snapshots, mesh/AP link timestamps, and separate network-layer discovery hints. FRITZ!Box exports "
            "are not packet captures."
        ),
    }
