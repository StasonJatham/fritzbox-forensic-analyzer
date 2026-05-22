from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from fritzbox_store_constants import WIFI_DEDUPE_SQL
from fritzbox_store_query_helpers import _combine_filter, _run_observation_sql


def security_advisory_summary(conn: sqlite3.Connection, run_id: int | None) -> dict[str, Any]:
    run_sql, run_params = _run_observation_sql("security_advisory", run_id)
    where = f"WHERE {run_sql}" if run_sql else ""
    params = run_params
    total = int(conn.execute(f"SELECT COUNT(*) FROM security_advisories t {where}", params).fetchone()[0])
    by_severity = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.severity, ''), 'unknown') AS label, COUNT(*) AS count
            FROM security_advisories t
            {where}
            GROUP BY label
            ORDER BY CASE label WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                     count DESC
            """,
            params,
        )
    ]
    by_category = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.category, ''), 'unknown') AS label, COUNT(*) AS count
            FROM security_advisories t
            {where}
            GROUP BY label
            ORDER BY count DESC, label
            LIMIT 8
            """,
            params,
        )
    ]
    top = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT id, advisory_id, severity, category, title, subject, recommendation, confidence
            FROM security_advisories t
            {where}
            ORDER BY CASE t.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                     t.id DESC
            LIMIT 8
            """,
            params,
        )
    ]
    return {
        "available": total > 0,
        "total": total,
        "high_or_critical": sum(int(row["count"]) for row in by_severity if row.get("label") in {"critical", "high"}),
        "wan_exposure": _security_category_count(by_category, "WAN exposure")
        + _security_category_count(by_category, "Remote access"),
        "upnp_pcp": _security_category_count(by_category, "Automatic port sharing"),
        "wireless": _security_category_count(by_category, "Wireless security"),
        "by_severity": by_severity,
        "by_category": by_category,
        "top": top,
    }


def _security_category_count(rows: list[dict[str, Any]], label: str) -> int:
    return sum(int(row.get("count") or 0) for row in rows if row.get("label") == label)


def _host_count(conn: sqlite3.Connection, host_filter: str, host_params: list[Any], predicate: str) -> int:
    filter_sql = host_filter + f" AND {predicate}"
    return int(conn.execute(f"SELECT COUNT(*) FROM hosts t{filter_sql}", host_params).fetchone()[0])


def raw_artifact_summaries(conn: sqlite3.Connection, run_id: int | None) -> dict[str, str]:
    params: list[Any] = []
    if run_id is None:
        where = "WHERE record_type = 'raw_artifact'"
    else:
        where = "WHERE record_type = 'raw_artifact' AND run_id = ?"
        params.append(run_id)
    rows = conn.execute(
        f"""
        SELECT json_extract(content_json, '$.name') AS name,
               json_extract(content_json, '$.content') AS content
        FROM record_observations
        {where}
        ORDER BY id DESC
        """,
        params,
    ).fetchall()
    artifacts: dict[str, str] = {}
    for row in rows:
        artifacts.setdefault(str(row["name"]), str(row["content"] or ""))
    return artifacts


def mesh_summary(content: str | None) -> dict[str, Any]:
    if not content:
        return {"available": False, "nodes": 0, "links": [], "link_counts": []}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {"available": False, "nodes": 0, "links": [], "link_counts": []}
    links: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for node in data.get("nodes") or []:
        for interface in node.get("node_interfaces") or []:
            for link in interface.get("node_links") or []:
                label = f"{link.get('type') or interface.get('type') or 'unknown'} / {link.get('state') or 'unknown'}"
                counts[label] = counts.get(label, 0) + 1
                links.append(
                    {
                        "device": node.get("device_name")
                        or node.get("device_friendly_name")
                        or node.get("device_mac_address"),
                        "interface": interface.get("name") or interface.get("type"),
                        "type": link.get("type") or interface.get("type"),
                        "state": link.get("state"),
                        "last_connected": unix_seconds_to_iso(link.get("last_connected")),
                        "rx": link.get("cur_data_rate_rx"),
                        "tx": link.get("cur_data_rate_tx"),
                    }
                )
    return {
        "available": True,
        "nodes": len(data.get("nodes") or []),
        "links": links[:20],
        "link_counts": [
            {"label": key, "count": value}
            for key, value in sorted(counts.items(), key=lambda item: item[1], reverse=True)
        ],
    }


def host_risk_summary(
    conn: sqlite3.Connection,
    host_filter: str,
    host_params: list[Any],
    port_mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT t.hostname, t.mac, t.ip, t.interface, t.active_now, t.blocked,
                   t.allow_pcp_and_upnp, t.pcp_count, t.upnp_count, t.myfritz_enabled,
                   t.last_activity, t.last_connected
            FROM hosts t{host_filter}
            """,
            host_params,
        )
    ]
    mappings_by_ip: dict[str, list[dict[str, Any]]] = {}
    for mapping in port_mappings:
        internal = str(mapping.get("internal_client") or "").strip()
        if internal:
            mappings_by_ip.setdefault(internal, []).append(mapping)

    scored = []
    totals = {"high": 0, "medium": 0, "low": 0}
    for row in rows:
        reasons = []
        score = 0
        mapped_ports = mappings_by_ip.get(str(row.get("ip") or ""), [])
        if mapped_ports:
            score += 5
            reasons.append(f"{len(mapped_ports)} WAN port mapping(s)")
        if truthy(row.get("allow_pcp_and_upnp")):
            score += 3
            reasons.append("PCP/UPnP allowed")
        if positive_number(row.get("upnp_count")) or positive_number(row.get("pcp_count")):
            score += 2
            reasons.append("UPnP/PCP mapping counters")
        if truthy(row.get("myfritz_enabled")):
            score += 2
            reasons.append("MyFRITZ enabled")
        if truthy(row.get("active_now")):
            score += 1
            reasons.append("active at acquisition")
        if truthy(row.get("blocked")):
            score = max(0, score - 2)
            reasons.append("blocked")
        if score <= 0 and not reasons:
            continue
        level = "high" if score >= 5 else "medium" if score >= 3 else "low"
        totals[level] += 1
        scored.append(
            {
                "hostname": row.get("hostname"),
                "mac": row.get("mac"),
                "ip": row.get("ip"),
                "interface": row.get("interface"),
                "score": score,
                "level": level,
                "reasons": reasons,
                "port_mappings": mapped_ports[:6],
                "last_activity": row.get("last_activity") or row.get("last_connected"),
            }
        )
    scored.sort(key=lambda item: (item["score"], item.get("last_activity") or ""), reverse=True)
    return {"available": bool(rows), "totals": totals, "devices": scored[:10]}


def last_used_histogram(conn: sqlite3.Connection, host_filter: str, host_params: list[Any]) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT substr(COALESCE(NULLIF(t.last_activity, ''), NULLIF(t.last_connected, ''), NULLIF(t.last_seen, '')), 1, 10) AS label,
               COUNT(*) AS count
        FROM hosts t{host_filter}
        AND COALESCE(NULLIF(t.last_activity, ''), NULLIF(t.last_connected, ''), NULLIF(t.last_seen, '')) != ''
        GROUP BY label
        ORDER BY label DESC
        LIMIT 14
        """,
        host_params,
    ).fetchall()
    return [dict(row) for row in reversed(rows)]


def advertisement_hint_summary(
    conn: sqlite3.Connection, run_id: int | None, start: str = "", end: str = ""
) -> dict[str, Any]:
    run_sql, run_params = _run_observation_sql("advertisement_hint", run_id)
    where: list[str] = []
    params: list[Any] = []
    if run_sql:
        where.append(run_sql)
        params.extend(run_params)
    if start:
        where.append("COALESCE(t.observed_at, '') >= ?")
        params.append(start)
    if end:
        where.append("COALESCE(t.observed_at, '') <= ?")
        params.append(end)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM advertisement_hints t {where_sql}", params).fetchone()[0])
    by_protocol = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.protocol, ''), 'unknown') AS label, COUNT(*) AS count
            FROM advertisement_hints t
            {where_sql}
            GROUP BY label
            ORDER BY count DESC
            LIMIT 8
            """,
            params,
        )
    ]
    by_confidence = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT COALESCE(NULLIF(t.confidence, ''), 'unknown') AS label, COUNT(*) AS count
            FROM advertisement_hints t
            {where_sql}
            GROUP BY label
            ORDER BY count DESC
            """,
            params,
        )
    ]
    recent = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT id, observed_at, hint_type, protocol, hostname, mac, ip, direction, confidence, summary, source
            FROM advertisement_hints t
            {where_sql}
            ORDER BY COALESCE(t.observed_at, '') DESC, t.id DESC
            LIMIT 8
            """,
            params,
        )
    ]
    return {
        "available": total > 0,
        "total": total,
        "by_protocol": by_protocol,
        "by_confidence": by_confidence,
        "recent": recent,
    }


def tr064_summary(content: str | None) -> dict[str, Any]:
    if not content:
        return {"available": False, "wlan_radios": [], "wan": {}}
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {"available": False, "wlan_radios": [], "wan": {}}
    actions = data.get("actions") or {}
    indexed = data.get("indexed_results") or {}
    wan_common = (actions.get("wan_common_link") or {}).get("response") or {}
    wan_ip = (actions.get("wan_ip_info") or {}).get("response") or {}
    wan_status = (actions.get("wan_ip_status") or {}).get("response") or {}
    wan_external = (actions.get("wan_ip_external") or {}).get("response") or {}
    port_mappings = parse_port_mappings(indexed)
    radios = []
    for radio in data.get("wlan") or []:
        info = (radio.get("info") or {}).get("response") or {}
        total = (radio.get("total_associations") or {}).get("response") or {}
        channel = (radio.get("channel_info") or {}).get("response") or {}
        stats = (radio.get("statistics") or {}).get("response") or {}
        radios.append(
            {
                "index": radio.get("index"),
                "enabled": info.get("NewEnable"),
                "status": info.get("NewStatus"),
                "ssid": info.get("NewSSID"),
                "channel": channel.get("NewChannel") or info.get("NewChannel"),
                "standard": info.get("NewStandard"),
                "associations": total.get("NewTotalAssociations") or info.get("NewTotalAssociations"),
                "bytes_sent": stats.get("NewTotalBytesSent"),
                "bytes_received": stats.get("NewTotalBytesReceived"),
            }
        )
    return {
        "available": True,
        "wan": {
            "access_type": wan_common.get("NewWANAccessType"),
            "physical_status": wan_common.get("NewPhysicalLinkStatus"),
            "downstream": wan_common.get("NewLayer1DownstreamMaxBitRate")
            or wan_common.get("NewX_AVM-DE_DownstreamCurrentMaxSpeed"),
            "upstream": wan_common.get("NewLayer1UpstreamMaxBitRate")
            or wan_common.get("NewX_AVM-DE_UpstreamCurrentMaxSpeed"),
            "connection_status": wan_status.get("NewConnectionStatus") or wan_ip.get("NewConnectionStatus"),
            "external_ip": wan_external.get("NewExternalIPAddress") or wan_ip.get("NewExternalIPAddress"),
            "port_mapping_count": len(port_mappings),
            "port_mappings": port_mappings,
        },
        "wlan_radios": radios,
    }


def parse_port_mappings(indexed: dict[str, Any]) -> list[dict[str, Any]]:
    mappings = []
    for source in ("wan_ip_port_mappings", "wan_ppp_port_mappings"):
        for item in (indexed.get(source) or {}).get("items") or []:
            if not item.get("ok"):
                continue
            response = item.get("response") or {}
            enabled = truthy(response.get("NewEnabled"))
            mappings.append(
                {
                    "source": source,
                    "enabled": enabled,
                    "remote_host": response.get("NewRemoteHost"),
                    "external_port": response.get("NewExternalPort"),
                    "protocol": response.get("NewProtocol"),
                    "internal_port": response.get("NewInternalPort"),
                    "internal_client": response.get("NewInternalClient"),
                    "description": response.get("NewPortMappingDescription"),
                    "lease_duration": response.get("NewLeaseDuration"),
                }
            )
    mappings.sort(key=lambda row: (not row.get("enabled"), str(row.get("external_port") or "")))
    return mappings[:50]


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on", "enabled", "allow", "allowed"}


def positive_number(value: Any) -> bool:
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def unix_seconds_to_iso(value: Any) -> str | None:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    try:
        return datetime.fromtimestamp(numeric).astimezone().isoformat()
    except (OSError, OverflowError, ValueError):
        return None


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


def _count_like(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    needles: list[str],
    start: str,
    end: str,
    time_column: str,
    run_id: int | None = None,
) -> int:
    range_sql, params = _time_range_sql(time_column, start, end)
    record_type = "event_log" if table == "event_log" else table
    run_sql, run_params = _run_observation_sql(record_type, run_id)
    range_sql, params = _combine_filter(range_sql, params, run_sql, run_params)
    clause = " OR ".join([f"lower({column}) LIKE ?" for _ in needles])
    if range_sql:
        sql = f"SELECT COUNT(*) FROM {table} t{range_sql} AND ({clause})"
    else:
        sql = f"SELECT COUNT(*) FROM {table} t WHERE {clause}"
    return int(conn.execute(sql, [*params, *[f"%{needle}%" for needle in needles]]).fetchone()[0])


def _hourly_counts(conn: sqlite3.Connection, start: str, end: str, run_id: int | None = None) -> list[dict[str, Any]]:
    event_filter, event_params = _time_range_sql("timestamp", start, end)
    event_run_sql, event_run_params = _run_observation_sql("event_log", run_id)
    event_filter, event_params = _combine_filter(event_filter, event_params, event_run_sql, event_run_params)
    wifi_filter, wifi_params = _time_range_sql("derived_connected_at", start, end)
    wifi_run_sql, wifi_run_params = _run_observation_sql("wifi_connection", run_id)
    wifi_filter, wifi_params = _combine_filter(wifi_filter, wifi_params, wifi_run_sql, wifi_run_params)
    sql = (
        f"""
        SELECT hour, SUM(count) AS count FROM (
            SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) AS count FROM event_log t{event_filter} GROUP BY hour
            UNION ALL
            SELECT substr(derived_connected_at, 12, 2) AS hour, COUNT(*) AS count FROM wifi_connections t{wifi_filter}{" AND " if wifi_filter else " WHERE "}"""
        + ("1=1" if run_id is not None else "t." + WIFI_DEDUPE_SQL.strip())
        + """ GROUP BY hour
        )
        WHERE hour IS NOT NULL AND hour != ''
        GROUP BY hour
        ORDER BY hour
    """
    )
    return [dict(row) for row in conn.execute(sql, [*event_params, *wifi_params])]


def _event_gaps(conn: sqlite3.Connection, run_id: int | None = None) -> list[dict[str, Any]]:
    run_sql, run_params = _run_observation_sql("event_log", run_id)
    where, params = _combine_filter(" WHERE t.timestamp IS NOT NULL", [], run_sql, run_params)
    rows = [
        row["timestamp"]
        for row in conn.execute(f"SELECT t.timestamp FROM event_log t{where} ORDER BY t.timestamp", params)
    ]
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
