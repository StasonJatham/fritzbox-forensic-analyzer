from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from fritzbox_siem_parser import parse_fritzbox_log_message

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
HOSTNAME_CORRELATION_RECORD_TYPES = {
    "hosts",
    "wifi_connections",
    "wlan_associations",
    "advertisement_hints",
    "device_risk_summaries",
}
MAX_CORRELATION_RECORD_REFS = 200
MAX_CORRELATION_EVENT_LINKS = 500
CORRELATION_RULE_VERSION = "1"


def refresh_siem_views(conn: sqlite3.Connection, run_id: int) -> dict[str, int]:
    """Rebuild normalized Mini-SIEM views for one acquisition run."""

    clear_siem_run(conn, run_id)
    events = list(build_siem_events(conn, run_id))
    event_ids: list[int] = []
    for event in events:
        event_id = insert_siem_event(conn, run_id, event)
        event["siem_event_id"] = event_id
        event_ids.append(event_id)
        add_siem_fts(conn, "siem_events", event_id, event["searchable"])

    correlations = build_siem_correlations(events)
    correlation_event_count = 0
    for correlation in correlations:
        correlation_id = insert_siem_correlation(conn, run_id, correlation)
        correlation_event_count += insert_siem_correlation_events(
            conn,
            run_id,
            correlation_id,
            correlation.get("_event_links", []),
        )
        add_siem_fts(conn, "siem_correlations", correlation_id, correlation["searchable"])

    return {
        "siem_events": len(event_ids),
        "siem_correlations": len(correlations),
        "siem_correlation_events": correlation_event_count,
    }


def clear_siem_run(conn: sqlite3.Connection, run_id: int) -> None:
    conn.execute(
        """
        DELETE FROM records_fts
        WHERE record_type = 'siem_events'
          AND record_id IN (SELECT id FROM siem_events WHERE run_id = ?)
        """,
        [run_id],
    )
    conn.execute(
        """
        DELETE FROM records_fts
        WHERE record_type = 'siem_correlations'
          AND record_id IN (SELECT id FROM siem_correlations WHERE run_id = ?)
        """,
        [run_id],
    )
    conn.execute("DELETE FROM siem_correlation_events WHERE run_id = ?", [run_id])
    conn.execute("DELETE FROM siem_events WHERE run_id = ?", [run_id])
    conn.execute("DELETE FROM siem_correlations WHERE run_id = ?", [run_id])


def build_siem_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    yield from event_log_events(conn, run_id)
    yield from wifi_connection_events(conn, run_id)
    yield from host_presence_events(conn, run_id)
    yield from wlan_association_events(conn, run_id)
    yield from advertisement_hint_events(conn, run_id)
    yield from support_finding_events(conn, run_id)
    yield from network_status_events(conn, run_id)
    yield from wan_port_mapping_events(conn, run_id)
    yield from mesh_topology_events(conn, run_id)
    yield from wlan_radio_events(conn, run_id)
    yield from host_filter_events(conn, run_id)
    yield from device_risk_events(conn, run_id)
    yield from security_advisory_events(conn, run_id)
    yield from typed_artifact_events(conn, run_id)
    yield from raw_artifact_events(conn, run_id)


def event_log_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(
        conn, "SELECT * FROM event_log WHERE run_id = ? ORDER BY COALESCE(timestamp, '')", [run_id]
    ):
        parsed = classify_router_log(row.get("message") or "", row.get("category") or "")
        fields = {
            "router_category": row.get("category"),
            "raw_message": row.get("message"),
            **parsed["fields"],
        }
        yield normalized_event(
            record_type="event_log",
            record_id=row["id"],
            event_time=row.get("timestamp"),
            event_category=parsed["category"] or row.get("category") or "router",
            event_kind=parsed["kind"],
            action=parsed["action"],
            outcome=parsed["outcome"],
            severity=parsed["severity"],
            hostname=parsed["hostname"],
            mac=row.get("mac") or parsed["mac"],
            ip=row.get("ip") or parsed["ip"],
            interface=parsed["interface"],
            protocol=parsed["protocol"],
            source=row.get("source") or "device_log",
            confidence="high" if row.get("timestamp") else "low",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("message"),
            tags=["router_log", *(parsed["tags"] or [])],
            fields=fields,
        )


def wifi_connection_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in observed_table_rows(conn, "wifi_connections", "wifi_connection", run_id):
        event = clean(row.get("event")) or "wifi_observation"
        time_type = clean(row.get("derived_time_type")) or "derived"
        is_exact = bool(row.get("exact_connection_time_available"))
        yield normalized_event(
            record_type="wifi_connections",
            record_id=row["id"],
            event_time=row.get("derived_connected_at"),
            event_category="wifi",
            event_kind=f"wifi.{slug(event)}",
            action=event,
            outcome=wifi_outcome(event),
            severity="info" if is_exact else "low",
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface="WLAN",
            protocol="802.11",
            source=row.get("source"),
            confidence=row.get("derived_time_confidence") or row.get("evidence"),
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("message") or event,
            tags=["wifi", time_type, "exact" if is_exact else "derived"],
            fields=row,
        )


def host_presence_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in observed_table_rows(conn, "hosts", "host", run_id):
        event_time = (
            row.get("last_activity") or row.get("last_connected") or row.get("last_seen") or row.get("first_seen")
        )
        active = bool(row.get("active_now"))
        interface = clean(row.get("interface"))
        tags = ["asset", "presence", "active" if active else "inactive"]
        if interface:
            tags.append(slug(interface))
        yield normalized_event(
            record_type="hosts",
            record_id=row["id"],
            event_time=event_time,
            event_category="asset",
            event_kind="asset.host_observed",
            action="observed",
            outcome="active" if active else "known",
            severity="info",
            hostname=row.get("hostname") or row.get("friendly_name"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=interface,
            protocol=None,
            source=row.get("last_activity_source") or "host_table",
            confidence=row.get("last_activity_confidence") or "medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=device_label(row),
            tags=tags,
            fields=row,
        )


def wlan_association_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in observed_table_rows(conn, "wlan_associations", "wlan_association", run_id):
        yield normalized_event(
            record_type="wlan_associations",
            record_id=row["id"],
            event_time=row.get("observed_at"),
            event_category="wifi",
            event_kind="wifi.association_snapshot",
            action="associated_snapshot",
            outcome="associated",
            severity="info",
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=f"WLAN radio {row.get('radio_index') or ''}".strip(),
            protocol="802.11",
            source=row.get("source"),
            confidence="high",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"WLAN association snapshot {device_label(row)}",
            tags=["wifi", "associated", "snapshot"],
            fields=row,
        )


def advertisement_hint_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in observed_table_rows(conn, "advertisement_hints", "advertisement_hint", run_id):
        protocol = clean(row.get("protocol")) or "discovery"
        hint_type = clean(row.get("hint_type")) or "discovery_hint"
        yield normalized_event(
            record_type="advertisement_hints",
            record_id=row["id"],
            event_time=row.get("observed_at"),
            event_category="discovery",
            event_kind=f"discovery.{slug(hint_type)}",
            action=hint_type,
            outcome="observed",
            severity="low",
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=None,
            protocol=protocol,
            source=row.get("source"),
            confidence=row.get("confidence"),
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("summary"),
            tags=["discovery", slug(protocol), slug(hint_type)],
            fields=row,
        )


def support_finding_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM support_findings WHERE run_id = ?", [run_id]):
        text = row.get("raw_text") or row.get("value") or row.get("key") or row.get("section")
        parsed = classify_router_log(str(text or ""), "support")
        yield normalized_event(
            record_type="support_findings",
            record_id=row["id"],
            event_time=row.get("observed_at"),
            event_category=parsed["category"] if parsed["category"] != "router" else "diagnostic",
            event_kind=f"diagnostic.{slug(row.get('finding_type') or 'finding')}",
            action=row.get("finding_type") or "finding",
            outcome="observed",
            severity=parsed["severity"] if parsed["severity"] != "info" else "low",
            hostname=None,
            mac=parsed["mac"],
            ip=parsed["ip"],
            interface=parsed["interface"],
            protocol=parsed["protocol"],
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=str(text or ""),
            tags=["support", "diagnostic", *(parsed["tags"] or [])],
            fields=row,
        )


def network_status_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM network_status_snapshots WHERE run_id = ?", [run_id]):
        area = clean(row.get("area")) or "network"
        metric = clean(row.get("metric")) or "metric"
        yield normalized_event(
            record_type="network_status_snapshots",
            record_id=row["id"],
            event_time=row.get("observed_at"),
            event_category="network",
            event_kind=f"network.{slug(area)}.{slug(metric)}",
            action="metric",
            outcome="observed",
            severity="info",
            hostname=None,
            mac=None,
            ip=None,
            interface=area,
            protocol=None,
            source=row.get("source"),
            confidence=row.get("confidence"),
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"{area} {metric}: {row.get('value') or ''} {row.get('unit') or ''}".strip(),
            tags=["network", slug(area), slug(metric)],
            fields=row,
        )


def wan_port_mapping_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM wan_port_mappings WHERE run_id = ?", [run_id]):
        enabled = truthy(row.get("enabled"))
        severity = wan_mapping_severity(row) if enabled else "info"
        external = clean(row.get("external_port")) or "?"
        internal = clean(row.get("internal_port")) or "?"
        protocol = clean(row.get("protocol")) or "unknown"
        remote_host = clean(row.get("remote_host"))
        description = clean(row.get("description"))
        yield normalized_event(
            record_type="wan_port_mappings",
            record_id=row["id"],
            event_time=None,
            event_category="security",
            event_kind="security.wan_port_mapping_enabled" if enabled else "security.wan_port_mapping_disabled",
            action="wan_port_mapping",
            outcome="enabled" if enabled else "disabled",
            severity=severity,
            hostname=None,
            mac=None,
            ip=row.get("internal_client"),
            interface="WAN",
            protocol=protocol,
            source=row.get("source"),
            confidence="high",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=(
                f"WAN {protocol.upper()} {external} -> {row.get('internal_client') or 'unknown'}:{internal}"
                + (f" ({description})" if description else "")
                + (f" remote {remote_host}" if remote_host else "")
            ),
            tags=[
                "security",
                "wan",
                "exposure",
                "port_mapping",
                "enabled" if enabled else "disabled",
                slug(protocol),
                f"wan_port_{external}",
            ],
            fields=row,
        )


def mesh_topology_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM mesh_topology_links WHERE run_id = ?", [run_id]):
        yield normalized_event(
            record_type="mesh_topology_links",
            record_id=row["id"],
            event_time=row.get("last_connected"),
            event_category="topology",
            event_kind="topology.mesh_link",
            action="linked",
            outcome=row.get("state") or "observed",
            severity="info",
            hostname=row.get("peer") or row.get("node"),
            mac=row.get("peer_mac") or row.get("node_mac"),
            ip=None,
            interface=row.get("interface"),
            protocol=row.get("link_type"),
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"Mesh link {row.get('node') or row.get('node_mac') or ''} -> {row.get('peer') or row.get('peer_mac') or ''}",
            tags=["topology", "mesh"],
            fields=row,
        )


def wlan_radio_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM wlan_radios WHERE run_id = ?", [run_id]):
        enabled = truthy(row.get("enabled"))
        yield normalized_event(
            record_type="wlan_radios",
            record_id=row["id"],
            event_time=None,
            event_category="wifi",
            event_kind="wifi.radio_state",
            action="radio_state",
            outcome="enabled" if enabled else "disabled",
            severity="info",
            hostname=row.get("ssid"),
            mac=row.get("bssid"),
            ip=None,
            interface=f"WLAN radio {row.get('radio_index') or ''}".strip(),
            protocol=row.get("standard"),
            source=row.get("source"),
            confidence="high",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"WLAN radio {row.get('radio_index') or ''} {row.get('ssid') or ''} {row.get('status') or ''}".strip(),
            tags=["wifi", "radio", "enabled" if enabled else "disabled"],
            fields=row,
        )


def host_filter_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM host_filter_profiles WHERE run_id = ?", [run_id]):
        yield normalized_event(
            record_type="host_filter_profiles",
            record_id=row["id"],
            event_time=None,
            event_category="policy",
            event_kind="policy.host_filter_profile",
            action="profile_observed",
            outcome="blocked" if truthy(row.get("blocked")) else "allowed",
            severity="info",
            hostname=row.get("name"),
            mac=None,
            ip=None,
            interface=None,
            protocol=None,
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"Host filter profile {row.get('name') or row.get('profile_id') or ''}".strip(),
            tags=["policy", "host_filter"],
            fields=row,
        )


def device_risk_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM device_risk_summaries WHERE run_id = ?", [run_id]):
        severity = clean(row.get("risk_level")) or "low"
        yield normalized_event(
            record_type="device_risk_summaries",
            record_id=row["id"],
            event_time=None,
            event_category="security",
            event_kind="security.device_risk",
            action="risk_scored",
            outcome=severity,
            severity=severity,
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=None,
            protocol=None,
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("summary"),
            tags=["security", "risk", severity],
            fields=row,
        )


def security_advisory_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(conn, "SELECT * FROM security_advisories WHERE run_id = ?", [run_id]):
        severity = clean(row.get("severity")) or "medium"
        advisory_id = clean(row.get("advisory_id")) or "advisory"
        advisory_kind = security_advisory_kind(row)
        yield normalized_event(
            record_type="security_advisories",
            record_id=row["id"],
            event_time=None,
            event_category="security",
            event_kind=advisory_kind,
            action=security_advisory_action(row),
            outcome=row.get("status") or "review",
            severity=severity,
            hostname=row.get("subject"),
            mac=first_mac(row.get("subject") or ""),
            ip=first_ip(row.get("subject") or ""),
            interface=None,
            protocol=None,
            source=row.get("source"),
            confidence=row.get("confidence"),
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("title") or row.get("recommendation"),
            tags=[
                "security",
                "advisory",
                severity,
                slug(row.get("category") or ""),
                slug(advisory_id),
                *security_advisory_tags(row),
            ],
            fields=row,
        )


def typed_artifact_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    yield from wlan_station_state_events(conn, run_id)
    yield from wlan_station_interval_events(conn, run_id)
    yield from wlan_ap_client_events(conn, run_id)
    yield from wlan_event_detail_events(conn, run_id)
    yield from dhcp_lease_events(conn, run_id)
    yield from generic_typed_artifact_events(conn, run_id)


def wlan_station_state_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    if not table_exists(conn, "wlan_station_state_snapshots"):
        return
    for row in select_dicts(conn, "SELECT * FROM wlan_station_state_snapshots WHERE run_id = ?", [run_id]):
        active = truthy(row.get("active"))
        outcome = "active" if active else "known"
        if clean(row.get("connect_state")) and not active:
            outcome = "state_retained"
        yield normalized_event(
            record_type="wlan_station_state_snapshots",
            record_id=row["id"],
            event_time=row.get("observed_at") or row.get("last_seen"),
            event_category="wifi",
            event_kind="wifi.station_state_snapshot",
            action="station_state_snapshot",
            outcome=outcome,
            severity="info",
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=row.get("interface"),
            protocol="802.11",
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"WLAN station snapshot {device_label(row)} on {row.get('interface') or 'unknown interface'}",
            tags=["wifi", "station", "snapshot", outcome, "guest" if truthy(row.get("guest")) else ""],
            fields=row,
        )


def wlan_station_interval_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    if not table_exists(conn, "wlan_station_intervals"):
        return
    for row in select_dicts(conn, "SELECT * FROM wlan_station_intervals WHERE run_id = ?", [run_id]):
        disconnected_at = clean(row.get("disconnected_at"))
        duration = seconds_between(row.get("connected_at"), disconnected_at)
        fields = {**row, "duration_seconds": duration}
        yield normalized_event(
            record_type="wlan_station_intervals",
            record_id=row["id"],
            event_time=row.get("connected_at"),
            event_category="wifi",
            event_kind="wifi.station_history_interval",
            action="station_interval",
            outcome="completed" if disconnected_at else "open",
            severity="info",
            hostname=None,
            mac=row.get("mac"),
            ip=None,
            interface=row.get("interface"),
            protocol="802.11",
            source=row.get("source"),
            confidence="high",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=(
                f"WLAN station interval {row.get('mac') or 'unknown station'} on {row.get('interface') or 'unknown interface'} "
                f"{row.get('connected_at') or '?'} -> {disconnected_at or 'open'}"
            ),
            tags=["wifi", "station", "interval", "session", "completed" if disconnected_at else "open"],
            fields=fields,
        )


def wlan_ap_client_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    if not table_exists(conn, "wlan_ap_client_events"):
        return
    for row in select_dicts(conn, "SELECT * FROM wlan_ap_client_events WHERE run_id = ?", [run_id]):
        semantics = ap_client_semantics(row)
        yield normalized_event(
            record_type="wlan_ap_client_events",
            record_id=row["id"],
            event_time=row.get("event_time"),
            event_category="wifi",
            event_kind=semantics["event_kind"],
            action=semantics["action"],
            outcome=semantics["outcome"],
            severity=semantics["severity"],
            hostname=None,
            mac=row.get("mac"),
            ip=None,
            interface=row.get("interface"),
            protocol="802.11",
            source=row.get("source"),
            confidence=semantics["confidence"],
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=row.get("message") or f"WLAN AP client {row.get('event_kind') or 'event'} {row.get('mac') or ''}",
            tags=["wifi", "ap_client", *semantics["tags"]],
            fields=row,
        )


def wlan_event_detail_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    if not table_exists(conn, "wlan_event_details"):
        return
    for row in select_dicts(conn, "SELECT * FROM wlan_event_details WHERE run_id = ?", [run_id]):
        yield normalized_event(
            record_type="wlan_event_details",
            record_id=row["id"],
            event_time=row.get("event_time"),
            event_category="wifi",
            event_kind="wifi.wlan_event_detail",
            action="wlan_event_detail",
            outcome="observed",
            severity="info",
            hostname=None,
            mac=row.get("mac"),
            ip=None,
            interface=row.get("interface"),
            protocol="802.11",
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"WLAN event detail {row.get('event_id') or ''} {row.get('details') or ''}".strip(),
            tags=["wifi", "diagnostic", "wlan_events"],
            fields=row,
        )


def dhcp_lease_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    if not table_exists(conn, "dhcp_leases"):
        return
    for row in select_dicts(conn, "SELECT * FROM dhcp_leases WHERE run_id = ?", [run_id]):
        active = truthy(row.get("active"))
        yield normalized_event(
            record_type="dhcp_leases",
            record_id=row["id"],
            event_time=row.get("observed_at"),
            event_category="network",
            event_kind="network.dhcp_lease_observed",
            action="dhcp_lease_observed",
            outcome="active" if active else "retained",
            severity="info",
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            ip=row.get("ip"),
            interface=None,
            protocol="DHCP",
            source=row.get("source"),
            confidence="medium",
            evidence_level=row.get("evidence_level"),
            evidence_note=row.get("evidence_note"),
            message=f"DHCP lease {device_label(row)} {row.get('ip') or ''}".strip(),
            tags=["network", "dhcp", "lease", "active" if active else "retained"],
            fields=row,
        )


GENERIC_TYPED_ARTIFACT_EVENT_SPECS = {
    "aha_device_states": ("iot", "iot.aha_device_state", "observed_at", "aha_device_state"),
    "telephony_records": ("telephony", "telephony.record", "timestamp", "telephony_record"),
}


def generic_typed_artifact_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for table, (category, kind, time_column, action) in GENERIC_TYPED_ARTIFACT_EVENT_SPECS.items():
        if not table_exists(conn, table):
            continue
        for row in select_dicts(conn, f"SELECT * FROM {table} WHERE run_id = ?", [run_id]):
            message = row.get("message") or row.get("summary") or row.get("name") or row.get("record_key")
            yield normalized_event(
                record_type=table,
                record_id=row["id"],
                event_time=row.get(time_column) or row.get("observed_at"),
                event_category=category,
                event_kind=kind,
                action=action,
                outcome=row.get("state") or "observed",
                severity="info",
                hostname=row.get("hostname") or row.get("name"),
                mac=row.get("mac"),
                ip=row.get("ip"),
                interface=row.get("interface"),
                protocol=None,
                source=row.get("source"),
                confidence="medium",
                evidence_level=row.get("evidence_level"),
                evidence_note=row.get("evidence_note"),
                message=str(message or action),
                tags=[category, action, slug(row.get("source") or "")],
                fields=row,
            )


def wan_mapping_severity(row: dict[str, Any]) -> str:
    port = clean(row.get("external_port"))
    if port in {"22", "80", "443", "3389", "5900", "8080", "8443"}:
        return "critical"
    return "high"


def security_advisory_kind(row: dict[str, Any]) -> str:
    advisory_id = slug(row.get("advisory_id") or "advisory")
    category = slug(row.get("category") or "")
    text = f"{advisory_id} {category} {row.get('title') or ''} {row.get('subject') or ''}".casefold()
    if "wan_port_mapping" in advisory_id:
        return "security.wan_port_mapping_enabled"
    if "user_remote_rights" in advisory_id or advisory_id in {
        "query_lua_user_remote_rights",
        "webui_user_remote_rights",
    }:
        return "security.user_remote_rights"
    if "myfritz" in text:
        return "security.myfritz_exposure"
    if "wireguard" in text or "vpn" in text or "ipsec" in text:
        return "security.vpn_exposure"
    if (
        "remote_admin" in advisory_id
        or "remote_login" in advisory_id
        or "remote access" in text
        or "fernzugriff" in text
    ):
        return "security.remote_admin_exposure"
    if "upnp" in advisory_id or "pcp" in advisory_id or "port sharing" in text:
        return "security.automatic_port_sharing"
    return f"security.{advisory_id or 'advisory'}"


def security_advisory_action(row: dict[str, Any]) -> str:
    kind = security_advisory_kind(row)
    if kind == "security.user_remote_rights":
        return "review_user_rights"
    if kind in {
        "security.remote_admin_exposure",
        "security.myfritz_exposure",
        "security.vpn_exposure",
        "security.wan_port_mapping_enabled",
        "security.automatic_port_sharing",
    }:
        return "review_exposure"
    return "review_advisory"


def security_advisory_tags(row: dict[str, Any]) -> list[str]:
    kind = security_advisory_kind(row)
    tags = []
    if kind in {
        "security.remote_admin_exposure",
        "security.myfritz_exposure",
        "security.vpn_exposure",
        "security.wan_port_mapping_enabled",
        "security.automatic_port_sharing",
    }:
        tags.append("exposure")
    if kind == "security.user_remote_rights":
        tags.extend(["user_rights", "remote_access"])
    if kind == "security.vpn_exposure":
        tags.append("vpn")
    if kind == "security.myfritz_exposure":
        tags.append("myfritz")
    return tags


def ap_client_semantics(row: dict[str, Any]) -> dict[str, Any]:
    raw_kind = slug(row.get("event_kind") or "")
    if raw_kind == "ap_sta_connected":
        return ap_semantics("wifi.ap_sta_connected", "connect", "success", "info", ["connect", "ap_sta"], "high")
    if raw_kind == "ap_sta_disconnected":
        return ap_semantics(
            "wifi.ap_sta_disconnected", "disconnect", "disconnected", "info", ["disconnect", "ap_sta"], "high"
        )
    if raw_kind in {"eapol_4way_completed", "wpa_pairwise_handshake", "wpa_group_handshake"}:
        return ap_semantics("wifi.wpa_key_handshake", "wpa_handshake", "success", "info", ["handshake", "wpa"], "high")
    if raw_kind == "radius_accounting_start":
        return ap_semantics(
            "wifi.radius_accounting_start", "accounting_start", "observed", "info", ["radius"], "medium"
        )
    if raw_kind in {"associated", "reassociated", "association_request_observed", "authenticated"}:
        return ap_semantics("wifi.association_request", "associate", "observed", "info", ["association"], "medium")
    if raw_kind in {"disassociated", "deauthenticated", "disconnected"}:
        return ap_semantics(
            "wifi.disconnected", "disconnect", "disconnected", "info", ["disconnect", "hostapd"], "high"
        )
    if "fail" in raw_kind or "reject" in raw_kind:
        return ap_semantics("wifi.connection_failed", "connect", "failure", "medium", ["failure", "hostapd"], "medium")
    return ap_semantics(
        "wifi.ap_client_event", raw_kind or "ap_client_event", "observed", "info", ["hostapd"], "medium"
    )


def ap_semantics(
    event_kind: str,
    action: str,
    outcome: str,
    severity: str,
    tags: list[str],
    confidence: str,
) -> dict[str, Any]:
    return {
        "event_kind": event_kind,
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "tags": tags,
        "confidence": confidence,
    }


def raw_artifact_events(conn: sqlite3.Connection, run_id: int) -> Iterable[dict[str, Any]]:
    for row in select_dicts(
        conn,
        "SELECT id, name, sha256, created_at, length(content) AS size_bytes FROM raw_artifacts WHERE run_id = ?",
        [run_id],
    ):
        yield normalized_event(
            record_type="raw_artifacts",
            record_id=row["id"],
            event_time=None,
            event_category="evidence",
            event_kind="evidence.raw_artifact_collected",
            action="collected",
            outcome="stored",
            severity="info",
            hostname=None,
            mac=None,
            ip=None,
            interface=None,
            protocol=None,
            source=row.get("name"),
            confidence="high",
            evidence_level="raw",
            evidence_note="Raw artifact collected and retained before parsing.",
            message=f"Raw artifact {row.get('name')}",
            tags=["raw", "artifact", slug(row.get("name") or "")],
            fields=row,
        )


def normalized_event(
    *,
    record_type: str,
    record_id: int,
    event_time: str | None,
    event_category: str,
    event_kind: str,
    action: str | None,
    outcome: str | None,
    severity: str | None,
    hostname: str | None,
    mac: str | None,
    ip: str | None,
    interface: str | None,
    protocol: str | None,
    source: str | None,
    confidence: str | None,
    evidence_level: str | None,
    evidence_note: str | None,
    message: str | None,
    tags: list[str],
    fields: dict[str, Any],
) -> dict[str, Any]:
    normalized_mac = normalize_mac(mac)
    normalized_ip = clean(ip) or first_ip(message or "")
    normalized_hostname = clean(hostname)
    normalized_tags = sorted({tag for tag in (slug(tag) for tag in tags) if tag})
    normalized_fields = clean_json(
        {
            **fields,
            "record_type": record_type,
            "record_id": record_id,
            "event_category": event_category,
            "event_kind": event_kind,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "hostname": normalized_hostname,
            "mac": normalized_mac,
            "ip": normalized_ip,
            "interface": interface,
            "protocol": protocol,
            "source": source,
            "confidence": confidence,
            "tags": normalized_tags,
        }
    )
    entity = entity_label(normalized_hostname, normalized_mac, normalized_ip)
    rendered_message = clean(message) or event_kind.replace("_", " ")
    searchable = searchable_text(
        {
            "time": event_time,
            "category": event_category,
            "kind": event_kind,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "entity": entity,
            "hostname": normalized_hostname,
            "mac": normalized_mac,
            "ip": normalized_ip,
            "interface": interface,
            "protocol": protocol,
            "source": source,
            "confidence": confidence,
            "message": rendered_message,
            "tags": normalized_tags,
            "fields": normalized_fields,
        }
    )
    return {
        "event_time": event_time,
        "event_category": event_category or "unknown",
        "event_kind": event_kind or "event.unknown",
        "action": action,
        "outcome": outcome,
        "severity": normalize_severity(severity),
        "entity": entity,
        "hostname": normalized_hostname,
        "mac": normalized_mac,
        "ip": normalized_ip,
        "interface": clean(interface),
        "protocol": clean(protocol),
        "source": clean(source),
        "confidence": clean(confidence),
        "evidence_level": clean(evidence_level),
        "evidence_note": clean(evidence_note),
        "record_type": record_type,
        "record_id": record_id,
        "message": rendered_message,
        "tags_json": json.dumps(normalized_tags, sort_keys=True),
        "fields_json": json.dumps(normalized_fields, sort_keys=True, default=str),
        "searchable": searchable,
    }


def insert_siem_event(conn: sqlite3.Connection, run_id: int, event: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT INTO siem_events(
            run_id, event_time, event_category, event_kind, action, outcome, severity,
            entity, hostname, mac, ip, interface, protocol, source, confidence,
            evidence_level, evidence_note, record_type, record_id, message,
            tags_json, fields_json, searchable
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            event["event_time"],
            event["event_category"],
            event["event_kind"],
            event["action"],
            event["outcome"],
            event["severity"],
            event["entity"],
            event["hostname"],
            event["mac"],
            event["ip"],
            event["interface"],
            event["protocol"],
            event["source"],
            event["confidence"],
            event["evidence_level"],
            event["evidence_note"],
            event["record_type"],
            event["record_id"],
            event["message"],
            event["tags_json"],
            event["fields_json"],
            event["searchable"],
        ),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("SIEM event insert did not return a row id")
    return int(cursor.lastrowid)


def build_siem_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    correlations = [
        *build_entity_rollup_correlations(events),
        *build_failed_login_burst_correlations(events),
        *build_wifi_failure_burst_correlations(events),
        *build_wifi_session_fragment_correlations(events),
        *build_station_interval_correlations(events),
        *build_dhcp_lease_change_correlations(events),
        *build_exposure_correlations(events),
    ]
    return sorted(correlations, key=lambda row: (row["last_seen"] or "", row["event_count"]), reverse=True)


def build_entity_rollup_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        for key in correlation_keys(event):
            grouped[key].append(event)

    correlations: list[dict[str, Any]] = []
    for key, items in grouped.items():
        if not items:
            continue
        label = best_entity_label(items) or key
        categories = sorted({clean(item.get("event_category")) or "unknown" for item in items})
        correlations.append(
            make_correlation(
                rule_id="entity.timeline_rollup",
                correlation_type="entity_rollup",
                entity_key=key,
                entity_label=label,
                events=items,
                severity=max((normalize_severity(item.get("severity")) for item in items), key=severity_weight),
                confidence="medium",
                summary=f"{label}: {len(items)} normalized events across {', '.join(categories)}",
                extra_fields={"purpose": "entity pivot / evidence rollup"},
            )
        )
    return correlations


def build_failed_login_burst_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = [
        event for event in events if event.get("event_kind") == "auth.login_failure" and event.get("event_time")
    ]
    return build_burst_correlations(
        failures,
        rule_id="auth.failed_login_burst",
        correlation_type="rule_match",
        window_seconds=15 * 60,
        threshold=3,
        severity="high",
        summary_action="failed login events",
        reason="Three or more failed authentication events for the same entity in 15 minutes.",
    )


def build_wifi_failure_burst_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = [
        event for event in events if event.get("event_kind") == "wifi.connection_failed" and event.get("event_time")
    ]
    return build_burst_correlations(
        failures,
        rule_id="wifi.connection_failure_burst",
        correlation_type="rule_match",
        window_seconds=30 * 60,
        threshold=3,
        severity="medium",
        summary_action="WiFi connection failures",
        reason="Three or more WiFi connection failures for the same entity in 30 minutes.",
    )


def build_burst_correlations(
    events: list[dict[str, Any]],
    *,
    rule_id: str,
    correlation_type: str,
    window_seconds: int,
    threshold: int,
    severity: str,
    summary_action: str,
    reason: str,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = primary_correlation_key(event)
        if key:
            grouped[key].append(event)

    correlations: list[dict[str, Any]] = []
    for key, items in grouped.items():
        ordered = sorted(items, key=lambda item: item.get("event_time") or "")
        for window in event_windows(ordered, window_seconds, threshold):
            label = best_entity_label(window) or key
            correlations.append(
                make_correlation(
                    rule_id=rule_id,
                    correlation_type=correlation_type,
                    entity_key=key,
                    entity_label=label,
                    events=window,
                    severity=severity,
                    confidence=window_confidence(window),
                    summary=f"{label}: {len(window)} {summary_action} within {window_seconds // 60} minutes",
                    extra_fields={
                        "threshold": threshold,
                        "window_seconds": window_seconds,
                        "reason": reason,
                    },
                    link_reason=reason,
                )
            )
    return correlations


def build_wifi_session_fragment_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wifi_events = [event for event in events if wifi_session_marker(event) and event.get("event_time")]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in wifi_events:
        key = primary_correlation_key(event)
        if key:
            grouped[key].append(event)

    correlations: list[dict[str, Any]] = []
    for key, items in grouped.items():
        ordered = sorted(items, key=lambda item: item.get("event_time") or "")
        pending_connect: dict[str, Any] | None = None
        for event in ordered:
            if is_wifi_connect_event(event):
                pending_connect = event
                continue
            if not is_wifi_disconnect_event(event) or pending_connect is None:
                continue
            if seconds_between(pending_connect.get("event_time"), event.get("event_time")) is None:
                continue
            label = best_entity_label([pending_connect, event]) or key
            duration = seconds_between(pending_connect.get("event_time"), event.get("event_time"))
            correlations.append(
                make_correlation(
                    rule_id="wifi.session_fragment",
                    correlation_type="session_fragment",
                    entity_key=key,
                    entity_label=label,
                    events=[pending_connect, event],
                    severity="info",
                    confidence=window_confidence([pending_connect, event]),
                    summary=f"{label}: WiFi session fragment from connect to disconnect",
                    extra_fields={
                        "duration_seconds": duration,
                        "reason": "Retained log contains a connect event followed by a disconnect event for the same entity.",
                    },
                    link_reason="Connect/disconnect pair for the same entity.",
                )
            )
            pending_connect = None
    return correlations


def build_station_interval_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    intervals = [
        event
        for event in events
        if event.get("event_kind") == "wifi.station_history_interval" and event.get("event_time")
    ]
    correlations: list[dict[str, Any]] = []
    for event in intervals:
        key = primary_correlation_key(event)
        if not key:
            continue
        fields = load_json_dict(event.get("fields_json"))
        disconnected_at = fields.get("disconnected_at")
        duration = fields.get("duration_seconds")
        label = best_entity_label([event]) or key
        correlations.append(
            make_correlation(
                rule_id="wifi.station_history_interval",
                correlation_type="session_fragment",
                entity_key=key,
                entity_label=label,
                events=[event],
                severity="info",
                confidence=event.get("confidence") or "high",
                summary=f"{label}: retained WLAN station interval from {event.get('event_time')} to {disconnected_at or 'open'}",
                extra_fields={
                    "duration_seconds": duration,
                    "disconnected_at": disconnected_at,
                    "reason": "FRITZ!Box support-data retained a station-history interval for this WLAN station.",
                },
                link_reason="Retained STATION_LIST interval evidence for this station.",
            )
        )
    return correlations


def build_dhcp_lease_change_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    leases = [event for event in events if event.get("event_kind") == "network.dhcp_lease_observed"]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in leases:
        if meaningful_mac(event.get("mac")):
            grouped[f"mac:{str(event['mac']).casefold()}"].append(event)

    correlations: list[dict[str, Any]] = []
    for key, items in grouped.items():
        ips = sorted({str(event.get("ip")) for event in items if meaningful_ip(event.get("ip"))})
        hostnames = sorted({str(event.get("hostname")) for event in items if clean(event.get("hostname"))})
        if len(ips) < 2 and len(hostnames) < 2:
            continue
        label = best_entity_label(items) or key
        correlations.append(
            make_correlation(
                rule_id="network.dhcp_lease_change",
                correlation_type="rule_match",
                entity_key=key,
                entity_label=label,
                events=items,
                severity="low",
                confidence=window_confidence(items),
                summary=f"{label}: DHCP lease identity changed across retained lease rows",
                extra_fields={
                    "ips": ips,
                    "hostnames": hostnames,
                    "reason": "Same MAC appears with multiple retained DHCP lease IPs or hostnames in this run.",
                },
                link_reason="DHCP lease row included in same-MAC lease-change comparison.",
            )
        )
    return correlations


def wifi_session_marker(event: dict[str, Any]) -> bool:
    return is_wifi_connect_event(event) or is_wifi_disconnect_event(event)


def is_wifi_connect_event(event: dict[str, Any]) -> bool:
    kind = clean(event.get("event_kind")) or ""
    action = clean(event.get("action")) or ""
    outcome = clean(event.get("outcome")) or ""
    if kind in {"wifi.connected", "wifi.ap_sta_connected"}:
        return True
    return action in {"connect", "ap_sta_connected"} and outcome in {"success", "connected", "observed"}


def is_wifi_disconnect_event(event: dict[str, Any]) -> bool:
    kind = clean(event.get("event_kind")) or ""
    action = clean(event.get("action")) or ""
    outcome = clean(event.get("outcome")) or ""
    if kind in {"wifi.disconnected", "wifi.ap_sta_disconnected", "wifi.hostapd_disconnected"}:
        return True
    return action in {"disconnect", "ap_sta_disconnected"} and outcome in {"success", "disconnected", "observed"}


def build_exposure_correlations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exposures = [event for event in events if actionable_exposure_event(event)]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in exposures:
        key = primary_correlation_key(event) or router_exposure_key(event)
        grouped[key].append(event)

    correlations: list[dict[str, Any]] = []
    for key, items in grouped.items():
        label = best_entity_label(items) or key
        correlations.append(
            make_correlation(
                rule_id="security.exposure_indicator",
                correlation_type="rule_match",
                entity_key=key,
                entity_label=label,
                events=items,
                severity=max((normalize_severity(item.get("severity")) for item in items), key=severity_weight),
                confidence=window_confidence(items),
                summary=f"{label}: router exposure indicator observed in {len(items)} events",
                extra_fields={
                    "reason": "Remote administration, MyFRITZ, VPN, UPnP/PCP, or WAN mapping evidence observed."
                },
                link_reason="Exposure-related event included in rule input.",
            )
        )
    return correlations


def make_correlation(
    *,
    rule_id: str,
    correlation_type: str,
    entity_key: str,
    entity_label: str,
    events: list[dict[str, Any]],
    severity: str,
    confidence: str,
    summary: str,
    extra_fields: dict[str, Any] | None = None,
    link_reason: str = "Entity evidence included in correlation.",
) -> dict[str, Any]:
    categories = sorted({clean(item.get("event_category")) or "unknown" for item in events})
    tags = sorted({tag for item in events for tag in load_json_list(item.get("tags_json"))})
    times = sorted_event_times(events)
    record_refs = sorted({f"{item.get('record_type')}:{item.get('record_id')}" for item in events})
    event_kinds = sorted({clean(item.get("event_kind")) or "unknown" for item in events})
    sources = sorted({clean(item.get("source")) or "unknown" for item in events})
    aliases = sorted({key for item in events for key in correlation_keys(item)})
    fields = {
        "entity_key": entity_key,
        "entity_label": entity_label,
        "entity_aliases": aliases,
        "record_ref_count": len(record_refs),
        "record_refs": record_refs[:MAX_CORRELATION_RECORD_REFS],
        "categories": categories,
        "event_kinds": event_kinds,
        "sources": sources,
        "rule_id": rule_id,
        "rule_version": CORRELATION_RULE_VERSION,
        **(extra_fields or {}),
    }
    searchable = searchable_text({**fields, "summary": summary, "severity": severity, "tags": tags})
    return {
        "correlation_type": correlation_type,
        "rule_id": rule_id,
        "rule_version": CORRELATION_RULE_VERSION,
        "confidence": confidence,
        "window_start": times[0] if times else None,
        "window_end": times[-1] if times else None,
        "entity_key": entity_key,
        "entity_label": entity_label,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "event_count": len(events),
        "categories_json": json.dumps(categories, sort_keys=True),
        "tags_json": json.dumps(tags, sort_keys=True),
        "severity": normalize_severity(severity),
        "summary": summary,
        "fields_json": json.dumps(fields, sort_keys=True, default=str),
        "searchable": searchable,
        "_event_links": correlation_event_links(events, link_reason),
    }


def insert_siem_correlation(conn: sqlite3.Connection, run_id: int, row: dict[str, Any]) -> int:
    cursor = conn.execute(
        """
        INSERT INTO siem_correlations(
            run_id, correlation_type, rule_id, rule_version, confidence, window_start, window_end,
            entity_key, entity_label, first_seen, last_seen, event_count,
            categories_json, tags_json, severity, summary, fields_json, searchable
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            row["correlation_type"],
            row["rule_id"],
            row["rule_version"],
            row["confidence"],
            row["window_start"],
            row["window_end"],
            row["entity_key"],
            row["entity_label"],
            row["first_seen"],
            row["last_seen"],
            row["event_count"],
            row["categories_json"],
            row["tags_json"],
            row["severity"],
            row["summary"],
            row["fields_json"],
            row["searchable"],
        ),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("SIEM correlation insert did not return a row id")
    return int(cursor.lastrowid)


def insert_siem_correlation_events(
    conn: sqlite3.Connection,
    run_id: int,
    correlation_id: int,
    links: list[dict[str, Any]],
) -> int:
    inserted = 0
    for link in links[:MAX_CORRELATION_EVENT_LINKS]:
        event_id = link.get("event_id")
        if not event_id:
            continue
        conn.execute(
            """
            INSERT INTO siem_correlation_events(
                run_id, correlation_id, event_id, role, reason, weight
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                correlation_id,
                event_id,
                link.get("role") or "evidence",
                link.get("reason") or "Correlation evidence.",
                int(link.get("weight") or 1),
            ),
        )
        inserted += 1
    return inserted


def add_siem_fts(conn: sqlite3.Connection, record_type: str, record_id: int, content: str) -> None:
    conn.execute(
        "INSERT INTO records_fts(record_type, record_id, content) VALUES (?, ?, ?)",
        (record_type, record_id, content),
    )


def classify_router_log(message: str, category: str) -> dict[str, Any]:
    return parse_fritzbox_log_message(message, category)


def with_update(base: dict[str, Any], **updates: Any) -> dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if key == "tags":
            merged["tags"] = [*merged.get("tags", []), *list(value or [])]
        else:
            merged[key] = value
    return merged


def select_dicts(conn: sqlite3.Connection, sql: str, params: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params)]


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", [table]).fetchone()
    return row is not None


def observed_table_rows(
    conn: sqlite3.Connection,
    table: str,
    observation_type: str,
    run_id: int,
) -> list[dict[str, Any]]:
    return select_dicts(
        conn,
        f"""
        SELECT DISTINCT t.*
        FROM {table} t
        WHERE t.run_id = ?
           OR t.id IN (
                SELECT record_table_id
                FROM record_observations
                WHERE run_id = ?
                  AND record_type = ?
                  AND record_table_id IS NOT NULL
           )
        """,
        [run_id, run_id, observation_type],
    )


def clean(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    if not rendered or rendered.casefold() in {"none", "null", "undefined"}:
        return None
    return rendered


def clean_json(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None and item != ""}


def first_mac(value: str) -> str | None:
    match = MAC_RE.search(value or "")
    return normalize_mac(match.group(0)) if match else None


def normalize_mac(value: Any) -> str | None:
    rendered = clean(value)
    if not rendered:
        return None
    match = MAC_RE.search(rendered)
    return match.group(0).lower() if match else rendered.lower()


def meaningful_mac(value: Any) -> bool:
    normalized = normalize_mac(value)
    if not normalized or not MAC_RE.fullmatch(normalized):
        return False
    if normalized in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return False
    first_octet = int(normalized.split(":", 1)[0], 16)
    return not bool(first_octet & 1)


def first_ip(value: str) -> str | None:
    match = IP_RE.search(value or "")
    return match.group(0) if match else None


def meaningful_ip(value: Any) -> bool:
    rendered = clean(value)
    if not rendered or not IP_RE.fullmatch(rendered):
        return False
    parts = [int(part) for part in rendered.split(".")]
    if parts == [0, 0, 0, 0] or parts == [255, 255, 255, 255]:
        return False
    if parts[0] == 127:
        return False
    return not 224 <= parts[0] <= 239


def parse_hostname(message: str, mac: str | None, ip: str | None) -> str | None:
    cleaned = message
    for value in (mac, ip):
        if value:
            cleaned = cleaned.replace(value, " ")
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[1]
    candidate = re.split(r"[,;(]", cleaned.strip(), maxsplit=1)[0].strip()
    if not plausible_hostname(candidate):
        return None
    if 1 < len(candidate) <= 80 and not first_ip(candidate) and not first_mac(candidate):
        return candidate
    return None


def plausible_hostname(value: str) -> bool:
    if not value or len(value) > 80:
        return False
    if any(token in value for token in ("=", "|", "[", "]", "{", "}", "0x")):
        return False
    lowered = value.casefold()
    if lowered in {
        "ap-sta-connected",
        "ap-sta-disconnected",
        "guest",
        "ip",
        "ipv4",
        "ipv6",
        "lan",
        "my_ipaddress",
        "not set",
        "operator",
        "remote_addr",
        "wan",
    }:
        return False
    if lowered.startswith(("ipv4:", "ipv6:", "wan:", "lan:")):
        return False
    if any(token in lowered for token in ("ieee 802.11", "sta_module", "update_topology", "avmipc", "shadow:")):
        return False
    if "_" in value:
        return False
    if len(value.split()) > 4:
        return False
    if re.fullmatch(r"\d+\s+\d+\s+secs?", lowered):
        return False
    if re.fullmatch(r"\d+\s+'[^']+'", value):
        return False
    if re.search(r"\b[0-9a-fA-F]{0,4}:[0-9a-fA-F:]{2,}\b", value):
        return False
    return bool(re.search(r"[A-Za-z]", value))


def parse_interface(message: str) -> str | None:
    match = re.search(r"\b(wlan\d+|wifi\d+|ath\d+|lan\d+|guest|mesh|radio\s+\d+)\b", message or "", re.I)
    return match.group(0) if match else None


def slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").casefold()).strip("_")


def truthy(value: Any) -> bool:
    return str(value).strip().casefold() in {"1", "true", "yes", "ja", "on", "enabled", "aktiv", "active"}


def normalize_severity(value: Any) -> str:
    severity = slug(value) or "info"
    return severity if severity in SEVERITY_WEIGHT else "info"


def severity_weight(value: Any) -> int:
    return SEVERITY_WEIGHT.get(normalize_severity(value), 0)


def wifi_outcome(event: str) -> str:
    lowered = event.casefold()
    if "fail" in lowered or "failed" in lowered:
        return "failure"
    if "disconnect" in lowered or "abgemeldet" in lowered:
        return "disconnected"
    if "connect" in lowered or "associated" in lowered or "angemeldet" in lowered:
        return "connected"
    return "observed"


def entity_label(hostname: str | None, mac: str | None, ip: str | None) -> str:
    return clean(hostname) or clean(mac) or clean(ip) or ""


def device_label(row: dict[str, Any]) -> str:
    return (
        entity_label(row.get("hostname") or row.get("friendly_name"), row.get("mac"), row.get("ip")) or "unknown device"
    )


def searchable_text(row: dict[str, Any]) -> str:
    values: list[str] = []
    for value in row.values():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            values.append(json.dumps(value, sort_keys=True, default=str))
        else:
            values.append(str(value))
    return " ".join(values)


def load_json_list(value: str | None) -> list[str]:
    try:
        payload = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item) for item in payload] if isinstance(payload, list) else []


def load_json_dict(value: str | None) -> dict[str, Any]:
    try:
        payload = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def correlation_event_links(events: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    links = []
    for event in events:
        event_id = event.get("siem_event_id")
        if not event_id:
            continue
        links.append(
            {
                "event_id": event_id,
                "role": event.get("event_kind") or "evidence",
                "reason": reason,
                "weight": max(severity_weight(event.get("severity")), 1),
            }
        )
    return links


def event_windows(events: list[dict[str, Any]], window_seconds: int, threshold: int) -> list[list[dict[str, Any]]]:
    windows: list[list[dict[str, Any]]] = []
    parsed: list[tuple[float, dict[str, Any]]] = []
    for event in events:
        timestamp = event_time_seconds(event.get("event_time"))
        if timestamp is not None:
            parsed.append((timestamp, event))
    parsed.sort(key=lambda item: item[0])
    index = 0
    while index < len(parsed):
        start_time = parsed[index][0]
        window_pairs = [
            (timestamp, event) for timestamp, event in parsed[index:] if 0 <= timestamp - start_time <= window_seconds
        ]
        window = [event for _timestamp, event in window_pairs]
        if len(window) >= threshold:
            windows.append(window)
            last_window_time = window_pairs[-1][0]
            while index < len(parsed) and parsed[index][0] <= last_window_time:
                index += 1
        else:
            index += 1
    return windows


def sorted_event_times(events: list[dict[str, Any]]) -> list[str]:
    parsed = [
        (timestamp, clean(event.get("event_time")))
        for event in events
        if (timestamp := event_time_seconds(event.get("event_time"))) is not None
    ]
    return [str(value) for _timestamp, value in sorted(parsed) if value]


def event_time_seconds(value: Any) -> float | None:
    rendered = clean(value)
    if not rendered:
        return None
    try:
        return datetime.fromisoformat(rendered.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def seconds_between(start: Any, end: Any) -> int | None:
    start_seconds = event_time_seconds(start)
    end_seconds = event_time_seconds(end)
    if start_seconds is None or end_seconds is None or end_seconds < start_seconds:
        return None
    return int(end_seconds - start_seconds)


def window_confidence(events: list[dict[str, Any]]) -> str:
    confidences = {clean(event.get("confidence")) for event in events}
    if confidences and confidences <= {"high", "exact"}:
        return "high"
    if "low" in confidences:
        return "low"
    return "medium"


def correlation_keys(event: dict[str, Any]) -> list[str]:
    keys = []
    mac = clean(event.get("mac"))
    if mac and meaningful_mac(mac):
        keys.append(f"mac:{mac.casefold()}")
    ip = clean(event.get("ip"))
    if ip and meaningful_ip(ip):
        keys.append(f"ip:{ip.casefold()}")
    hostname = clean(event.get("hostname"))
    if hostname and event.get("record_type") in HOSTNAME_CORRELATION_RECORD_TYPES and plausible_hostname(hostname):
        keys.append(f"host:{hostname.casefold()}")
    return keys


def primary_correlation_key(event: dict[str, Any]) -> str | None:
    keys = correlation_keys(event)
    for prefix in ("mac:", "ip:", "host:"):
        for key in keys:
            if key.startswith(prefix):
                return key
    return keys[0] if keys else None


def actionable_exposure_event(event: dict[str, Any]) -> bool:
    if event.get("event_kind") in {"security.wan_port_mapping", "security.wan_port_mapping_enabled"}:
        return event.get("outcome") == "enabled"
    if event.get("event_kind") in {
        "security.remote_admin_exposure",
        "security.myfritz_exposure",
        "security.vpn_exposure",
        "security.user_remote_rights",
        "security.automatic_port_sharing",
    }:
        return True
    if event.get("event_kind") != "security.exposure_event":
        return False
    if event.get("record_type") in {"wan_port_mappings", "hosts", "security_advisories"}:
        return True
    return bool(meaningful_mac(event.get("mac")) or meaningful_ip(event.get("ip")))


def router_exposure_key(event: dict[str, Any]) -> str:
    kind = clean(event.get("event_kind")) or "security.exposure"
    if kind == "security.user_remote_rights":
        subject = slug(event.get("hostname") or event.get("entity") or "")
        return f"router:user_rights:{subject or 'unknown'}"
    return f"router:{kind}"


def best_entity_label(events: list[dict[str, Any]]) -> str | None:
    for event in events:
        value = clean(event.get("hostname"))
        if event.get("record_type") in HOSTNAME_CORRELATION_RECORD_TYPES and value and plausible_hostname(value):
            return value
    for field in ("mac", "ip", "entity"):
        for event in events:
            value = clean(event.get(field))
            if field == "mac" and value and meaningful_mac(value):
                return value
            if field == "ip" and value and meaningful_ip(value):
                return value
            if field == "entity" and value and plausible_hostname(value):
                return value
    return None
