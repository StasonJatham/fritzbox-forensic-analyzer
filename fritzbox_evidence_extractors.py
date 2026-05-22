from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from fritzbox_artifact_normalizers import (
    extract_aha_device_stats,
    extract_data_lua_network_status,
    extract_data_lua_wlan_associations,
    extract_query_lua_user_right_advisories,
    extract_query_lua_wlan_associations,
    extract_telephony_context,
)
from fritzbox_evidence_tables import ADDITIONAL_EVIDENCE_TABLES

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ADVERTISEMENT_PROTOCOL_PATTERNS = {
    "UPnP": re.compile(r"\b(upnp|igd_fw_cnt_upnp|allow_pcp_and_upnp|igd|internetgatewaydevice)\b", re.I),
    "PCP": re.compile(r"\b(pcp|igd_fw_cnt_pcp)\b", re.I),
    "SSDP": re.compile(r"\b(ssdp|239\.255\.255\.250|1900/udp|udp.?1900)\b", re.I),
    "mDNS/Bonjour": re.compile(r"\b(mdns|bonjour|224\.0\.0\.251|5353/udp|udp.?5353)\b", re.I),
    "IGMP/Multicast": re.compile(r"\b(igmp|multicast|224\.0\.0\.|239\.)\b", re.I),
    "LLMNR": re.compile(r"\b(llmnr|224\.0\.0\.252|5355/udp|udp.?5355)\b", re.I),
    "NetBIOS": re.compile(r"\b(netbios|nbns|nbtns|137/udp|138/udp|udp.?137|udp.?138)\b", re.I),
    "ARP/Neighbor": re.compile(r"\b(arp|neighbou?r|ndp|neighbor solicitation|neighbor advertisement)\b", re.I),
    "DHCP": re.compile(r"\b(dhcp|bootp|67/udp|68/udp|udp.?67|udp.?68)\b", re.I),
}


def extract_additional_evidence(dataset: dict[str, Any], generated_at: str) -> dict[str, list[dict[str, Any]]]:
    from fritzbox_parsers import parse_support_wifi_details, parse_webui_typed_artifacts

    rows: dict[str, list[dict[str, Any]]] = {table: [] for table in ADDITIONAL_EVIDENCE_TABLES}
    for table, spec in ADDITIONAL_EVIDENCE_TABLES.items():
        for key in spec["dataset_keys"]:
            value = dataset.get(key)
            if isinstance(value, list):
                rows[table].extend([item for item in value if isinstance(item, dict)])
            elif isinstance(value, dict):
                rows[table].append(value)

    raw_exports = dataset.get("raw_exports") or {}
    tr064_raw = raw_exports.get("tr064_snapshot_json")
    if isinstance(tr064_raw, str):
        try:
            tr064 = json.loads(tr064_raw)
        except json.JSONDecodeError:
            tr064 = {}
    elif isinstance(tr064_raw, dict):
        tr064 = tr064_raw
    else:
        tr064 = {}
    if tr064:
        rows["host_filter_profiles"].extend(extract_host_filter_profiles(tr064))
        rows["wan_port_mappings"].extend(extract_wan_port_mappings(tr064))
        rows["wlan_radios"].extend(extract_wlan_radios(tr064))
        rows["wlan_associations"].extend(extract_wlan_associations(tr064, generated_at))
        rows["network_status_snapshots"].extend(extract_network_status_snapshots(tr064, generated_at))

    mesh_raw = raw_exports.get("mesh_list")
    rows["mesh_topology_links"].extend(extract_mesh_links(mesh_raw))
    rows["wan_port_mappings"].extend(extract_query_lua_port_mappings(raw_exports.get("query_lua_artifacts_json")))
    rows["wlan_associations"].extend(
        extract_query_lua_wlan_associations(raw_exports.get("query_lua_artifacts_json"), generated_at)
    )
    rows["wlan_associations"].extend(
        extract_data_lua_wlan_associations(raw_exports.get("data_lua_pages_json"), generated_at)
    )
    for table, parsed_rows in parse_support_wifi_details(raw_exports.get("support_data_txt"), generated_at).items():
        rows[table].extend(parsed_rows)
    for table, parsed_rows in parse_webui_typed_artifacts(raw_exports, generated_at).items():
        rows[table].extend(parsed_rows)
    rows["network_status_snapshots"].extend(
        extract_data_lua_network_status(raw_exports.get("data_lua_pages_json"), generated_at)
    )
    rows["network_status_snapshots"].extend(
        extract_aha_device_stats(raw_exports.get("aha_device_stats_json"), generated_at)
    )
    rows["network_status_snapshots"].extend(
        extract_telephony_context(
            raw_exports.get("call_list_xml"),
            raw_exports.get("phonebooks_xml_json"),
            generated_at,
        )
    )
    rows["security_advisories"].extend(
        extract_query_lua_user_right_advisories(raw_exports.get("query_lua_artifacts_json"))
    )
    rows["advertisement_hints"].extend(
        build_advertisement_hints(dataset, raw_exports, rows["wan_port_mappings"], generated_at)
    )

    if not rows["device_risk_summaries"]:
        rows["device_risk_summaries"].extend(build_device_risk_summaries(dataset))
    rows["security_advisories"].extend(build_security_advisories(dataset, raw_exports, rows))
    return rows


def normalize_additional_row(table: str, row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    if table == "host_filter_profiles":
        normalized.setdefault("profile_id", first_value(row, "profile_id", "uid", "id", "NewProfileID", "NewID"))
        normalized.setdefault("name", first_value(row, "name", "profile_name", "NewName", "NewProfileName"))
        normalized.setdefault("access_mode", first_value(row, "access_mode", "mode", "NewAccessMode"))
        normalized.setdefault("time_budget", first_value(row, "time_budget", "NewTimeBudget", "budget"))
        normalized.setdefault("blocked", first_value(row, "blocked", "NewBlocked", "is_blocked"))
        normalized.setdefault("devices_json", first_value(row, "devices_json", "devices", "assigned_devices"))
        normalized.setdefault("source", "X_AVM-DE_HostFilter:GetFilterProfiles")
    elif table == "mesh_topology_links":
        normalized.setdefault("link_type", first_value(row, "link_type", "type"))
        normalized.setdefault("node", first_value(row, "node", "device", "device_name"))
        normalized.setdefault("peer", first_value(row, "peer", "remote", "remote_name"))
        normalized.setdefault("rx", first_value(row, "rx", "cur_data_rate_rx"))
        normalized.setdefault("tx", first_value(row, "tx", "cur_data_rate_tx"))
        normalized.setdefault("source", "mesh_list")
    elif table == "wan_port_mappings":
        normalized.setdefault("protocol", first_value(row, "protocol", "NewProtocol"))
        normalized.setdefault("external_port", first_value(row, "external_port", "NewExternalPort"))
        normalized.setdefault("internal_client", first_value(row, "internal_client", "NewInternalClient"))
        normalized.setdefault("internal_port", first_value(row, "internal_port", "NewInternalPort"))
        normalized.setdefault("description", first_value(row, "description", "NewPortMappingDescription"))
        normalized.setdefault("enabled", first_value(row, "enabled", "NewEnabled"))
        normalized.setdefault("remote_host", first_value(row, "remote_host", "NewRemoteHost"))
        normalized.setdefault("lease_duration", first_value(row, "lease_duration", "NewLeaseDuration"))
        normalized.setdefault("source", "WANIPConn:GetGenericPortMappingEntry")
    elif table == "wlan_radios":
        normalized.setdefault("radio_index", first_value(row, "radio_index", "index"))
        normalized.setdefault("total_associations", first_value(row, "total_associations", "associations"))
        normalized.setdefault("source", "WLANConfiguration:GetInfo")
    elif table == "wlan_associations":
        normalized.setdefault("observed_at", first_value(row, "observed_at", "timestamp", "last_observed"))
        normalized.setdefault(
            "association_index", first_value(row, "association_index", "index", "NewAssociatedDeviceIndex")
        )
        normalized.setdefault(
            "association_index", first_value(row, "association_index") or f"mesh:{row.get('mac') or ''}"
        )
        normalized.setdefault("mac", first_value(row, "mac", "NewAssociatedDeviceMACAddress"))
        normalized.setdefault(
            "ip", first_value(row, "ip", "NewAssociatedDeviceIPAddress") or ", ".join(row.get("ip_addresses") or [])
        )
        normalized.setdefault("hostname", first_value(row, "hostname", "NewAssociatedDeviceName"))
        normalized.setdefault("auth_state", first_value(row, "auth_state", "NewAssociatedDeviceAuthState"))
        normalized.setdefault("channel", first_value(row, "channel", "current_channel"))
        normalized.setdefault("source", "WLANConfiguration:GetGenericAssociatedDeviceInfo")
    elif table == "advertisement_hints":
        normalized.setdefault("observed_at", first_value(row, "observed_at", "timestamp"))
        normalized.setdefault("hint_type", first_value(row, "hint_type", "type"))
        normalized.setdefault("protocol", first_value(row, "protocol", "service", "keyword"))
        normalized.setdefault("hostname", first_value(row, "hostname", "host", "device"))
        normalized.setdefault("mac", first_value(row, "mac", "client_mac"))
        normalized.setdefault("ip", first_value(row, "ip", "client_ip", "internal_client"))
        normalized.setdefault("direction", first_value(row, "direction"))
        normalized.setdefault("confidence", first_value(row, "confidence", "derived_time_confidence"))
        normalized.setdefault("summary", first_value(row, "summary", "message", "raw_text"))
        normalized.setdefault("source", first_value(row, "source", "artifact"))
    elif table == "network_status_snapshots":
        normalized.setdefault("observed_at", first_value(row, "observed_at", "timestamp"))
        normalized.setdefault("area", first_value(row, "area", "section"))
        normalized.setdefault("metric", first_value(row, "metric", "key", "name"))
        normalized.setdefault("value", first_value(row, "value"))
        normalized.setdefault("unit", first_value(row, "unit"))
        normalized.setdefault("source", first_value(row, "source"))
        normalized.setdefault("confidence", first_value(row, "confidence"))
    elif table == "device_risk_summaries":
        device_key = first_value(row, "device_key", "mac", "ip", "hostname")
        normalized.setdefault("device_key", device_key)
        normalized.setdefault("reasons_json", first_value(row, "reasons_json", "reasons"))
        normalized.setdefault("source", "derived_device_risk")
    elif table == "security_advisories":
        normalized.setdefault("advisory_id", first_value(row, "advisory_id", "id", "rule_id"))
        normalized.setdefault("severity", first_value(row, "severity", "risk_level", "level"))
        normalized.setdefault("category", first_value(row, "category", "area"))
        normalized.setdefault("title", first_value(row, "title", "summary"))
        normalized.setdefault("subject", first_value(row, "subject", "device", "host", "service"))
        normalized.setdefault("status", first_value(row, "status") or "review")
        normalized.setdefault("recommendation", first_value(row, "recommendation", "remediation"))
        normalized.setdefault("source", first_value(row, "source") or "derived_security_advisory")
        normalized.setdefault("confidence", first_value(row, "confidence") or "medium")
        normalized.setdefault("evidence_json", first_value(row, "evidence_json", "evidence"))
        normalized.setdefault("evidence_level", "inferred")
        normalized.setdefault(
            "evidence_note",
            "Security advisory derived from parsed FRITZ!Box settings and retained evidence; verify raw artifacts before remediation.",
        )
    return normalized


def extract_host_filter_profiles(tr064: dict[str, Any]) -> list[dict[str, Any]]:
    response = ((tr064.get("actions") or {}).get("host_filter_profiles") or {}).get("response") or {}
    profiles = (
        response.get("NewProfileList")
        or response.get("NewFilterProfileList")
        or response.get("profiles")
        or response.get("Profiles")
    )
    if isinstance(profiles, list):
        return [
            {**profile, "source": "X_AVM-DE_HostFilter:GetFilterProfiles"}
            for profile in profiles
            if isinstance(profile, dict)
        ]
    if isinstance(profiles, str) and profiles.strip():
        return [{"name": profiles, "source": "X_AVM-DE_HostFilter:GetFilterProfiles", "raw_profile_list": profiles}]
    return []


def extract_wan_port_mappings(tr064: dict[str, Any]) -> list[dict[str, Any]]:
    indexed = tr064.get("indexed_results") or {}
    rows: list[dict[str, Any]] = []
    for key in ("wan_ip_port_mappings", "wan_ppp_port_mappings"):
        for item in (indexed.get(key) or {}).get("items") or []:
            if not isinstance(item, dict) or not item.get("ok"):
                continue
            response = item.get("response") or {}
            if isinstance(response, dict):
                rows.append({**response, "source": key})
    return rows


def extract_query_lua_port_mappings(content: str | None) -> list[dict[str, Any]]:
    if not content:
        return []
    try:
        artifacts = json.loads(content)
    except json.JSONDecodeError:
        return []
    port_sharing = artifacts.get("port_sharing") or {}
    data = port_sharing.get("data") if isinstance(port_sharing, dict) else {}
    rows = data.get("port_sharing") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    mappings: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        mappings.append(
            {
                "protocol": row.get("protocol"),
                "external_port": row.get("port"),
                "internal_client": row.get("fwip"),
                "internal_port": row.get("fwport"),
                "description": row.get("description"),
                "enabled": row.get("enabled") if row.get("enabled") not in (None, "") else "unknown",
                "remote_host": row.get("sourceip"),
                "lease_duration": None,
                "source": "query_lua_port_sharing",
                "record_index": index,
                "raw": row,
                "evidence_note": "Port-sharing rule parsed from internal FRITZ!Box query.lua response.",
            }
        )
    return mappings


def extract_wlan_radios(tr064: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for radio in tr064.get("wlan") or []:
        if not isinstance(radio, dict):
            continue
        info = (radio.get("info") or {}).get("response") or {}
        total = (radio.get("total_associations") or {}).get("response") or {}
        channel = (radio.get("channel_info") or {}).get("response") or {}
        stats = (radio.get("statistics") or {}).get("response") or {}
        rows.append(
            {
                "radio_index": radio.get("index"),
                "ssid": info.get("NewSSID"),
                "enabled": info.get("NewEnable"),
                "status": info.get("NewStatus"),
                "standard": info.get("NewStandard"),
                "channel": channel.get("NewChannel") or info.get("NewChannel"),
                "total_associations": total.get("NewTotalAssociations") or info.get("NewTotalAssociations"),
                "bytes_sent": stats.get("NewTotalBytesSent"),
                "bytes_received": stats.get("NewTotalBytesReceived"),
                "source": f"WLANConfiguration:{radio.get('index')}:GetInfo",
            }
        )
    return rows


def extract_wlan_associations(tr064: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, value in (tr064.get("indexed_results") or {}).items():
        match = re.fullmatch(r"wlan_(\d+)_associations", str(key))
        if not match:
            continue
        for index, item in enumerate((value or {}).get("items") or []):
            if not isinstance(item, dict) or not item.get("ok"):
                continue
            response = item.get("response") or {}
            if isinstance(response, dict):
                rows.append(
                    {
                        **response,
                        "observed_at": observed_at,
                        "radio_index": match.group(1),
                        "association_index": response.get("NewAssociatedDeviceIndex") or str(index),
                        "source": key,
                    }
                )
    return rows


def extract_network_status_snapshots(tr064: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    actions = tr064.get("actions") or {}
    action_specs = {
        "wan_common_link": ("wan", "WANCommonIFC:GetCommonLinkProperties"),
        "wan_common_bytes_sent": ("wan", "WANCommonIFC:GetTotalBytesSent"),
        "wan_common_bytes_received": ("wan", "WANCommonIFC:GetTotalBytesReceived"),
        "wan_common_packets_sent": ("wan", "WANCommonIFC:GetTotalPacketsSent"),
        "wan_common_packets_received": ("wan", "WANCommonIFC:GetTotalPacketsReceived"),
        "wan_common_online_monitor": ("wan", "WANCommonIFC:X_AVM-DE_GetOnlineMonitor"),
        "wan_ip_info": ("wan", "WANIPConn:GetInfo"),
        "wan_ip_status": ("wan", "WANIPConn:GetStatusInfo"),
        "wan_ip_external": ("wan", "WANIPConn:GetExternalIPAddress"),
        "wan_dsl_interface": ("dsl", "WANDSLInterfaceConfig:GetInfo"),
        "wan_dsl_stats": ("dsl", "WANDSLInterfaceConfig:GetStatisticsTotal"),
        "wan_dsl_link": ("dsl", "WANDSLLinkConfig:GetInfo"),
        "lan_host_config": ("lan", "LANHostConfigManagement:GetInfo"),
        "lan_eth_info": ("lan", "LANEthernetInterfaceConfig:GetInfo"),
        "lan_eth_stats": ("lan", "LANEthernetInterfaceConfig:GetStatistics"),
        "time_info": ("router", "Time:GetInfo"),
        "device_info": ("router", "DeviceInfo:GetInfo"),
        "user_interface": ("router", "UserInterface:GetInfo"),
    }
    for key, (area, source) in action_specs.items():
        result = actions.get(key) or {}
        response = result.get("response") or {}
        if not isinstance(response, dict):
            continue
        for metric, value in response.items():
            if value in (None, ""):
                continue
            rows.append(
                {
                    "observed_at": observed_at,
                    "area": area,
                    "metric": metric,
                    "value": value,
                    "unit": metric_unit(metric),
                    "source": source,
                    "confidence": "high" if result.get("ok") else "low",
                    "evidence_level": "parsed_from_raw",
                    "evidence_note": "Point-in-time TR-064 network/router status value; use repeated acquisitions for deltas.",
                }
            )
    for radio in tr064.get("wlan") or []:
        if not isinstance(radio, dict):
            continue
        radio_index = radio.get("index")
        for section, result in radio.items():
            if section == "index" or not isinstance(result, dict):
                continue
            response = result.get("response") or {}
            if not isinstance(response, dict):
                continue
            for metric, value in response.items():
                if value in (None, ""):
                    continue
                rows.append(
                    {
                        "observed_at": observed_at,
                        "area": "wlan",
                        "metric": f"radio_{radio_index}_{metric}",
                        "value": value,
                        "unit": metric_unit(metric),
                        "source": f"WLANConfiguration:{radio_index}:{section}",
                        "confidence": "high" if result.get("ok") else "low",
                        "evidence_level": "parsed_from_raw",
                        "evidence_note": "Point-in-time WLAN radio status/counter value; use repeated acquisitions for deltas.",
                    }
                )
    return rows


def metric_unit(metric: str) -> str | None:
    lower = metric.casefold()
    if "byte" in lower:
        return "bytes"
    if "packet" in lower:
        return "packets"
    if "bitrate" in lower or "speed" in lower:
        return "bit/s"
    if "snr" in lower or "noise" in lower:
        return "dB"
    if "attenuation" in lower:
        return "dB"
    if "time" in lower:
        return "time"
    return None


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


def extract_mesh_links(content: Any) -> list[dict[str, Any]]:
    if not content:
        return []
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
    elif isinstance(content, dict):
        data = content
    else:
        return []
    rows: list[dict[str, Any]] = []
    for node in data.get("nodes") or []:
        for interface in node.get("node_interfaces") or []:
            for link in interface.get("node_links") or []:
                rows.append(
                    {
                        "node": node.get("device_name") or node.get("device_friendly_name"),
                        "node_mac": node.get("device_mac_address"),
                        "interface": interface.get("name") or interface.get("type"),
                        "peer": link.get("remote_name") or link.get("name"),
                        "peer_mac": link.get("remote_mac") or link.get("mac"),
                        "link_type": link.get("type") or interface.get("type"),
                        "state": link.get("state"),
                        "last_connected": unix_seconds_to_iso(link.get("last_connected")),
                        "rx": link.get("cur_data_rate_rx"),
                        "tx": link.get("cur_data_rate_tx"),
                        "source": "mesh_list",
                    }
                )
    return rows


def build_advertisement_hints(
    dataset: dict[str, Any],
    raw_exports: dict[str, Any],
    wan_port_mappings: list[dict[str, Any]],
    observed_at: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    host_index = host_lookup_index(dataset.get("known_hosts") or [])
    for host in dataset.get("known_hosts") or []:
        if not isinstance(host, dict):
            continue
        hostname = first_value(host, "hostname", "friendly_name", "name")
        mac = first_value(host, "mac", "mac_address")
        ip = first_value(host, "ip", "ipv4")
        if truthy_value(host.get("allow_pcp_and_upnp")):
            rows.append(
                advertisement_hint_row(
                    observed_at=observed_at,
                    hint_type="router_upnp_pcp_policy",
                    protocol="UPnP/PCP",
                    hostname=hostname,
                    mac=mac,
                    ip=ip,
                    direction="client_to_router_permission",
                    confidence="medium",
                    summary="FRITZ!Box host state allows PCP/UPnP for this device.",
                    source="host_table",
                )
            )
        for key, protocol in (("upnp_count", "UPnP"), ("pcp_count", "PCP")):
            count = int_string(host.get(key))
            if not count:
                continue
            rows.append(
                advertisement_hint_row(
                    observed_at=observed_at,
                    hint_type="router_mapping_counter",
                    protocol=protocol,
                    hostname=hostname,
                    mac=mac,
                    ip=ip,
                    direction="client_to_router_counter",
                    confidence="medium",
                    summary=f"FRITZ!Box host state reports {count} {protocol} mapping counter(s).",
                    source="host_table",
                )
            )

    for mapping in wan_port_mappings:
        if not isinstance(mapping, dict):
            continue
        ip = first_value(mapping, "internal_client", "NewInternalClient")
        host = host_index.get(str(ip or "").casefold(), {})
        external = first_value(mapping, "external_port", "NewExternalPort")
        proto = first_value(mapping, "protocol", "NewProtocol")
        description = first_value(mapping, "description", "NewPortMappingDescription")
        rows.append(
            advertisement_hint_row(
                observed_at=observed_at,
                hint_type="wan_port_mapping_state",
                protocol="UPnP/PCP candidate",
                hostname=first_value(host, "hostname", "friendly_name"),
                mac=first_value(host, "mac", "mac_address"),
                ip=ip,
                direction="router_to_wan_exposure",
                confidence="medium",
                summary=(
                    f"Router has {proto or 'unknown'} WAN mapping {external or '?'}"
                    f" to {ip or 'unknown'}"
                    f"{f' ({description})' if description else ''}."
                ),
                source=first_value(mapping, "source") or "wan_port_mappings",
            )
        )

    rows.extend(raw_advertisement_hints(raw_exports, host_index, observed_at))
    return rows


def advertisement_hint_row(**values: Any) -> dict[str, Any]:
    return {
        **values,
        "evidence_level": "inferred",
        "evidence_note": (
            "Best-effort advertisement/broadcast hint from retained FRITZ!Box artifacts or router state; "
            "not packet-level proof of every broadcast or service advertisement."
        ),
    }


def raw_advertisement_hints(
    raw_exports: dict[str, Any], host_index: dict[str, dict[str, Any]], observed_at: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source, content in raw_exports.items():
        text_content = artifact_text(content)
        if not text_content:
            continue
        per_source_protocol_counts: dict[str, int] = {}
        for protocol, pattern in ADVERTISEMENT_PROTOCOL_PATTERNS.items():
            for match in pattern.finditer(text_content):
                if per_source_protocol_counts.get(protocol, 0) >= 12 or len(rows) >= 250:
                    break
                snippet = artifact_snippet(text_content, match.start())
                key = (str(source), protocol, snippet)
                if key in seen:
                    continue
                seen.add(key)
                per_source_protocol_counts[protocol] = per_source_protocol_counts.get(protocol, 0) + 1
                mac = first_regex(MAC_RE, snippet)
                ip = first_regex(IPV4_RE, snippet)
                host = host_index.get(str(mac or "").casefold()) or host_index.get(str(ip or "").casefold()) or {}
                rows.append(
                    advertisement_hint_row(
                        observed_at=observed_at,
                        hint_type="raw_artifact_keyword",
                        protocol=protocol,
                        hostname=first_value(host, "hostname", "friendly_name"),
                        mac=mac or first_value(host, "mac", "mac_address"),
                        ip=ip or first_value(host, "ip", "ipv4"),
                        direction="unknown_retained_artifact",
                        confidence="low",
                        summary=f"{protocol} keyword hit in {source}: {snippet}",
                        source=source,
                    )
                )
            if len(rows) >= 250:
                break
    return rows


def host_lookup_index(hosts: list[Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for key in ("mac", "mac_address", "ip", "ipv4", "hostname", "friendly_name"):
            value = host.get(key)
            if value not in (None, ""):
                index[str(value).casefold()] = host
    return index


def artifact_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    if isinstance(content, (dict, list)):
        return json.dumps(content, sort_keys=True, default=str)
    if content is None:
        return ""
    return str(content)


def artifact_snippet(content: str, offset: int, size: int = 360) -> str:
    start = max(0, offset - size // 2)
    end = min(len(content), offset + size // 2)
    snippet = re.sub(r"\s+", " ", content[start:end]).strip()
    return snippet[:size]


def first_regex(pattern: re.Pattern[str], content: str) -> str | None:
    match = pattern.search(content)
    return match.group(0) if match else None


def int_string(value: Any) -> int:
    try:
        return int(str(value or "0").strip())
    except (TypeError, ValueError):
        return 0


def build_device_risk_summaries(dataset: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    mappings_by_client: dict[str, int] = {}
    for mapping in dataset.get("wan_port_mappings") or dataset.get("wan_exposure") or []:
        if isinstance(mapping, dict) and mapping.get("internal_client"):
            client = str(mapping["internal_client"])
            mappings_by_client[client] = mappings_by_client.get(client, 0) + 1
    for host in dataset.get("known_hosts") or []:
        if not isinstance(host, dict):
            continue
        reasons: list[str] = []
        score = 0
        if truthy_value(host.get("allow_pcp_and_upnp")):
            reasons.append("PCP/UPnP allowed for host")
            score += 30
        for key, label in (("pcp_count", "PCP mappings"), ("upnp_count", "UPnP mappings")):
            try:
                count = int(host.get(key) or 0)
            except (TypeError, ValueError):
                count = 0
            if count:
                reasons.append(f"{count} {label}")
                score += min(count * 10, 30)
        if host.get("ip") in mappings_by_client:
            reasons.append(f"{mappings_by_client[str(host['ip'])]} WAN port mappings target host")
            score += 40
        if truthy_value(host.get("myfritz_enabled")):
            reasons.append("MyFRITZ enabled for host")
            score += 10
        if not reasons:
            continue
        level = "high" if score >= 60 else "medium" if score >= 30 else "low"
        rows.append(
            {
                "device_key": host.get("mac") or host.get("ip") or host.get("hostname"),
                "hostname": host.get("hostname"),
                "mac": host.get("mac"),
                "ip": host.get("ip"),
                "risk_level": level,
                "risk_score": str(score),
                "reasons_json": reasons,
                "summary": "; ".join(reasons),
                "source": "derived_device_risk",
                "evidence_level": "inferred",
                "evidence_note": "Derived from host attributes and WAN exposure evidence; review raw settings before drawing conclusions.",
            }
        )
    return rows


def build_security_advisories(
    dataset: dict[str, Any],
    raw_exports: dict[str, Any],
    extracted: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    generated_at = str(dataset.get("generated_at") or datetime.now().astimezone().isoformat())
    known_hosts = [host for host in dataset.get("known_hosts") or [] if isinstance(host, dict)]
    event_log = [event for event in dataset.get("event_log") or [] if isinstance(event, dict)]
    wan_mappings = [row for row in extracted.get("wan_port_mappings", []) if isinstance(row, dict)]
    wlan_radios = [row for row in extracted.get("wlan_radios", []) if isinstance(row, dict)]
    network_status = [row for row in extracted.get("network_status_snapshots", []) if isinstance(row, dict)]
    raw_text = "\n".join(f"{name}\n{artifact_text(content)}" for name, content in raw_exports.items())

    for mapping in wan_mappings:
        if not truthy_value(first_value(mapping, "enabled", "NewEnabled")):
            continue
        external = first_value(mapping, "external_port", "NewExternalPort")
        internal_client = first_value(mapping, "internal_client", "NewInternalClient")
        internal_port = first_value(mapping, "internal_port", "NewInternalPort")
        protocol = first_value(mapping, "protocol", "NewProtocol")
        description = first_value(mapping, "description", "NewPortMappingDescription")
        severity = "critical" if str(external or "") in {"80", "443", "22", "3389", "5900", "8080", "8443"} else "high"
        rows.append(
            security_advisory_row(
                advisory_id="wan_port_mapping_enabled",
                severity=severity,
                category="WAN exposure",
                title="Enabled WAN port mapping exposes an internal service",
                subject=" ".join(
                    part
                    for part in [
                        str(protocol or "").upper(),
                        str(external or "?"),
                        "to",
                        str(internal_client or "unknown"),
                        str(internal_port or ""),
                    ]
                    if part
                ),
                recommendation=(
                    "Remove the port sharing rule unless it is explicitly required. Prefer VPN access, restrict the exposed "
                    "service, and confirm the internal device is patched."
                ),
                source=first_value(mapping, "source") or "wan_port_mappings",
                confidence="high",
                evidence={
                    "external_port": external,
                    "internal_client": internal_client,
                    "internal_port": internal_port,
                    "protocol": protocol,
                    "description": description,
                },
            )
        )

    for host in known_hosts:
        hostname = first_value(host, "hostname", "friendly_name", "name")
        mac = first_value(host, "mac", "mac_address")
        ip = first_value(host, "ip", "ipv4")
        subject = " / ".join(str(value) for value in (hostname, ip, mac) if value)
        if truthy_value(host.get("allow_pcp_and_upnp")):
            rows.append(
                security_advisory_row(
                    advisory_id="host_upnp_pcp_allowed",
                    severity="medium",
                    category="Automatic port sharing",
                    title="Device is allowed to create UPnP/PCP port mappings",
                    subject=subject or "Unknown host",
                    recommendation=(
                        "Disable autonomous port sharing for this device unless there is a documented need. Review existing "
                        "port mappings and application requirements."
                    ),
                    source="host_table",
                    confidence="medium",
                    evidence={
                        "hostname": hostname,
                        "mac": mac,
                        "ip": ip,
                        "allow_pcp_and_upnp": host.get("allow_pcp_and_upnp"),
                        "pcp_count": host.get("pcp_count"),
                        "upnp_count": host.get("upnp_count"),
                    },
                )
            )
        if int_string(host.get("upnp_count")) or int_string(host.get("pcp_count")):
            rows.append(
                security_advisory_row(
                    advisory_id="host_upnp_pcp_activity",
                    severity="medium",
                    category="Automatic port sharing",
                    title="Device has UPnP/PCP mapping counters",
                    subject=subject or "Unknown host",
                    recommendation="Inspect active WAN mappings and disable UPnP/PCP for devices that do not need inbound access.",
                    source="host_table",
                    confidence="medium",
                    evidence={
                        "hostname": hostname,
                        "mac": mac,
                        "ip": ip,
                        "pcp_count": host.get("pcp_count"),
                        "upnp_count": host.get("upnp_count"),
                    },
                )
            )
        if truthy_value(host.get("myfritz_enabled")):
            rows.append(
                security_advisory_row(
                    advisory_id="host_myfritz_enabled",
                    severity="medium",
                    category="Remote access",
                    title="MyFRITZ is enabled for a host",
                    subject=subject or "Unknown host",
                    recommendation="Confirm the MyFRITZ exposure is intentional and protected with strong credentials and MFA where available.",
                    source="host_table",
                    confidence="medium",
                    evidence={
                        "hostname": hostname,
                        "mac": mac,
                        "ip": ip,
                        "myfritz_enabled": host.get("myfritz_enabled"),
                    },
                )
            )

    for radio in wlan_radios:
        if not truthy_value(first_value(radio, "enabled", "NewEnable")):
            continue
        ssid = first_value(radio, "ssid", "NewSSID")
        security = first_value(radio, "security", "NewBeaconType", "beacon_type", "encryption")
        lower_security = str(security or "").casefold()
        if security and any(token in lower_security for token in ("none", "open", "wep")):
            rows.append(
                security_advisory_row(
                    advisory_id="wlan_insecure_encryption",
                    severity="critical" if "none" in lower_security or "open" in lower_security else "high",
                    category="Wireless security",
                    title="WLAN radio appears to use weak or no encryption",
                    subject=str(ssid or f"radio {radio.get('radio_index') or '?'}"),
                    recommendation="Use WPA2/WPA3 with a strong passphrase. Disable open or WEP networks.",
                    source=first_value(radio, "source") or "wlan_radios",
                    confidence="medium",
                    evidence={"ssid": ssid, "security": security, "radio_index": radio.get("radio_index")},
                )
            )
        if ssid and any(token in str(ssid).casefold() for token in ("guest", "gast")):
            rows.append(
                security_advisory_row(
                    advisory_id="guest_wlan_enabled",
                    severity="low",
                    category="Wireless security",
                    title="Guest WLAN appears enabled",
                    subject=str(ssid),
                    recommendation="Verify guest isolation, captive access expectations, and that guest clients cannot reach internal systems.",
                    source=first_value(radio, "source") or "wlan_radios",
                    confidence="low",
                    evidence={"ssid": ssid, "radio_index": radio.get("radio_index"), "enabled": radio.get("enabled")},
                )
            )

    for row in network_status:
        metric = str(first_value(row, "metric") or "")
        value = first_value(row, "value")
        if metric.endswith("NewUpgradeAvailable") and truthy_value(value):
            rows.append(
                security_advisory_row(
                    advisory_id="firmware_update_available",
                    severity="medium",
                    category="Firmware",
                    title="FRITZ!Box reports an available firmware update",
                    subject="Router firmware",
                    recommendation="Review and apply the firmware update after preserving evidence required for the case.",
                    source=first_value(row, "source") or "network_status_snapshots",
                    confidence="high",
                    evidence={"metric": metric, "value": value},
                )
            )
        if "AutoUpdate" in metric and str(value).casefold() in {"0", "off", "disabled", "false"}:
            rows.append(
                security_advisory_row(
                    advisory_id="auto_update_disabled",
                    severity="low",
                    category="Firmware",
                    title="Automatic firmware update appears disabled",
                    subject="Router firmware",
                    recommendation="Confirm patch-management policy and enable automatic updates where operationally acceptable.",
                    source=first_value(row, "source") or "network_status_snapshots",
                    confidence="medium",
                    evidence={"metric": metric, "value": value},
                )
            )

    failed_auth = [
        event
        for event in event_log
        if re.search(
            r"(failed|fehlgeschlagen|falsches|wrong|incorrect|kennwort)", str(event.get("message") or ""), re.I
        )
    ]
    if len(failed_auth) >= 3:
        rows.append(
            security_advisory_row(
                advisory_id="repeated_failed_login",
                severity="high" if len(failed_auth) >= 10 else "medium",
                category="Authentication",
                title="Repeated failed FRITZ!Box login attempts retained in logs",
                subject=f"{len(failed_auth)} retained failed-login events",
                recommendation="Review source IPs, change admin credentials if unexpected, and restrict remote/admin access paths.",
                source="device_log_xml",
                confidence="high",
                evidence={
                    "count": len(failed_auth),
                    "source_ips": sorted({str(event.get("ip")) for event in failed_auth if event.get("ip")}),
                    "first": min(
                        (str(event.get("timestamp")) for event in failed_auth if event.get("timestamp")), default=None
                    ),
                    "last": max(
                        (str(event.get("timestamp")) for event in failed_auth if event.get("timestamp")), default=None
                    ),
                },
            )
        )

    remote_patterns = {
        "remote_admin_enabled": r"(remote access|internet access to.*fritz|zugriff aus dem internet|fernzugriff|https-port)",
        "vpn_enabled": r"\b(wireguard|vpn|ipsec)\b",
        "exposed_router_service": r"(myfritz|fritz!nas|ftp server|webdav|portfreigabe|port sharing)",
    }
    for advisory_id, pattern in remote_patterns.items():
        match = re.search(pattern, raw_text, re.I)
        if not match:
            continue
        severity = "high" if advisory_id in {"remote_admin_enabled", "exposed_router_service"} else "low"
        title = {
            "remote_admin_enabled": "Raw settings mention possible remote router administration",
            "vpn_enabled": "VPN-related router setting or state retained",
            "exposed_router_service": "Raw settings mention externally reachable router/service exposure",
        }[advisory_id]
        recommendation = {
            "remote_admin_enabled": "Verify whether router administration from the internet is enabled. Disable it unless strictly required.",
            "vpn_enabled": "Confirm VPN users/keys are expected and revoke unused access.",
            "exposed_router_service": "Review internet-facing router services and disable unused exposure.",
        }[advisory_id]
        rows.append(
            security_advisory_row(
                advisory_id=advisory_id,
                severity=severity,
                category="Remote access",
                title=title,
                subject=match.group(0),
                recommendation=recommendation,
                source="raw_artifacts",
                confidence="low",
                evidence={"matched_text": artifact_snippet(raw_text, match.start(), 240)},
            )
        )

    if re.search(r"<q:Flag>\s*remote_login_service\s*</q:Flag>|remote_login_service", raw_text, re.I):
        rows.append(
            security_advisory_row(
                advisory_id="juis_remote_login_service_flag",
                severity="high",
                category="Remote access",
                title="Router metadata reports remote login service flag",
                subject="remote_login_service",
                recommendation=(
                    "Verify whether FRITZ!Box login from the internet or provider/remote-login service paths are enabled. "
                    "Disable unused remote access and prefer WireGuard/VPN-only administration."
                ),
                source="juis_boxinfo_xml",
                confidence="medium",
                evidence={"flag": "remote_login_service"},
            )
        )

    if re.search(r"<q:Flag>\s*2nd_factor_disabled\s*</q:Flag>|2nd_factor_disabled", raw_text, re.I):
        rows.append(
            security_advisory_row(
                advisory_id="juis_second_factor_disabled_flag",
                severity="medium",
                category="Authentication",
                title="Router metadata reports second factor disabled",
                subject="2nd_factor_disabled",
                recommendation=(
                    "Review FRITZ!Box login protection settings. For remote administration or MyFRITZ/VPN management, "
                    "enable the strongest available confirmation and use unique admin credentials."
                ),
                source="juis_boxinfo_xml",
                confidence="medium",
                evidence={"flag": "2nd_factor_disabled"},
            )
        )

    if re.search(r"<q:Flag>\s*mesh_master_no_trusted\s*</q:Flag>|mesh_master_no_trusted", raw_text, re.I):
        rows.append(
            security_advisory_row(
                advisory_id="juis_mesh_master_no_trusted_flag",
                severity="low",
                category="Mesh security",
                title="Router metadata reports mesh trust flag",
                subject="mesh_master_no_trusted",
                recommendation=(
                    "Verify mesh topology and trusted repeater/AP state in the FRITZ!Box UI. Unexpected mesh peers should "
                    "be removed before analysis continues."
                ),
                source="juis_boxinfo_xml",
                confidence="low",
                evidence={"flag": "mesh_master_no_trusted"},
            )
        )

    if "support_data_txt" in raw_exports or "config_export_file" in raw_exports:
        present = [name for name in ("support_data_txt", "config_export_file") if name in raw_exports]
        rows.append(
            security_advisory_row(
                advisory_id="sensitive_artifacts_retained",
                severity="low",
                category="Evidence handling",
                title="Sensitive support/config artifacts are retained in the local case database",
                subject=", ".join(present),
                recommendation="Protect the local database and exported forensic packages. Avoid sharing support/config artifacts without redaction.",
                source="raw_artifacts",
                confidence="high",
                evidence={"artifacts": present, "observed_at": generated_at},
            )
        )

    return dedupe_security_advisories(rows)


def security_advisory_row(**values: Any) -> dict[str, Any]:
    evidence = values.get("evidence") or {}
    return {
        **values,
        "status": values.get("status") or "review",
        "evidence_json": evidence,
        "evidence_level": "inferred",
        "evidence_note": (
            "Security advisory derived from parsed FRITZ!Box settings and retained evidence; "
            "verify raw artifacts before remediation."
        ),
    }


def dedupe_security_advisories(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for row in rows:
        key = "|".join(str(row.get(field) or "") for field in ("advisory_id", "subject", "source"))
        current = deduped.get(key)
        if not current or severity_order.get(str(row.get("severity")), 0) > severity_order.get(
            str(current.get("severity")), 0
        ):
            deduped[key] = row
    return list(deduped.values())


def first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def json_column_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, bool):
        return "1" if value else "0"
    return value


def keyed_record_key(row: dict[str, Any], fields: tuple[str, ...]) -> str:
    values = {field: json_column_value(row.get(field)) for field in fields}
    if not any(value not in (None, "") for value in values.values()):
        values = row
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def truthy_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on", "enabled"}
