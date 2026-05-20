from __future__ import annotations

import json
import urllib.request
from typing import Any

from fritzbox_parsers import parse_device_log_xml


def get_device_log(fc: Any) -> str:
    try:
        response = fc.call_action("DeviceInfo:1", "GetDeviceLog")
    except Exception as exc:
        raise SystemExit(f"Could not read FRITZ!Box device log via TR-064: {type(exc).__name__}: {exc}") from exc
    return str(response.get("NewDeviceLog") or "")


def get_device_info(fc: Any) -> dict[str, Any]:
    try:
        response = fc.call_action("DeviceInfo:1", "GetInfo")
    except Exception:
        return {}
    return {
        "manufacturer": response.get("NewManufacturerName"),
        "model": response.get("NewModelName") or response.get("NewProductClass"),
        "description": response.get("NewDescription"),
        "firmware": response.get("NewSoftwareVersion"),
        "hardware": response.get("NewHardwareVersion"),
        "serial": response.get("NewSerialNumber"),
    }


def get_router_time(fc: Any) -> dict[str, Any]:
    try:
        response = fc.call_action("Time:1", "GetInfo")
    except Exception:
        return {
            "current_time": None,
            "status": "unavailable",
            "note": "TR-064 Time:GetInfo did not return a router clock value.",
        }
    current_time = response.get("NewCurrentLocalTime") or response.get("NewCurrentTime")
    return {
        "current_time": current_time,
        "status": "reported" if current_time else "not_reported",
        "raw": json.loads(json.dumps(response, default=str)),
    }


def get_hosts(fc: Any) -> list[dict[str, Any]]:
    try:
        count_response = fc.call_action("Hosts:1", "GetHostNumberOfEntries")
        count = int(count_response.get("NewHostNumberOfEntries") or 0)
    except Exception:
        return []

    hosts: list[dict[str, Any]] = []
    for index in range(count):
        try:
            host = fc.call_action("Hosts:1", "GetGenericHostEntry", NewIndex=index)
        except Exception:
            continue
        hosts.append(host)
    return hosts


def fetch_avm_exports(fc: Any, address: str, port: int) -> dict[str, Any]:
    exports: dict[str, Any] = {}
    path_specs = [
        ("device_log_xml", "DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath", "NewDeviceLogPath"),
        ("mesh_list", "Hosts:1", "X_AVM-DE_GetMeshListPath", "NewX_AVM-DE_MeshListPath"),
        ("host_list_xml", "Hosts:1", "X_AVM-DE_GetHostListPath", "NewX_AVM-DE_HostListPath"),
    ]
    for key, service, action, field in path_specs:
        try:
            path = fc.call_action(service, action).get(field)
        except Exception:
            continue
        if not path:
            continue
        content = fetch_avm_path(address, port, str(path))
        if content is not None:
            exports[key] = content

    wlan_device_lists: dict[str, str] = {}
    for index in range(1, 5):
        try:
            path = fc.call_action(f"WLANConfiguration:{index}", "X_AVM-DE_GetWLANDeviceListPath").get(
                "NewX_AVM-DE_WLANDeviceListPath"
            )
        except Exception:
            continue
        if not path:
            continue
        content = fetch_avm_path(address, port, str(path))
        if content is None:
            continue
        key = f"wlan_device_list_xml_{index}"
        exports[key] = content
        wlan_device_lists[str(index)] = content
    if wlan_device_lists:
        exports["wlan_device_list_xml"] = json.dumps(wlan_device_lists, sort_keys=True)

    if "device_log_xml" in exports:
        parsed_log = parse_device_log_xml(exports["device_log_xml"])
        if parsed_log:
            exports["device_log_text"] = parsed_log
    data_lua_pages = fetch_data_lua_pages(fc)
    if data_lua_pages:
        exports["data_lua_pages_json"] = json.dumps(data_lua_pages, sort_keys=True, default=str)
    landevice_query = fetch_landevice_query(fc)
    if landevice_query:
        exports["landevice_query_json"] = landevice_query
    tr064_snapshot = collect_tr064_snapshot(fc)
    if tr064_snapshot:
        exports["tr064_snapshot_json"] = json.dumps(tr064_snapshot, sort_keys=True, default=str)
    return exports


def fetch_data_lua_pages(fc: Any) -> dict[str, Any]:
    pages: dict[str, Any] = {}
    for page in ("homeNet", "log", "netCnt", "netMoni"):
        try:
            response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/data.lua", {"page": page})
        except Exception as exc:
            pages[page] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            continue
        raw = getattr(response, "text", "")
        if not raw:
            pages[page] = {"ok": False, "error": "empty response"}
            continue
        try:
            pages[page] = {"ok": True, "data": json.loads(raw)}
        except json.JSONDecodeError:
            pages[page] = {"ok": True, "raw": raw}
    return pages


def fetch_landevice_query(fc: Any) -> str | None:
    rich_fields = [
        "UID",
        "ip",
        "iplist",
        "mac",
        "maclist",
        "name",
        "friendly_name",
        "neighbour_name",
        "vendorname",
        "modelname",
        "manu_name",
        "parentuid",
        "parentsource",
        "source",
        "flags",
        "modification_flags",
        "interface",
        "wlan_station_type",
        "wlan_UIDs",
        "plc_UIDs",
        "ethernetport",
        "active",
        "online",
        "speed",
        "dhcp",
        "static_dhcp",
        "deleteable",
        "wakeup",
        "auto_wakeup",
        "firstused",
        "lastused",
        "blocked",
        "allow_pcp_and_upnp",
        "igd_fw_cnt_pcp",
        "igd_fw_cnt_upnp",
        "myfritz_enabled",
        "url",
    ]
    fallback_fields = [
        "UID",
        "ip",
        "mac",
        "name",
        "friendly_name",
        "active",
        "online",
        "interface",
        "firstused",
        "lastused",
    ]
    for fields in (rich_fields, fallback_fields):
        query = f"landevice:settings/landevice/list({','.join(fields)})"
        try:
            response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/query.lua", {"mq_landevices": query})
        except Exception:
            continue
        text = getattr(response, "text", "")
        if text and "landevice" in text:
            return text
    return None


def collect_tr064_snapshot(fc: Any) -> dict[str, Any]:
    actions = [
        ("device_info", "DeviceInfo:1", "GetInfo", {}),
        ("time_info", "Time:1", "GetInfo", {}),
        ("user_interface", "UserInterface:1", "GetInfo", {}),
        ("app_config", "X_AVM-DE_AppSetup:1", "GetConfig", {}),
        ("app_remote_info", "X_AVM-DE_AppSetup:1", "GetAppRemoteInfo", {}),
        ("myfritz_info", "X_AVM-DE_MyFritz:1", "GetInfo", {}),
        ("host_count", "Hosts:1", "GetHostNumberOfEntries", {}),
        ("host_filter_profiles", "X_AVM-DE_HostFilter:1", "GetFilterProfiles", {}),
        ("lan_host_config", "LANHostConfigManagement:1", "GetInfo", {}),
        ("lan_eth_info", "LANEthernetInterfaceConfig:1", "GetInfo", {}),
        ("lan_eth_stats", "LANEthernetInterfaceConfig:1", "GetStatistics", {}),
        ("wan_common_link", "WANCommonIFC:1", "GetCommonLinkProperties", {}),
        ("wan_common_bytes_sent", "WANCommonIFC:1", "GetTotalBytesSent", {}),
        ("wan_common_bytes_received", "WANCommonIFC:1", "GetTotalBytesReceived", {}),
        ("wan_common_packets_sent", "WANCommonIFC:1", "GetTotalPacketsSent", {}),
        ("wan_common_packets_received", "WANCommonIFC:1", "GetTotalPacketsReceived", {}),
        ("wan_common_online_monitor", "WANCommonIFC:1", "X_AVM-DE_GetOnlineMonitor", {}),
        ("wan_ip_info", "WANIPConn:1", "GetInfo", {}),
        ("wan_ip_status", "WANIPConn:1", "GetStatusInfo", {}),
        ("wan_ip_external", "WANIPConn:1", "GetExternalIPAddress", {}),
        ("wan_dsl_interface", "WANDSLInterfaceConfig:1", "GetInfo", {}),
        ("wan_dsl_stats", "WANDSLInterfaceConfig:1", "GetStatisticsTotal", {}),
        ("wan_dsl_link", "WANDSLLinkConfig:1", "GetInfo", {}),
    ]
    snapshot: dict[str, Any] = {"actions": {}, "wlan": []}
    for key, service, action, arguments in actions:
        snapshot["actions"][key] = safe_call_action(fc, service, action, arguments)
    for index in range(1, 5):
        service = f"WLANConfiguration:{index}"
        radio = {
            "index": index,
            "info": safe_call_action(fc, service, "GetInfo", {}),
            "statistics": safe_call_action(fc, service, "GetStatistics", {}),
            "packet_statistics": safe_call_action(fc, service, "GetPacketStatistics", {}),
            "total_associations": safe_call_action(fc, service, "GetTotalAssociations", {}),
            "channel_info": safe_call_action(fc, service, "GetChannelInfo", {}),
            "ext_info": safe_call_action(fc, service, "X_AVM-DE_GetWLANExtInfo", {}),
            "wps_info": safe_call_action(fc, service, "X_AVM-DE_GetWPSInfo", {}),
        }
        if any(value.get("ok") for key, value in radio.items() if isinstance(value, dict)):
            snapshot["wlan"].append(radio)
    return snapshot


def safe_call_action(fc: Any, service: str, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        response = (
            fc.call_action(service, action, arguments=arguments) if arguments else fc.call_action(service, action)
        )
        return {
            "ok": True,
            "service": service,
            "action": action,
            "response": json.loads(json.dumps(response, default=str)),
        }
    except Exception as exc:
        return {"ok": False, "service": service, "action": action, "error": f"{type(exc).__name__}: {exc}"}


def fetch_avm_path(address: str, port: int, path: str) -> str | None:
    for base in (f"http://{address}:{port}", f"http://{address}"):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception:
            continue
    return None
