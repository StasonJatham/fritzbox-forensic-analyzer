from __future__ import annotations

import json
import re
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
        mac = host.get("NewMACAddress")
        if mac:
            try:
                specific = fc.call_action("Hosts:1", "GetSpecificHostEntry", NewMACAddress=mac)
            except Exception:
                specific = {}
            if specific:
                host.update(specific)
        hosts.append(host)
    return hosts


READ_ONLY_ACTION_PREFIXES = ("Get", "X_AVM-DE_Get")
BLOCKED_ACTION_WORDS = (
    "Add",
    "Create",
    "Delete",
    "Dial",
    "Force",
    "Import",
    "Mark",
    "Reboot",
    "Reset",
    "Set",
    "Start",
    "Stop",
    "Update",
    "Wake",
)
DATA_LUA_PAGES = (
    "homeNet",
    "log",
    "netCnt",
    "netMoni",
    "overview",
    "netDev",
    "mesh",
    "wlan",
    "wGuest",
    "inetstat",
    "dsl",
    "docInfo",
    "syslog",
    "foncalls",
    "phonebook",
    "dect",
    "usb",
    "nas",
    "vpn",
    "wireguard",
    "users",
    "myfritz",
    "shareUsb",
    "portShare",
    "forwardRules",
    "netSet",
    "wlanSet",
    "wlanRadio",
    "wlanSecurity",
    "wlanMesh",
    "filter",
    "kids",
    "userSettings",
    "remoteAccess",
    "support",
    "diagnosis",
    "energy",
    "energyStat",
    "wlanSta",
    "wlanMonitor",
    "wlanRadar",
    "wlanRepeater",
    "wlanGuest",
    "wlanWps",
    "meshSet",
    "netOverview",
    "netRoute",
    "netNeighbor",
    "netDhcp",
    "netDns",
    "netShares",
    "dslStat",
    "dslSpectrum",
    "dslFeedback",
    "internet",
    "onlineMoni",
    "pushService",
    "system",
    "systemBackup",
    "update",
    "diagnosisSecurity",
    "diagnosisFunction",
)
MAX_WEBUI_ARTIFACT_BYTES = 2_000_000
WEBUI_READONLY_ENDPOINTS = (
    ("juis_boxinfo_xml", "/juis_boxinfo.xml", {}),
    ("login_sid_v2", "/login_sid.lua", {"version": "2"}),
    ("menu_data_lua", "/menus/menu_data.lua", {}),
    ("inetstat_monitor_lua", "/internet/inetstat_monitor.lua", {}),
    ("inetstat_counter_lua", "/internet/inetstat_counter.lua", {}),
)


def fetch_avm_exports(fc: Any, address: str, port: int, export_password: str | None = None) -> dict[str, Any]:
    exports: dict[str, Any] = {}
    manifest = AcquisitionManifest()
    path_specs = [
        ("device_log_xml", "DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath", "NewDeviceLogPath"),
        ("mesh_list", "Hosts:1", "X_AVM-DE_GetMeshListPath", "NewX_AVM-DE_MeshListPath"),
        ("host_list_xml", "Hosts:1", "X_AVM-DE_GetHostListPath", "NewX_AVM-DE_HostListPath"),
    ]
    for key, service, action, field in path_specs:
        try:
            path = fc.call_action(service, action).get(field)
        except Exception as exc:
            manifest.add(key, "tr064_export_path", ok=False, service=service, action=action, error=exc)
            continue
        if not path:
            manifest.add(key, "tr064_export_path", ok=False, service=service, action=action, error="empty path")
            continue
        content = fetch_avm_path(address, port, str(path), fc=fc)
        if content is not None:
            exports[key] = content
        manifest.add(key, "tr064_export_path", ok=content is not None, service=service, action=action, path=str(path))

    wlan_device_lists: dict[str, str] = {}
    for index in range(1, 5):
        key = f"wlan_device_list_xml_{index}"
        try:
            path = fc.call_action(f"WLANConfiguration:{index}", "X_AVM-DE_GetWLANDeviceListPath").get(
                "NewX_AVM-DE_WLANDeviceListPath"
            )
        except Exception as exc:
            manifest.add(
                key,
                "tr064_export_path",
                ok=False,
                service=f"WLANConfiguration:{index}",
                action="X_AVM-DE_GetWLANDeviceListPath",
                error=exc,
            )
            continue
        if not path:
            manifest.add(
                key,
                "tr064_export_path",
                ok=False,
                service=f"WLANConfiguration:{index}",
                action="X_AVM-DE_GetWLANDeviceListPath",
                error="empty path",
            )
            continue
        content = fetch_avm_path(address, port, str(path), fc=fc)
        if content is not None:
            exports[key] = content
            wlan_device_lists[str(index)] = content
        manifest.add(
            key,
            "tr064_export_path",
            ok=content is not None,
            service=f"WLANConfiguration:{index}",
            action="X_AVM-DE_GetWLANDeviceListPath",
            path=str(path),
        )
    if wlan_device_lists:
        exports["wlan_device_list_xml"] = json.dumps(wlan_device_lists, sort_keys=True)
        manifest.add("wlan_device_list_xml", "combined_artifact", ok=True, count=len(wlan_device_lists))

    if "device_log_xml" in exports:
        parsed_log = parse_device_log_xml(exports["device_log_xml"])
        if parsed_log:
            exports["device_log_text"] = parsed_log
    data_lua_pages = fetch_data_lua_pages(fc)
    if data_lua_pages:
        exports["data_lua_pages_json"] = json.dumps(data_lua_pages, sort_keys=True, default=str)
        manifest.extend_from_result_map("data_lua_pages_json", "webui_data_lua", data_lua_pages)
    landevice_query = fetch_landevice_query(fc)
    if landevice_query:
        exports["landevice_query_json"] = landevice_query
    manifest.add("landevice_query_json", "webui_query_lua", ok=bool(landevice_query), query="landevice list")
    query_artifacts = fetch_query_lua_artifacts(fc)
    if query_artifacts:
        exports["query_lua_artifacts_json"] = json.dumps(query_artifacts, sort_keys=True, default=str)
        manifest.extend_from_result_map("query_lua_artifacts_json", "webui_query_lua", query_artifacts)
    webui_artifacts = fetch_webui_readonly_artifacts(fc)
    if webui_artifacts:
        exports["webui_readonly_artifacts_json"] = json.dumps(webui_artifacts, sort_keys=True, default=str)
        manifest.extend_from_result_map(
            "webui_readonly_artifacts_json",
            "webui_readonly_get",
            webui_artifacts.get("endpoints") or {},
        )
    tr064_snapshot = collect_tr064_snapshot(fc)
    if tr064_snapshot:
        exports["tr064_snapshot_json"] = json.dumps(tr064_snapshot, sort_keys=True, default=str)
        manifest.add(
            "tr064_snapshot_json",
            "tr064_snapshot",
            ok=True,
            dynamic_readonly=len(tr064_snapshot.get("dynamic_readonly") or {}),
            services=len(tr064_snapshot.get("service_inventory") or []),
        )
    telephony = fetch_telephony_exports(fc, address, port)
    exports.update(telephony)
    for key in ("call_list_xml", "phonebooks_xml_json"):
        manifest.add(key, "telephony_export", ok=key in telephony)
    aha = fetch_aha_artifacts(fc)
    exports.update(aha)
    for key in ("aha_device_list_xml", "aha_switch_list_txt", "aha_device_stats_json"):
        manifest.add(key, "aha_http", ok=key in aha)
    if export_password:
        config_export = fetch_config_export(fc, address, port, export_password)
        if config_export:
            exports["config_export_file"] = config_export
        manifest.add("config_export_file", "device_config_export", ok=bool(config_export))
    else:
        manifest.add("config_export_file", "device_config_export", ok=False, error="no export password")
    support_lua = fetch_support_lua_page(fc)
    if support_lua:
        exports["support_lua_page_html"] = support_lua
    manifest.add("support_lua_page_html", "webui_support_lua", ok=bool(support_lua))
    support_data = fetch_support_data(fc)
    if support_data:
        exports["support_data_txt"] = support_data
    manifest.add("support_data_txt", "support_data", ok=bool(support_data))
    exports["acquisition_manifest_json"] = json.dumps(manifest.as_dict(), sort_keys=True, default=str)
    return exports


class AcquisitionManifest:
    def __init__(self) -> None:
        self.attempts: list[dict[str, Any]] = []

    def add(self, artifact: str, surface: str, ok: bool, **details: Any) -> None:
        normalized: dict[str, Any] = {"artifact": artifact, "surface": surface, "ok": bool(ok)}
        for key, value in details.items():
            if isinstance(value, Exception):
                normalized[key] = f"{type(value).__name__}: {value}"
            else:
                normalized[key] = value
        self.attempts.append(normalized)

    def extend_from_result_map(self, artifact: str, surface: str, result_map: dict[str, Any]) -> None:
        for name, result in result_map.items():
            if isinstance(result, dict):
                self.add(
                    artifact,
                    surface,
                    ok=bool(result.get("ok")),
                    name=name,
                    error=result.get("error"),
                    query=result.get("query"),
                )
            else:
                self.add(artifact, surface, ok=True, name=name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt_count": len(self.attempts),
            "successful_count": sum(1 for item in self.attempts if item.get("ok")),
            "failed_count": sum(1 for item in self.attempts if not item.get("ok")),
            "attempts": self.attempts,
        }


def fetch_support_data(fc: Any) -> str | None:
    """Download the FRITZ!Box support-data text dump via the hidden support workflow."""
    http = getattr(fc, "http_interface", None)
    if http is None:
        return None
    session = getattr(getattr(http, "fc", None), "session", None)
    if session is None:
        return None
    try:
        sid = next(http._get_sid())
    except Exception:
        return None
    if not sid or sid == "0000000000000000":
        return None

    url = f"{http.router_url}/cgi-bin/firmwarecfg"
    for field in ("SupportDataEnhanced", "SupportData"):
        try:
            response = session.post(url, files={"sid": (None, sid), field: (None, "")}, timeout=90)
        except TypeError:
            try:
                response = session.post(url, files={"sid": (None, sid), field: (None, "")})
            except Exception:
                continue
        except Exception:
            continue
        if getattr(response, "status_code", None) != 200:
            continue
        content = getattr(response, "content", b"")
        if not content:
            text = getattr(response, "text", "")
        else:
            text = content.decode("utf-8", errors="replace")
        if is_support_data_response(text):
            return text
    return None


def fetch_support_lua_page(fc: Any) -> str | None:
    """Retain the support.lua UI page when the firmware exposes it.

    The page itself is not the support dump, but it is useful coverage evidence:
    firmware variants expose support controls and diagnostic labels here.
    """
    http = getattr(fc, "http_interface", None)
    if http is None:
        return None
    session = getattr(getattr(http, "fc", None), "session", None)
    if session is None:
        return None
    try:
        sid = next(http._get_sid())
    except Exception:
        sid = ""
    params = f"?sid={sid}" if sid and sid != "0000000000000000" else ""
    url = f"{http.router_url}/support.lua{params}"
    try:
        response = session.get(url, timeout=15)
    except TypeError:
        try:
            response = session.get(url)
        except Exception:
            return None
    except Exception:
        return None
    if getattr(response, "status_code", None) != 200:
        return None
    text = getattr(response, "text", "") or getattr(response, "content", b"").decode("utf-8", errors="replace")
    if not text or "support" not in text.casefold():
        return None
    return text


def is_support_data_response(text: str) -> bool:
    sample = text[:500].casefold()
    if len(text) < 1000:
        return False
    if "<html" in sample or "<!doctype html" in sample:
        return False
    support_markers = ("support", "fritz", "box", "kernel", "device", "system", "wlan", "dsl", "mesh")
    return sum(1 for marker in support_markers if marker in text.casefold()) >= 3


def fetch_data_lua_pages(fc: Any) -> dict[str, Any]:
    pages: dict[str, Any] = {}
    for page in DATA_LUA_PAGES:
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


def fetch_query_lua_artifacts(fc: Any) -> dict[str, Any]:
    """Best-effort snapshots of unstable query.lua namespaces.

    These are intentionally raw-first. FRITZ!OS firmware decides which query
    paths exist; failures are retained so source coverage explains gaps.
    """
    queries = {
        "landevice_all": "landevice:settings/landevice/list(UID,ip,iplist,mac,maclist,name,friendly_name,neighbour_name,vendorname,modelname,parentuid,parentsource,source,flags,modification_flags,interface,wlan_station_type,wlan_UIDs,plc_UIDs,ethernetport,active,online,guest,speed,dhcp,static_dhcp,deleteable,wakeup,auto_wakeup,firstused,lastused,blocked,allow_pcp_and_upnp,igd_fw_cnt_pcp,igd_fw_cnt_upnp,myfritz_enabled,url)",
        "landevice_topology": "landevice:settings/landevice/list(UID,name,friendly_name,parentuid,parentsource,source,interface,wlan_UIDs,plc_UIDs,ethernetport,active,online,guest,speed,lastused)",
        "hostfilter_profiles": "filter:settings/profile/list(id,name,type,netappsid,blocked,autoupdate,disabled)",
        "hostfilter_rules": "filter:settings/rule/list(id,name,enabled,profile,device,uid,mac,ip,blocked)",
        "wlan_stations": "wlan:settings/station/list(mac,ip,name,UID,active,guest,ap,ssid,rssi,speed,flags)",
        "wlan_radios": "wlan:settings/radio/list(uid,enabled,ssid,channel,autochannel,standard,mac,guest)",
        "wlan_known_devices": "wlan:settings/known/list(mac,name,active,guest,ssid,last_connected,rssi,speed)",
        "wlan_guest": "wlan:settings/guest(enabled,ssid,encrypted,timeout,remaining)",
        "port_sharing": "forwardrules:settings/rule/list(description,enabled,protocol,port,end_port,fwip,fwport,sourceip)",
        "net_routes": "route:settings/route/list(ip,mask,gateway,metric,active)",
        "net_dns": "dns:settings/server/list(name,ip,source,active)",
        "net_dhcp": "dhcp:settings/lease/list(hostname,mac,ip,expires,active)",
        "vpn_users": "vpn:settings/connection/list(name,enabled,type,remote_ip,local_ip,last_connected)",
        "wireguard": "wireguard:settings/peer/list(name,enabled,remote_endpoint,allowed_ips,last_handshake)",
        "user_rights": "user:settings/user/list(name,enabled,box_admin,ftp_access,vpn_access,frominternet)",
        "myfritz_services": "myfritz:settings/service/list(name,enabled,port,protocol,device)",
        "usb_devices": "usb:settings/device/list(name,type,connected,manufacturer,product)",
        "dect_devices": "dect:settings/handset/list(name,intern,manufacturer,model,connected)",
    }
    artifacts: dict[str, Any] = {}
    for name, query in queries.items():
        try:
            response = fc.http_interface.call_url(f"{fc.http_interface.router_url}/query.lua", {name: query})
        except Exception as exc:
            artifacts[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "query": query}
            continue
        text = getattr(response, "text", "")
        if not text:
            artifacts[name] = {"ok": False, "error": "empty response", "query": query}
            continue
        try:
            artifacts[name] = {"ok": True, "data": json.loads(text), "query": query}
        except json.JSONDecodeError:
            artifacts[name] = {"ok": True, "raw": text, "query": query}
    return artifacts


def fetch_webui_readonly_artifacts(fc: Any) -> dict[str, Any]:
    """Best-effort raw GET snapshots from additional read-only Web UI endpoints."""
    http = getattr(fc, "http_interface", None)
    if http is None:
        return {}
    session = getattr(getattr(http, "fc", None), "session", None)
    if session is None:
        return {}

    sid = get_webui_sid(http)
    endpoints: dict[str, Any] = {}
    for name, path, params in WEBUI_READONLY_ENDPOINTS:
        request_params = dict(params)
        if sid and path.endswith(".lua"):
            request_params.setdefault("sid", sid)
        endpoints[name] = fetch_webui_readonly_endpoint(
            session,
            str(getattr(http, "router_url", "")).rstrip("/"),
            path,
            request_params,
        )
    return {
        "schema_version": 1,
        "max_body_bytes": MAX_WEBUI_ARTIFACT_BYTES,
        "endpoints": endpoints,
    }


def get_webui_sid(http: Any) -> str | None:
    try:
        sid = next(http._get_sid())
    except Exception:
        return None
    if not sid or sid == "0000000000000000":
        return None
    return str(sid)


def fetch_webui_readonly_endpoint(
    session: Any,
    router_url: str,
    path: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    url = path if path.startswith(("http://", "https://")) else f"{router_url}/{path.lstrip('/')}"
    metadata = {
        "ok": False,
        "method": "GET",
        "path": path,
        "params": redacted_params(params),
    }
    try:
        response = session.get(url, params=params, timeout=15)
    except TypeError:
        try:
            response = session.get(url, params=params)
        except Exception as exc:
            return {**metadata, "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:
        return {**metadata, "error": f"{type(exc).__name__}: {exc}"}

    try:
        status_code = getattr(response, "status_code", None)
        headers = getattr(response, "headers", {}) or {}
        content_type = headers.get("content-type") or headers.get("Content-Type")
        content = response_content_bytes(response)
        raw = content[:MAX_WEBUI_ARTIFACT_BYTES].decode("utf-8", errors="replace")
        result = {
            **metadata,
            "status_code": status_code,
            "content_type": content_type,
            "body_bytes": len(content),
            "truncated": len(content) > MAX_WEBUI_ARTIFACT_BYTES,
        }
        if status_code != 200:
            return {**result, "error": f"HTTP {status_code}"}
        if is_html_response(raw, content_type):
            return {**result, "error": "HTML response instead of raw API payload"}
        return {**result, "ok": True, "raw": raw}
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def response_content_bytes(response: Any) -> bytes:
    content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    text = getattr(response, "text", "")
    return str(text).encode("utf-8", errors="replace")


def is_html_response(raw: str, content_type: str | None) -> bool:
    if content_type and "html" in content_type.casefold():
        return True
    sample = raw[:300].casefold()
    return "<html" in sample or "<!doctype html" in sample


def redacted_params(params: dict[str, Any]) -> dict[str, Any]:
    return {key: "<redacted>" if key.lower() == "sid" else value for key, value in params.items()}


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
    snapshot: dict[str, Any] = {
        "actions": {},
        "wlan": [],
        "service_inventory": tr064_service_inventory(fc),
        "dynamic_readonly": collect_dynamic_readonly_actions(fc),
        "indexed_results": collect_indexed_results(fc),
    }
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


def tr064_service_inventory(fc: Any) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for service_name, service in sorted((getattr(fc, "services", {}) or {}).items()):
        actions = []
        try:
            action_items = sorted(service.actions.items())
        except Exception:
            action_items = []
        for action_name, action in action_items:
            actions.append(
                {
                    "name": action_name,
                    "input_arguments": action_input_arguments(action),
                    "output_arguments": action_output_arguments(action),
                    "read_only_candidate": is_read_only_action(action_name),
                }
            )
        inventory.append(
            {
                "service": service_name,
                "service_type": getattr(service, "serviceType", None),
                "control_url": getattr(service, "controlURL", None),
                "scpd_url": getattr(service, "SCPDURL", None),
                "actions": actions,
            }
        )
    return inventory


def collect_dynamic_readonly_actions(fc: Any, max_actions: int = 220) -> dict[str, Any]:
    results: dict[str, Any] = {}
    called = 0
    for service_name, service in sorted((getattr(fc, "services", {}) or {}).items()):
        try:
            action_items = sorted(service.actions.items())
        except Exception:
            continue
        for action_name, action in action_items:
            if called >= max_actions:
                return results
            if not is_read_only_action(action_name):
                continue
            if action_input_arguments(action):
                continue
            key = f"{service_name}:{action_name}"
            results[key] = safe_call_action(fc, service_name, action_name, {})
            called += 1
    return results


def collect_indexed_results(fc: Any) -> dict[str, Any]:
    specs = [
        (
            "Hosts:1",
            "GetHostNumberOfEntries",
            "NewHostNumberOfEntries",
            "GetGenericHostEntry",
            "NewIndex",
            "hosts_generic",
        ),
        (
            "WANIPConn:1",
            "GetPortMappingNumberOfEntries",
            "NewPortMappingNumberOfEntries",
            "GetGenericPortMappingEntry",
            "NewPortMappingIndex",
            "wan_ip_port_mappings",
        ),
        (
            "WANPPPConn:1",
            "GetPortMappingNumberOfEntries",
            "NewPortMappingNumberOfEntries",
            "GetGenericPortMappingEntry",
            "NewPortMappingIndex",
            "wan_ppp_port_mappings",
        ),
    ]
    indexed: dict[str, Any] = {}
    for service, count_action, count_field, item_action, index_arg, key in specs:
        count_result = safe_call_action(fc, service, count_action, {})
        indexed[key] = {"count": count_result, "items": []}
        if not count_result.get("ok"):
            continue
        try:
            count = int((count_result.get("response") or {}).get(count_field) or 0)
        except (TypeError, ValueError):
            continue
        for index in range(min(count, 512)):
            indexed[key]["items"].append(safe_call_action(fc, service, item_action, {index_arg: index}))

    for radio_index in range(1, 5):
        service = f"WLANConfiguration:{radio_index}"
        count_result = safe_call_action(fc, service, "GetTotalAssociations", {})
        key = f"wlan_{radio_index}_associations"
        indexed[key] = {"count": count_result, "items": []}
        if not count_result.get("ok"):
            continue
        try:
            count = int((count_result.get("response") or {}).get("NewTotalAssociations") or 0)
        except (TypeError, ValueError):
            continue
        for index in range(min(count, 256)):
            indexed[key]["items"].append(
                safe_call_action(fc, service, "GetGenericAssociatedDeviceInfo", {"NewAssociatedDeviceIndex": index})
            )
    return indexed


def is_read_only_action(action_name: str) -> bool:
    if not action_name.startswith(READ_ONLY_ACTION_PREFIXES):
        return False
    return not any(word in action_name for word in BLOCKED_ACTION_WORDS)


def action_input_arguments(action: Any) -> list[str]:
    return [
        name
        for name, argument in getattr(action, "arguments", {}).items()
        if getattr(argument, "direction", None) == "in"
    ]


def action_output_arguments(action: Any) -> list[str]:
    return [
        name
        for name, argument in getattr(action, "arguments", {}).items()
        if getattr(argument, "direction", None) == "out"
    ]


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


def fetch_telephony_exports(fc: Any, address: str, port: int) -> dict[str, str]:
    exports: dict[str, str] = {}
    call_list = safe_call_action(fc, "X_AVM-DE_OnTel:1", "GetCallList", {})
    call_list_url = (call_list.get("response") or {}).get("NewCallListURL")
    if call_list_url:
        content = fetch_avm_path(address, port, str(call_list_url), fc=fc)
        if content is not None:
            exports["call_list_xml"] = content

    phonebooks = safe_call_action(fc, "X_AVM-DE_OnTel:1", "GetPhonebookList", {})
    phonebook_ids = re.findall(r"\d+", str((phonebooks.get("response") or {}).get("NewPhonebookList") or ""))
    phonebook_exports: dict[str, str] = {}
    for phonebook_id in phonebook_ids[:20]:
        result = safe_call_action(fc, "X_AVM-DE_OnTel:1", "GetPhonebook", {"NewPhonebookID": int(phonebook_id)})
        url = (result.get("response") or {}).get("NewPhonebookURL")
        if not url:
            continue
        content = fetch_avm_path(address, port, str(url), fc=fc)
        if content is not None:
            phonebook_exports[phonebook_id] = content
    if phonebook_exports:
        exports["phonebooks_xml_json"] = json.dumps(phonebook_exports, sort_keys=True)
    return exports


def fetch_aha_artifacts(fc: Any) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for command, artifact_name in (
        ("getdevicelistinfos", "aha_device_list_xml"),
        ("getswitchlist", "aha_switch_list_txt"),
    ):
        try:
            response = fc.call_http(command)
        except Exception:
            continue
        content = response.get("content")
        if content:
            artifacts[artifact_name] = str(content)

    switch_list = artifacts.get("aha_switch_list_txt", "")
    stats: dict[str, Any] = {}
    for ain in re.split(r"\s*,\s*", switch_list.strip()):
        if not ain:
            continue
        try:
            stats[ain] = fc.call_http("getbasicdevicestats", ain).get("content")
        except Exception as exc:
            stats[ain] = {"error": f"{type(exc).__name__}: {exc}"}
    if stats:
        artifacts["aha_device_stats_json"] = json.dumps(stats, sort_keys=True, default=str)
    return artifacts


def fetch_config_export(fc: Any, address: str, port: int, export_password: str) -> str | None:
    result = safe_call_action(
        fc,
        "DeviceConfig:1",
        "X_AVM-DE_GetConfigFile",
        {"NewX_AVM-DE_Password": export_password},
    )
    path = (result.get("response") or {}).get("NewX_AVM-DE_ConfigFileUrl")
    if not path:
        return None
    return fetch_avm_path(address, port, str(path), fc=fc)


def fetch_avm_path(address: str, port: int, path: str, fc: Any | None = None) -> str | None:
    if fc is not None:
        content = fetch_authenticated_path(fc, path)
        if content is not None:
            return content
    for base in (f"http://{address}:{port}", f"http://{address}"):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def fetch_authenticated_path(fc: Any, path: str) -> str | None:
    http = getattr(fc, "http_interface", None)
    if http is None:
        return None
    session = getattr(getattr(http, "fc", None), "session", None)
    if session is None:
        return None
    url = path if path.startswith(("http://", "https://")) else f"{http.router_url}{path}"
    try:
        with session.get(url, timeout=15) as response:
            if getattr(response, "status_code", None) != 200:
                return None
            return response.content.decode("utf-8", errors="replace")
    except TypeError:
        try:
            with session.get(url) as response:
                if getattr(response, "status_code", None) != 200:
                    return None
                return response.content.decode("utf-8", errors="replace")
        except Exception:
            return None
    except Exception:
        return None
