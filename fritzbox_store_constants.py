from __future__ import annotations

EXPECTED_RAW_ARTIFACTS = [
    "device_log_xml",
    "device_log_xml_wlan",
    "mesh_list",
    "host_list_xml",
    "wlan_device_list_xml",
    "landevice_query_json",
    "query_lua_artifacts_json",
    "data_lua_pages_json",
    "webui_readonly_artifacts_json",
    "tr064_snapshot_json",
    "call_list_xml",
    "phonebooks_xml_json",
    "aha_device_list_xml",
    "aha_switch_list_txt",
    "aha_device_stats_json",
    "config_export_file",
    "support_lua_page_html",
    "support_data_txt",
    "acquisition_manifest_json",
]
WIFI_DEDUPE_SQL = """
    id IN (
        SELECT MAX(id) FROM wifi_connections
        GROUP BY COALESCE(derived_connected_at, ''), COALESCE(event, ''), COALESCE(hostname, ''),
                 COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(source, '')
    )
"""
