function text(value) {
  return value === null || value === undefined ? "" : String(value);
}

function display(value, fallback = "-") {
  const rendered = text(value).trim();
  return rendered === "" || rendered.toLowerCase() === "null" || rendered.toLowerCase() === "undefined"
    ? fallback
    : rendered;
}

function escapeRegExp(value) {
  return text(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function evidenceLabel(value) {
  const rendered = display(value);
  const wlanDeviceList = /^wlan_device_list_xml_(\d+)$/.exec(rendered);
  if (wlanDeviceList) return `WLAN device list radio ${wlanDeviceList[1]}`;
  const labels = {
    parsed_from_raw: "parsed raw",
    raw: "raw",
    siem_events: "SIEM events",
    siem_correlations: "correlations",
    events: "events",
    correlations: "correlations",
    enriched_from_current_host_table: "host context",
    inferred: "inferred",
    exact_wifi_connection: "exact WiFi log",
    retained_log_match: "router log match",
    wifi_event: "WiFi log",
    mesh_last_observed: "mesh observed",
    wlan_association_snapshot: "WLAN associated now",
    active_host_snapshot: "active at fetch",
    fritzbox_landevice_lastused: "FRITZ!Box last used",
    landevice_query_json: "LAN device state",
    query_lua_artifacts_json: "Web UI query.lua",
    data_lua_pages_json: "Web UI data.lua",
    webui_readonly_artifacts_json: "Web UI read-only probes",
    device_log: "device log",
    device_log_text: "device log text",
    device_log_xml: "device log",
    device_log_xml_wlan: "WLAN-filtered device log",
    host_list_xml: "host list",
    mesh_list: "mesh list",
    support_data_txt: "support data",
    support_data_hostapd: "support hostapd/WLAN log",
    support_data_steering: "support WLAN steering log",
    wlan_device_list_xml: "WLAN device list",
    tr064_snapshot_json: "TR-064 snapshot",
    call_list_xml: "call list",
    phonebooks_xml_json: "phonebooks",
    aha_device_list_xml: "AHA device list",
    aha_switch_list_txt: "AHA switch list",
    aha_device_stats_json: "AHA device stats",
    config_export_file: "config export",
    support_lua_page_html: "support.lua page",
    acquisition_manifest_json: "acquisition manifest",
    host_filter_profiles: "host filters",
    mesh_topology_links: "mesh links",
    wan_port_mappings: "WAN exposure",
    wlan_radios: "WLAN radios",
    wlan_associations: "WLAN associations",
    advertisement_hints: "ad/broadcast hints",
    connected_seen: "connected in range",
    connected_active: "active in range",
    connected_now: "associated snapshot",
    mesh_roaming_link: "roaming/AP link",
    broadcast_hint: "network discovery hint",
    network_discovery_hint: "network discovery hint",
    nearby_probe: "nearby/probe evidence",
    historical_connected: "connected",
    historical_seen: "seen near AP",
    historical_probe: "802.11 probe request",
    station_history_interval: "station interval",
    wlan_event_table_row: "WLAN event",
    ap_sta_connected: "AP connected",
    ap_sta_disconnected: "AP disconnected",
    wpa_pairwise_handshake: "WPA handshake",
    wpa_group_handshake: "WPA group key",
    radius_accounting_start: "RADIUS accounting",
    association_request_observed: "association request",
    steering_observation: "steering/RSSI",
    probe_request: "probe request",
    probe_response: "probe response",
    association_request: "association request",
    authentication: "authentication",
    deauthentication: "deauthentication",
    disassociation: "disassociation",
    network_status_snapshots: "network status",
    device_risk_summaries: "device risk",
    security_advisories: "security advisories",
    critical: "critical",
    UPnP: "UPnP",
    PCP: "PCP",
    SSDP: "SSDP",
    "mDNS/Bonjour": "mDNS/Bonjour",
    "IGMP/Multicast": "IGMP/Multicast",
    LLMNR: "LLMNR",
    NetBIOS: "NetBIOS",
    "ARP/Neighbor": "ARP/Neighbor",
    DHCP: "DHCP",
    high: "high",
    medium: "medium",
    low: "low"
  };
  return labels[rendered] || rendered;
}

function cleanRecord(value) {
  if (Array.isArray(value)) return value.map(cleanRecord);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cleanRecord(item)]));
  }
  return value === null || value === undefined ? "" : value;
}

function escapeHtml(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function cssToken(value) {
  return display(value, "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return display(value);
  return date.toLocaleString();
}

function isoFromLocal(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const offset = -date.getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const hours = String(Math.floor(Math.abs(offset) / 60)).padStart(2, "0");
  const minutes = String(Math.abs(offset) % 60).padStart(2, "0");
  return `${value.length === 16 ? `${value}:00` : value}${sign}${hours}:${minutes}`;
}

function localInputValue(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate())
  ].join("-") + `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function syncRangeInputs() {
  if ($("investigation-start")) $("investigation-start").value = $("range-start").value;
  if ($("investigation-end")) $("investigation-end").value = $("range-end").value;
}

function isExact(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function debounce(fn, delay = 220) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

async function readError(response) {
  const body = await response.text();
  try {
    const payload = JSON.parse(body);
    return payload.detail || payload.error || body || `${response.status} ${response.statusText}`;
  } catch {
    return body || `${response.status} ${response.statusText}`;
  }
}
