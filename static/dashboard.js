const state = {
  latest: null,
  profiles: [],
  profile: "local",
  runs: [],
  runId: "latest",
  data: null,
  analysis: null,
  view: "timeline",
  query: "",
  category: "all",
  evidenceLevel: "all",
  timeType: "all",
  rows: [],
  offset: 0,
  limit: 50,
  total: 0,
  loading: false,
  hasMore: true,
  sortBy: "timestamp",
  sortDir: "desc",
  rangeStart: "",
  rangeEnd: "",
  pollActive: false
};

const $ = (id) => document.getElementById(id);

function text(value) {
  return value === null || value === undefined ? "" : String(value);
}

function display(value, fallback = "-") {
  const rendered = text(value).trim();
  return rendered === "" || rendered.toLowerCase() === "null" || rendered.toLowerCase() === "undefined"
    ? fallback
    : rendered;
}

function evidenceLabel(value) {
  const labels = {
    parsed_from_raw: "parsed raw",
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
    device_log_xml: "device log",
    host_list_xml: "host list",
    mesh_list: "mesh list",
    support_data_txt: "support data",
    wlan_device_list_xml: "WLAN device list",
    tr064_snapshot_json: "TR-064 snapshot",
    call_list_xml: "call list",
    phonebooks_xml_json: "phonebooks",
    aha_device_list_xml: "AHA device list",
    aha_switch_list_txt: "AHA switch list",
    aha_device_stats_json: "AHA device stats",
    config_export_file: "config export",
    host_filter_profiles: "host filters",
    mesh_topology_links: "mesh links",
    wan_port_mappings: "WAN exposure",
    wlan_radios: "WLAN radios",
    wlan_associations: "WLAN associations",
    device_risk_summaries: "device risk",
    high: "high",
    medium: "medium",
    low: "low"
  };
  return labels[value] || display(value);
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

function isExact(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

async function loadStored({ quiet = false } = {}) {
  if (!quiet) $("status").textContent = "Loading stored evidence...";
  const response = await fetch(`/api/latest?profile=${encodeURIComponent(state.profile)}&run_id=${encodeURIComponent(state.runId)}`);
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  state.latest = await response.json();
  state.data = null;
  renderAcquisitionStatus();
  setMetrics();
  await Promise.all([loadAnalysis(), loadEntities(), loadSideTimeline(), loadPolling()]);
  await loadRows(true);
  if (!quiet) $("status").textContent = state.latest.has_data ? `${state.rows.length} of ${state.total} rows loaded` : "No stored acquisition yet.";
}

async function runAcquisition() {
  state.profile = "local";
  $("profile").value = "local";
  const saved = await saveSettings({ quiet: true });
  if (!saved) return;
  $("status").textContent = "Running FRITZ!Box acquisition...";
  const hours = $("hours").value;
  const response = await fetch(`/api/export?hours=${encodeURIComponent(hours)}&include_disconnects=true`);
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  state.data = await response.json();
  $("subtitle").textContent = `${display(state.data.router?.address, "FRITZ!Box")} - acquired ${formatTime(state.data.generated_at)}`;
  await loadStored({ quiet: true });
  await loadProfiles();
  await loadRuns();
  $("status").textContent = "Acquisition complete. Stored evidence reloaded.";
}

async function loadProfiles(selected = state.profile) {
  const response = await fetch("/api/profiles");
  if (!response.ok) return;
  const payload = await response.json();
  state.profiles = payload.profiles || [];
  $("profile").innerHTML = state.profiles.map((profile) => `
    <option value="${escapeHtml(profile.id)}">${escapeHtml(profile.label || profile.id)}</option>
  `).join("");
  if (state.profiles.some((profile) => profile.id === selected)) {
    state.profile = selected;
  } else {
    state.profile = "local";
  }
  $("profile").value = state.profile;
}

async function loadRuns(selected = state.runId) {
  const response = await fetch(`/api/runs?profile=${encodeURIComponent(state.profile)}`);
  if (!response.ok) return;
  const payload = await response.json();
  state.runs = payload.runs || [];
  $("run").innerHTML = [
    `<option value="latest">Latest acquisition</option>`,
    `<option value="all">All acquisitions</option>`,
    ...state.runs.map((run) => `
      <option value="${escapeHtml(run.id)}">${escapeHtml(run.label || `Run ${run.id}`)}</option>
    `)
  ].join("");
  const valid = selected === "latest" || selected === "all" || state.runs.some((run) => String(run.id) === String(selected));
  state.runId = valid ? String(selected) : "latest";
  $("run").value = state.runId;
}

async function importPackage(file) {
  if (!file) return;
  $("status").textContent = `Importing ${file.name}...`;
  const response = await fetch(`/api/import/package?filename=${encodeURIComponent(file.name)}`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: await file.arrayBuffer()
  });
  $("import-file").value = "";
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  const payload = await response.json();
  const imported = payload.profile || {};
  await loadProfiles(imported.id || "local");
  state.runId = "latest";
  await loadRuns();
  await loadStored({ quiet: true });
  $("status").textContent = `Imported ${imported.label || imported.id || "package"}.`;
}

async function loadSettings() {
  const response = await fetch("/api/settings");
  if (!response.ok) return;
  const settings = await response.json();
  $("cfg-address").value = settings.address || "192.168.178.1";
  $("settings-note").textContent = settings.has_password
    ? "Saved local settings include a password. Leave password blank to keep it."
    : "No password saved yet. Settings are stored locally in fritzbox-analysis.sqlite3.";
}

async function saveSettings({ quiet = false } = {}) {
  $("settings-note").textContent = "Saving settings...";
  const payload = {
    address: $("cfg-address").value.trim(),
    password: $("cfg-password").value,
    user: "",
    port: 49000,
    tls: false
  };
  const response = await fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    $("settings-note").textContent = await readError(response);
    return false;
  }
  $("cfg-password").value = "";
  await loadSettings();
  if (!quiet) $("status").textContent = "Settings saved. Run acquisition when ready.";
  return true;
}

function currentSummary() {
  const counts = state.latest?.counts || {};
  const retained = state.latest?.retained || {};
  return {
    available_wifi_connections: counts.wifi_connections || 0,
    event_log_entries: counts.event_log || 0,
    known_hosts: counts.hosts || 0,
    active_hosts: counts.active_hosts || 0,
    hosts_with_last_connected: counts.hosts_with_last_connected || 0,
    hosts_with_first_seen: counts.hosts_with_first_seen || 0,
    last_wifi_connection: state.latest?.last_exact_wifi || "",
    last_device_connected: state.latest?.last_device_connected || state.latest?.last_exact_wifi || "",
    oldest_event: retained.oldest_event || "",
    newest_event: retained.newest_event || ""
  };
}

function setMetrics() {
  const summary = state.data?.summary || currentSummary();
  $("m-wifi").textContent = summary.available_wifi_connections ?? summary.wifi_events ?? 0;
  $("m-log").textContent = summary.event_log_entries ?? 0;
  $("m-hosts").textContent = summary.known_hosts ?? 0;
  $("m-active").textContent = summary.active_hosts ?? 0;
  $("m-last").textContent = summary.last_device_connected ? formatTime(summary.last_device_connected) : "None retained";
  const oldest = summary.oldest_event ? formatTime(summary.oldest_event) : "unknown";
  const newest = summary.newest_event ? formatTime(summary.newest_event) : "unknown";
  const warnings = state.latest?.source_coverage?.warnings || [];
  $("forensic-notice").innerHTML = `<strong>Evidence model:</strong> retained log window ${escapeHtml(oldest)} to ${escapeHtml(newest)}. <strong>Last device use</strong> comes from FRITZ!Box device state when available; it is not a full session log. Absence of a row is not proof an event did not happen.${warnings.length ? ` <strong>Coverage:</strong> ${escapeHtml(warnings[0])}` : ""}`;
}

function renderAcquisitionStatus() {
  const latest = state.latest || {};
  const run = latest.latest_run || {};
  const counts = latest.counts || {};
  const retained = latest.retained || {};
  const generated = run.generated_at ? formatTime(run.generated_at) : "No run";
  const router = run.router_address || run.router?.address || $("cfg-address").value || "Not set";
  const windowText = retained.oldest_event || retained.newest_event
    ? `${formatTime(retained.oldest_event)} to ${formatTime(retained.newest_event)}`
    : "No retained log window";
  const coverage = latest.source_coverage || {};
  const missing = coverage.missing_raw_artifacts || [];
  const coverageText = missing.length ? `missing ${missing.map(evidenceLabel).join(", ")}` : "all expected raw sources";
  $("acquisition-status").innerHTML = `
    <span>Latest run<strong>${escapeHtml(generated)}</strong></span>
    <span>Router<strong>${escapeHtml(router)}</strong></span>
    <span>Retained window<strong>${escapeHtml(windowText)}</strong></span>
    <span>Stored records<strong>${escapeHtml((counts.event_log || 0) + " logs / " + (counts.wifi_connections || 0) + " wifi / " + (counts.hosts || 0) + " hosts")}</strong></span>
    <span>Device timestamps<strong>${escapeHtml((counts.hosts_with_last_connected || 0) + " last-used / " + (counts.hosts_with_first_seen || 0) + " first-seen")}</strong></span>
    <span>Source coverage<strong>${escapeHtml(coverageText)}</strong></span>
  `;
  $("subtitle").textContent = latest.has_data ? `Stored evidence from ${display(router, "FRITZ!Box")}` : "No stored evidence yet";
}

async function loadAnalysis() {
  const params = new URLSearchParams({ start: state.rangeStart, end: state.rangeEnd, profile: state.profile, run_id: state.runId });
  const response = await fetch(`/api/analysis?${params.toString()}`);
  if (!response.ok) return;
  state.analysis = await response.json();
  renderCharts();
}

async function loadEntities() {
  const params = new URLSearchParams({ q: state.query, limit: "40", profile: state.profile, run_id: state.runId });
  const response = await fetch(`/api/entities?${params.toString()}`);
  if (!response.ok) return;
  const payload = await response.json();
  renderEntities(payload.rows || []);
}

async function loadSideTimeline() {
  const params = new URLSearchParams({
    q: state.query,
    category: state.category,
    start: state.rangeStart,
    end: state.rangeEnd,
    evidence_level: state.evidenceLevel,
    time_type: state.timeType,
    profile: state.profile,
    run_id: state.runId,
    limit: "8",
    offset: "0"
  });
  const response = await fetch(`/api/timeline?${params.toString()}`);
  if (!response.ok) return;
  const payload = await response.json();
  renderTimeline(payload.rows || []);
}

async function loadRows(reset = false) {
  if (state.loading) return;
  if (!reset && !state.hasMore) return;
  state.loading = true;
  if (reset) {
    state.rows = [];
    state.offset = 0;
    state.total = 0;
    state.hasMore = true;
    $("table").scrollTop = 0;
  }
  $("status").textContent = reset ? "Searching backend index..." : "Loading more rows...";
  const params = new URLSearchParams({
    view: state.view,
    q: state.query,
    category: state.category,
    evidence_level: state.evidenceLevel,
    time_type: state.timeType,
    limit: String(state.limit),
    offset: String(state.offset),
    sort_by: state.sortBy,
    sort_dir: state.sortDir,
    profile: state.profile,
    run_id: state.runId,
    start: state.rangeStart,
    end: state.rangeEnd
  });
  let endpoint = "/api/search";
  if (state.view === "timeline") {
    endpoint = "/api/timeline";
    params.set("start", state.rangeStart);
    params.set("end", state.rangeEnd);
  } else if (state.view === "entities") {
    endpoint = "/api/entities";
    params.delete("view");
    params.delete("category");
    params.delete("evidence_level");
    params.delete("time_type");
    params.delete("sort_by");
    params.delete("sort_dir");
    params.delete("start");
    params.delete("end");
  }
  const response = await fetch(`${endpoint}?${params.toString()}`);
  state.loading = false;
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  const payload = await response.json();
  state.total = payload.total || 0;
  state.rows = reset ? payload.rows || [] : state.rows.concat(payload.rows || []);
  state.offset = state.rows.length;
  state.hasMore = state.rows.length < state.total;
  renderTable();
}

function renderCharts() {
  const analysis = state.analysis || {};
  const hourly = new Map((analysis.hourly_counts || []).map((row) => [String(row.hour).padStart(2, "0"), row.count || 0]));
  const maxHour = Math.max(1, ...Array.from(hourly.values()));
  $("hour-chart").innerHTML = Array.from({ length: 24 }, (_, index) => {
    const hour = String(index).padStart(2, "0");
    const count = hourly.get(hour) || 0;
    const height = Math.max(2, Math.round((count / maxHour) * 100));
    const label = index % 3 === 0 ? `<span>${hour}</span>` : "";
    return `<div class="bar" title="${hour}:00 - ${count} records" style="height:${height}%">${label}</div>`;
  }).join("");
  renderMiniChart("category-chart", analysis.category_counts || []);
  renderMiniChart("confidence-chart", analysis.confidence_counts || []);
  renderMiniChart("interface-chart", analysis.interface_counts || []);
  renderMiniChart("timestamp-chart", Object.entries(analysis.timestamp_coverage || {}).map(([label, count]) => ({ label, count })));
  renderMeshLinks(analysis.mesh_summary || {});
  renderSourceCoverage(analysis.source_coverage || {});
  renderWlanRadios(analysis.tr064_summary?.wlan_radios || []);
  renderWanState(analysis.tr064_summary?.wan || {});
  renderWanExposure(analysis.tr064_summary?.wan || {});
  renderDeviceRisk(analysis.host_risk_summary || {});
  renderLastUsedHistogram(analysis.last_used_histogram || []);
  renderPresenceSummary(state.latest?.presence_summary || {});
}

function renderMiniChart(id, rows) {
  const max = Math.max(1, ...rows.map((row) => row.count || 0));
  $(id).innerHTML = rows.length ? rows.slice(0, 7).map((row) => `
    <div>
      <div class="mini-row"><span>${escapeHtml(evidenceLabel(display(row.label, "unknown")))}</span><strong>${escapeHtml(row.count || 0)}</strong></div>
      <div class="mini-meter"><div style="width:${Math.max(4, Math.round(((row.count || 0) / max) * 100))}%"></div></div>
    </div>
  `).join("") : `<div class="empty">No chart data.</div>`;
}

function renderSourceCoverage(coverage) {
  const present = new Set((coverage.present_raw_artifacts || []).map((row) => row.name));
  const expected = coverage.expected_raw_artifacts || [];
  const matrix = coverage.matrix || [];
  const summary = expected.length ? expected.map((name) => `
    <div class="mini-row">
      <span>${escapeHtml(evidenceLabel(name))}</span>
      <strong>${present.has(name) ? "present" : "missing"}</strong>
    </div>
  `).join("") : "";
  const details = matrix.map((row) => `
    <div class="coverage-row ${escapeHtml(cssToken(row.state))}">
      <div class="mini-row">
        <span>${escapeHtml(row.area)}</span>
        <strong>${escapeHtml(row.present)} / ${escapeHtml(row.expected)}</strong>
      </div>
      <div class="subtitle">${escapeHtml(row.detail)}</div>
      <div class="coverage-artifacts">
        ${(row.artifacts || []).map((artifact) => `
          <span class="${artifact.present ? "present" : "missing"}" title="${escapeHtml(formatTime(artifact.last_observed))}">
            ${escapeHtml(evidenceLabel(artifact.name))}
          </span>
        `).join("")}
      </div>
    </div>
  `).join("");
  $("source-coverage").innerHTML = details || summary || `<div class="empty">No source coverage data.</div>`;
}

function renderWlanRadios(radios) {
  $("wlan-radio-list").innerHTML = radios.length ? radios.map((radio) => `
    <div>
      <div class="mini-row"><span>${escapeHtml(display(radio.ssid, `Radio ${radio.index}`))}</span><strong>${escapeHtml(display(radio.associations, "0"))} assoc</strong></div>
      <div class="subtitle">${escapeHtml([radio.status, radio.enabled ? "enabled" : "disabled", radio.channel ? `ch ${radio.channel}` : "", radio.standard].filter(Boolean).join(" / "))}</div>
    </div>
  `).join("") : `<div class="empty">No WLAN radio snapshot.</div>`;
}

function renderWanState(wan) {
  const rows = [
    ["Status", wan.connection_status],
    ["Physical", wan.physical_status],
    ["Access", wan.access_type],
    ["Downstream", wan.downstream],
    ["Upstream", wan.upstream],
    ["External IP", wan.external_ip]
  ].filter(([, value]) => display(value, "") !== "");
  $("wan-state").innerHTML = rows.length ? rows.map(([label, value]) => `
    <div class="mini-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(display(value))}</strong></div>
  `).join("") : `<div class="empty">No WAN snapshot.</div>`;
}

function renderMeshLinks(mesh) {
  const links = mesh.links || [];
  if (!mesh.available) {
    $("mesh-links").innerHTML = `<div class="empty">No mesh topology artifact.</div>`;
    return;
  }
  $("mesh-links").innerHTML = `
    <div class="mini-row"><span>Nodes</span><strong>${escapeHtml(mesh.nodes || 0)}</strong></div>
    ${links.length ? links.slice(0, 8).map((link) => `
      <div class="topology-row">
        <div class="mini-row">
          <span>${escapeHtml(display(link.device, "Unknown device"))}</span>
          <strong>${escapeHtml(display(link.state, "unknown"))}</strong>
        </div>
        <div class="subtitle">${escapeHtml([link.interface, link.type, link.rx ? `${link.rx} rx` : "", link.tx ? `${link.tx} tx` : "", link.last_connected ? formatTime(link.last_connected) : ""].filter(Boolean).join(" / "))}</div>
      </div>
    `).join("") : `<div class="empty compact">No mesh links reported.</div>`}
  `;
}

function renderWanExposure(wan) {
  const mappings = wan.port_mappings || [];
  const enabled = mappings.filter((mapping) => mapping.enabled);
  const rows = [
    ["External IP", wan.external_ip],
    ["Port mappings", mappings.length ? `${enabled.length} enabled / ${mappings.length} total` : ""]
  ].filter(([, value]) => display(value, "") !== "");
  $("wan-exposure").innerHTML = rows.length || mappings.length ? `
    ${rows.map(([label, value]) => `<div class="mini-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(display(value))}</strong></div>`).join("")}
    ${mappings.slice(0, 8).map((mapping) => `
      <div class="exposure-row ${mapping.enabled ? "enabled" : "disabled"}">
        <div class="mini-row">
          <span>${escapeHtml(display(mapping.description, "Port mapping"))}</span>
          <strong>${escapeHtml([mapping.external_port, mapping.protocol].filter(Boolean).join("/"))}</strong>
        </div>
        <div class="subtitle">${escapeHtml([mapping.internal_client, mapping.internal_port ? `internal ${mapping.internal_port}` : "", mapping.enabled ? "enabled" : "disabled"].filter(Boolean).join(" / "))}</div>
      </div>
    `).join("")}
  ` : `<div class="empty">No WAN exposure details.</div>`;
}

function renderDeviceRisk(risk) {
  const devices = risk.devices || [];
  const totals = risk.totals || {};
  if (!risk.available) {
    $("device-risk").innerHTML = `<div class="empty">No host inventory for risk scoring.</div>`;
    return;
  }
  $("device-risk").innerHTML = `
    <div class="risk-summary">
      ${["high", "medium", "low"].map((level) => `<span class="pill ${level}">${escapeHtml(level)} ${escapeHtml(totals[level] || 0)}</span>`).join("")}
    </div>
    ${devices.length ? devices.slice(0, 6).map((device) => `
      <button class="risk-device" data-entity="${escapeHtml(device.mac || device.ip || device.hostname || "")}">
        <div class="mini-row">
          <span>${escapeHtml(display(device.hostname || device.ip || device.mac, "Unknown device"))}</span>
          <strong>${escapeHtml(device.score)}</strong>
        </div>
        <div class="subtitle">${escapeHtml((device.reasons || []).join(" / "))}</div>
      </button>
    `).join("") : `<div class="empty compact">No elevated device-risk signals.</div>`}
  `;
}

function renderLastUsedHistogram(rows) {
  const max = Math.max(1, ...rows.map((row) => row.count || 0));
  $("last-used-histogram").innerHTML = rows.length ? rows.map((row) => {
    const height = Math.max(8, Math.round(((row.count || 0) / max) * 100));
    return `
      <div class="histogram-bar" title="${escapeHtml(row.label)} - ${escapeHtml(row.count)} devices">
        <div style="height:${height}%"></div>
        <span>${escapeHtml(String(row.label || "").slice(5))}</span>
      </div>
    `;
  }).join("") : `<div class="empty">No retained last-used timestamps.</div>`;
}

function renderPresenceSummary(summary) {
  const rows = [
    ["Devices", summary.total],
    ["First seen", summary.first_seen],
    ["Last connected/used", summary.last_connected],
    ["Last activity", summary.last_activity],
    ["Exact WiFi log", summary.exact_wifi],
    ["FRITZ!Box lastused", summary.device_state],
    ["Active snapshot", summary.active_snapshot],
    ["Newest activity", summary.newest_activity ? formatTime(summary.newest_activity) : ""]
  ];
  $("presence-summary").innerHTML = rows.some(([, value]) => value) ? rows.map(([label, value]) => `
    <div class="mini-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(display(value, "0"))}</strong></div>
  `).join("") : `<div class="empty">No device presence timestamps yet.</div>`;
}

function renderTimeline(rows) {
  $("timeline").innerHTML = rows.map((row) => `
    <button class="timeline-row ${escapeHtml(cssToken(row.event_class || row.category))}" data-record-type="${escapeHtml(row.record_type || "")}" data-record-id="${escapeHtml(row.record_id || "")}">
      <div class="dot"></div>
      <div>
        <div class="timeline-main">${escapeHtml(display(row.message, "No message"))}</div>
        <div>${escapeHtml(formatTime(row.event_time || row.timestamp))} ${confidenceBadge(row)}</div>
      </div>
    </button>
  `).join("") || `<div class="empty">No retained router log entries.</div>`;
}

function renderEntities(rows) {
  $("entities").innerHTML = rows.length ? rows.map((row) => `
    <button class="entity-card" data-entity="${escapeHtml(row.mac || row.ip || row.hostname || row.key)}">
      <strong>${escapeHtml(display(row.hostname || row.mac || row.ip, "Unknown"))}</strong>
      <span>${escapeHtml([row.mac, row.ip, row.interface].filter(Boolean).join(" / "))}</span>
      <span>${escapeHtml((row.event_count || 0) + " log / " + (row.wifi_count || 0) + " wifi")}</span>
    </button>
  `).join("") : `<div class="empty">No entities match.</div>`;
}

function renderTable() {
  const rows = state.rows;
  if (!rows.length) {
    const message = state.latest?.has_data
      ? "No rows match the current filters."
      : "No stored evidence yet. Save router settings, then run acquisition.";
    $("table").innerHTML = `<div class="empty">${escapeHtml(message)}</div>`;
    $("status").textContent = `0 of ${state.total} rows`;
    return;
  }
  if (state.view === "wifi") {
    $("table").innerHTML = table([
      ["Action", ""], ["Derived Time", "derived_connected_at"], ["Type", "type"], ["Host", "hostname"], ["MAC", "mac"],
      ["IP", "ip"], ["Confidence", "evidence"], ["Source", "source"], ["Evidence", "evidence"]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.derived_connected_at || row.timestamp), row.derived_time_type || row.event,
      row.hostname, row.mac, row.ip, confidenceBadge(row), row.source, row.derived_time_confidence || row.confidence
    ]), rows);
  } else if (state.view === "presence") {
    $("table").innerHTML = table([
      ["Action", ""], ["Device", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"],
      ["First Seen", "first_seen"], ["Last Connected / Used", "last_connected"], ["Last Activity", "last_activity"],
      ["Observed Span", ""], ["Now", "active_now"], ["Evidence", "presence_confidence"], ["Source", "presence_source"]
    ], rows.map((row) => [
      rowAction(row), row.hostname, row.mac, row.ip, row.interface,
      formatTime(row.first_seen), formatTime(row.last_connected), formatTime(row.last_activity),
      presenceSpan(row), row.active_now ? "active" : "not active", activityBadge(row), evidenceLabel(row.last_activity_source)
    ]), rows);
  } else if (state.view === "hosts") {
    $("table").innerHTML = table([
      ["Action", ""], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
      ["Last Activity", "last_activity"], ["Activity Evidence", "last_activity_confidence"],
      ["Last Connected", "last_connected"], ["First Seen", "first_seen"], ["Last Seen", "last_seen"]
    ], rows.map((row) => [
      rowAction(row), row.hostname, row.mac, row.ip, row.interface, row.active_now ? "yes" : "no",
      formatTime(row.last_activity), activityBadge(row), formatTime(row.last_connected),
      formatTime(row.first_seen), formatTime(row.last_seen)
    ]), rows);
  } else if (state.view === "timeline") {
    $("table").innerHTML = table([
      ["Action", ""], ["Timestamp", "timestamp"], ["Class", "category"], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Confidence", "evidence"], ["Message", "message"]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.event_time), pill(row.event_class, row.event_class), row.hostname, row.mac, row.ip,
      confidenceBadge(row), row.message
    ]), rows);
  } else if (state.view === "support") {
    $("table").innerHTML = table([
      ["Action", ""], ["Line", "line_number"], ["Type", "finding_type"], ["Section", "section"], ["Key", "key"],
      ["Value", "value"], ["Evidence", "evidence_level"]
    ], rows.map((row) => [
      rowAction(row), row.line_number, pill(row.finding_type, row.finding_type), row.section, row.key,
      row.value || row.raw_text, confidenceBadge(row)
    ]), rows);
  } else if (state.view === "raw") {
    $("table").innerHTML = table([
      ["Action", ""], ["Created", "created_at"], ["Artifact", "name"], ["SHA-256", "sha256"], ["Size", ""], ["Preview", ""]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.created_at), evidenceLabel(row.name), row.sha256,
      text(row.content).length, text(row.content).slice(0, 220)
    ]), rows);
  } else if (state.view === "wan_port_mappings") {
    $("table").innerHTML = table([
      ["Action", ""], ["Protocol", "protocol"], ["External", "external_port"], ["Internal Host", "internal_client"],
      ["Internal Port", "internal_port"], ["Enabled", "enabled"], ["Description", "description"], ["Source", "source"]
    ], rows.map((row) => [
      rowAction(row), row.protocol, row.external_port, row.internal_client, row.internal_port,
      row.enabled, row.description, row.source
    ]), rows);
  } else if (state.view === "mesh_topology_links") {
    $("table").innerHTML = table([
      ["Action", ""], ["Last Connected", "last_connected"], ["Node", "node"], ["Interface", "interface"],
      ["Peer", "peer"], ["Type", "link_type"], ["State", "state"], ["RX", "rx"], ["TX", "tx"]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.last_connected), row.node || row.node_mac, row.interface,
      row.peer || row.peer_mac, row.link_type, row.state, row.rx, row.tx
    ]), rows);
  } else if (state.view === "wlan_radios") {
    $("table").innerHTML = table([
      ["Action", ""], ["Radio", "radio_index"], ["SSID", "ssid"], ["Enabled", "enabled"], ["Status", "status"],
      ["Standard", "standard"], ["Channel", "channel"], ["Associations", "total_associations"], ["Bytes RX", "bytes_received"], ["Bytes TX", "bytes_sent"]
    ], rows.map((row) => [
      rowAction(row), row.radio_index, row.ssid, row.enabled, row.status, row.standard,
      row.channel, row.total_associations, row.bytes_received, row.bytes_sent
    ]), rows);
  } else if (state.view === "wlan_associations") {
    $("table").innerHTML = table([
      ["Action", ""], ["Observed", "observed_at"], ["Radio", "radio_index"], ["MAC", "mac"], ["IP", "ip"],
      ["Host", "hostname"], ["Auth", "auth_state"], ["Speed", "speed"], ["Signal", "signal_strength"], ["Guest", "guest"]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.observed_at), row.radio_index, row.mac, row.ip,
      row.hostname, row.auth_state, row.speed, row.signal_strength, row.guest
    ]), rows);
  } else if (state.view === "host_filter_profiles") {
    $("table").innerHTML = table([
      ["Action", ""], ["Profile", "name"], ["ID", "profile_id"], ["Access", "access_mode"],
      ["Budget", "time_budget"], ["Blocked", "blocked"], ["Devices", "devices_json"], ["Source", "source"]
    ], rows.map((row) => [
      rowAction(row), row.name, row.profile_id, row.access_mode, row.time_budget,
      row.blocked, row.devices_json, row.source
    ]), rows);
  } else if (state.view === "device_risk_summaries") {
    $("table").innerHTML = table([
      ["Action", ""], ["Risk", "risk_score"], ["Level", "risk_level"], ["Host", "hostname"], ["MAC", "mac"],
      ["IP", "ip"], ["Reasons", "reasons_json"], ["Summary", "summary"]
    ], rows.map((row) => [
      rowAction(row), row.risk_score, pill(row.risk_level, row.risk_level), row.hostname,
      row.mac, row.ip, row.reasons_json, row.summary
    ]), rows);
  } else if (state.view === "entities") {
    $("table").innerHTML = table([
      ["Action", ""], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
      ["First Seen", "first_seen"], ["Last Seen", "last_seen"], ["Events", "event_count"], ["WiFi", "wifi_count"]
    ], rows.map((row) => [
      entityAction(row), row.hostname, row.mac, row.ip, row.interface, row.active_now ? "yes" : "no",
      formatTime(row.first_seen), formatTime(row.last_seen), row.event_count, row.wifi_count
    ]), rows);
  } else {
    $("table").innerHTML = table([
      ["Action", ""], ["Timestamp", "timestamp"], ["Category", "category"], ["MAC", "mac"], ["IP", "ip"], ["Message", "message"]
    ], rows.map((row) => [
      rowAction(row), formatTime(row.timestamp), pill(row.category, row.category), row.mac, row.ip, row.message
    ]), rows);
  }
  $("status").textContent = `${state.rows.length} of ${state.total} rows loaded${state.hasMore ? " - scroll for more" : ""}`;
  ensureScrollable();
}

function rowAction(row) {
  const type = row.record_type || (
    state.view === "wifi" ? "wifi" :
    state.view === "log" ? "log" :
    state.view === "presence" ? "hosts" :
    state.view === "hosts" ? "hosts" :
    state.view === "support" ? "support" :
    state.view === "raw" ? "raw" :
    additionalEvidenceView(state.view) ? state.view : ""
  );
  const id = row.record_id || row.id || "";
  return `<button class="row-action" data-action="evidence" data-record-type="${escapeHtml(type)}" data-record-id="${escapeHtml(id)}">Open</button>`;
}

function entityAction(row) {
  const value = row.mac || row.ip || row.hostname || row.key || "";
  return `<button class="row-action" data-action="entity" data-entity="${escapeHtml(value)}">Open</button>`;
}

function ensureScrollable() {
  window.setTimeout(() => {
    const el = $("table");
    if (state.hasMore && !state.loading && el.scrollHeight <= el.clientHeight + 8) {
      loadRows(false);
    }
  }, 40);
}

function pill(label, cls) {
  return `<span class="pill ${escapeHtml(cssToken(cls || label))}">${escapeHtml(evidenceLabel(display(label, "unknown")))}</span>`;
}

function confidenceBadge(row) {
  const exact = isExact(row.exact_time ?? row.exact_connection_time_available);
  const confidence = row.confidence || row.derived_time_confidence || row.evidence || (exact ? "high" : "low");
  const timeType = row.time_type || row.derived_time_type || (exact ? "exact" : "derived");
  const evidenceLevel = row.evidence_level || (exact ? "parsed_from_raw" : "inferred");
  return `${pill(timeType, timeType)} ${pill(confidence, confidence)} ${pill(evidenceLevel, evidenceLevel)}`;
}

function activityBadge(row) {
  const confidence = row.last_activity_confidence || (row.last_connected ? "high" : row.last_activity ? "medium" : "");
  const source = row.last_activity_source || (row.last_connected ? "exact_wifi_connection" : row.last_activity ? "inferred_activity" : "");
  if (!confidence && !source) return "";
  return `${pill(confidence || "unknown", confidence || "unknown")} ${pill(source || "activity", source || "activity")}`;
}

function table(headers, rows, sourceRows = []) {
  return `<table><thead><tr>${headers.map(([label, key]) => {
    if (!key) return `<th>${escapeHtml(label)}</th>`;
    const marker = state.sortBy === key ? (state.sortDir === "asc" ? " ▲" : " ▼") : "";
    return `<th class="sortable" data-sort="${escapeHtml(key)}">${escapeHtml(label + marker)}</th>`;
  }).join("")}</tr></thead><tbody>${
    rows.map((row, index) => {
      const source = sourceRows[index] || {};
      const type = source.record_type || (
        state.view === "wifi" ? "wifi" :
        state.view === "log" ? "log" :
        state.view === "presence" ? "hosts" :
        state.view === "hosts" ? "hosts" :
        state.view === "support" ? "support" :
        state.view === "raw" ? "raw" :
        additionalEvidenceView(state.view) ? state.view : ""
      );
      const id = source.record_id || source.id || "";
      return `<tr data-record-type="${escapeHtml(type)}" data-record-id="${escapeHtml(id)}">${row.map((cell, cellIndex) => {
        const raw = text(cell);
        const html = raw.startsWith("<span") || raw.startsWith("<button");
        const label = headers[cellIndex]?.[0] || "";
        return `<td data-label="${escapeHtml(label)}">${html ? raw : escapeHtml(display(cell))}</td>`;
      }).join("")}</tr>`;
    }).join("")
  }</tbody></table>`;
}

function defaultSortForView(view) {
  if (view === "hosts") return "last_activity";
  if (view === "presence") return "last_activity";
  if (view === "log") return "timestamp";
  if (view === "timeline") return "timestamp";
  if (view === "entities") return "last_seen";
  if (view === "support") return "line_number";
  if (view === "raw") return "created_at";
  if (view === "wan_port_mappings") return "external_port";
  if (view === "mesh_topology_links") return "last_connected";
  if (view === "wlan_radios") return "radio_index";
  if (view === "wlan_associations") return "observed_at";
  if (view === "host_filter_profiles") return "name";
  if (view === "device_risk_summaries") return "risk_score";
  return "derived_connected_at";
}

function presenceSpan(row) {
  const start = parseDate(row.first_seen);
  const end = parseDate(row.last_activity || row.last_connected || row.last_seen);
  if (!start || !end || end < start) return "";
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return "< 1 min";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function additionalEvidenceView(view) {
  return [
    "wan_port_mappings",
    "mesh_topology_links",
    "wlan_radios",
    "wlan_associations",
    "host_filter_profiles",
    "device_risk_summaries"
  ].includes(view);
}

async function openEvidence(type, id) {
  if (!type || !id) return;
  const response = await fetch(
    `/api/evidence?record_type=${encodeURIComponent(type)}&record_id=${encodeURIComponent(id)}&profile=${encodeURIComponent(state.profile)}`
  );
  if (!response.ok) return;
  const payload = await response.json();
  $("drawer-body").innerHTML = `
    <p class="section-title">Parsed Record</p>
    <pre>${escapeHtml(JSON.stringify(cleanRecord(payload.record || {}), null, 2))}</pre>
    <p class="section-title">Raw Artifact Matches</p>
    ${(payload.artifacts || []).map((artifact) => `
      <div class="mini-row"><strong>${escapeHtml(display(artifact.name, "artifact"))}</strong><span>${escapeHtml(formatTime(artifact.created_at))}</span></div>
      <pre>${escapeHtml(artifact.snippet || "")}</pre>
    `).join("") || `<div class="empty">No matching raw artifact snippet found for this row.</div>`}
  `;
  $("drawer").classList.add("open");
}

async function openEntity(value) {
  if (!value) return;
  const response = await fetch(
    `/api/entity?value=${encodeURIComponent(value)}&profile=${encodeURIComponent(state.profile)}&run_id=${encodeURIComponent(state.runId)}`
  );
  if (!response.ok) return;
  const payload = await response.json();
  $("drawer-body").innerHTML = `
    <p class="section-title">Entity Pivot</p>
    <pre>${escapeHtml(JSON.stringify(cleanRecord(payload.hosts?.[0] || payload.entity || {}), null, 2))}</pre>
    <p class="section-title">Related Timeline</p>
    ${(payload.timeline || []).slice(0, 80).map((row) => `
      <button class="timeline-row ${escapeHtml(cssToken(row.event_class))}" data-record-type="${escapeHtml(row.record_type || "")}" data-record-id="${escapeHtml(row.record_id || "")}">
        <div class="dot"></div>
        <div><div class="timeline-main">${escapeHtml(display(row.message, "No message"))}</div><div>${escapeHtml(formatTime(row.event_time))} ${confidenceBadge(row)}</div></div>
      </button>
    `).join("") || `<div class="empty">No related retained evidence.</div>`}
  `;
  $("drawer").classList.add("open");
}

async function loadPolling() {
  const response = await fetch("/api/polling");
  if (!response.ok) return;
  const payload = await response.json();
  state.pollActive = Boolean(payload.active);
  $("poll-status").textContent = payload.active ? `Running every ${payload.interval_minutes} min` : "Stopped";
  $("toggle-poll").textContent = payload.active ? "Stop Polling" : "Start Polling";
}

async function togglePolling() {
  const interval = Number($("poll-interval").value || 15);
  const response = await fetch("/api/polling", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ active: !state.pollActive, interval_minutes: interval })
  });
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  await loadPolling();
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

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    state.view = tab.dataset.view;
    state.sortBy = defaultSortForView(state.view);
    state.sortDir = "desc";
    $("category").disabled = !["log", "timeline"].includes(state.view);
    loadRows(true);
  });
});

$("table").addEventListener("click", (event) => {
  const action = event.target.closest("[data-action]");
  if (action?.dataset.action === "evidence") {
    openEvidence(action.dataset.recordType, action.dataset.recordId);
    return;
  }
  if (action?.dataset.action === "entity") {
    openEntity(action.dataset.entity);
    return;
  }
  const header = event.target.closest("th[data-sort]");
  if (!header) return;
  const nextSort = header.dataset.sort;
  if (state.sortBy === nextSort) {
    state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
  } else {
    state.sortBy = nextSort;
    state.sortDir = "asc";
  }
  loadRows(true);
});

$("search").addEventListener("input", debounce(async (event) => {
  state.query = event.target.value;
  await Promise.all([loadRows(true), loadEntities(), loadSideTimeline()]);
}));

$("category").addEventListener("change", async (event) => {
  state.category = event.target.value;
  await Promise.all([loadRows(true), loadSideTimeline()]);
});

$("evidence-level").addEventListener("change", async (event) => {
  state.evidenceLevel = event.target.value;
  await Promise.all([loadRows(true), loadSideTimeline()]);
});

$("time-type").addEventListener("change", async (event) => {
  state.timeType = event.target.value;
  await Promise.all([loadRows(true), loadSideTimeline()]);
});

$("apply-range").addEventListener("click", async () => {
  state.rangeStart = isoFromLocal($("range-start").value);
  state.rangeEnd = isoFromLocal($("range-end").value);
  await Promise.all([loadAnalysis(), loadSideTimeline(), loadRows(true)]);
});

$("refresh").addEventListener("click", () => loadStored());
$("run-acquisition").addEventListener("click", runAcquisition);
$("profile").addEventListener("change", async (event) => {
  state.profile = event.target.value || "local";
  state.runId = "latest";
  await loadRuns();
  await loadStored();
});
$("run").addEventListener("change", async (event) => {
  state.runId = event.target.value || "latest";
  await loadStored();
});
$("import-package").addEventListener("click", () => $("import-file").click());
$("import-file").addEventListener("change", (event) => {
  importPackage(event.target.files?.[0]);
});
$("download-raw").addEventListener("click", () => {
  window.location.href = `/api/raw-artifacts/download?profile=${encodeURIComponent(state.profile)}`;
});
$("download-package").addEventListener("click", () => {
  window.location.href = `/api/acquisition-package/download?profile=${encodeURIComponent(state.profile)}`;
});
$("save-settings").addEventListener("click", saveSettings);
$("toggle-poll").addEventListener("click", togglePolling);
$("table").addEventListener("scroll", () => {
  const el = $("table");
  if (el.scrollTop + el.clientHeight >= el.scrollHeight - 160) {
    loadRows(false);
  }
});
$("table").addEventListener("dblclick", (event) => {
  const row = event.target.closest("tr[data-record-id]");
  if (!row) return;
  openEvidence(row.dataset.recordType, row.dataset.recordId);
});
$("timeline").addEventListener("click", (event) => {
  const row = event.target.closest("[data-record-id]");
  if (!row) return;
  openEvidence(row.dataset.recordType, row.dataset.recordId);
});
$("entities").addEventListener("click", (event) => {
  const card = event.target.closest("[data-entity]");
  if (!card) return;
  openEntity(card.dataset.entity);
});
$("device-risk").addEventListener("click", (event) => {
  const card = event.target.closest("[data-entity]");
  if (!card) return;
  openEntity(card.dataset.entity);
});
$("drawer-body").addEventListener("click", (event) => {
  const row = event.target.closest("[data-record-id]");
  if (!row) return;
  openEvidence(row.dataset.recordType, row.dataset.recordId);
});
$("drawer-close").addEventListener("click", () => $("drawer").classList.remove("open"));
$("drawer-close-backdrop").addEventListener("click", () => $("drawer").classList.remove("open"));
$("category").disabled = false;
loadSettings().then(async () => {
  await loadProfiles();
  await loadRuns();
  await loadStored();
});
