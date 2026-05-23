
function renderCharts() {
  const analysis = state.analysis || {};
  const hourly = new Map((analysis.hourly_counts || []).map((row) => [String(row.hour).padStart(2, "0"), row.count || 0]));
  const maxHour = Math.max(1, ...Array.from(hourly.values()));
  if ($("hour-chart")) {
    $("hour-chart").innerHTML = Array.from({ length: 24 }, (_, index) => {
      const hour = String(index).padStart(2, "0");
      const count = hourly.get(hour) || 0;
      const height = Math.max(2, Math.round((count / maxHour) * 100));
      const label = index % 3 === 0 ? `<span>${hour}</span>` : "";
      return `<div class="bar" title="${hour}:00 - ${count} records" style="height:${height}%">${label}</div>`;
    }).join("");
  }
  renderMiniChart("category-chart", analysis.category_counts || []);
  renderMiniChart("confidence-chart", analysis.confidence_counts || []);
  renderMiniChart("artifact-confidence-chart", analysis.confidence_counts || []);
  renderMiniChart("interface-chart", analysis.interface_counts || []);
  renderMiniChart("timestamp-chart", Object.entries(analysis.timestamp_coverage || {}).map(([label, count]) => ({ label, count })));
  renderMeshLinks(analysis.mesh_summary || {});
  renderSourceCoverage(analysis.source_coverage || {});
  renderSourceChips(analysis.source_coverage || {});
  renderCorrelations(analysis);
  renderAlertPivots(analysis);
  renderWlanRadios(analysis.tr064_summary?.wlan_radios || []);
  renderWanState(analysis.tr064_summary?.wan || {});
  renderWanExposure(analysis.tr064_summary?.wan || {});
  renderDeviceRisk(analysis.host_risk_summary || {});
  renderSecurityAdvisories(analysis.security_advisories || {});
  renderLastUsedHistogram(analysis.last_used_histogram || []);
  renderPresenceSummary(state.latest?.presence_summary || {});
  renderAdvertisementHints(analysis.advertisement_hints || {});
}

function renderInvestigation() {
  if (!$("investigation-results")) return;
  const data = state.investigation || {};
  const rows = investigationTableRows(data);
  $("investigation-summary").textContent = investigationSummaryLine(data);
  $("investigation-results").innerHTML = rows.length ? rows.map((row) => {
    const device = investigationDeviceDisplay(row);
    return `
      <tr data-record-type="${escapeHtml(row.recordType)}" data-record-id="${escapeHtml(row.recordId || "")}">
        <td data-label="Evidence">
          <span class="pill ${escapeHtml(cssToken(row.kind))}">${escapeHtml(row.kindLabel)}</span>
        </td>
        <td data-label="Device">
          <strong>${escapeHtml(display(device.primary, "Unknown"))}</strong>
          ${device.meta ? `<div class="subtitle">${escapeHtml(device.meta)}</div>` : ""}
          <div class="subtitle">${escapeHtml(display(row.detail, ""))}</div>
        </td>
        <td data-label="MAC / IP">${escapeHtml([row.mac, row.ip].filter(Boolean).join(" / ") || "-")}</td>
        <td data-label="When">${escapeHtml(row.timeRange || "-")}</td>
        <td data-label="Source">${escapeHtml(row.source || "-")}</td>
      </tr>
    `;
  }).join("") : `<tr><td colspan="5"><div class="empty compact">No historic connection, AP-side observation, or retained 802.11 probe row matches this filter.</div></td></tr>`;
}

function investigationSummaryLine(data) {
  const counts = data.counts || {};
  const discovery = data.discovery_devices || {};
  const probe = data.probe_telemetry || {};
  const wifiRows = data.samples?.wifi || [];
  const connectedRows = wifiRows.filter((row) => investigationWifiKind(row).kind === "historical_connected").length;
  const seenRows = wifiRows.filter((row) => investigationWifiKind(row).kind === "historical_seen").length;
  const probeRows = probe.total || counts.probe_requests || 0;
  const hostCandidates = counts.device_candidates || counts.presence_points || 0;
  const discoveryHints = discovery.total || counts.discovery_hints_in_range || 0;
  if (connectedRows || seenRows || probeRows || hostCandidates || discoveryHints) {
    return [
      `${connectedRows} connected evidence row(s)`,
      `${seenRows} AP-side seen/nearby 802.11 row(s)`,
      `${probeRows} retained probe-request row(s)`,
      `${hostCandidates} host-state candidate(s)`,
      `${discoveryHints} discovery/broadcast context row(s)`
    ].join(" / ");
  }
  return probe.note || "No connected devices or 802.11 probe evidence match this window. That means no retained evidence was found, not that nothing happened.";
}

function investigationTableRows(data) {
  const wifiRows = (data.samples?.wifi || []).map((row) => {
    const kind = investigationWifiKind(row);
    return {
      kind: kind.kind,
      kindLabel: kind.label,
      recordType: "wifi_connections",
      recordId: row.id,
      device: row.device_label || row.friendly_name || row.hostname || row.mac || row.ip,
      friendlyName: row.friendly_name,
      deviceType: row.device_type,
      vendor: row.vendor,
      model: row.model,
      mac: row.mac,
      ip: row.ip,
      timeRange: formatTime(row.derived_connected_at),
      source: [
        evidenceLabel(row.derived_time_type),
        row.source,
        evidenceLabel(row.derived_time_confidence || row.evidence_level || "")
      ].filter(Boolean).join(" / "),
      detail: row.message || row.evidence_note || ""
    };
  });
  const connectedRows = (data.devices?.rows || []).map((row) => {
    const first = formatTime(row.presence_start || row.first_seen);
    const last = formatTime(row.presence_end || row.last_activity || row.last_connected);
    const match = row.window_match || row.last_activity_source || "seen";
    return {
      kind: row.active_now ? "connected_active" : "connected_seen",
      kindLabel: row.active_now ? "active in range" : "connected in range",
      recordType: "hosts",
      recordId: row.id,
      device: row.device_label || row.friendly_name || row.hostname || row.mac || row.ip,
      friendlyName: row.friendly_name,
      deviceType: row.device_type,
      vendor: row.vendor,
      model: row.model,
      mac: row.mac,
      ip: row.ip,
      timeRange: [first ? `first ${first}` : "", last ? `last ${last}` : ""].filter(Boolean).join(" - "),
      source: [row.interface || "unknown interface", evidenceLabel(row.last_activity_confidence || ""), evidenceLabel(match)]
        .filter(Boolean)
        .join(" / "),
      detail: row.evidence_note || ""
    };
  });
  const discoveryRows = (data.discovery_devices?.rows || []).map((row) => ({
    kind: row.kind === "nearby_probe" ? "historical_probe" : "historical_seen",
    kindLabel: row.kind === "nearby_probe" ? "802.11 probe request" : evidenceLabel(row.kind || row.hint_type || "nearby_probe"),
    recordType: row.record_type || "advertisement_hints",
    recordId: row.id,
    device: row.device_label || row.friendly_name || row.title || row.hostname || row.mac || row.ip || row.protocol,
    friendlyName: row.friendly_name,
    deviceType: row.device_type,
    vendor: row.vendor,
    model: row.model,
    mac: row.mac,
    ip: row.ip,
    timeRange: formatTime(row.time || row.observed_at || row.last_connected) || "retained without exact event time",
    source: [
      row.protocol,
      row.direction || row.state || row.auth_state,
      row.signal,
      evidenceLabel(row.confidence || row.evidence_level || "")
    ].filter(Boolean).join(" / "),
    detail: row.summary || row.evidence_note || ""
  }));
  return wifiRows.concat(discoveryRows, connectedRows);
}

function investigationDeviceDisplay(row) {
  const primary = row.device || row.friendlyName || row.hostname || row.mac || row.ip || "Unknown";
  const type = row.deviceType || inferInvestigationDeviceType(row);
  const meta = [
    row.friendlyName && row.friendlyName !== primary ? `friendly: ${row.friendlyName}` : "",
    type ? `type: ${type}` : "",
    meaningfulDeviceMeta(row.model) && row.model !== type ? row.model : "",
    meaningfulDeviceMeta(row.vendor) && row.vendor !== row.model ? row.vendor : ""
  ].filter(Boolean).join(" / ");
  return { primary, meta };
}

function meaningfulDeviceMeta(value) {
  const normalized = String(value || "").trim();
  return normalized && !["0", "false", "none", "null", "unknown"].includes(normalized.toLowerCase());
}

function inferInvestigationDeviceType(row) {
  const haystack = [row.device, row.friendlyName, row.detail, row.model, row.vendor].filter(Boolean).join(" ").toLowerCase();
  const rules = [
    ["iPhone", ["iphone"]],
    ["iPad", ["ipad"]],
    ["Apple Watch", ["watch"]],
    ["Mac", ["macbook", "mac ", "imac"]],
    ["Android", ["android", "pixel", "galaxy", "samsung", "xiaomi", "huawei", "oneplus"]],
    ["Router/AP", ["router", "dreamrouter", "fritz.box", "repeater", "access point"]],
    ["TV", ["tv", "chromecast", "fire tv", "appletv"]]
  ];
  const match = rules.find(([, needles]) => needles.some((needle) => haystack.includes(needle)));
  return match ? match[0] : "";
}

function investigationWifiKind(row) {
  const type = row.derived_time_type || "";
  const event = row.event || "";
  if (type.includes("probe") || event.includes("probe")) {
    return { kind: "historical_probe", label: "802.11 probe request" };
  }
  if (
    row.exact_connection_time_available ||
    type === "80211_station_history_interval" ||
    type === "80211_ap_sta_connected" ||
    type === "connection_event" ||
    type === "wlan_association_snapshot" ||
    type === "80211_wpa_pairwise_handshake" ||
    type === "80211_radius_accounting_start"
  ) {
    return { kind: "historical_connected", label: "connected" };
  }
  return { kind: "historical_seen", label: "seen near AP" };
}

function renderInvestigationDevices(devices) {
  if (!$("investigation-devices")) return;
  const rows = devices.rows || [];
  const interfaceCounts = devices.by_interface || [];
  const confidenceCounts = devices.by_confidence || [];
  const summary = [
    ...interfaceCounts.slice(0, 4).map((row) => `${display(row.label, "unknown")}: ${row.count || 0}`),
    ...confidenceCounts.slice(0, 3).map((row) => `${evidenceLabel(display(row.label, "unknown"))}: ${row.count || 0}`)
  ].join(" / ");
  $("investigation-device-summary").innerHTML = `
    <div class="mini-row"><span>Device candidates</span><strong>${escapeHtml(rows.length)}</strong></div>
    <div class="subtitle">${escapeHtml(summary || devices.note || "No device candidates for the selected filters.")}</div>
  `;
  $("investigation-devices").innerHTML = rows.length ? rows.map((row) => {
    const entity = [row.hostname, row.mac, row.ip].filter(Boolean).join(" ");
    const match = row.window_match || row.last_activity_source || "presence";
    const range = [
      row.presence_start ? `first ${formatTime(row.presence_start)}` : "",
      row.presence_end ? `last ${formatTime(row.presence_end)}` : ""
    ].filter(Boolean).join(" / ");
    const meta = [
      row.interface || "unknown interface",
      row.active_now ? "active at fetch" : "",
      evidenceLabel(row.last_activity_confidence || row.evidence_level || ""),
      evidenceLabel(match)
    ].filter(Boolean).join(" / ");
    return `
      <button class="device-candidate" data-record-type="hosts" data-record-id="${escapeHtml(row.id || "")}" data-entity="${escapeHtml(entity)}">
        <div class="device-candidate-main">
          <strong>${escapeHtml(display(row.hostname || row.mac || row.ip, "Unknown device"))}</strong>
          <span>${escapeHtml(range || "No retained timestamp range")}</span>
        </div>
        <div class="subtitle">${escapeHtml([row.mac, row.ip, meta].filter(Boolean).join(" / "))}</div>
      </button>
    `;
  }).join("") : `<div class="empty compact">No devices match this window and filter set.</div>`;
}

function renderInvestigationDiscoveryDevices(discovery) {
  if (!$("investigation-discovery-devices")) return;
  const rows = discovery.rows || [];
  const byKind = discovery.by_kind || [];
  $("investigation-discovery-summary").innerHTML = `
    <div class="mini-row"><span>Discovery rows</span><strong>${escapeHtml(discovery.total || 0)}</strong></div>
    <div class="subtitle">${escapeHtml(byKind.map((row) => `${evidenceLabel(row.label)}: ${row.count || 0}`).join(" / ") || discovery.note || "No retained discovery rows for this filter.")}</div>
  `;
  $("investigation-discovery-devices").innerHTML = rows.length ? rows.map((row) => {
    const recordType = row.record_type || "advertisement_hints";
    const title = row.title || row.hostname || row.mac || row.ip || row.protocol || "Discovery evidence";
    const meta = [
      formatTime(row.time || row.observed_at || row.last_connected),
      evidenceLabel(row.kind || row.hint_type || row.record_type),
      row.protocol,
      row.direction || row.state || row.auth_state,
      row.signal,
      evidenceLabel(row.confidence || row.evidence_level || "")
    ].filter(Boolean).join(" / ");
    return `
      <button class="device-candidate" data-record-type="${escapeHtml(recordType)}" data-record-id="${escapeHtml(row.id || "")}">
        <div class="device-candidate-main">
          <strong>${escapeHtml(display(title, "Discovery evidence"))}</strong>
          <span>${escapeHtml(formatTime(row.time || row.observed_at || row.last_connected) || "no timestamp")}</span>
        </div>
        <div class="subtitle">${escapeHtml([row.mac, row.ip, meta].filter(Boolean).join(" / "))}</div>
        <div class="subtitle">${escapeHtml(display(row.summary || row.evidence_note, ""))}</div>
      </button>
    `;
  }).join("") : `<div class="empty compact">No WLAN association, mesh roaming, broadcast, or discovery rows match this window.</div>`;
}

function renderInvestigationTimeline(id, rows, type) {
  const emptyMessages = {
    timeline: "No exact retained timeline rows in this window.",
    auth: "No retained auth/login attempts in this window.",
    presence: "No host first/last/last-used points in this window.",
    wifi: "No retained WiFi evidence points in this window."
  };
  $(id).innerHTML = rows.length ? rows.map((row) => {
    const recordType = type === "presence" ? "hosts" : type === "wifi" ? "wifi_connections" : "event_log";
    const recordId = row.record_id || row.id || "";
    const when = row.event_time || row.timestamp || row.derived_connected_at || row.last_activity || row.last_connected || row.first_seen;
    const title = row.message || row.hostname || row.ip || row.mac || row.event || row.derived_time_type || "Evidence";
    const meta = [
      formatTime(when),
      row.category || row.event_class || row.derived_time_type || row.interface,
      row.last_activity_confidence || row.derived_time_confidence || row.confidence,
      row.source || row.last_activity_source
    ].filter(Boolean).join(" / ");
    return `
      <button class="timeline-row ${escapeHtml(cssToken(type))}" data-record-type="${escapeHtml(recordType)}" data-record-id="${escapeHtml(recordId)}">
        <div class="dot"></div>
        <div>
          <div class="timeline-main">${escapeHtml(display(title, "Evidence"))}</div>
          <div>${escapeHtml(meta)}</div>
        </div>
      </button>
    `;
  }).join("") : `<div class="empty compact">${escapeHtml(emptyMessages[type] || "No retained evidence.")}</div>`;
}

function renderInvestigationDiscovery(discovery) {
  const all = discovery.all_retained || {};
  const inRange = discovery.in_range || {};
  const protocols = all.by_protocol || [];
  const recent = all.recent || [];
  $("investigation-discovery").innerHTML = `
    <div class="mini-row"><span>In selected window</span><strong>${escapeHtml(inRange.total || 0)}</strong></div>
    <div class="mini-row"><span>All retained hints</span><strong>${escapeHtml(all.total || 0)}</strong></div>
    <div class="subtitle">${escapeHtml(discovery.note || "")}</div>
    ${protocols.slice(0, 6).map((row) => `
      <div class="mini-row"><span>${escapeHtml(evidenceLabel(row.label))}</span><strong>${escapeHtml(row.count || 0)}</strong></div>
    `).join("")}
    ${recent.slice(0, 5).map((row) => `
      <button class="advisory-card" data-record-type="advertisement_hints" data-record-id="${escapeHtml(row.id || "")}">
        <div class="mini-row">
          <span>${escapeHtml(display(row.hostname || row.ip || row.mac || row.protocol, "Discovery hint"))}</span>
          <strong>${escapeHtml(evidenceLabel(row.confidence || "low"))}</strong>
        </div>
        <div class="subtitle">${escapeHtml([row.protocol, row.direction, row.source].filter(Boolean).join(" / "))}</div>
      </button>
    `).join("")}
  `;
}

function renderMiniChart(id, rows) {
  if (!$(id)) return;
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
            ${artifact.attempted && !artifact.present ? ` (${escapeHtml(artifact.failed_attempts || 0)} failed)` : ""}
          </span>
        `).join("")}
      </div>
    </div>
  `).join("");
  const html = details || summary || `<div class="empty">No source coverage data.</div>`;
  if ($("source-coverage")) $("source-coverage").innerHTML = html;
  if ($("artifact-source-coverage")) $("artifact-source-coverage").innerHTML = html;
}

function renderSourceChips(coverage) {
  const target = $("source-chips");
  if (!target) return;
  const present = new Set((coverage.present_raw_artifacts || []).map((row) => row.name).filter(Boolean));
  const expected = coverage.expected_raw_artifacts || [];
  const names = expected.length
    ? expected
    : (coverage.present_raw_artifacts || []).map((row) => row.name).filter(Boolean);
  const chips = names.slice(0, 14).map((name) => {
    const available = present.has(name);
    const label = evidenceLabel(name);
    return `
      <button
        class="source-chip ${available ? "present" : "missing"}"
        type="button"
        data-source-query="${escapeHtml(name)}"
        data-source-view="raw"
        title="${escapeHtml(label)}"
      >${escapeHtml(label)}${available ? "" : " missing"}</button>
    `;
  }).join("");
  target.innerHTML = chips
    ? `<button class="source-chip" type="button" data-source-query="" data-source-view="all">all sources</button>${chips}`
    : `<span class="subtitle">No source coverage loaded.</span>`;
}

function renderCorrelations(analysis = {}) {
  const target = $("correlations");
  if (!target) return;
  const counts = state.latest?.counts || {};
  const wanMappings = analysis.tr064_summary?.wan?.port_mappings || [];
  const enabledWan = wanMappings.filter((mapping) => mapping.enabled).length;
  const security = analysis.security_advisories || {};
  const risk = analysis.host_risk_summary || {};
  const riskTotals = risk.totals || {};
  const advertisement = analysis.advertisement_hints || {};
  const rows = [
    {
      label: "WiFi joins",
      value: counts.wifi_connections || 0,
      meta: "connection, station, and WLAN association evidence",
      view: "wifi",
      category: "wifi"
    },
    {
      label: "Active hosts",
      value: counts.active_hosts || 0,
      meta: "current host table entities",
      view: "entities"
    },
    {
      label: "WAN exposure",
      value: enabledWan,
      meta: `${wanMappings.length || 0} retained port mapping row(s)`,
      view: "wan_port_mappings",
      category: "internet"
    },
    {
      label: "Security findings",
      value: security.high_or_critical || security.total || 0,
      meta: "advisory rows and device risk signals",
      view: "security_advisories"
    },
    {
      label: "Device risk",
      value: riskTotals.high || riskTotals.medium || 0,
      meta: "ranked host risk summary",
      view: "device_risk_summaries"
    },
    {
      label: "Discovery hints",
      value: advertisement.total || 0,
      meta: "broadcast and advertisement context",
      view: "advertisement_hints",
      category: "network"
    }
  ];
  target.innerHTML = rows.map((row) => `
    <button
      class="correlation-pivot"
      type="button"
      data-pivot-view="${escapeHtml(row.view)}"
      data-pivot-category="${escapeHtml(row.category || "all")}"
    >
      <strong>${escapeHtml(row.label)}</strong>
      <span>${escapeHtml(row.value)}</span>
      <small>${escapeHtml(row.meta)}</small>
    </button>
  `).join("");
}

function renderAlertPivots(analysis = {}) {
  const target = $("alert-pivots");
  if (!target) return;
  const security = analysis.security_advisories || {};
  const siemAlerts = analysis.siem_alerts || {};
  const risk = analysis.host_risk_summary || {};
  const riskTotals = risk.totals || {};
  const wan = analysis.tr064_summary?.wan || {};
  const enabledWan = (wan.port_mappings || []).filter((mapping) => mapping.enabled).length;
  const topAlerts = (siemAlerts.top || []).slice(0, 4).map((row) => ({
    label: evidenceLabel(row.rule_id || "SIEM alert"),
    value: evidenceLabel(row.severity || "review"),
    meta: row.summary || [row.entity_label, row.event_count ? `${row.event_count} events` : ""].filter(Boolean).join(" / "),
    view: "correlations",
    level: row.severity || "medium"
  }));
  const top = (security.top || []).slice(0, 3).map((row) => ({
    label: row.title || row.advisory_id || "Security advisory",
    value: evidenceLabel(row.severity || "review"),
    meta: [row.category, row.subject].filter(Boolean).join(" / ") || "security advisory",
    view: "security_advisories",
    section: "security",
    level: row.severity || "medium"
  }));
  const rows = [
    {
      label: "SIEM alerts",
      value: siemAlerts.open ?? siemAlerts.total ?? 0,
      meta: `${siemAlerts.high_or_critical || 0} critical/high open / ${siemAlerts.resolved || 0} resolved`,
      view: "correlations",
      level: siemAlerts.high_or_critical ? "high" : siemAlerts.open ? "medium" : "low"
    },
    {
      label: "Critical / high",
      value: security.high_or_critical || 0,
      meta: "router exposure and configuration advisories",
      view: "security_advisories",
      section: "security",
      level: security.high_or_critical ? "high" : "low"
    },
    {
      label: "WAN exposure",
      value: enabledWan,
      meta: `${(wan.port_mappings || []).length} retained mapping row(s)`,
      view: "wan_port_mappings",
      section: "security",
      level: enabledWan ? "medium" : "low"
    },
    {
      label: "Elevated devices",
      value: riskTotals.high || riskTotals.medium || 0,
      meta: "host risk summary pivots",
      view: "device_risk_summaries",
      section: "security",
      level: riskTotals.high ? "high" : riskTotals.medium ? "medium" : "low"
    },
    ...topAlerts,
    ...top
  ];
  target.innerHTML = rows.map((row) => `
    <button
      class="alert-pivot ${escapeHtml(cssToken(row.level))}"
      type="button"
      data-pivot-section="${escapeHtml(row.section || "")}"
      data-pivot-view="${escapeHtml(row.view)}"
      data-pivot-category="all"
    >
      <strong>${escapeHtml(row.label)}</strong>
      <span>${escapeHtml(row.value)}</span>
      <small>${escapeHtml(row.meta)}</small>
    </button>
  `).join("");
}

function updateSearchChrome() {
  if ($("search-summary")) {
    const query = state.query.trim();
    const noun = state.total === 1 ? "row" : "rows";
    $("search-summary").textContent = query
      ? `${state.total} ${noun} for "${query}"`
      : `${state.total} retained ${noun}`;
  }
  if ($("table-subtitle")) {
    const filters = [
      state.category !== "all" ? evidenceLabel(state.category) : "",
      state.severity !== "all" ? evidenceLabel(state.severity) : "",
      state.eventKind !== "all" ? evidenceLabel(state.eventKind) : "",
      state.parserRule !== "all" ? evidenceLabel(state.parserRule) : "",
      state.source !== "all" ? evidenceLabel(state.source) : "",
      state.evidenceLevel !== "all" ? evidenceLabel(state.evidenceLevel) : "",
      state.timeType !== "all" ? evidenceLabel(state.timeType) : ""
    ].filter(Boolean);
    $("table-subtitle").textContent = filters.length
      ? filters.join(" / ")
      : "Open any row to inspect parsed fields and raw artifact snippets.";
  }
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

function renderSecurityAdvisories(summary) {
  const totals = summary.by_severity || [];
  const categories = summary.by_category || [];
  const top = summary.top || [];
  const total = summary.total || 0;
  const high = summary.high_or_critical || 0;
  $("security-summary").innerHTML = `
    <div class="security-card ${high ? "high" : "low"}">
      <span>Open advisories</span>
      <strong>${escapeHtml(total)}</strong>
      <small>${escapeHtml(high)} critical/high</small>
    </div>
    <div class="security-card">
      <span>WAN exposure</span>
      <strong>${escapeHtml(summary.wan_exposure || 0)}</strong>
      <small>enabled mappings and router exposure hints</small>
    </div>
    <div class="security-card">
      <span>UPnP / PCP</span>
      <strong>${escapeHtml(summary.upnp_pcp || 0)}</strong>
      <small>automatic port sharing signals</small>
    </div>
    <div class="security-card">
      <span>Wireless</span>
      <strong>${escapeHtml(summary.wireless || 0)}</strong>
      <small>guest, WPS, weak encryption hints</small>
    </div>
  `;
  renderMiniChart("security-severity", totals);
  renderMiniChart("security-categories", categories);
  $("security-top").innerHTML = top.length ? top.map((row) => `
    <button class="advisory-card" data-record-id="${escapeHtml(row.id || "")}" data-record-type="security_advisories">
      <div class="mini-row">
        <span>${escapeHtml(display(row.title, "Security advisory"))}</span>
        <strong>${escapeHtml(evidenceLabel(row.severity))}</strong>
      </div>
      <div class="subtitle">${escapeHtml([row.category, row.subject].filter(Boolean).join(" / "))}</div>
    </button>
  `).join("") : `<div class="empty">No security advisories for this run.</div>`;
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

function renderAdvertisementHints(summary) {
  const recent = summary.recent || [];
  const protocols = summary.by_protocol || [];
  if (!summary.available) {
    $("advertisement-hints").innerHTML = `<div class="empty">No retained advertisement or broadcast hints.</div>`;
    return;
  }
  $("advertisement-hints").innerHTML = `
    <div class="mini-row"><span>Total hints</span><strong>${escapeHtml(summary.total || 0)}</strong></div>
    ${protocols.slice(0, 5).map((row) => `
      <div class="mini-row"><span>${escapeHtml(evidenceLabel(row.label))}</span><strong>${escapeHtml(row.count || 0)}</strong></div>
    `).join("")}
    ${recent.slice(0, 5).map((row) => `
      <div class="topology-row">
        <div class="mini-row">
          <span>${escapeHtml(display(row.hostname || row.ip || row.mac || row.protocol, "Hint"))}</span>
          <strong>${escapeHtml(evidenceLabel(row.confidence))}</strong>
        </div>
        <div class="subtitle">${escapeHtml([row.protocol, row.direction, row.source].filter(Boolean).join(" / "))}</div>
      </div>
    `).join("")}
  `;
}

function renderTimeline(rows) {
  if (!$("timeline")) return;
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
  if (!$("entities")) return;
  $("entities").innerHTML = rows.length ? rows.map((row) => `
    <button class="entity-card" data-entity="${escapeHtml(row.mac || row.ip || row.hostname || row.key)}">
      <strong>${escapeHtml(display(row.hostname || row.mac || row.ip, "Unknown"))}</strong>
      <span>${escapeHtml([row.mac, row.ip, row.interface].filter(Boolean).join(" / "))}</span>
      <span>${escapeHtml((row.event_count || 0) + " log / " + (row.wifi_count || 0) + " wifi")}</span>
    </button>
  `).join("") : `<div class="empty">No entities match.</div>`;
}

function renderFacets() {
  const target = $("field-facets");
  if (!target) return;
  const payload = state.facets || {};
  const facets = payload.facets || {};
  const specs = [
    ["category", "Categories", state.category],
    ["kind", "Event kinds", state.eventKind],
    ["severity", "Severities", state.severity],
    ["source", "Sources", state.source],
    ["parser_rule", "Parser rules", state.parserRule],
    ["entity", "Entities", "all"]
  ];
  target.innerHTML = specs.map(([field, label, selected]) => {
    const rows = facets[field] || [];
    if (!rows.length) return "";
    return `
      <div class="facet-block">
        <div class="facet-title">${escapeHtml(label)}</div>
        ${rows.map((row) => {
          const value = row.value || "unknown";
          const active = selected === value ? " active" : "";
          return `
            <button class="facet-row${active}" type="button" data-facet-field="${escapeHtml(field)}" data-facet-value="${escapeHtml(value)}">
              <span>${escapeHtml(evidenceLabel(value))}</span>
              <strong>${escapeHtml(row.count || 0)}</strong>
            </button>
          `;
        }).join("")}
      </div>
    `;
  }).join("") || `<div class="empty">No SIEM fields for the current search.</div>`;
  renderActiveFilters();
}

function renderActiveFilters() {
  const target = $("active-filters");
  if (!target) return;
  const filters = [
    ["category", state.category, "Category"],
    ["severity", state.severity, "Severity"],
    ["kind", state.eventKind, "Kind"],
    ["parser_rule", state.parserRule, "Parser"],
    ["source", state.source, "Source"],
    ["evidence", state.evidenceLevel, "Evidence"],
    ["time", state.timeType, "Time"]
  ].filter(([, value]) => value && value !== "all");
  target.innerHTML = filters.map(([field, value, label]) => `
    <button class="active-filter" type="button" data-clear-filter="${escapeHtml(field)}">
      ${escapeHtml(label)}: ${escapeHtml(evidenceLabel(value))} <span aria-hidden="true">x</span>
    </button>
  `).join("");
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
  if (!$("m-wifi")) return;
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
  if (!$("acquisition-status")) return;
  const latest = state.latest || {};
  const run = latest.latest_run || {};
  const counts = latest.counts || {};
  const retained = latest.retained || {};
  const generated = run.generated_at ? formatTime(run.generated_at) : "No run";
  const router = run.router_address || run.router?.address || $("cfg-address").value || "Not set";
  const windowText = retained.oldest_event || retained.newest_event
    ? `${formatTime(retained.oldest_event)} to ${formatTime(retained.newest_event)}`
    : "No retained log window";
  const eventCount = `${counts.event_log || 0} logs`;
  const timestampedCount = retained.timestamped_event_count !== undefined
    ? ` / ${retained.timestamped_event_count || 0} timestamped`
    : "";
  const coverage = latest.source_coverage || {};
  const missing = coverage.missing_raw_artifacts || [];
  const coverageText = missing.length ? `missing ${missing.map(evidenceLabel).join(", ")}` : "all expected raw sources";
  $("acquisition-status").innerHTML = `
    <span>Latest run<strong>${escapeHtml(generated)}</strong></span>
    <span>Router<strong>${escapeHtml(router)}</strong></span>
    <span>Retained window<strong>${escapeHtml(windowText)}</strong></span>
    <span>Stored records<strong>${escapeHtml(eventCount + timestampedCount + " / " + (counts.wifi_connections || 0) + " wifi / " + (counts.hosts || 0) + " hosts")}</strong></span>
    <span>Device timestamps<strong>${escapeHtml((counts.hosts_with_last_connected || 0) + " last-used / " + (counts.hosts_with_first_seen || 0) + " first-seen")}</strong></span>
    <span>Source coverage<strong>${escapeHtml(coverageText)}</strong></span>
  `;
  $("subtitle").textContent = latest.has_data ? `Stored evidence from ${display(router, "FRITZ!Box")}` : "No stored evidence yet";
}
