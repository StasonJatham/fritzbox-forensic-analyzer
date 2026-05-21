
let loadRowsCallback = null;

function setLoadRowsCallback(callback) {
  loadRowsCallback = callback;
}

const DEFAULT_TABLE_VIEW_SPEC = {
  defaultSort: "derived_connected_at",
  headers: [
    ["Action", ""], ["Timestamp", "timestamp"], ["Category", "category"], ["MAC", "mac"], ["IP", "ip"],
    ["Source", "source"], ["Message", "message"]
  ],
  rowCells: (row) => [
    rowAction(row), formatTime(row.timestamp), pill(row.category, row.category), row.mac, row.ip,
    evidenceLabel(row.source), row.message
  ]
};

const SIEM_EVENT_TABLE_SPEC = {
  defaultSort: "event_time",
  widths: [180, 120, 170, 230, 520, 160, 132],
  headers: [
    ["Time", "event_time"], ["Severity", "severity"], ["Source", "source"],
    ["Entity", ""], ["Message", ""], ["Tags", ""], ["Inspect", ""]
  ],
  rowCells: (row) => [
    formatTime(siemEventTime(row)), pill(siemSeverity(row), siemSeverity(row)),
    evidenceLabel(siemSource(row)), siemEntity(row), siemMessage(row),
    siemTags(row.tags_json || row.record_class), rowAction(row)
  ]
};

const SIEM_CORRELATION_TABLE_SPEC = {
  defaultSort: "record_time",
  widths: [230, 120, 180, 180, 90, 220, 520, 132],
  headers: [
    ["Entity", ""], ["Severity", "evidence_level"], ["First Seen", "record_time"],
    ["Last Seen", ""], ["Events", ""], ["Categories", "record_type"],
    ["Summary", ""], ["Inspect", ""]
  ],
  rowCells: (row) => [
    row.entity_label || row.entity_key || siemEntity(row), pill(siemSeverity(row), siemSeverity(row)),
    formatTime(row.first_seen || row.record_time), formatTime(row.last_seen || row.record_time),
    row.event_count || "", siemTags(row.categories_json || row.record_class),
    row.summary || siemMessage(row), rowAction(row)
  ]
};

const TABLE_VIEW_SPECS = {
  events: SIEM_EVENT_TABLE_SPEC,
  siem_events: SIEM_EVENT_TABLE_SPEC,
  correlations: SIEM_CORRELATION_TABLE_SPEC,
  siem_correlations: SIEM_CORRELATION_TABLE_SPEC,
  all: {
    defaultSort: "",
    widths: [72, 52, 112, 146, 130, 112, 300],
    headers: [
      ["Action", ""], ["Rank", "rank"], ["Source", "record_type"], ["When", "record_time"],
      ["Entity", ""], ["Evidence", "evidence_level"], ["Result", ""]
    ],
    rowCells: (row) => [
      rowAction(row), allEvidenceRank(row), allEvidenceType(row), formatTime(row.record_time),
      allEvidenceEntity(row), pill(row.evidence_level || "unknown", row.evidence_level || "unknown"),
      allEvidenceMatch(row)
    ]
  },
  log: {
    defaultSort: "timestamp",
    widths: [132, 170, 118, 150, 150, 170, 520],
    headers: [
      ["Action", ""], ["Timestamp", "timestamp"], ["Category", "category"], ["MAC", "mac"], ["IP", "ip"],
      ["Source", "source"], ["Message", "message"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.timestamp), pill(row.category, row.category), row.mac, row.ip,
      evidenceLabel(row.source), row.message
    ]
  },
  wifi: {
    defaultSort: "derived_connected_at",
    headers: [
      ["Action", ""], ["Derived Time", "derived_connected_at"], ["Type", "type"], ["Host", "hostname"], ["MAC", "mac"],
      ["IP", "ip"], ["Confidence", "evidence"], ["Source", "source"], ["Evidence", "evidence"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.derived_connected_at || row.timestamp), row.derived_time_type || row.event,
      row.hostname, row.mac, row.ip, confidenceBadge(row), evidenceLabel(row.source),
      row.derived_time_confidence || row.confidence
    ]
  },
  presence: {
    defaultSort: "last_activity",
    headers: [
      ["Action", ""], ["Device", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"],
      ["First Seen", "first_seen"], ["Last Connected / Used", "last_connected"], ["Last Activity", "last_activity"],
      ["Observed Span", ""], ["Now", "active_now"], ["Evidence", "presence_confidence"], ["Source", "presence_source"]
    ],
    rowCells: (row) => [
      rowAction(row), row.hostname, row.mac, row.ip, row.interface,
      formatTime(row.first_seen), formatTime(row.last_connected), formatTime(row.last_activity),
      presenceSpan(row), row.active_now ? "active" : "not active", activityBadge(row), evidenceLabel(row.last_activity_source)
    ]
  },
  hosts: {
    defaultSort: "last_activity",
    headers: [
      ["Action", ""], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
      ["Last Activity", "last_activity"], ["Activity Evidence", "last_activity_confidence"],
      ["Last Connected", "last_connected"], ["First Seen", "first_seen"], ["Last Seen", "last_seen"]
    ],
    rowCells: (row) => [
      rowAction(row), row.hostname, row.mac, row.ip, row.interface, row.active_now ? "yes" : "no",
      formatTime(row.last_activity), activityBadge(row), formatTime(row.last_connected),
      formatTime(row.first_seen), formatTime(row.last_seen)
    ]
  },
  timeline: {
    defaultSort: "timestamp",
    headers: [
      ["Action", ""], ["Timestamp", "timestamp"], ["Class", "category"], ["Host", "hostname"], ["MAC", "mac"],
      ["IP", "ip"], ["Source", "source"], ["Confidence", "evidence"], ["Message", "message"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.event_time), pill(row.event_class, row.event_class), row.hostname, row.mac, row.ip,
      evidenceLabel(row.source), confidenceBadge(row), row.message
    ]
  },
  support: {
    defaultSort: "line_number",
    headers: [
      ["Action", ""], ["Line", "line_number"], ["Type", "finding_type"], ["Section", "section"], ["Key", "key"],
      ["Value", "value"], ["Evidence", "evidence_level"]
    ],
    rowCells: (row) => [
      rowAction(row), row.line_number, pill(row.finding_type, row.finding_type), row.section, row.key,
      row.value || row.raw_text, confidenceBadge(row)
    ]
  },
  raw: {
    defaultSort: "created_at",
    headers: [
      ["Action", ""], ["Created", "created_at"], ["Artifact", "name"], ["SHA-256", "sha256"], ["Size", ""], ["Preview", ""]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.created_at), evidenceLabel(row.name), row.sha256,
      text(row.content).length, text(row.content).slice(0, 220)
    ]
  },
  wan_port_mappings: {
    defaultSort: "external_port",
    headers: [
      ["Action", ""], ["Protocol", "protocol"], ["External", "external_port"], ["Internal Host", "internal_client"],
      ["Internal Port", "internal_port"], ["Enabled", "enabled"], ["Description", "description"], ["Source", "source"]
    ],
    rowCells: (row) => [
      rowAction(row), row.protocol, row.external_port, row.internal_client, row.internal_port,
      row.enabled, row.description, row.source
    ]
  },
  mesh_topology_links: {
    defaultSort: "last_connected",
    headers: [
      ["Action", ""], ["Last Connected", "last_connected"], ["Node", "node"], ["Interface", "interface"],
      ["Peer", "peer"], ["Type", "link_type"], ["State", "state"], ["RX", "rx"], ["TX", "tx"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.last_connected), row.node || row.node_mac, row.interface,
      row.peer || row.peer_mac, row.link_type, row.state, row.rx, row.tx
    ]
  },
  wlan_radios: {
    defaultSort: "radio_index",
    headers: [
      ["Action", ""], ["Radio", "radio_index"], ["SSID", "ssid"], ["Enabled", "enabled"], ["Status", "status"],
      ["Standard", "standard"], ["Channel", "channel"], ["Associations", "total_associations"], ["Bytes RX", "bytes_received"], ["Bytes TX", "bytes_sent"]
    ],
    rowCells: (row) => [
      rowAction(row), row.radio_index, row.ssid, row.enabled, row.status, row.standard,
      row.channel, row.total_associations, row.bytes_received, row.bytes_sent
    ]
  },
  wlan_associations: {
    defaultSort: "observed_at",
    headers: [
      ["Action", ""], ["Observed", "observed_at"], ["Radio", "radio_index"], ["MAC", "mac"], ["IP", "ip"],
      ["Host", "hostname"], ["Auth", "auth_state"], ["Speed", "speed"], ["Signal", "signal_strength"],
      ["Guest", "guest"], ["Source", "source"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.observed_at), row.radio_index, row.mac, row.ip,
      row.hostname, row.auth_state, row.speed, row.signal_strength, row.guest, evidenceLabel(row.source)
    ]
  },
  advertisement_hints: {
    defaultSort: "observed_at",
    headers: [
      ["Action", ""], ["Observed", "observed_at"], ["Protocol", "protocol"], ["Host", "hostname"],
      ["MAC", "mac"], ["IP", "ip"], ["Direction", "direction"], ["Confidence", "confidence"],
      ["Source", "source"], ["Summary", "summary"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.observed_at), pill(row.protocol, row.protocol), row.hostname,
      row.mac, row.ip, row.direction, confidenceBadge(row), evidenceLabel(row.source), row.summary
    ]
  },
  network_status_snapshots: {
    defaultSort: "observed_at",
    headers: [
      ["Action", ""], ["Observed", "observed_at"], ["Area", "area"], ["Metric", "metric"],
      ["Value", "value"], ["Unit", "unit"], ["Confidence", "confidence"], ["Source", "source"]
    ],
    rowCells: (row) => [
      rowAction(row), formatTime(row.observed_at), pill(row.area, row.area), row.metric,
      row.value, row.unit, confidenceBadge(row), evidenceLabel(row.source)
    ]
  },
  host_filter_profiles: {
    defaultSort: "name",
    headers: [
      ["Action", ""], ["Profile", "name"], ["ID", "profile_id"], ["Access", "access_mode"],
      ["Budget", "time_budget"], ["Blocked", "blocked"], ["Devices", "devices_json"], ["Source", "source"]
    ],
    rowCells: (row) => [
      rowAction(row), row.name, row.profile_id, row.access_mode, row.time_budget,
      row.blocked, row.devices_json, evidenceLabel(row.source)
    ]
  },
  device_risk_summaries: {
    defaultSort: "risk_score",
    headers: [
      ["Action", ""], ["Risk", "risk_score"], ["Level", "risk_level"], ["Host", "hostname"], ["MAC", "mac"],
      ["IP", "ip"], ["Reasons", "reasons_json"], ["Summary", "summary"]
    ],
    rowCells: (row) => [
      rowAction(row), row.risk_score, pill(row.risk_level, row.risk_level), row.hostname,
      row.mac, row.ip, row.reasons_json, row.summary
    ]
  },
  security_advisories: {
    defaultSort: "severity",
    headers: [
      ["Action", ""], ["Severity", "severity"], ["Category", "category"], ["Rule", "advisory_id"],
      ["Subject", "subject"], ["Confidence", "confidence"], ["Recommendation", "recommendation"], ["Evidence", "evidence_json"]
    ],
    rowCells: (row) => [
      rowAction(row), pill(row.severity || "review", row.severity || "review"), row.category, row.title || row.advisory_id,
      row.subject, pill(row.confidence || "medium", row.confidence || "medium"), row.recommendation, row.evidence_json
    ]
  },
  entities: {
    defaultSort: "last_seen",
    headers: [
      ["Action", ""], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
      ["First Seen", "first_seen"], ["Last Seen", "last_seen"], ["Events", "event_count"], ["WiFi", "wifi_count"]
    ],
    rowCells: (row) => [
      entityAction(row), row.hostname, row.mac, row.ip, row.interface, row.active_now ? "yes" : "no",
      formatTime(row.first_seen), formatTime(row.last_seen), row.event_count, row.wifi_count
    ]
  }
};

function renderTable() {
  const rows = state.rows;
  if (!rows.length) {
    const message = state.latest?.has_data
      ? "No rows match the current filters."
      : "No stored evidence yet. Save router settings, then run acquisition.";
    $("table").innerHTML = `<div class="empty">${escapeHtml(message)}</div>`;
    $("status").textContent = `0 of ${state.total} rows`;
    if (typeof updateSearchChrome === "function") updateSearchChrome();
    return;
  }
  const spec = TABLE_VIEW_SPECS[state.view] || DEFAULT_TABLE_VIEW_SPEC;
  $("table").innerHTML = table(spec.headers, rows.map(spec.rowCells), rows);
  $("status").textContent = `${state.rows.length} of ${state.total} rows loaded${state.hasMore ? " - scroll for more" : ""}`;
  if (typeof updateSearchChrome === "function") updateSearchChrome();
  ensureScrollable();
}

function rowAction(row) {
  const type = recordTypeForView(state.view, row);
  const id = row.record_id || row.id || "";
  return `
    <div class="row-actions">
      <button class="row-action" data-action="evidence" data-record-type="${escapeHtml(type)}" data-record-id="${escapeHtml(id)}">Inspect</button>
      <button class="row-action row-details-toggle" data-action="row-details" type="button" aria-expanded="false">Details</button>
    </div>
  `;
}

function entityAction(row) {
  const value = row.mac || row.ip || row.hostname || row.key || "";
  return `
    <div class="row-actions">
      <button class="row-action" data-action="entity" data-entity="${escapeHtml(value)}">Pivot</button>
      <button class="row-action row-details-toggle" data-action="row-details" type="button" aria-expanded="false">Details</button>
    </div>
  `;
}

function allEvidenceRank(row) {
  return state.query.trim() ? `<span class="rank-chip">#${escapeHtml(row.rank_position || "-")}</span>` : "";
}

function allEvidenceType(row) {
  const label = row.record_label || evidenceLabel(row.record_type);
  const cls = row.record_type || label;
  return `${pill(label, cls)}<span class="muted-id">${escapeHtml(display(row.record_id))}</span>`;
}

function allEvidenceEntity(row) {
  const entity = display(row.record_entity, "");
  if (!entity) return "";
  const normalized = entity.replace(/\s+/g, " ").trim();
  return `<button class="entity-inline" data-action="entity" data-entity="${escapeHtml(normalized)}">${escapeHtml(normalized)}</button>`;
}

function allEvidenceMatch(row) {
  const title = display(row.record_title, evidenceLabel(row.record_type));
  const detail = snippetAroundQuery(row.match_text || row.content || "", state.query, 240);
  const klass = display(row.record_class, "");
  return `
    <div class="result-cell">
      <div class="result-title">${escapeHtml(title)}</div>
      <div class="result-meta">
        ${klass ? pill(klass, klass) : ""}
        ${row.evidence_note ? `<span>${escapeHtml(row.evidence_note)}</span>` : ""}
      </div>
      <div class="result-snippet">${highlightQuery(detail, state.query)}</div>
    </div>
  `;
}

function snippetAroundQuery(value, query, width = 220) {
  const content = text(value).replace(/\s+/g, " ").trim();
  if (!content || content.length <= width) return content;
  const tokens = (query.match(/[\w]+/g) || []).filter(Boolean);
  const lowered = content.toLowerCase();
  const index = tokens.reduce((best, token) => {
    const found = lowered.indexOf(token.toLowerCase());
    return found >= 0 && (best < 0 || found < best) ? found : best;
  }, -1);
  const start = index >= 0 ? Math.max(0, index - Math.floor(width / 3)) : 0;
  const end = Math.min(content.length, start + width);
  return `${start > 0 ? "... " : ""}${content.slice(start, end)}${end < content.length ? " ..." : ""}`;
}

function highlightQuery(value, query) {
  const tokens = Array.from(new Set((query.match(/[\w]+/g) || []).filter((token) => token.length > 1)));
  let escaped = escapeHtml(value);
  tokens.sort((a, b) => b.length - a.length).forEach((token) => {
    escaped = escaped.replace(new RegExp(`(${escapeRegExp(escapeHtml(token))})`, "ig"), "<mark>$1</mark>");
  });
  return escaped;
}

function ensureScrollable() {
  if (!sharedTableIsActive()) return;
  window.setTimeout(() => {
    const el = $("table");
    if (!sharedTableIsActive()) return;
    if (state.hasMore && !state.loading && el.scrollHeight <= el.clientHeight + 8) {
      loadRowsCallback?.(false);
    }
  }, 40);
}

function sharedTableIsActive() {
  const el = $("table");
  const section = el?.closest("[data-section-panel]");
  if (!el || !section || !section.classList.contains("active")) return false;
  return Boolean(section.querySelector("[data-shared-table-slot]"));
}

function pill(label, cls) {
  return `<span class="pill ${escapeHtml(cssToken(cls || label))}">${escapeHtml(evidenceLabel(display(label, "unknown")))}</span>`;
}

function siemTags(value) {
  let tags = [];
  try {
    const parsed = JSON.parse(value || "[]");
    tags = Array.isArray(parsed) ? parsed : [];
  } catch {
    tags = text(value).split(/[,\s]+/).filter(Boolean);
  }
  return tags.slice(0, 5).map((tag) => pill(tag, tag)).join(" ");
}

function siemEventTime(row) {
  return row.event_time || row.record_time || row.timestamp || row.derived_connected_at || row.observed_at || row.last_seen;
}

function siemSeverity(row) {
  return row.severity || row.risk_level || row.evidence_level || row.confidence || "info";
}

function siemCategory(row) {
  return row.event_category || row.category || row.record_class || row.record_type || "event";
}

function siemKind(row) {
  return row.event_kind || row.record_label || evidenceLabel(row.record_type || row.source || "evidence");
}

function siemEntity(row) {
  return row.entity || row.record_entity || row.hostname || [row.mac, row.ip].filter(Boolean).join(" ") || "";
}

function siemSource(row) {
  return row.source || row.record_label || row.record_type || "source";
}

function siemMessage(row) {
  if (row.message || row.summary) return row.message || row.summary;
  if (row.record_title || row.match_text || row.content) return allEvidenceMatch(row);
  return "";
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
  const spec = TABLE_VIEW_SPECS[state.view] || DEFAULT_TABLE_VIEW_SPEC;
  const tableKey = cssToken(state.view || "table");
  const widths = columnWidthsForView(tableKey);
  const resolvedWidths = headers.map(([label, key], index) => (
    widths[index] || spec.widths?.[index] || defaultColumnWidth(label, key, headers.length)
  ));
  const minWidth = resolvedWidths.reduce((total, width) => total + width, 0);
  const colgroup = `<colgroup>${resolvedWidths.map((width, index) => (
    `<col data-col-index="${index}" style="width:${width}px">`
  )).join("")}</colgroup>`;
  const sortableHeaders = headers.filter(([, key]) => key);
  const mobileSort = sortableHeaders.length ? `
    <div class="mobile-table-toolbar">
      <label>Sort
        <select data-action="mobile-sort-by">
          ${sortableHeaders.map(([label, key]) => `<option value="${escapeHtml(key)}"${state.sortBy === key ? " selected" : ""}>${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <button type="button" data-action="mobile-sort-dir">${state.sortDir === "asc" ? "Ascending" : "Descending"}</button>
    </div>
  ` : "";
  return `${mobileSort}<table class="evidence-table" data-table-view="${escapeHtml(tableKey)}" style="min-width:${minWidth}px">${colgroup}<thead><tr>${headers.map(([label, key], index) => {
    const resizer = `<span class="col-resizer" data-col-index="${index}" role="separator" aria-orientation="vertical" title="Resize column"></span>`;
    if (!key) return `<th><span class="th-content">${escapeHtml(label)}</span>${resizer}</th>`;
    const marker = state.sortBy === key ? (state.sortDir === "asc" ? " ▲" : " ▼") : "";
    return `<th class="sortable" data-sort="${escapeHtml(key)}"><span class="th-content">${escapeHtml(label + marker)}</span>${resizer}</th>`;
  }).join("")}</tr></thead><tbody>${
    rows.map((row, index) => {
      const source = sourceRows[index] || {};
      const type = recordTypeForView(state.view, source);
      const id = source.record_id || source.id || "";
      return `<tr data-record-type="${escapeHtml(type)}" data-record-id="${escapeHtml(id)}">${row.map((cell, cellIndex) => {
        const raw = text(cell);
        const html = raw.startsWith("<span") || raw.startsWith("<button") || raw.trim().startsWith("<div");
        const label = headers[cellIndex]?.[0] || "";
        const key = headers[cellIndex]?.[1] || "";
        const mobileClass = mobilePrimaryColumn(state.view, label, key, cellIndex) ? " mobile-primary" : "";
        return `<td class="${mobileClass.trim()}" data-label="${escapeHtml(label)}">${html ? raw : escapeHtml(display(cell))}</td>`;
      }).join("")}</tr>`;
    }).join("")
  }</tbody></table>`;
}

function mobilePrimaryColumn(view, label, key, index) {
  if (index === 0) return true;
  const value = `${label} ${key || ""}`.toLowerCase();
  const matches = (...tokens) => tokens.some((token) => value.includes(token));
  if (["all", "events", "siem_events", "normalized_events", "correlations", "siem_correlations"].includes(view)) {
    return matches("time", "when", "severity", "category", "entity", "message", "summary", "result");
  }
  if (view === "presence" || view === "hosts") return matches("device", "host", "ip", "last connected", "last activity");
  if (view === "timeline" || view === "log") return matches("timestamp", "class", "message");
  if (view === "wifi" || view === "wlan_associations") return matches("time", "observed", "host", "mac", "ip");
  if (view === "security_advisories") return matches("severity", "category", "rule", "subject");
  if (view === "raw") return matches("created", "artifact", "size");
  if (view === "advertisement_hints") return matches("observed", "protocol", "host", "ip", "summary");
  if (view === "network_status_snapshots") return matches("observed", "area", "metric", "value");
  return index <= 4;
}

function columnWidthsForView(view) {
  if (state.columnWidths[view]) return state.columnWidths[view];
  try {
    state.columnWidths[view] = JSON.parse(localStorage.getItem(`fritzbox-table-widths:${view}`) || "{}");
  } catch {
    state.columnWidths[view] = {};
  }
  return state.columnWidths[view];
}

function saveColumnWidths(view, widths) {
  state.columnWidths[view] = widths;
  localStorage.setItem(`fritzbox-table-widths:${view}`, JSON.stringify(widths));
}

function defaultColumnWidth(label, key, columnCount) {
  const normalized = `${label} ${key || ""}`.toLowerCase();
  if (normalized.includes("action")) return 126;
  if (normalized.includes("rank")) return 76;
  if (normalized.includes("severity") || normalized.includes("confidence") || normalized.includes("evidence")) return 150;
  if (normalized.includes("timestamp") || normalized.includes("created") || normalized.includes("connected") || normalized.includes("activity") || normalized.includes("seen") || normalized.includes("observed") || normalized.includes("when")) return 190;
  if (normalized.includes("mac") || normalized.includes("sha")) return 180;
  if (normalized.includes("ip") || normalized.includes("port") || normalized.includes("radio") || normalized.includes("line") || normalized.includes("risk")) return 110;
  if (normalized.includes("message") || normalized.includes("match") || normalized.includes("preview") || normalized.includes("recommendation") || normalized.includes("summary") || normalized.includes("value") || normalized.includes("reason")) return 420;
  if (normalized.includes("host") || normalized.includes("entity") || normalized.includes("subject") || normalized.includes("rule") || normalized.includes("artifact")) return 240;
  if (columnCount >= 10) return 138;
  return 170;
}

function resizeColumn(event, resizer) {
  event.preventDefault();
  event.stopPropagation();
  const tableElement = resizer.closest("table");
  const index = Number(resizer.dataset.colIndex);
  const col = tableElement?.querySelector(`col[data-col-index="${index}"]`);
  if (!tableElement || !col) return;

  const view = tableElement.dataset.tableView || cssToken(state.view || "table");
  const startX = event.clientX;
  const startWidth = parseFloat(col.style.width) || defaultColumnWidth("", "", 8);
  const columns = Array.from(tableElement.querySelectorAll("col"));
  const widths = columnWidthsForView(view);

  document.body.classList.add("resizing-columns");
  tableElement.classList.add("resizing-columns");

  const onMove = (moveEvent) => {
    const nextWidth = Math.max(76, Math.min(760, Math.round(startWidth + moveEvent.clientX - startX)));
    col.style.width = `${nextWidth}px`;
    widths[index] = nextWidth;
    const minWidth = columns.reduce((total, column) => total + (parseFloat(column.style.width) || 0), 0);
    tableElement.style.minWidth = `${minWidth}px`;
  };

  const onUp = () => {
    document.body.classList.remove("resizing-columns");
    tableElement.classList.remove("resizing-columns");
    saveColumnWidths(view, widths);
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
    window.removeEventListener("pointercancel", onUp);
  };

  window.addEventListener("pointermove", onMove);
  window.addEventListener("pointerup", onUp, { once: true });
  window.addEventListener("pointercancel", onUp, { once: true });
}

function defaultSortForView(view) {
  const spec = TABLE_VIEW_SPECS[view] || DEFAULT_TABLE_VIEW_SPEC;
  return spec.defaultSort;
}

function recordTypeForView(view, row = {}) {
  if (view === "events" || view === "siem_events" || view === "normalized_events") return "siem_events";
  if (view === "correlations" || view === "siem_correlations") return "siem_correlations";
  if (row.record_type) return row.record_type;
  if (view === "wifi") return "wifi";
  if (view === "log") return "log";
  if (view === "presence" || view === "hosts") return "hosts";
  if (view === "support") return "support";
  if (view === "raw") return "raw";
  if (additionalEvidenceView(view)) return view;
  return "";
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
    "advertisement_hints",
    "network_status_snapshots",
    "host_filter_profiles",
    "device_risk_summaries",
    "security_advisories"
  ].includes(view);
}
