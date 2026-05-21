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
  await Promise.all([loadAnalysis(), loadInvestigation(), loadEntities(), loadSideTimeline(), loadFacets(), loadPolling()]);
  await loadRows(true);
  if (!quiet) $("status").textContent = state.latest.has_data ? `${state.rows.length} of ${state.total} rows loaded` : "No stored acquisition yet.";
}

async function loadAnalysis() {
  const params = new URLSearchParams({ start: state.rangeStart, end: state.rangeEnd, profile: state.profile, run_id: state.runId });
  const response = await fetch(`/api/analysis?${params.toString()}`);
  if (!response.ok) return;
  state.analysis = await response.json();
  renderCharts();
}

async function loadInvestigation() {
  const requestSeq = ++state.investigationRequestSeq;
  const params = new URLSearchParams({
    start: state.rangeStart,
    end: state.rangeEnd,
    q: state.investigationQuery,
    interface: state.investigationInterface,
    presence_mode: state.investigationMode,
    confidence: state.investigationConfidence,
    profile: state.profile,
    run_id: state.runId
  });
  const response = await fetch(`/api/investigation?${params.toString()}`);
  if (!response.ok) return;
  const payload = await response.json();
  if (requestSeq !== state.investigationRequestSeq) return;
  state.investigation = payload;
  renderInvestigation();
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
    kind: state.eventKind,
    severity: state.severity,
    source: state.source,
    parser_rule: state.parserRule,
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

async function loadFacets() {
  const params = new URLSearchParams({
    q: state.query,
    category: state.category,
    start: state.rangeStart,
    end: state.rangeEnd,
    evidence_level: state.evidenceLevel,
    time_type: state.timeType,
    kind: state.eventKind,
    severity: state.severity,
    source: state.source,
    parser_rule: state.parserRule,
    profile: state.profile,
    run_id: state.runId
  });
  const response = await fetch(`/api/siem/facets?${params.toString()}`);
  if (!response.ok) return;
  state.facets = await response.json();
  renderFacets();
}

async function loadRows(reset = false) {
  if (state.loading) {
    if (reset) {
      state.pendingRowsReset = true;
      state.rowsController?.abort();
    }
    return;
  }
  if (!reset && !state.hasMore) return;
  const requestSeq = ++state.rowRequestSeq;
  const controller = new AbortController();
  state.rowsController = controller;
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
    kind: state.eventKind,
    severity: state.severity,
    source: state.source,
    parser_rule: state.parserRule,
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
    params.delete("kind");
    params.delete("severity");
    params.delete("source");
    params.delete("parser_rule");
    params.delete("sort_by");
    params.delete("sort_dir");
    params.delete("start");
    params.delete("end");
  }
  let response;
  try {
    response = await fetch(`${endpoint}?${params.toString()}`, { signal: controller.signal });
  } catch (error) {
    state.loading = false;
    if (error.name !== "AbortError") {
      $("status").textContent = error.message || "Search failed";
    }
    if (state.pendingRowsReset) {
      state.pendingRowsReset = false;
      loadRows(true);
    }
    return;
  }
  if (requestSeq !== state.rowRequestSeq) {
    state.loading = false;
    return;
  }
  state.loading = false;
  state.rowsController = null;
  if (!response.ok) {
    $("status").textContent = await readError(response);
    if (state.pendingRowsReset) {
      state.pendingRowsReset = false;
      loadRows(true);
    }
    return;
  }
  const payload = await response.json();
  state.total = payload.total || 0;
  state.rows = reset ? payload.rows || [] : state.rows.concat(payload.rows || []);
  state.offset = state.rows.length;
  state.hasMore = state.rows.length < state.total;
  renderTable();
  if (state.pendingRowsReset) {
    state.pendingRowsReset = false;
    loadRows(true);
  }
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

setLoadRowsCallback(loadRows);
