
function assertDashboardBootOrder() {
  const missing = [];
  if (typeof state === "undefined") missing.push("state");
  if (typeof $ !== "function") missing.push("$");
  if (typeof renderTable !== "function") missing.push("renderTable");
  if (typeof renderCharts !== "function") missing.push("renderCharts");
  if (typeof loadStored !== "function") missing.push("loadStored");
  if (typeof loadRows !== "function") missing.push("loadRows");
  if (typeof loadFacets !== "function") missing.push("loadFacets");
  if (typeof openEvidence !== "function") missing.push("openEvidence");
  if (typeof openEntity !== "function") missing.push("openEntity");
  if (typeof openEvidenceFromEvent !== "function") missing.push("openEvidenceFromEvent");
  if (typeof openEntityFromEvent !== "function") missing.push("openEntityFromEvent");
  if (typeof setSection !== "function") missing.push("setSection");
  if (missing.length) {
    throw new Error(`Dashboard boot failed: missing ${missing.join(", ")}. Check static script order in dashboard.html.`);
  }
}

assertDashboardBootOrder();

function setSelectValue(id, value) {
  const select = $(id);
  if (!select) return;
  const option = Array.from(select.options || []).find((item) => item.value === value);
  if (option) select.value = value;
}

async function applySearchPivot({
  query = "",
  view = SECTION_DEFAULT_VIEWS.search || "all",
  category = "all",
  evidenceLevel = "all",
  timeType = "all",
  kind = "all",
  severity = "all",
  source = "all",
  parserRule = "all"
} = {}) {
  state.query = query;
  state.category = category;
  state.evidenceLevel = evidenceLevel;
  state.timeType = timeType;
  state.eventKind = kind;
  state.severity = severity;
  state.source = source;
  state.parserRule = parserRule;
  $("search").value = query;
  setSelectValue("category", category);
  setSelectValue("evidence-level", evidenceLevel);
  setSelectValue("time-type", timeType);
  setSelectValue("severity-filter", severity);
  setSection("search", { load: false, preserveView: true });
  setView(view, { load: false });
  await Promise.all([loadRows(true), loadEntities(), loadSideTimeline(), loadFacets()]);
}

async function setSearchState(partial = {}, { includeAnalysis = false, includeInvestigation = false } = {}) {
  Object.assign(state, partial);
  if ("query" in partial && $("search")) $("search").value = state.query;
  if ("category" in partial) setSelectValue("category", state.category);
  if ("evidenceLevel" in partial) setSelectValue("evidence-level", state.evidenceLevel);
  if ("timeType" in partial) setSelectValue("time-type", state.timeType);
  if ("severity" in partial) setSelectValue("severity-filter", state.severity);
  const jobs = [loadRows(true), loadEntities(), loadSideTimeline(), loadFacets()];
  if (includeAnalysis) jobs.push(loadAnalysis());
  if (includeInvestigation) jobs.push(loadInvestigation());
  await Promise.all(jobs);
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const panel = tab.closest("[data-section-panel]");
    const section = panel?.dataset.sectionPanel || state.section;
    setSection(section, { load: false, preserveView: true });
    setView(tab.dataset.view);
  });
});

document.querySelectorAll(".section-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const view = tab.dataset.view;
    if (!view) {
      setSection(tab.dataset.section);
      return;
    }
    setSection(tab.dataset.section, { load: false, preserveView: true });
    setView(view);
  });
});

$("table").addEventListener("click", (event) => {
  const action = event.target.closest("[data-action]");
  if (action?.dataset.action === "mobile-sort-dir") {
    state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
    loadRows(true);
    return;
  }
  if (action?.dataset.action === "row-details") {
    const row = action.closest("tr");
    const expanded = !row?.classList.contains("expanded");
    row?.classList.toggle("expanded", expanded);
    action.setAttribute("aria-expanded", expanded ? "true" : "false");
    action.textContent = expanded ? "Hide" : "Details";
    return;
  }
  if (action?.dataset.action === "evidence") {
    openEvidence(action.dataset.recordType, action.dataset.recordId);
    return;
  }
  if (action?.dataset.action === "alert-state") {
    const nextStatus = action.dataset.alertStatus || "resolved";
    setAlertState(action.dataset.recordId, nextStatus)
      .then(async () => {
        $("status").textContent = nextStatus === "resolved" ? "Alert marked resolved." : "Alert reopened.";
        await Promise.all([loadRows(true), loadAnalysis()]);
      })
      .catch((error) => {
        $("status").textContent = error.message || "Could not update alert state.";
      });
    return;
  }
  if (action?.dataset.action === "entity") {
    openEntity(action.dataset.entity);
    return;
  }
  const header = event.target.closest("th[data-sort]");
  if (event.target.closest(".col-resizer")) return;
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

$("table").addEventListener("change", (event) => {
  const select = event.target.closest("[data-action='mobile-sort-by']");
  if (!select) return;
  state.sortBy = select.value;
  loadRows(true);
});

$("table").addEventListener("pointerdown", (event) => {
  const resizer = event.target.closest(".col-resizer");
  if (!resizer) return;
  resizeColumn(event, resizer);
});

$("search").addEventListener("input", debounce(async (event) => {
  await setSearchState({ query: event.target.value });
}));

$("clear-search").addEventListener("click", async () => {
  await applySearchPivot();
});

$("run-search")?.addEventListener("click", async () => {
  await setSearchState({ query: $("search").value });
});

$("category").addEventListener("change", async (event) => {
  await setSearchState({ category: event.target.value });
});

$("severity-filter")?.addEventListener("change", async (event) => {
  await setSearchState({ severity: event.target.value });
});

$("evidence-level").addEventListener("change", async (event) => {
  await setSearchState({ evidenceLevel: event.target.value });
});

$("time-type").addEventListener("change", async (event) => {
  await setSearchState({ timeType: event.target.value });
});

const updateInvestigationRange = debounce(async () => {
  $("range-start").value = $("investigation-start").value;
  $("range-end").value = $("investigation-end").value;
  state.rangeStart = isoFromLocal($("range-start").value);
  state.rangeEnd = isoFromLocal($("range-end").value);
  await Promise.all([loadAnalysis(), loadInvestigation(), loadSideTimeline(), loadRows(true), loadFacets()]);
}, 350);

["investigation-start", "investigation-end"].forEach((id) => {
  $(id).addEventListener("input", updateInvestigationRange);
  $(id).addEventListener("change", updateInvestigationRange);
});

$("investigation-search").addEventListener("input", debounce(async (event) => {
  state.investigationQuery = event.target.value;
  await loadInvestigation();
}));

$("investigation-mode")?.addEventListener("change", async (event) => {
  state.investigationMode = event.target.value;
  await loadInvestigation();
});

$("investigation-interface").addEventListener("change", async (event) => {
  state.investigationInterface = event.target.value;
  await loadInvestigation();
});

$("investigation-confidence")?.addEventListener("change", async (event) => {
  state.investigationConfidence = event.target.value;
  await loadInvestigation();
});

document.querySelectorAll("[data-investigation-preset]").forEach((button) => {
  button.addEventListener("click", () => applyInvestigationPreset(button.dataset.investigationPreset));
});
$("export-investigation")?.addEventListener("click", exportInvestigationCsv);
$("live-refresh")?.addEventListener("click", loadLiveCaptureStatus);
$("live-start")?.addEventListener("click", startLiveCapture);
$("live-download")?.addEventListener("click", downloadLivePcap);

$("apply-range").addEventListener("click", async () => {
  state.rangeStart = isoFromLocal($("range-start").value);
  state.rangeEnd = isoFromLocal($("range-end").value);
  syncRangeInputs();
  await setSearchState({}, { includeAnalysis: true, includeInvestigation: true });
});

document.querySelectorAll("[data-search-preset]").forEach((button) => {
  button.addEventListener("click", () => applySearchRangePreset(button.dataset.searchPreset));
});

async function applySearchRangePreset(preset) {
  const now = new Date();
  let start = "";
  let end = "";
  if (preset === "24h") {
    start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    end = now;
  } else if (preset === "7d") {
    start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    end = now;
  }
  $("range-start").value = start ? localInputValue(start) : "";
  $("range-end").value = end ? localInputValue(end) : "";
  syncRangeInputs();
  state.rangeStart = isoFromLocal($("range-start").value);
  state.rangeEnd = isoFromLocal($("range-end").value);
  await setSearchState({}, { includeAnalysis: true, includeInvestigation: true });
}

$("field-facets")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-facet-field]");
  if (!button) return;
  const field = button.dataset.facetField;
  const value = button.dataset.facetValue || "all";
  if (field === "category") {
    await setSearchState({ category: state.category === value ? "all" : value });
    return;
  } else if (field === "kind") {
    state.eventKind = state.eventKind === value ? "all" : value;
  } else if (field === "parser_rule") {
    state.parserRule = state.parserRule === value ? "all" : value;
  } else if (field === "severity") {
    state.severity = state.severity === value ? "all" : value;
    setSelectValue("severity-filter", state.severity);
  } else if (field === "source") {
    state.source = state.source === value ? "all" : value;
  } else if (field === "entity") {
    state.query = value === "unknown" ? "" : value;
    $("search").value = state.query;
  }
  await setSearchState({});
});

$("active-filters")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-clear-filter]");
  if (!button) return;
  const field = button.dataset.clearFilter;
  if (field === "category") {
    state.category = "all";
    setSelectValue("category", "all");
  } else if (field === "severity") {
    state.severity = "all";
    setSelectValue("severity-filter", "all");
  } else if (field === "kind") {
    state.eventKind = "all";
  } else if (field === "source") {
    state.source = "all";
  } else if (field === "parser_rule") {
    state.parserRule = "all";
  } else if (field === "evidence") {
    state.evidenceLevel = "all";
    setSelectValue("evidence-level", "all");
  } else if (field === "time") {
    state.timeType = "all";
    setSelectValue("time-type", "all");
  }
  await setSearchState({});
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
$("clear-data").addEventListener("click", clearCurrentData);
$("download-package").addEventListener("click", () => {
  window.location.href = `/api/acquisition-package/download?profile=${encodeURIComponent(state.profile)}`;
});
$("artifact-download-raw").addEventListener("click", () => $("download-raw").click());
$("artifact-download-package").addEventListener("click", () => $("download-package").click());
$("save-settings").addEventListener("click", saveSettings);
$("save-webhook").addEventListener("click", saveWebhookSettings);
$("plan-vpn")?.addEventListener("click", planVpnProvision);
$("toggle-poll").addEventListener("click", togglePolling);
$("table").addEventListener("scroll", () => {
  if (!sharedTableIsActive()) return;
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
$("timeline")?.addEventListener("click", (event) => {
  openEvidenceFromEvent(event);
});
$("entities")?.addEventListener("click", (event) => {
  openEntityFromEvent(event);
});
$("source-chips")?.addEventListener("click", async (event) => {
  const chip = event.target.closest("[data-source-query]");
  if (!chip) return;
  await applySearchPivot({
    query: chip.dataset.sourceQuery || "",
    view: chip.dataset.sourceView || "all"
  });
});
$("correlations")?.addEventListener("click", async (event) => {
  const pivot = event.target.closest("[data-pivot-view]");
  if (!pivot) return;
  await applySearchPivot({
    view: pivot.dataset.pivotView || "all",
    category: pivot.dataset.pivotCategory || "all"
  });
});
$("alert-pivots")?.addEventListener("click", async (event) => {
  const pivot = event.target.closest("[data-pivot-view]");
  if (!pivot) return;
  const view = pivot.dataset.pivotView || "security_advisories";
  const category = pivot.dataset.pivotCategory || "all";
  if (pivot.dataset.pivotSection === "security") {
    state.query = "";
    state.category = category;
    $("search").value = "";
    setSelectValue("category", category);
    setSection("security", { load: false, preserveView: true });
    setView(view);
    return;
  }
  await applySearchPivot({ view, category });
});
$("device-risk").addEventListener("click", (event) => {
  openEntityFromEvent(event);
});
$("security-top").addEventListener("click", (event) => {
  openEvidenceFromEvent(event);
});
["investigation-timeline", "investigation-auth", "investigation-presence", "investigation-wifi", "investigation-discovery"].forEach((id) => {
  $(id)?.addEventListener("click", (event) => {
    openEvidenceFromEvent(event);
  });
});
$("investigation-devices")?.addEventListener("click", (event) => {
  openEvidenceFromEvent(event);
});
$("investigation-discovery-devices")?.addEventListener("click", (event) => {
  openEvidenceFromEvent(event);
});
$("investigation-results")?.addEventListener("click", (event) => {
  openEvidenceFromEvent(event);
});
$("drawer-body").addEventListener("click", (event) => {
  const action = event.target.closest("[data-action='alert-state']");
  if (action) {
    const nextStatus = action.dataset.alertStatus || "resolved";
    setAlertState(action.dataset.recordId, nextStatus)
      .then(async () => {
        $("drawer").classList.remove("open");
        $("status").textContent = nextStatus === "resolved" ? "Alert marked resolved." : "Alert reopened.";
        await Promise.all([loadRows(true), loadAnalysis()]);
      })
      .catch((error) => {
        $("status").textContent = error.message || "Could not update alert state.";
      });
    return;
  }
  openEvidenceFromEvent(event);
});
$("drawer-close").addEventListener("click", () => $("drawer").classList.remove("open"));
$("drawer-close-backdrop").addEventListener("click", () => $("drawer").classList.remove("open"));
setSection("search", { load: false });
loadSettings().then(async () => {
  await loadProfiles();
  await loadRuns();
  await loadStored();
});
