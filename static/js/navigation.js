
function moveSharedTable(section) {
  const tableElement = $("table");
  const targetSection = section === "overview" ? "search" : section;
  const slot = document.querySelector(`[data-shared-table-slot="${targetSection}"]`);
  if (slot && tableElement && tableElement.parentElement !== slot) {
    slot.appendChild(tableElement);
  }
}

function updateViewChrome() {
  document.querySelectorAll(".section-tab").forEach((tab) => {
    let active = tab.dataset.section === state.section;
    if (tab.dataset.section === "search" && tab.dataset.view === "events") {
      active = state.section === "search";
    } else if (tab.dataset.view) {
      active = state.section === tab.dataset.section && state.view === tab.dataset.view;
    }
    tab.classList.toggle("active", active);
  });
  document.querySelectorAll("[data-section-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.sectionPanel === state.section);
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    const panel = tab.closest("[data-section-panel]");
    const activeSection = panel?.dataset.sectionPanel === state.section;
    tab.classList.toggle("active", activeSection && tab.dataset.view === state.view);
  });
  if ($("category")) {
    $("category").disabled = ![
      "all", "events", "siem_events", "normalized_events", "correlations", "siem_correlations", "log", "timeline"
    ].includes(state.view);
  }
  if ($("table-title")) $("table-title").textContent = VIEW_LABELS[state.view] || evidenceLabel(state.view);
}

function setView(view, { load = true } = {}) {
  state.view = view;
  state.sortBy = defaultSortForView(state.view);
  state.sortDir = "desc";
  updateViewChrome();
  if (load) loadRows(true);
}

function setSection(section, { load = true, preserveView = false } = {}) {
  state.section = section;
  updateViewChrome();
  if (section === "overview") return;
  if (section === "investigate") {
    loadInvestigation();
    return;
  }
  if (section === "live80211") {
    loadLiveCaptureStatus();
    return;
  }
  moveSharedTable(section);
  const nextView = preserveView ? state.view : (SECTION_DEFAULT_VIEWS[section] || state.view);
  if (state.view !== nextView) {
    setView(nextView, { load });
    return;
  }
  updateViewChrome();
  if (load) loadRows(true);
}
