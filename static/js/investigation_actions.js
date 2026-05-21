function exportInvestigationCsv() {
  const rows = investigationTableRows(state.investigation || {});
  const headers = ["evidence", "device", "mac", "ip", "when", "source", "detail"];
  const csvRows = [
    headers.join(","),
    ...rows.map((row) => [
      row.kindLabel,
      row.device,
      row.mac,
      row.ip,
      row.timeRange,
      row.source,
      row.detail
    ].map(csvCell).join(","))
  ];
  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "fritzbox-investigation-evidence.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  return `"${text(value).replace(/"/g, '""')}"`;
}

async function applyInvestigationPreset(preset) {
  const now = new Date();
  let start = "";
  let end = "";
  if (preset === "today") {
    start = new Date(now);
    start.setHours(0, 0, 0, 0);
    end = now;
  } else if (preset === "24h") {
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
  await Promise.all([loadAnalysis(), loadInvestigation(), loadSideTimeline(), loadRows(true), loadFacets()]);
}
