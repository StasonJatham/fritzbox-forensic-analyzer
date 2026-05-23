async function openEvidence(type, id) {
  if (!type || !id) return;
  const response = await fetch(
    `/api/evidence?record_type=${encodeURIComponent(type)}&record_id=${encodeURIComponent(id)}&profile=${encodeURIComponent(state.profile)}`
  );
  if (!response.ok) return;
  const payload = await response.json();
  const record = cleanRecord(payload.record || {});
  const artifacts = payload.artifacts || [];
  const title = record.message || record.summary || record.hostname || record.mac || record.ip || record.record_type || type;
  const isAlert = type === "siem_correlations" && record.correlation_type === "alert";
  const nextAlertState = record.alert_status === "resolved" ? "open" : "resolved";
  const alertAction = isAlert
    ? `<button class="row-action" data-action="alert-state" data-record-id="${escapeHtml(id)}" data-alert-status="${escapeHtml(nextAlertState)}">${escapeHtml(nextAlertState === "resolved" ? "Resolve Alert" : "Reopen Alert")}</button>`
    : "";
  $("drawer-body").innerHTML = `
    <div class="drawer-summary">
      <div><span>Record</span><strong>${escapeHtml(display(title, "Evidence row"))}</strong></div>
      <div><span>Type</span><strong>${escapeHtml(evidenceLabel(type))}</strong></div>
      <div><span>Raw Matches</span><strong>${escapeHtml(artifacts.length)}</strong></div>
    </div>
    ${alertAction ? `<div class="drawer-actions">${alertAction}</div>` : ""}
    <p class="section-title">Parsed Record</p>
    <pre>${escapeHtml(JSON.stringify(record, null, 2))}</pre>
    <p class="section-title">Raw Evidence</p>
    ${artifacts.map((artifact) => `
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
  const entity = cleanRecord(payload.hosts?.[0] || payload.entity || {});
  const timeline = payload.timeline || [];
  $("drawer-body").innerHTML = `
    <div class="drawer-summary">
      <div><span>Entity</span><strong>${escapeHtml(display(value, "Unknown"))}</strong></div>
      <div><span>Hosts</span><strong>${escapeHtml(payload.hosts?.length || 0)}</strong></div>
      <div><span>Related Rows</span><strong>${escapeHtml(timeline.length)}</strong></div>
    </div>
    <p class="section-title">Entity Pivot</p>
    <pre>${escapeHtml(JSON.stringify(entity, null, 2))}</pre>
    <p class="section-title">Related Timeline</p>
    ${timeline.slice(0, 80).map((row) => `
      <button class="timeline-row ${escapeHtml(cssToken(row.event_class))}" data-record-type="${escapeHtml(row.record_type || "")}" data-record-id="${escapeHtml(row.record_id || "")}">
        <div class="dot"></div>
        <div><div class="timeline-main">${escapeHtml(display(row.message, "No message"))}</div><div>${escapeHtml(formatTime(row.event_time))} ${confidenceBadge(row)}</div></div>
      </button>
    `).join("") || `<div class="empty">No related retained evidence.</div>`}
  `;
  $("drawer").classList.add("open");
}

function openEvidenceFromEvent(event) {
  const row = event.target.closest("[data-record-id]");
  if (!row) return false;
  openEvidence(row.dataset.recordType, row.dataset.recordId);
  return true;
}

function openEntityFromEvent(event) {
  const card = event.target.closest("[data-entity]");
  if (!card) return false;
  openEntity(card.dataset.entity);
  return true;
}
