async function runAcquisition() {
  state.profile = "local";
  $("profile").value = "local";
  const saved = await saveSettings({ quiet: true });
  if (!saved) return;
  $("status").textContent = "Starting background FRITZ!Box acquisition...";
  const hours = $("hours").value;
  $("run-acquisition").disabled = true;
  const response = await fetch(`/api/acquisition/start?hours=${encodeURIComponent(hours)}&include_disconnects=true`, {
    method: "POST"
  });
  if (!response.ok) {
    $("status").textContent = await readError(response);
    $("run-acquisition").disabled = false;
    return;
  }
  const job = await response.json();
  await pollAcquisitionJob(job.job_id);
}

async function pollAcquisitionJob(jobId) {
  if (!jobId) {
    $("status").textContent = "Acquisition did not return a job id.";
    $("run-acquisition").disabled = false;
    return;
  }
  const started = Date.now();
  while (true) {
    const response = await fetch(`/api/acquisition/status?job_id=${encodeURIComponent(jobId)}`);
    if (!response.ok) {
      $("status").textContent = await readError(response);
      $("run-acquisition").disabled = false;
      return;
    }
    const job = await response.json();
    renderAcquisitionJobStatus(job, started);
    if (job.status === "completed") {
      state.runId = "latest";
      await loadStored({ quiet: true });
      await loadProfiles();
      await loadRuns();
      $("status").textContent = `Acquisition complete. Run ${job.run_id || "stored"} reloaded.`;
      $("run-acquisition").disabled = false;
      return;
    }
    if (job.status === "failed") {
      $("status").textContent = `Acquisition failed: ${job.error || "unknown error"}`;
      $("run-acquisition").disabled = false;
      return;
    }
    await sleep(1500);
  }
}

function renderAcquisitionJobStatus(job, started) {
  const stages = Object.values(job.stages || {});
  const completed = stages.filter((stage) => stage.status === "completed").length;
  const failed = stages.filter((stage) => stage.status === "failed").length;
  const active = job.active_stage || stages.find((stage) => stage.status === "running")?.stage || "queued";
  const elapsed = Math.max(0, Math.round((Date.now() - started) / 1000));
  $("status").textContent = `Acquisition ${job.status}: ${active} (${completed} done, ${failed} failed, ${elapsed}s)`;
  const statusPanel = $("acquisition-status");
  if (statusPanel) {
    statusPanel.innerHTML = stages.length
      ? stages.map((stage) => `
        <span><strong>${escapeHtml(stage.stage)}</strong>${escapeHtml(stage.status || "")}</span>
      `).join("")
      : `<span>Queued background acquisition...</span>`;
  }
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

async function clearCurrentData() {
  const profileLabel = $("profile").selectedOptions[0]?.textContent || state.profile;
  const confirmation = window.prompt(`Clear all stored evidence for ${profileLabel}? Type DELETE to continue.`);
  if (confirmation !== "DELETE") {
    $("status").textContent = "Clear data cancelled.";
    return;
  }
  $("status").textContent = "Clearing stored evidence...";
  const response = await fetch(
    `/api/profile?profile=${encodeURIComponent(state.profile)}&confirm=${encodeURIComponent(confirmation)}`,
    { method: "DELETE" }
  );
  if (!response.ok) {
    $("status").textContent = await readError(response);
    return;
  }
  state.runId = "latest";
  state.rows = [];
  state.total = 0;
  await loadProfiles(state.profile);
  await loadRuns();
  await loadStored({ quiet: true });
  $("status").textContent = `Cleared stored evidence for ${profileLabel}.`;
}

async function loadSettings() {
  const response = await fetch("/api/settings");
  if (!response.ok) return;
  const settings = await response.json();
  $("cfg-address").value = settings.address || "192.168.178.1";
  $("settings-note").textContent = settings.password_source === "env"
    ? "Password is available from the server environment. Save settings only if you want to override it."
    : settings.has_password
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

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function planVpnProvision() {
  const payload = {
    dyndns: {
      enabled: true,
      provider: "user-defined",
      domain: $("vpn-dyndns-domain").value.trim(),
      username: $("vpn-dyndns-user").value.trim(),
      password: $("vpn-dyndns-password").value,
      update_url: $("vpn-dyndns-url").value.trim(),
      replace_existing: false
    },
    wireguard: {
      client_name: $("vpn-client-name").value.trim(),
      allowed_ips: $("vpn-allowed-ips").value.trim() || "192.168.178.0/24",
      dns: $("vpn-dns").value.trim() || "192.168.178.1",
      endpoint_port: Number($("vpn-port").value || 51820),
      route_all_traffic: false,
      replace_existing: false
    }
  };
  $("vpn-plan-output").textContent = "Building dry-run plan...";
  const response = await fetch("/api/vpn-provision/plan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    $("vpn-plan-output").textContent = await readError(response);
    return;
  }
  const plan = await response.json();
  const lines = [
    `Dry run: ${plan.dry_run ? "yes" : "no"}`,
    `Apply supported: ${plan.apply_supported ? "yes" : "no"}`,
    `Safe to apply after review: ${plan.safe_to_apply ? "yes" : "no"}`,
    "",
    ...((plan.steps || []).map((step) => [
      `[${step.status}] ${step.component}: ${step.action}`,
      `  ${step.reason}`,
      Object.keys(step.details || {}).length ? `  ${JSON.stringify(step.details)}` : ""
    ].filter(Boolean).join("\n"))),
    "",
    ...(plan.notes || []).map((note) => `Note: ${note}`)
  ];
  $("vpn-plan-output").textContent = lines.join("\n");
  $("vpn-dyndns-password").value = "";
}
