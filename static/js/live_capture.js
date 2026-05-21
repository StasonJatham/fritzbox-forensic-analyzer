async function loadLiveCaptureStatus() {
  if (!$("live-interface")) return;
  $("live-summary").textContent = "Checking FRITZ!Box capture interfaces...";
  const response = await fetch("/api/live-80211/status");
  if (!response.ok) {
    $("live-summary").textContent = await readError(response);
    return;
  }
  const payload = await response.json();
  const interfaces = payload.interfaces || [];
  $("live-interface").innerHTML = interfaces.length
    ? interfaces.map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)} (${escapeHtml(item.value)})</option>`).join("")
    : `<option value="">No WLAN capture interface exposed</option>`;
  if (payload.preferred) $("live-interface").value = payload.preferred;
  $("live-summary").textContent = interfaces.length
    ? `${interfaces.length} capture interface(s) found. Preferred: ${display($("live-interface").selectedOptions[0]?.textContent, "auto")}.`
    : display(payload.note, "No capture interfaces found.");
}

async function startLiveCapture() {
  if (!$("live-results")) return;
  $("live-start").disabled = true;
  $("live-download").disabled = true;
  $("live-summary").textContent = "Capturing realtime 802.11 management traffic...";
  $("live-results").innerHTML = `<tr><td colspan="5"><div class="empty compact">Capture running. Keep nearby client devices scanning if you want probe requests.</div></td></tr>`;
  const response = await fetch("/api/live-80211/capture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      interface: $("live-interface").value,
      duration_seconds: Number($("live-duration").value || 10)
    })
  });
  $("live-start").disabled = false;
  if (!response.ok) {
    $("live-summary").textContent = await readError(response);
    return;
  }
  state.liveCapture = await response.json();
  state.livePcapBase64 = state.liveCapture.pcap_base64 || "";
  state.livePcapFilename = state.liveCapture.pcap_filename || "fritzbox-80211-live.pcap";
  $("live-download").disabled = !state.livePcapBase64;
  renderLiveCapture();
}

function renderLiveCapture() {
  const capture = state.liveCapture || {};
  const frames = capture.frames || [];
  const parse = capture.parse || {};
  $("live-summary").textContent = [
    `${capture.duration_seconds || 0}s realtime capture`,
    `${capture.pcap_bytes || 0} bytes`,
    `${parse.packet_count || 0} packet(s)`,
    `${parse.probe_request_count || 0} probe request(s)`,
    capture.error ? `error: ${capture.error}` : ""
  ].filter(Boolean).join(" / ");
  $("live-results").innerHTML = frames.length ? frames.map((row) => `
    <tr>
      <td data-label="Frame"><span class="pill ${escapeHtml(cssToken(row.event))}">${escapeHtml(evidenceLabel(row.event))}</span></td>
      <td data-label="Device"><strong>${escapeHtml(display(row.source_mac, "Unknown"))}</strong><div class="subtitle">${escapeHtml(display(row.event, ""))}</div></td>
      <td data-label="MAC / BSSID">${escapeHtml([row.source_mac, row.bssid].filter(Boolean).join(" / ") || "-")}</td>
      <td data-label="When">${escapeHtml(formatTime(row.time) || "-")}</td>
      <td data-label="SSID / Channel">${escapeHtml([display(row.ssid, "hidden/empty SSID"), row.channel ? `ch ${row.channel}` : ""].filter(Boolean).join(" / "))}</td>
    </tr>
  `).join("") : `<tr><td colspan="5"><div class="empty compact">${escapeHtml(capture.note || parse.error || "No 802.11 management frames parsed from this capture.")}</div></td></tr>`;
}

function downloadLivePcap() {
  if (!state.livePcapBase64) return;
  const bytes = Uint8Array.from(atob(state.livePcapBase64), (char) => char.charCodeAt(0));
  const blob = new Blob([bytes], { type: "application/vnd.tcpdump.pcap" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = state.livePcapFilename;
  link.click();
  URL.revokeObjectURL(url);
}
