#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
import io
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
from typing import Any
import zipfile

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

import fritzbox_wifi_export as exporter
from fritzbox_log_store import (
    DEFAULT_DB,
    analysis_snapshot,
    entity_pivot,
    evidence_for_record,
    get_settings,
    ingest_dataset,
    query_entities,
    query_records,
    query_timeline,
    save_settings,
)


APP_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/static/favicon.ico" sizes="any">
  <link rel="icon" href="/static/logo.svg" type="image/svg+xml">
  <link rel="apple-touch-icon" href="/static/logo-192.png">
  <title>FRITZ!Box WiFi Timeline</title>
  <style>
    :root {
      --canvas: #010102;
      --surface-1: #0d0e12;
      --surface-2: #14151b;
      --surface-3: #191b22;
      --surface-4: #20222b;
      --hairline: #23252a;
      --hairline-strong: #30333d;
      --hairline-tertiary: #3b3f4a;
      --ink: #f7f8f8;
      --ink-muted: #d0d6e0;
      --ink-subtle: #8a8f98;
      --ink-tertiary: #62666d;
      --primary: #5e6ad2;
      --primary-hover: #828fff;
      --primary-focus: rgba(94, 105, 209, .5);
      --success: #27a644;
      --overlay: rgba(0, 0, 0, .72);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--canvas);
      color: var(--ink);
      font-family: Inter, "SF Pro Display", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      letter-spacing: 0;
      font-weight: 400;
    }

    header {
      border-bottom: 1px solid var(--hairline);
      background: rgba(1, 1, 2, .96);
    }

    .wrap {
      width: min(1280px, calc(100vw - 32px));
      margin: 0 auto;
    }

    .topbar {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) auto;
      align-items: center;
      gap: 24px;
      min-height: 72px;
    }

    h1 {
      margin: 0;
      font-size: 28px;
      line-height: 1.2;
      font-weight: 600;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .brand-mark {
      width: 42px;
      height: 42px;
      flex: 0 0 auto;
      display: block;
    }

    .brand-copy {
      min-width: 0;
    }

    .subtitle {
      margin-top: 6px;
      color: var(--ink-subtle);
      font-size: 13px;
    }

    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
      align-items: center;
    }

    input, select, button {
      height: 40px;
      border: 1px solid var(--hairline);
      border-radius: 8px;
      background: var(--surface-1);
      color: var(--ink);
      font: inherit;
      font-size: 14px;
      outline: none;
    }

    input, select {
      padding: 0 12px;
      min-width: 120px;
    }

    input:focus, select:focus, button:focus-visible {
      border-color: var(--hairline-strong);
      outline: 2px solid var(--primary-focus);
      outline-offset: 0;
    }

    label {
      display: grid;
      gap: 6px;
      color: var(--ink-subtle);
      font-size: 12px;
    }

    .settings {
      border-bottom: 1px solid var(--hairline);
      background: var(--canvas);
    }

    .settings-inner {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      padding: 14px 0;
      align-items: end;
    }

    .settings input {
      width: 100%;
      min-width: 0;
    }

    .check-row {
      display: flex;
      gap: 8px;
      align-items: center;
      height: 38px;
    }

    .check-row input {
      min-width: 0;
      width: 16px;
      height: 16px;
    }

    .settings-note {
      color: var(--ink-tertiary);
      font-size: 12px;
      padding-bottom: 8px;
    }

    .forensic-bar {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr)) auto auto;
      gap: 10px;
      align-items: end;
      margin-bottom: 12px;
    }

    .forensic-notice {
      border: 1px solid var(--hairline);
      border-radius: 12px;
      background: var(--surface-1);
      padding: 14px 16px;
      margin-bottom: 16px;
      color: var(--ink-subtle);
      font-size: 13px;
      line-height: 1.45;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, .035);
    }

    .forensic-notice strong {
      color: var(--ink);
      font-weight: 600;
    }

    .search { min-width: min(320px, 60vw); }

    button {
      padding: 0 14px;
      background: var(--surface-1);
      border-color: var(--hairline);
      cursor: pointer;
      font-weight: 500;
    }

    button:hover {
      background: var(--surface-2);
      border-color: var(--hairline-strong);
      color: var(--ink);
    }

    #save-settings, #toggle-poll {
      background: var(--primary);
      border-color: var(--primary);
      color: #fff;
    }

    #save-settings:hover, #toggle-poll:hover {
      background: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    main {
      padding: 16px 0 28px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .metric {
      min-height: 76px;
      border: 1px solid var(--hairline);
      border-radius: 12px;
      background: var(--surface-1);
      padding: 16px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, .035);
    }

    .metric .label {
      color: var(--ink-subtle);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 500;
    }

    .metric .value {
      margin-top: 6px;
      font-size: 25px;
      line-height: 1.2;
      font-weight: 600;
    }

    .metric .accent {
      margin-top: 8px;
      height: 1px;
      background: var(--hairline-tertiary);
    }

    .metric .value.small {
      font-size: 15px;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }

    .charts {
      display: grid;
      grid-template-columns: 1.6fr 1fr 1fr;
      gap: 12px;
      margin-bottom: 16px;
    }

    .chart-panel, .entity-panel {
      border: 1px solid var(--hairline);
      border-radius: 12px;
      background: var(--surface-1);
      padding: 16px;
      min-width: 0;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, .035);
    }

    .bar-chart {
      display: grid;
      grid-template-columns: repeat(24, minmax(10px, 1fr));
      gap: 4px;
      align-items: end;
      height: 118px;
      padding-top: 8px;
    }

    .bar {
      min-height: 2px;
      border-radius: 4px 4px 0 0;
      background: var(--primary);
      position: relative;
    }

    .bar span {
      position: absolute;
      bottom: -18px;
      left: 50%;
      transform: translateX(-50%);
      color: var(--ink-tertiary);
      font-size: 10px;
    }

    .mini-list {
      display: grid;
      gap: 8px;
      color: var(--ink-subtle);
      font-size: 12px;
    }

    .mini-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
    }

    .mini-meter {
      height: 7px;
      margin-top: 4px;
      border-radius: 999px;
      background: var(--surface-3);
      overflow: hidden;
    }

    .mini-meter div {
      height: 100%;
      background: var(--primary);
    }

    .tabs {
      display: flex;
      gap: 8px;
      margin: 8px 0 12px;
      border-bottom: 1px solid var(--hairline);
    }

    .tab {
      border: 0;
      border-bottom: 2px solid transparent;
      border-radius: 0;
      background: transparent;
      color: var(--ink-subtle);
      height: 38px;
    }

    .tab.active {
      color: var(--ink);
      border-bottom-color: var(--primary);
    }

    .workspace {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 16px;
      min-height: 0;
    }

    aside, .table-shell {
      border: 1px solid var(--hairline);
      border-radius: 16px;
      background: var(--surface-1);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, .035);
    }

    aside {
      padding: 14px;
      align-self: start;
    }

    .section-title {
      color: var(--ink-subtle);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 500;
      margin: 0 0 10px;
    }

    .timeline {
      display: grid;
      gap: 10px;
    }

    .timeline-row {
      display: grid;
      grid-template-columns: 10px 1fr;
      gap: 10px;
      align-items: start;
      color: var(--ink-subtle);
      font-size: 12px;
    }

    .dot {
      width: 9px;
      height: 9px;
      margin-top: 4px;
      border-radius: 50%;
      background: var(--primary);
    }

    .timeline-row.wifi .dot, .timeline-row.connected .dot { background: var(--success); }

    .timeline-main {
      color: var(--ink);
      font-size: 13px;
      margin-bottom: 2px;
      overflow-wrap: anywhere;
    }

    .entity-panel {
      margin-top: 12px;
    }

    .entity-list {
      display: grid;
      gap: 8px;
      max-height: 240px;
      overflow: auto;
    }

    .entity-card {
      width: 100%;
      height: auto;
      padding: 10px;
      text-align: left;
      border-radius: 8px;
      background: var(--surface-2);
    }

    .entity-card strong {
      display: block;
      font-size: 13px;
      overflow-wrap: anywhere;
    }

    .entity-card span {
      display: block;
      margin-top: 3px;
      color: var(--ink-subtle);
      font-size: 12px;
      overflow-wrap: anywhere;
    }

    .table-shell {
      overflow: hidden;
      height: clamp(520px, calc(100vh - 360px), 820px);
      overflow-y: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th, td {
      border-bottom: 1px solid var(--hairline);
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
      overflow-wrap: anywhere;
    }

    th {
      color: var(--ink-subtle);
      background: var(--surface-2);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 500;
      position: sticky;
      top: 0;
      z-index: 1;
    }

    th.sortable {
      cursor: pointer;
      user-select: none;
    }

    th.sortable:hover {
      color: var(--ink);
    }

    tbody tr:hover { background: var(--surface-2); }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border: 1px solid var(--hairline);
      border-radius: 999px;
      padding: 0 8px;
      font-size: 12px;
      color: var(--ink-muted);
      background: var(--surface-2);
    }

    .pill.wifi, .pill.connected, .pill.high, .pill.exact {
      border-color: rgba(39, 166, 68, .45);
      color: #8fe0a2;
    }

    .pill.low, .pill.derived, .pill.mesh_last_observed {
      border-color: rgba(94, 106, 210, .45);
      color: var(--primary-hover);
    }

    .pill.raw, .pill.parsed_from_raw {
      border-color: rgba(39, 166, 68, .45);
      color: #8fe0a2;
    }

    .pill.inferred, .pill.enriched_from_current_host_table {
      border-color: rgba(94, 106, 210, .45);
      color: var(--primary-hover);
    }

    .status {
      margin: 0 0 8px;
      color: var(--ink-subtle);
      font-size: 13px;
      min-height: 18px;
    }

    .empty {
      padding: 32px;
      color: var(--ink-subtle);
      text-align: center;
    }

    .drawer {
      position: fixed;
      inset: 0;
      display: none;
      z-index: 10;
    }

    .drawer.open { display: block; }

    .drawer-backdrop {
      position: absolute;
      inset: 0;
      background: var(--overlay);
    }

    .drawer-panel {
      position: absolute;
      top: 0;
      right: 0;
      width: min(720px, 100vw);
      height: 100%;
      overflow: auto;
      border-left: 1px solid var(--hairline);
      background: var(--surface-1);
      padding: 24px;
    }

    .drawer-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }

    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      border: 1px solid var(--hairline);
      border-radius: 8px;
      background: var(--canvas);
      padding: 12px;
      color: var(--ink-muted);
      font-size: 12px;
      font-family: "JetBrains Mono", "SF Mono", ui-monospace, Menlo, monospace;
    }

    @media (max-width: 900px) {
      .topbar, .workspace { grid-template-columns: 1fr; }
      .controls { justify-content: flex-start; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .charts, .forensic-bar { grid-template-columns: 1fr; }
      aside { order: 2; }
      .table-shell { order: 1; }
    }

    @media (max-width: 560px) {
      .wrap { width: min(100vw - 20px, 1420px); }
      .metrics { grid-template-columns: 1fr; }
      input, select, button, .search { width: 100%; }
      th, td { padding: 10px 8px; font-size: 12px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div class="brand">
        <img class="brand-mark" src="/static/logo.svg" alt="" width="42" height="42">
        <div class="brand-copy">
          <h1>FRITZ!Box WiFi Timeline</h1>
          <div class="subtitle" id="subtitle">Local router export dashboard</div>
        </div>
      </div>
      <div class="controls">
        <input class="search" id="search" placeholder="Filter table by words, host, MAC, IP">
        <select id="hours">
          <option value="24">24h</option>
          <option value="168">7d</option>
          <option value="720">30d</option>
          <option value="3000" selected>All retained</option>
        </select>
        <select id="category">
          <option value="all">All categories</option>
          <option value="wifi">WiFi</option>
          <option value="internet">Internet</option>
          <option value="network">Network</option>
          <option value="auth">Auth</option>
          <option value="system">System</option>
        </select>
        <button id="refresh">Refresh</button>
        <button id="download-raw">Download Raw</button>
        <button id="download-package">Forensic Package</button>
      </div>
    </div>
    <div class="settings">
      <div class="wrap settings-inner">
        <label>FRITZ!Box IP<input id="cfg-address" placeholder="192.168.178.1"></label>
        <label>Admin Password<input id="cfg-password" type="password" placeholder="Leave blank to keep saved"></label>
        <button id="save-settings">Save & Fetch</button>
      </div>
      <div class="wrap settings-note" id="settings-note">Settings are stored locally in fritzbox-analysis.sqlite3.</div>
    </div>
  </header>
  <main class="wrap">
    <section class="forensic-notice" id="forensic-notice">
      <strong>Evidence model:</strong> this tool shows what the FRITZ!Box retained and exposed at acquisition time.
      Absence of a row is not proof an event did not happen. Mesh observations are inferred context, not exact WiFi join times.
    </section>
    <section class="forensic-bar">
      <label>Start Time<input id="range-start" type="datetime-local"></label>
      <label>End Time<input id="range-end" type="datetime-local"></label>
      <label>Poll Interval<select id="poll-interval"><option value="5">5 min</option><option value="10">10 min</option><option value="15" selected>15 min</option></select></label>
      <label>Polling State<div class="check-row" id="poll-status">Stopped</div></label>
      <button id="apply-range">Apply Range</button>
      <button id="toggle-poll">Start Polling</button>
    </section>
    <section class="metrics">
      <div class="metric"><div class="label">WiFi Observed</div><div class="value" id="m-wifi">0</div><div class="accent"></div></div>
      <div class="metric"><div class="label">Retained Logs</div><div class="value" id="m-log">0</div><div class="accent"></div></div>
      <div class="metric"><div class="label">Known Hosts</div><div class="value" id="m-hosts">0</div><div class="accent"></div></div>
      <div class="metric"><div class="label">Active Hosts</div><div class="value" id="m-active">0</div><div class="accent"></div></div>
      <div class="metric"><div class="label">Last Exact WiFi</div><div class="value small" id="m-last">None retained</div><div class="accent"></div></div>
    </section>
    <section class="charts">
      <div class="chart-panel">
        <p class="section-title">Connection / Event High Times</p>
        <div class="bar-chart" id="hour-chart"></div>
      </div>
      <div class="chart-panel">
        <p class="section-title">Event Classes</p>
        <div class="mini-list" id="category-chart"></div>
      </div>
      <div class="chart-panel">
        <p class="section-title">Evidence Confidence</p>
        <div class="mini-list" id="confidence-chart"></div>
      </div>
    </section>
    <div class="tabs">
      <button class="tab active" data-view="wifi">WiFi Connections</button>
      <button class="tab" data-view="log">Router Log</button>
      <button class="tab" data-view="hosts">Host Table</button>
      <button class="tab" data-view="timeline">Timeline</button>
      <button class="tab" data-view="entities">Entity Pivot</button>
    </div>
    <p class="status" id="status"></p>
    <section class="workspace">
      <aside>
        <p class="section-title">Recent Signal</p>
        <div class="timeline" id="timeline"></div>
        <div class="entity-panel">
          <p class="section-title">Entities</p>
          <div class="entity-list" id="entities"></div>
        </div>
      </aside>
      <div class="table-shell" id="table"></div>
    </section>
  </main>
  <div class="drawer" id="drawer">
    <div class="drawer-backdrop" id="drawer-close-backdrop"></div>
    <div class="drawer-panel">
      <div class="drawer-head">
        <div>
          <h2 style="margin:0;font-size:18px;">Evidence</h2>
          <div class="subtitle">Parsed row and matching retained raw artifact snippet</div>
        </div>
        <button id="drawer-close">Close</button>
      </div>
      <div id="drawer-body"></div>
    </div>
  </div>
  <script>
    const state = {
      data: null, analysis: null, view: "wifi", query: "", category: "all",
      rows: [], offset: 0, limit: 50, total: 0, loading: false, hasMore: true,
      sortBy: "derived_connected_at", sortDir: "desc", rangeStart: "", rangeEnd: "",
      pollActive: false
    };
    const $ = (id) => document.getElementById(id);

    function text(value) {
      return value === null || value === undefined || value === "" ? "" : String(value);
    }

    function escapeHtml(value) {
      return text(value).replace(/[&<>"']/g, (char) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[char]));
    }

    async function refresh() {
      $("status").textContent = "Loading export...";
      const hours = $("hours").value;
      const response = await fetch(`/api/export?hours=${encodeURIComponent(hours)}&include_disconnects=true`);
      if (!response.ok) {
        $("status").textContent = await readError(response);
        return;
      }
      state.data = await response.json();
      if ((state.data.summary?.available_wifi_connections || 0) === 0 && (state.data.summary?.event_log_entries || 0) > 0) {
        state.view = "log";
        document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item.dataset.view === "log"));
        $("category").disabled = false;
      }
      $("subtitle").textContent = `${state.data.router.address} - generated ${formatTime(state.data.generated_at)}`;
      setMetrics();
      await loadAnalysis();
      await loadEntities();
      await loadSideTimeline();
      await loadRows(true);
      await loadPolling();
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

    async function saveAndFetch() {
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
        return;
      }
      $("cfg-password").value = "";
      await loadSettings();
      await refresh();
    }

    function formatTime(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString();
    }

    function setMetrics() {
      const summary = state.data?.summary || {};
      $("m-wifi").textContent = summary.available_wifi_connections ?? summary.wifi_events ?? 0;
      $("m-log").textContent = summary.event_log_entries ?? 0;
      $("m-hosts").textContent = summary.known_hosts ?? 0;
      $("m-active").textContent = summary.active_hosts ?? 0;
      $("m-last").textContent = summary.last_wifi_connection ? formatTime(summary.last_wifi_connection) : "None retained";
      const oldest = summary.oldest_event ? formatTime(summary.oldest_event) : "unknown";
      const newest = summary.newest_event ? formatTime(summary.newest_event) : "unknown";
      $("forensic-notice").innerHTML = `<strong>Evidence model:</strong> retained log window ${escapeHtml(oldest)} to ${escapeHtml(newest)}. Rows marked <strong>parsed_from_raw</strong> come from retained FRITZ!Box logs; <strong>inferred</strong> mesh rows are context, not exact WiFi join times. Absence of a row is not proof an event did not happen.`;
    }

    function isoFromLocal(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return "";
      return date.toISOString();
    }

    async function loadAnalysis() {
      const params = new URLSearchParams({ start: state.rangeStart, end: state.rangeEnd });
      const response = await fetch(`/api/analysis?${params.toString()}`);
      if (!response.ok) return;
      state.analysis = await response.json();
      renderCharts();
    }

    async function loadEntities() {
      const params = new URLSearchParams({ q: state.query, limit: "40" });
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
        limit: String(state.limit),
        offset: String(state.offset),
        sort_by: state.sortBy,
        sort_dir: state.sortDir
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
        params.delete("sort_by");
        params.delete("sort_dir");
      }
      const response = await fetch(`${endpoint}?${params.toString()}`);
      state.loading = false;
      if (!response.ok) {
        $("status").textContent = await readError(response);
        return;
      }
      const payload = await response.json();
      state.total = payload.total || 0;
      state.rows = reset ? payload.rows : state.rows.concat(payload.rows || []);
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
    }

    function renderMiniChart(id, rows) {
      const max = Math.max(1, ...rows.map((row) => row.count || 0));
      $(id).innerHTML = rows.length ? rows.slice(0, 7).map((row) => `
        <div>
          <div class="mini-row"><span>${escapeHtml(row.label)}</span><strong>${escapeHtml(row.count)}</strong></div>
          <div class="mini-meter"><div style="width:${Math.max(4, Math.round((row.count / max) * 100))}%"></div></div>
        </div>
      `).join("") : `<div class="empty">No chart data.</div>`;
    }

    function renderTimeline(rows) {
      $("timeline").innerHTML = rows.map((row) => `
        <div class="timeline-row ${escapeHtml(row.event_class || row.category)}">
          <div class="dot"></div>
          <div>
            <div class="timeline-main">${escapeHtml(row.message)}</div>
            <div>${escapeHtml(formatTime(row.event_time || row.timestamp))} ${confidenceBadge(row)}</div>
          </div>
        </div>
      `).join("") || `<div class="empty">No retained router log entries.</div>`;
    }

    function renderEntities(rows) {
      $("entities").innerHTML = rows.length ? rows.map((row) => `
        <button class="entity-card" data-entity="${escapeHtml(row.mac || row.ip || row.hostname || row.key)}">
          <strong>${escapeHtml(row.hostname || row.mac || row.ip || "Unknown")}</strong>
          <span>${escapeHtml([row.mac, row.ip, row.interface].filter(Boolean).join(" · "))}</span>
          <span>${escapeHtml((row.event_count || 0) + " log / " + (row.wifi_count || 0) + " wifi")}</span>
        </button>
      `).join("") : `<div class="empty">No entities match.</div>`;
    }

    function renderTable() {
      const rows = state.rows;
      if (!rows.length) {
        $("table").innerHTML = `<div class="empty">No rows match the current filters.</div>`;
        $("status").textContent = `0 of ${state.total} rows`;
        return;
      }
      if (state.view === "wifi") {
        $("table").innerHTML = table([
          ["Derived Time", "derived_connected_at"], ["Type", "type"], ["Host", "hostname"], ["MAC", "mac"],
          ["IP", "ip"], ["Confidence", "evidence"], ["Source", "source"], ["Evidence", "evidence"]
        ], rows.map((row) => [
          formatTime(row.derived_connected_at || row.timestamp), row.derived_time_type || row.event, row.hostname, row.mac, row.ip,
          confidenceBadge(row), row.source, row.derived_time_confidence || row.confidence
        ]), rows);
      } else if (state.view === "hosts") {
        $("table").innerHTML = table([
          ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
          ["First Seen", "first_seen"], ["Last Seen", "last_seen"], ["Last Connected", "last_connected"]
        ], rows.map((row) => [
          row.hostname, row.mac, row.ip, row.interface, row.active_now, formatTime(row.first_seen), formatTime(row.last_seen), formatTime(row.last_connected)
        ]), rows);
      } else if (state.view === "timeline") {
        $("table").innerHTML = table([
          ["Timestamp", "timestamp"], ["Class", "category"], ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Confidence", "evidence"], ["Message", "message"]
        ], rows.map((row) => [
          formatTime(row.event_time), pill(row.event_class, row.event_class), row.hostname, row.mac, row.ip, confidenceBadge(row), row.message
        ]), rows);
      } else if (state.view === "entities") {
        $("table").innerHTML = table([
          ["Host", "hostname"], ["MAC", "mac"], ["IP", "ip"], ["Interface", "interface"], ["Active", "active_now"],
          ["First Seen", "first_seen"], ["Last Seen", "last_seen"], ["Events", "event_count"], ["WiFi", "wifi_count"]
        ], rows.map((row) => [
          row.hostname, row.mac, row.ip, row.interface, row.active_now, formatTime(row.first_seen), formatTime(row.last_seen), row.event_count, row.wifi_count
        ]), rows);
      } else {
        $("table").innerHTML = table([
          ["Timestamp", "timestamp"], ["Category", "category"], ["MAC", "mac"], ["IP", "ip"], ["Message", "message"]
        ], rows.map((row) => [
          formatTime(row.timestamp), pill(row.category, row.category), row.mac, row.ip, row.message
        ]), rows);
      }
      $("status").textContent = `${state.rows.length} of ${state.total} rows loaded${state.hasMore ? " - scroll for more" : ""}`;
      ensureScrollable();
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
      return `<span class="pill ${escapeHtml(cls)}">${escapeHtml(label)}</span>`;
    }

    function confidenceBadge(row) {
      const exact = row.exact_time ?? row.exact_connection_time_available;
      const confidence = row.confidence || row.derived_time_confidence || row.evidence || (exact ? "high" : "low");
      const timeType = row.time_type || row.derived_time_type || (exact ? "exact" : "derived");
      const evidenceLevel = row.evidence_level || (exact ? "parsed_from_raw" : "inferred");
      return `${pill(timeType || "derived", timeType || "derived")} ${pill(confidence || "low", confidence || "low")} ${pill(evidenceLevel, evidenceLevel)}`;
    }

    function table(headers, rows, sourceRows = []) {
      return `<table><thead><tr>${headers.map(([label, key]) => {
        const marker = state.sortBy === key ? (state.sortDir === "asc" ? " ▲" : " ▼") : "";
        return `<th class="sortable" data-sort="${escapeHtml(key)}">${escapeHtml(label + marker)}</th>`;
      }).join("")}</tr></thead><tbody>${
        rows.map((row, index) => {
          const source = sourceRows[index] || {};
          const type = source.record_type || (state.view === "wifi" ? "wifi" : state.view === "log" ? "log" : state.view === "hosts" ? "hosts" : "");
          const id = source.record_id || source.id || "";
          return `<tr data-record-type="${escapeHtml(type)}" data-record-id="${escapeHtml(id)}">${row.map((cell) => `<td>${String(cell).startsWith("<span") ? cell : escapeHtml(cell)}</td>`).join("")}</tr>`;
        }).join("")
      }</tbody></table>`;
    }

    function defaultSortForView(view) {
      if (view === "hosts") return "last_seen";
      if (view === "log") return "timestamp";
      if (view === "timeline") return "timestamp";
      if (view === "entities") return "last_seen";
      return "derived_connected_at";
    }

    function render() {
      setMetrics();
      renderTable();
      $("status").textContent = `${state.rows.length} of ${state.total} rows loaded${state.hasMore ? " - scroll for more" : ""}`;
    }

    async function openEvidence(type, id) {
      if (!type || !id || state.view === "entities") return;
      const response = await fetch(`/api/evidence?record_type=${encodeURIComponent(type)}&record_id=${encodeURIComponent(id)}`);
      if (!response.ok) return;
      const payload = await response.json();
      $("drawer-body").innerHTML = `
        <p class="section-title">Parsed Record</p>
        <pre>${escapeHtml(JSON.stringify(payload.record || {}, null, 2))}</pre>
        <p class="section-title">Raw Artifact Matches</p>
        ${(payload.artifacts || []).map((artifact) => `
          <div class="mini-row"><strong>${escapeHtml(artifact.name)}</strong><span>${escapeHtml(formatTime(artifact.created_at))}</span></div>
          <pre>${escapeHtml(artifact.snippet || "")}</pre>
        `).join("") || `<div class="empty">No matching raw artifact snippet found for this row.</div>`}
      `;
      $("drawer").classList.add("open");
    }

    async function openEntity(value) {
      const response = await fetch(`/api/entity?value=${encodeURIComponent(value)}`);
      if (!response.ok) return;
      const payload = await response.json();
      $("drawer-body").innerHTML = `
        <p class="section-title">Entity Pivot</p>
        <pre>${escapeHtml(JSON.stringify(payload.hosts?.[0] || payload.entity || {}, null, 2))}</pre>
        <p class="section-title">Related Timeline</p>
        ${(payload.timeline || []).slice(0, 80).map((row) => `
          <div class="timeline-row ${escapeHtml(row.event_class)}">
            <div class="dot"></div>
            <div><div class="timeline-main">${escapeHtml(row.message)}</div><div>${escapeHtml(formatTime(row.event_time))} ${confidenceBadge(row)}</div></div>
          </div>
        `).join("") || `<div class="empty">No related retained evidence.</div>`}
      `;
      $("drawer").classList.add("open");
    }

    async function loadPolling() {
      const response = await fetch("/api/polling");
      if (!response.ok) return;
      const payload = await response.json();
      state.pollActive = payload.active;
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
    $("apply-range").addEventListener("click", async () => {
      state.rangeStart = isoFromLocal($("range-start").value);
      state.rangeEnd = isoFromLocal($("range-end").value);
      await Promise.all([loadAnalysis(), loadSideTimeline(), loadRows(true)]);
    });
    $("hours").addEventListener("change", refresh);
    $("refresh").addEventListener("click", refresh);
    $("download-raw").addEventListener("click", () => {
      window.location.href = "/api/raw-artifacts/download";
    });
    $("download-package").addEventListener("click", () => {
      window.location.href = "/api/acquisition-package/download";
    });
    $("save-settings").addEventListener("click", saveAndFetch);
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
    $("entities").addEventListener("click", (event) => {
      const card = event.target.closest("[data-entity]");
      if (!card) return;
      openEntity(card.dataset.entity);
    });
    $("drawer-close").addEventListener("click", () => $("drawer").classList.remove("open"));
    $("drawer-close-backdrop").addEventListener("click", () => $("drawer").classList.remove("open"));
    $("category").disabled = true;
    loadSettings().then(refresh);
  </script>
</body>
</html>
"""


class Poller:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.interval_minutes = 15
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_run_id: int | None = None

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict[str, Any]:
        return {
            "active": self.active,
            "interval_minutes": self.interval_minutes,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
            "last_run_id": self.last_run_id,
        }

    def start(self, interval_minutes: int) -> dict[str, Any]:
        with self._lock:
            self.interval_minutes = max(5, min(15, int(interval_minutes or 15)))
            if self.active:
                return self.snapshot()
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            return self.snapshot()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._stop.set()
            return self.snapshot()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                dataset = export_from_stored_settings(hours=10000, include_disconnects=True)
                self.last_run_id = ingest_dataset(dataset, DEFAULT_DB)
                self.last_error = None
                self.last_run_at = datetime.now().astimezone().isoformat()
            except Exception as exc:  # pragma: no cover - depends on router availability
                self.last_error = str(exc)
                self.last_run_at = datetime.now().astimezone().isoformat()
            self._stop.wait(self.interval_minutes * 60)


poller = Poller()


def export_from_stored_settings(hours: int, include_disconnects: bool) -> dict[str, Any]:
    exporter.load_env_file(Path(".env"))
    exporter.load_env_file(Path(".fritzbox.env"))
    stored = get_settings(DEFAULT_DB, include_secret=True)
    args = SimpleNamespace(
        address=stored.get("address") or exporter.os.getenv("FRITZBOX_ADDRESS") or exporter.os.getenv("FRITZBOX_IP") or "192.168.178.1",
        user=None,
        password=stored.get("password") or exporter.os.getenv("FRITZBOX_PASSWORD") or exporter.os.getenv("FRITZBOX_ADMIN_PASS"),
        port=49000,
        tls=False,
        hours=hours,
        include_disconnects=include_disconnects,
    )
    if not args.password:
        raise HTTPException(status_code=401, detail="Set the FRITZ!Box admin password in the UI or .env.")
    return exporter.export_dataset(args)


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def build_raw_artifacts_zip() -> bytes:
    conn = sqlite3.connect(DEFAULT_DB)
    conn.row_factory = sqlite3.Row
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, run_id, name, sha256, content, created_at
            FROM raw_artifacts
            ORDER BY created_at DESC, id DESC
            """
        )
    ]
    conn.close()
    if not rows:
        raise HTTPException(status_code=404, detail="No raw FRITZ!Box artifacts are stored yet. Run a fetch first.")

    manifest: list[dict[str, Any]] = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            name = safe_artifact_name(str(row["name"] or "artifact"))
            extension = guess_artifact_extension(name, str(row["content"] or ""))
            created = safe_artifact_name(str(row["created_at"] or "unknown")).replace("T", "_")
            filename = f"raw_artifacts/run-{row['run_id']}/{row['id']:06d}_{created}_{name}{extension}"
            archive.writestr(filename, str(row["content"] or ""))
            manifest.append(
                {
                    "id": row["id"],
                    "run_id": row["run_id"],
                    "name": row["name"],
                    "sha256": row["sha256"],
                    "created_at": row["created_at"],
                    "path": filename,
                    "bytes": len(str(row["content"] or "").encode("utf-8")),
                }
            )
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return buffer.getvalue()


def build_forensic_acquisition_zip() -> bytes:
    conn = sqlite3.connect(DEFAULT_DB)
    conn.row_factory = sqlite3.Row
    tables = {
        "export_runs": "SELECT * FROM export_runs ORDER BY id",
        "raw_artifacts": "SELECT id, run_id, name, sha256, created_at FROM raw_artifacts ORDER BY id",
        "event_log": "SELECT * FROM event_log ORDER BY COALESCE(timestamp, ''), id",
        "wifi_connections": "SELECT * FROM wifi_connections ORDER BY COALESCE(derived_connected_at, ''), id",
        "hosts": "SELECT * FROM hosts ORDER BY hostname, mac, ip, id",
        "record_observations": "SELECT * FROM record_observations ORDER BY observed_at, id",
    }
    table_rows = {name: rows_for_query(conn, sql) for name, sql in tables.items()}
    raw_rows = rows_for_query(
        conn,
        """
        SELECT id, run_id, name, sha256, content, created_at
        FROM raw_artifacts
        ORDER BY created_at DESC, id DESC
        """,
    )
    package_manifest = forensic_manifest(conn, table_rows, raw_rows)
    conn.close()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(package_manifest, indent=2, sort_keys=True))
        archive.writestr("limitations.md", forensic_limitations_text())
        for name, rows in table_rows.items():
            archive.writestr(f"parsed/{name}.json", json.dumps(rows, indent=2, sort_keys=True, default=str))
        for row in raw_rows:
            artifact_name = safe_artifact_name(str(row["name"] or "artifact"))
            extension = guess_artifact_extension(artifact_name, str(row["content"] or ""))
            created = safe_artifact_name(str(row["created_at"] or "unknown")).replace("T", "_")
            filename = f"raw_artifacts/run-{row['run_id']}/{row['id']:06d}_{created}_{artifact_name}{extension}"
            archive.writestr(filename, str(row["content"] or ""))
        archive.writestr("database/fritzbox-analysis.sqlite3", sqlite_backup_bytes(DEFAULT_DB))
    return buffer.getvalue()


def rows_for_query(conn: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql)]


def forensic_manifest(
    conn: sqlite3.Connection,
    table_rows: dict[str, list[dict[str, Any]]],
    raw_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    latest_run = conn.execute("SELECT * FROM export_runs ORDER BY id DESC LIMIT 1").fetchone()
    retained = conn.execute(
        "SELECT MIN(timestamp) AS oldest_event, MAX(timestamp) AS newest_event, COUNT(*) AS event_count FROM event_log"
    ).fetchone()
    generated_at = datetime.now().astimezone().isoformat()
    raw_manifest = [
        {
            "id": row["id"],
            "run_id": row["run_id"],
            "name": row["name"],
            "sha256": row["sha256"],
            "created_at": row["created_at"],
            "bytes": len(str(row["content"] or "").encode("utf-8")),
        }
        for row in raw_rows
    ]
    return {
        "package_type": "fritzbox_forensic_acquisition_package",
        "generated_at": generated_at,
        "latest_run": dict(latest_run) if latest_run else None,
        "retained_event_window": dict(retained) if retained else None,
        "record_counts": {name: len(rows) for name, rows in table_rows.items()},
        "raw_artifacts": raw_manifest,
        "hashes": {
            "raw_artifacts": [{"id": row["id"], "sha256": row["sha256"]} for row in raw_rows],
        },
        "evidence_levels": {
            "raw": "Raw artifact exposed by FRITZ!Box during acquisition.",
            "parsed_from_raw": "Field or event parsed from retained raw FRITZ!Box data.",
            "enriched_from_current_host_table": "Context from current/known host table at acquisition time; not proof of historical ownership.",
            "inferred": "Derived context, such as mesh last-observed WLAN rows; not an exact association timestamp.",
        },
        "timestamp_assumptions": {
            "router_event_timestamps": "Parsed from retained FRITZ!Box log text and interpreted in collector local time unless a source includes an offset.",
            "router_clock_status": "Not independently validated by this package.",
        },
        "contamination_notice": {
            "tool_login_may_create_router_log_entries": True,
            "polling_may_create_repeated_observations": True,
            "initial_acquisition_should_be_distinguished_from_monitoring": True,
        },
    }


def sqlite_backup_bytes(path: Path) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp:
        source = sqlite3.connect(path)
        target = sqlite3.connect(tmp.name)
        try:
            source.backup(target)
            target.execute("UPDATE settings SET value = '[redacted from forensic package]' WHERE key = 'password'")
            target.commit()
        finally:
            target.close()
            source.close()
        return Path(tmp.name).read_bytes()


def forensic_limitations_text() -> str:
    return """# FRITZ!Box Forensic Package Limitations

This package preserves what the FRITZ!Box exposed through the local collection tool at acquisition time.

- Retained router log entries are not a full historical record.
- Absence of a log row means only that it was not observed in retained/exported data.
- Mesh `last_observed` values are low-confidence context and are not exact WiFi join times.
- Current host table enrichment can be stale or reassigned.
- Router timestamps are not independently validated unless separately documented.
- Tool login and polling may create router log entries and repeated observations.
"""


def safe_artifact_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned or "artifact"


def guess_artifact_extension(name: str, content: str) -> str:
    if Path(name).suffix:
        return ""
    stripped = content.lstrip()
    if stripped.startswith("<"):
        return ".xml"
    if stripped.startswith("{") or stripped.startswith("["):
        return ".json"
    return ".txt"


def create_app() -> FastAPI:
    app = FastAPI(title="FRITZ!Box Forensic Analyzer")
    static_dir = next(
        path for path in (Path(__file__).resolve().parent / "static", Path.cwd() / "static") if path.exists()
    )
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return APP_HTML

    @app.get("/api/export")
    def api_export(
        hours: int = Query(default=24, ge=1, le=10000),
        include_disconnects: bool = True,
    ) -> JSONResponse:
        try:
            dataset = export_from_stored_settings(hours, include_disconnects)
            ingest_dataset(dataset, DEFAULT_DB)
            return JSONResponse(json_safe(dataset))
        except SystemExit as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"FRITZ!Box export failed: {type(exc).__name__}: {exc}") from exc

    @app.get("/api/raw-artifacts/download")
    def api_download_raw_artifacts() -> Response:
        payload = build_raw_artifacts_zip()
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="fritzbox-raw-artifacts-{stamp}.zip"'},
        )

    @app.get("/api/acquisition-package/download")
    def api_download_acquisition_package() -> Response:
        payload = build_forensic_acquisition_zip()
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="fritzbox-forensic-package-{stamp}.zip"'},
        )

    @app.get("/api/search")
    def api_search(
        q: str = "",
        view: str = Query(default="all", pattern="^(all|wifi|hosts|log)$"),
        category: str = Query(default="all"),
        limit: int = Query(default=50, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        sort_by: str = "",
        sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    ) -> JSONResponse:
        return JSONResponse(json_safe(query_records(DEFAULT_DB, q, view, limit, offset, category, sort_by, sort_dir)))

    @app.get("/api/timeline")
    def api_timeline(
        q: str = "",
        category: str = Query(default="all"),
        start: str = "",
        end: str = "",
        limit: int = Query(default=50, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        return JSONResponse(json_safe(query_timeline(DEFAULT_DB, q, category, start, end, limit, offset)))

    @app.get("/api/analysis")
    def api_analysis(start: str = "", end: str = "") -> JSONResponse:
        return JSONResponse(json_safe(analysis_snapshot(DEFAULT_DB, start, end)))

    @app.get("/api/entities")
    def api_entities(q: str = "", limit: int = Query(default=100, ge=1, le=500)) -> JSONResponse:
        return JSONResponse(json_safe(query_entities(DEFAULT_DB, q, limit)))

    @app.get("/api/entity")
    def api_entity(value: str = "") -> JSONResponse:
        return JSONResponse(json_safe(entity_pivot(DEFAULT_DB, value)))

    @app.get("/api/evidence")
    def api_evidence(
        record_type: str = Query(default=""),
        record_id: int = Query(default=0, ge=0),
    ) -> JSONResponse:
        return JSONResponse(json_safe(evidence_for_record(DEFAULT_DB, record_type, record_id)))

    @app.get("/api/polling")
    def api_get_polling() -> JSONResponse:
        return JSONResponse(json_safe(poller.snapshot()))

    @app.post("/api/polling")
    async def api_set_polling(request: Request) -> JSONResponse:
        payload = await request.json()
        if payload.get("active"):
            return JSONResponse(json_safe(poller.start(int(payload.get("interval_minutes") or 15))))
        return JSONResponse(json_safe(poller.stop()))

    @app.get("/api/settings")
    def api_get_settings() -> JSONResponse:
        settings = get_settings(DEFAULT_DB)
        if not settings.get("address"):
            settings["address"] = exporter.os.getenv("FRITZBOX_ADDRESS") or exporter.os.getenv("FRITZBOX_IP") or "192.168.178.1"
        return JSONResponse(settings)

    @app.post("/api/settings")
    async def api_save_settings(request: Request) -> JSONResponse:
        payload = await request.json()
        if not payload.get("address"):
            raise HTTPException(status_code=400, detail="FRITZ!Box IP/address is required.")
        return JSONResponse(save_settings(payload, DEFAULT_DB))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(prog="fritzbox-wifi-dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(), host=args.host, port=args.port)


app = create_app()


if __name__ == "__main__":
    main()
