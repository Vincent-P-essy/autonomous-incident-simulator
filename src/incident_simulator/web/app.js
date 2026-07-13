"use strict";

const byId = (id) => document.getElementById(id);
let scenarios = [];

function replaceRows(body, rows, emptyColumns) {
  body.replaceChildren();
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = emptyColumns;
    cell.textContent = "No data";
    row.append(cell);
    body.append(row);
    return;
  }
  rows.forEach((values) => {
    const row = document.createElement("tr");
    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      row.append(cell);
    });
    body.append(row);
  });
}

function replaceChecks(list, entries) {
  list.replaceChildren();
  entries.forEach(({ label, pass }) => {
    const item = document.createElement("li");
    item.textContent = label;
    item.className = pass ? "pass" : "fail";
    list.append(item);
  });
}

async function request(path, options = {}) {
  const response = await fetch(path, options);
  const value = await response.json();
  if (!response.ok) throw new Error(value.detail || value.error || `HTTP ${response.status}`);
  return value;
}

function selectScenario() {
  const selected = scenarios.find((item) => item.id === byId("scenario-select").value);
  byId("scenario-description").textContent = selected ? selected.description : "No scenario selected";
}

function render(payload) {
  const report = payload.report;
  byId("metric-duration").textContent = `${report.simulation.duration_seconds}s`;
  byId("metric-techniques").textContent = report.metrics.technique_count;
  byId("metric-events").textContent = report.metrics.event_count;
  byId("metric-sources").textContent = report.metrics.telemetry_source_count;
  byId("metric-checks").textContent = `${Math.round(report.metrics.expected_result_pass_rate * 100)}%`;
  byId("digest").textContent = payload.report_sha256;
  replaceRows(byId("plan-body"), report.plan.steps.map((step) => [
    step.index, step.primitive_id, `${step.technique_id} · ${step.technique_name}`, `${step.duration_seconds}s`,
  ]), 4);
  replaceRows(byId("event-body"), report.telemetry.map((event) => [
    event.timestamp, event.source, event.event_type, event.technique.id,
  ]), 4);
  replaceChecks(byId("detection-list"), report.detection_results.map((item) => ({
    label: `${item.title} — ${item.reason}`, pass: item.matched,
  })));
  replaceChecks(byId("safety-list"), [
    { label: "Catalog-only planning", pass: report.safety.catalog_only },
    { label: "No process execution", pass: !report.safety.process_execution },
    { label: "No real network activity", pass: !report.safety.real_network_activity },
    { label: "No forbidden capability observed", pass: report.safety.forbidden_capabilities_observed.length === 0 },
  ]);
}

async function run() {
  const button = byId("run-button");
  const error = byId("error");
  button.disabled = true;
  error.hidden = true;
  try {
    const scenario = await request(`/api/v1/scenarios/${encodeURIComponent(byId("scenario-select").value)}`);
    const payload = await request("/api/v1/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scenario),
    });
    render(payload);
  } catch (reason) {
    error.textContent = reason instanceof Error ? reason.message : String(reason);
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

async function boot() {
  try {
    await request("/api/v1/health");
    byId("health").textContent = "PURE MODE / READY";
    const index = await request("/api/v1/scenarios");
    scenarios = index.scenarios;
    const select = byId("scenario-select");
    scenarios.forEach((scenario) => {
      const option = document.createElement("option");
      option.value = scenario.id;
      option.textContent = scenario.title;
      select.append(option);
    });
    select.addEventListener("change", selectScenario);
    byId("run-button").addEventListener("click", run);
    selectScenario();
  } catch (reason) {
    byId("health").textContent = "UNAVAILABLE";
    byId("error").textContent = reason instanceof Error ? reason.message : String(reason);
    byId("error").hidden = false;
  }
}

window.addEventListener("DOMContentLoaded", boot);
