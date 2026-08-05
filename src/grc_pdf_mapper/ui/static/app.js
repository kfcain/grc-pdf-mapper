const drop = document.getElementById("drop");
const fileInput = document.getElementById("file-input");
const browse = document.getElementById("browse");
const statusEl = document.getElementById("status");
const offlineEl = document.getElementById("offline");
const results = document.getElementById("results");
const rowsEl = document.getElementById("obligation-rows");
const emptyEl = document.getElementById("empty-obligations");
const markdownView = document.getElementById("markdown-view");
const jsonView = document.getElementById("json-view");
const csvFrameworksView = document.getElementById("csv-frameworks-view");
const csvControlsView = document.getElementById("csv-controls-view");
const downloadJson = document.getElementById("download-json");
const downloadCsvFrameworks = document.getElementById("download-csv-frameworks");
const downloadCsvControls = document.getElementById("download-csv-controls");

let lastPayload = null;

function setStatus(message, kind = "") {
  statusEl.textContent = message;
  statusEl.classList.remove("is-error", "is-ok");
  if (kind) statusEl.classList.add(kind);
}

function setBusy(busy) {
  drop.classList.toggle("is-busy", busy);
  browse.disabled = busy;
}

async function analyzeFile(file) {
  if (!file) return;
  setBusy(true);
  setStatus(`Parsing ${file.name}…`);
  results.hidden = true;

  const body = new FormData();
  body.append("file", file, file.name);
  body.append("offline", offlineEl.checked ? "true" : "false");
  body.append("format", "json");

  try {
    const res = await fetch("/api/analyze", { method: "POST", body });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail || res.statusText || "Parse failed";
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    lastPayload = data;
    renderResults(data);
    setStatus(`Parsed ${file.name}`, "is-ok");
  } catch (err) {
    lastPayload = null;
    setStatus(err.message || String(err), "is-error");
  } finally {
    setBusy(false);
  }
}

function renderResults(data) {
  document.getElementById("doc-title").textContent =
    data.title || data.original_name || data.doc_id || "Document";
  const format = data.detected_format || "unknown";
  document.getElementById("doc-meta").textContent =
    `${data.original_name} · ${format} · id ${data.doc_id}`;
  document.getElementById("stat-statements").textContent = String(data.statement_count ?? 0);
  document.getElementById("stat-frameworks").textContent = String(
    (data.frameworks_covered || []).length
  );
  document.getElementById("stat-engine").textContent = data.engine || "—";

  rowsEl.replaceChildren();
  const statements = data.statements || [];
  emptyEl.hidden = statements.length > 0;
  for (const row of statements) {
    const tr = document.createElement("tr");
    const strength = (row.strength || "descriptive").toLowerCase();
    const controls = (row.controls || [])
      .map((c) => `<span>${escapeHtml(c.framework)}:${escapeHtml(c.control_id)}</span>`)
      .join("");

    tr.innerHTML = `
      <td><span class="strength is-${escapeAttr(strength)}">${escapeHtml(strength)}</span></td>
      <td class="obligation">${escapeHtml(row.text || "")}</td>
      <td><div class="controls">${controls || "<span>—</span>"}</div></td>
    `;
    rowsEl.appendChild(tr);
  }

  markdownView.textContent = data.markdown_preview || data.markdown || "";
  jsonView.textContent = JSON.stringify(data.report || data, null, 2);
  csvFrameworksView.textContent = data.csv?.frameworks || "";
  csvControlsView.textContent = data.csv?.controls || "";
  results.hidden = false;
  activateTab("obligations");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll(" ", "-");
}

function activateTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    const on = tab.dataset.tab === name;
    tab.classList.toggle("is-active", on);
    tab.setAttribute("aria-selected", on ? "true" : "false");
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.hidden = panel.id !== `panel-${name}`;
  }
}

function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

browse.addEventListener("click", (event) => {
  event.stopPropagation();
  fileInput.click();
});

drop.addEventListener("click", () => fileInput.click());
drop.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  analyzeFile(file);
  fileInput.value = "";
});

["dragenter", "dragover"].forEach((type) => {
  drop.addEventListener(type, (event) => {
    event.preventDefault();
    drop.classList.add("is-drag");
  });
});

["dragleave", "drop"].forEach((type) => {
  drop.addEventListener(type, (event) => {
    event.preventDefault();
    drop.classList.remove("is-drag");
  });
});

drop.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  analyzeFile(file);
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

downloadJson.addEventListener("click", () => {
  if (!lastPayload?.report) return;
  downloadText(
    `${lastPayload.doc_id || "report"}.json`,
    JSON.stringify(lastPayload.report, null, 2),
    "application/json"
  );
});

downloadCsvFrameworks.addEventListener("click", () => {
  if (!lastPayload?.csv?.frameworks) return;
  downloadText(
    `${lastPayload.doc_id || "report"}-frameworks.csv`,
    lastPayload.csv.frameworks,
    "text/csv;charset=utf-8"
  );
});

downloadCsvControls.addEventListener("click", () => {
  if (!lastPayload?.csv?.controls) return;
  downloadText(
    `${lastPayload.doc_id || "report"}-framework-controls.csv`,
    lastPayload.csv.controls,
    "text/csv;charset=utf-8"
  );
});
