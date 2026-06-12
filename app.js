const titles = {
  overview: "Overview",
  scanner: "Scanner",
  traffic: "Traffic",
  quarantine: "Quarantine",
  startup: "Startup audit",
  rules: "Rules",
  learn: "Learn"
};

const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => Array.from(root.querySelectorAll(selector));

let currentStatus = null;
const busyButtons = new WeakSet();
let scanResults = [];
let trafficRows = [];
let quarantineItems = [];
let startupRows = [];
let activeScanJobId = null;
let scanPollTimer = null;

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new Error("The ClearGuard agent API is not available from this page. Open http://127.0.0.1:5288/ after starting python server.py.");
  }
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }
  return data;
}

function riskClass(risk) {
  return ["medium", "high", "critical"].includes(risk) ? risk : "low";
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function empty(container, message) {
  container.replaceChildren();
  const item = document.createElement("div");
  item.className = "empty-state";
  item.textContent = message;
  container.append(item);
}

function setBusy(button, busy, label) {
  if (!button) return;
  if (busy) {
    busyButtons.add(button);
    button.dataset.idleText = button.textContent;
    button.disabled = true;
    button.classList.add("is-loading");
    if (label) button.textContent = label;
  } else {
    busyButtons.delete(button);
    button.disabled = false;
    button.classList.remove("is-loading");
    if (button.dataset.idleText) {
      button.textContent = button.dataset.idleText;
      delete button.dataset.idleText;
    }
  }
}

async function withBusy(button, label, work) {
  if (busyButtons.has(button)) return;
  setBusy(button, true, label);
  try {
    return await work();
  } finally {
    setBusy(button, false);
  }
}

function sanitizeDomainInput(value) {
  const trimmed = value.trim().replace(/^["'`]+|["'`]+$/g, "");
  if (!trimmed) return "";
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    return url.hostname.replace(/^www\./i, "").replace(/\.$/, "").toLowerCase();
  } catch {
    return trimmed.replace(/^https?:\/\//i, "").split("/")[0].replace(/^www\./i, "").replace(/\.$/, "").toLowerCase();
  }
}

function textMatches(value, query) {
  return !query || String(value || "").toLowerCase().includes(query.toLowerCase());
}

function renderMetrics(container, items) {
  container.replaceChildren();
  items.forEach((item) => {
    const metric = document.createElement("div");
    metric.className = "metric-chip";
    metric.innerHTML = `<strong></strong><span></span>`;
    qs("strong", metric).textContent = item.value;
    qs("span", metric).textContent = item.label;
    container.append(metric);
  });
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function countBy(items, key, value) {
  return items.filter((item) => item[key] === value).length;
}

function switchView(view) {
  qsa(".view").forEach((section) => section.classList.toggle("active", section.id === view));
  qsa(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  qs("#viewTitle").textContent = titles[view];

  if (view === "traffic") refreshTraffic();
  if (view === "quarantine") refreshQuarantine();
  if (view === "startup") refreshStartup();
  if (view === "rules") {
    renderRules(currentStatus?.rules || []);
    refreshBlocklists();
  }
}

function setMode(mode) {
  qsa(".mode-button").forEach((button) => button.classList.toggle("active", button.dataset.mode === mode));
  const labels = { quiet: "Low alerts", balanced: "Recommended", strict: "High alert" };
  qs("#viewTitle").title = `Protection mode: ${labels[mode] || mode}`;
}

function renderStatus(status) {
  currentStatus = status;
  qs("#trustScore").textContent = status.trust_score;
  qs("#trustCopy").textContent = trustCopy(status);
  qs("#overviewSummary").textContent = overviewSummary(status);
  setMode(status.mode);

  const lastScan = status.last_scan;
  if (!lastScan) {
    qs("#fileStatus").textContent = "No scan has run yet. Start with Downloads or a folder you are worried about.";
  } else {
    const risky = (lastScan.counts.medium || 0) + (lastScan.counts.high || 0) + (lastScan.counts.critical || 0);
    qs("#fileStatus").textContent = `${lastScan.file_count} file(s) scanned. ${risky} need review.`;
  }
  qs("#networkStatus").textContent = `${status.network_count} live outbound connection(s). ${status.high_network_count} high-risk process match(es). ${status.blocked_ip_count || 0} ClearGuard block rule(s).`;
  qs("#quarantineStatus").textContent = status.quarantine_count
    ? `${status.quarantine_count} file(s) are contained.`
    : "No files contained.";
  qs("#realtimeStatus").textContent = `${status.realtime_enabled ? "Realtime monitor on" : "Realtime monitor off"}. ${status.notifications_enabled ? "Notifications on" : "Notifications off"}. ${status.persistence_installed ? "Starts at login." : "Run install script to start at login."}`;
  const defender = status.defender_status || {};
  qs("#engineStatus").textContent = status.defender_enabled
    ? defender.Available
      ? `Defender ${defender.AntivirusEnabled ? "on" : "off"}. Realtime ${defender.RealTimeProtectionEnabled ? "on" : "off"}. Definitions ${defender.AntivirusSignatureVersion || "unknown"}.`
      : `Defender unavailable: ${defender.Error || "unknown error"}`
    : "Defender engine disabled in ClearGuard settings.";
  qs("#defenderToggle").checked = Boolean(status.defender_enabled);
  qs("#realtimeToggle").checked = Boolean(status.realtime_enabled);
  qs("#notificationsToggle").checked = Boolean(status.notifications_enabled);
  renderActionList(status);
  renderProtectedPaths(status.protected_paths || []);
  renderActivity(status.activity || []);
}

function overviewSummary(status) {
  const admin = status.is_admin ? "Admin controls ready" : "Inspection mode; firewall and hosts enforcement need Administrator.";
  const persistence = status.persistence_installed ? "Starts at login" : "Startup persistence is not installed.";
  return `${admin} ${persistence} ${status.network_count} live connection(s), ${status.quarantine_count} contained file(s).`;
}

function trustCopy(status) {
  if (status.trust_score >= 85) return "Healthy. No urgent local signal is currently dominating risk.";
  if (status.trust_score >= 75) return "Worth reviewing. One or more local signals need attention.";
  return "High attention. Review scan findings, traffic, and quarantine.";
}

function renderActionList(status) {
  const list = qs("#actionList");
  list.replaceChildren();
  const actions = [];
  if (!status.persistence_installed) actions.push({ title: "Install startup persistence", detail: "Run scripts/install-clearguard.ps1 as Administrator so ClearGuard starts after reboot.", view: "learn" });
  if (!status.is_admin) actions.push({ title: "Restart as Administrator", detail: "Required for Windows Firewall IP blocks and hosts-file domain enforcement.", view: "rules" });
  if (!status.last_scan) actions.push({ title: "Run your first scan", detail: "Scan Downloads or another folder you are worried about.", view: "scanner" });
  if (status.high_network_count) actions.push({ title: "Review high-risk traffic", detail: `${status.high_network_count} live connection(s) are from commonly abused process names.`, view: "traffic" });
  if (status.quarantine_count) actions.push({ title: "Review quarantine", detail: `${status.quarantine_count} file(s) are contained and waiting for restore/delete decisions.`, view: "quarantine" });
  if (!actions.length) actions.push({ title: "Keep monitoring", detail: "No urgent action is dominating the local signal right now.", view: "overview" });
  actions.slice(0, 4).forEach((item) => {
    const article = document.createElement("article");
    article.className = "action-item";
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
      </div>
      <button class="secondary-action" type="button">Open</button>
    `;
    qs("h4", article).textContent = item.title;
    qs("p", article).textContent = item.detail;
    qs("button", article).addEventListener("click", () => switchView(item.view));
    list.append(article);
  });
}

function renderActivity(events) {
  const list = qs("#activityList");
  if (!events.length) {
    empty(list, "No local activity recorded yet. Run a scan or check traffic to create real events.");
    return;
  }
  list.replaceChildren();
  events.forEach((event) => {
    const article = document.createElement("article");
    article.className = "activity-item";
    article.innerHTML = `
      <div class="risk-dot ${riskClass(event.risk)}"></div>
      <div>
        <h4></h4>
        <p></p>
        <small></small>
      </div>
    `;
    qs("h4", article).textContent = event.title;
    qs("p", article).textContent = event.detail;
    qs("small", article).textContent = `${event.kind} - ${formatTime(event.time)}`;
    list.append(article);
  });
}

function renderRules(rules) {
  const list = qs("#rulesList");
  if (!rules.length) {
    empty(list, "No rules are configured.");
    return;
  }
  list.replaceChildren();
  rules.forEach((rule) => {
    const article = document.createElement("article");
    article.className = "rule-item";
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
        <small></small>
      </div>
    `;
    qs("h4", article).textContent = rule.name;
    qs("p", article).textContent = rule.plain;
    qs("small", article).textContent = `Action: ${rule.action}`;
    list.append(article);
  });
}

function renderProtectedPaths(paths) {
  const list = qs("#protectedPathList");
  if (!list) return;
  renderMetrics(qs("#scanMetrics"), [
    { value: paths.length, label: "protected path(s)" },
    { value: currentStatus?.realtime_enabled ? "On" : "Off", label: "realtime monitor" },
    { value: currentStatus?.defender_enabled ? "On" : "Off", label: "Defender engine" }
  ]);
  if (!paths.length) {
    empty(list, "No protected paths are configured.");
    return;
  }
  list.replaceChildren();
  paths.forEach((path) => {
    const article = document.createElement("article");
    article.className = "rule-item";
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
      </div>
      <div class="quarantine-actions">
        <button class="secondary-action scan-path-action" type="button">Scan</button>
        <button class="secondary-action remove-path-action" type="button">Remove</button>
      </div>
    `;
    qs("h4", article).textContent = path;
    qs("p", article).textContent = "Realtime folder monitoring watches this path while the local agent is running.";
    qs(".scan-path-action", article).addEventListener("click", (event) => withBusy(event.currentTarget, "Scanning", () => runScan(path)));
    qs(".remove-path-action", article).addEventListener("click", (event) => withBusy(event.currentTarget, "Removing", async () => {
      await api("/api/protected-paths", { method: "POST", body: JSON.stringify({ action: "remove", path }) });
      await refreshStatus();
    }));
    list.append(article);
  });
}

async function refreshStatus() {
  try {
    renderStatus(await api("/api/status"));
  } catch (error) {
    qs("#trustScore").textContent = "--";
    qs("#trustCopy").textContent = `Agent error: ${error.message}`;
  }
}

async function runScan(path) {
  const summary = qs("#scanSummary");
  const findings = qs("#scanFindings");
  if (activeScanJobId) {
    summary.textContent = "A scan is already running. ClearGuard will show the result here when it finishes.";
    return;
  }
  summary.textContent = "Starting background scan...";
  findings.replaceChildren();
  scanResults = [];
  try {
    const job = await api("/api/scan-job", {
      method: "POST",
      body: JSON.stringify({ path })
    });
    activeScanJobId = job.id;
    setScanControlsRunning(true);
    renderScanJob(job);
    pollScanJob(job.id);
  } catch (error) {
    summary.textContent = error.message;
    activeScanJobId = null;
    setScanControlsRunning(false);
  }
}

function setScanControlsRunning(running) {
  [qs("#scanDefault"), qs("#scanPathButton")].forEach((button) => {
    if (!button) return;
    button.disabled = running;
    button.classList.toggle("is-loading", running);
  });
}

function renderScanJob(job) {
  const summary = qs("#scanSummary");
  const elapsed = job.elapsed_seconds ?? 0;
  summary.innerHTML = `
    <strong>Scan running in the background</strong><br>
    Target: ${job.target}<br>
    Elapsed: ${elapsed}s. You can stay on this page or use other ClearGuard pages while it runs.
  `;
}

function finishScanJob(result) {
  const summary = qs("#scanSummary");
  const findings = qs("#scanFindings");
  const risky = result.risky.length;
  scanResults = result.risky || [];
  summary.innerHTML = `
    <strong>${result.file_count} file(s) scanned</strong><br>
    ${risky} item(s) need review. Completed in ${result.duration_seconds}s.<br>
    Malware engine: ${result.defender?.available ? `${result.defender.ok ? "Defender scan completed" : "Defender scan had an issue"} (${result.defender.detection_count} detection(s))` : "Defender unavailable or disabled"}.<br>
    Target: ${result.target}${result.truncated ? "<br>Large folder safety limit reached; ClearGuard scanned the first batch instead of timing out the UI." : ""}
  `;
  if (!risky) {
    empty(findings, "No risky files found by local rules.");
  } else {
    renderFindings();
  }
}

async function pollScanJob(jobId) {
  window.clearTimeout(scanPollTimer);
  let stillRunning = false;
  try {
    const job = await api(`/api/scan-job?id=${encodeURIComponent(jobId)}`);
    if (job.status === "running") {
      renderScanJob(job);
      stillRunning = true;
      scanPollTimer = window.setTimeout(() => pollScanJob(jobId), 1500);
      return;
    }
    if (job.status === "completed") {
      finishScanJob(job.result);
      await refreshStatus();
    } else {
      qs("#scanSummary").textContent = job.error || "Scan failed.";
    }
  } catch (error) {
    qs("#scanSummary").textContent = error.message;
  } finally {
    if (!stillRunning && activeScanJobId === jobId) {
      activeScanJobId = null;
      setScanControlsRunning(false);
    }
  }
}

function renderFindings(items = scanResults) {
  const list = qs("#scanFindings");
  const query = qs("#scanFindingSearch")?.value || "";
  const risk = qs("#scanRiskFilter")?.value || "all";
  const visible = items.filter((item) => {
    const matchesRisk = risk === "all" || item.risk === risk;
    const haystack = `${item.name} ${item.path} ${(item.findings || []).join(" ")} ${(item.sources || []).join(" ")}`;
    return matchesRisk && textMatches(haystack, query);
  });
  if (!visible.length) {
    empty(list, items.length ? "No scan findings match this filter." : "No risky files found by local rules.");
    return;
  }
  list.replaceChildren();
  visible.forEach((item) => {
    const article = document.createElement("article");
    article.className = `finding-item ${riskClass(item.risk)}`;
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
        <small></small>
      </div>
      <button class="primary-action danger" type="button">Quarantine</button>
    `;
    qs("h4", article).textContent = `${item.risk.toUpperCase()} - ${item.name}`;
    qs("p", article).textContent = item.findings.join(" ");
    qs("small", article).textContent = `${(item.sources || ["ClearGuard heuristics"]).join(" + ")} - ${item.path}`;
    qs("button", article).addEventListener("click", async () => {
      await api("/api/quarantine", {
        method: "POST",
        body: JSON.stringify({ path: item.path, reason: item.findings.join("; ") })
      });
      article.remove();
      await refreshStatus();
    });
    list.append(article);
  });
}

async function refreshTraffic() {
  const refreshButton = qs("#refreshTraffic");
  const body = qs("#trafficTable");
  body.innerHTML = `<tr><td colspan="5">Reading live TCP connections...</td></tr>`;
  if (currentStatus) {
    qs("#trafficHelp").textContent = currentStatus.is_admin
      ? "ClearGuard is running with administrator rights, so firewall block rules can be created from here."
      : "ClearGuard is not running as Administrator. You can inspect traffic here, but creating Windows Firewall block rules requires elevation.";
  }
  try {
    const rows = await withBusy(refreshButton, "Refreshing", () => api("/api/network"));
    trafficRows = rows || [];
    renderTrafficRows();
    await refreshBlocked();
  } catch (error) {
    body.innerHTML = `<tr><td colspan="5">${error.message}</td></tr>`;
  }
}

function renderTrafficRows() {
  const body = qs("#trafficTable");
  renderMetrics(qs("#trafficMetrics"), [
    { value: trafficRows.length, label: "live connections" },
    { value: countBy(trafficRows, "risk", "high"), label: "high risk" },
    { value: countBy(trafficRows, "risk", "medium"), label: "medium risk" },
    { value: new Set(trafficRows.map((row) => row.process)).size, label: "processes" }
  ]);
  if (!trafficRows.length) {
    body.innerHTML = `<tr><td colspan="5">No established outbound TCP connections found.</td></tr>`;
    return;
  }
  const query = qs("#trafficSearch")?.value || "";
  const risk = qs("#trafficRiskFilter")?.value || "all";
  const visible = trafficRows.filter((row) => {
    const matchesRisk = risk === "all" || row.risk === risk;
    const haystack = `${row.process} ${row.pid} ${row.remote} ${row.remote_address} ${row.host || ""} ${row.path || ""} ${row.service_hint || ""} ${(row.findings || []).join(" ")}`;
    return matchesRisk && textMatches(haystack, query);
  });
  if (!visible.length) {
    body.innerHTML = `<tr><td colspan="5">No live connections match this filter.</td></tr>`;
    return;
  }
  body.replaceChildren();
  visible.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="risk-pill ${riskClass(row.risk)}"></span></td>
      <td></td>
      <td></td>
      <td></td>
      <td><button class="secondary-action" type="button">Block IP</button></td>
    `;
    tr.children[0].querySelector("span").textContent = row.risk;
    tr.children[1].innerHTML = `<strong></strong><br><small></small>`;
    tr.children[1].querySelector("strong").textContent = `${row.process} (PID ${row.pid})`;
    tr.children[1].querySelector("small").textContent = row.path || "Process path unavailable";
    tr.children[2].innerHTML = `<strong></strong><br><small></small>`;
    tr.children[2].querySelector("strong").textContent = row.host || row.remote_address;
    tr.children[2].querySelector("small").textContent = row.remote;
    tr.children[3].textContent = row.findings.join(" ");
    tr.querySelector("button").addEventListener("click", async () => {
      const ok = window.confirm(`Create a Windows Firewall block rule for ${row.remote_address}? This can break the app or website using that IP.`);
      if (!ok) return;
      try {
        await withBusy(tr.querySelector("button"), "Blocking", () => api("/api/block-ip", {
          method: "POST",
          body: JSON.stringify({ remote_address: row.remote_address })
        }));
        await refreshStatus();
        await refreshBlocked();
      } catch (error) {
        window.alert(error.message);
      }
    });
    body.append(tr);
  });
}

async function refreshBlocked() {
  const list = qs("#blockedList");
  try {
    const rows = await withBusy(qs("#refreshBlocked"), "Refreshing", () => api("/api/blocked-ips"));
    if (!rows.length) {
      empty(list, "No ClearGuard/user-created outbound IP blocks found. Internal system and sandbox firewall rules are hidden.");
      return;
    }
    list.replaceChildren();
    rows.forEach((row) => {
      const article = document.createElement("article");
      article.className = "rule-item";
      article.innerHTML = `
        <div>
          <h4></h4>
          <p></p>
          <small></small>
        </div>
        <button class="secondary-action" type="button">Unblock</button>
      `;
      qs("h4", article).textContent = row.remote_address;
      qs("p", article).textContent = row.name;
      qs("small", article).textContent = `${row.action} ${row.direction} - ${row.enabled}`;
      qs("button", article).addEventListener("click", async () => {
        const ok = window.confirm(`Remove this Windows Firewall block rule?\n\n${row.name}`);
        if (!ok) return;
        try {
          await api("/api/unblock-ip", {
            method: "POST",
            body: JSON.stringify({ rule_name: row.name })
          });
          await refreshBlocked();
          await refreshStatus();
        } catch (error) {
          window.alert(error.message);
        }
      });
      list.append(article);
    });
  } catch (error) {
    empty(list, error.message);
  }
}

async function refreshQuarantine() {
  const list = qs("#quarantineList");
  try {
    const items = await api("/api/quarantine");
    quarantineItems = items || [];
    renderQuarantineItems();
  } catch (error) {
    empty(list, error.message);
  }
}

function renderQuarantineItems() {
  const list = qs("#quarantineList");
  renderMetrics(qs("#quarantineMetrics"), [
    { value: quarantineItems.length, label: "total records" },
    { value: countBy(quarantineItems, "status", "contained"), label: "contained" },
    { value: countBy(quarantineItems, "status", "restored"), label: "restored" },
    { value: countBy(quarantineItems, "status", "deleted"), label: "deleted" }
  ]);
  if (!quarantineItems.length) {
    empty(list, "No files are in quarantine.");
    return;
  }
  const query = qs("#quarantineSearch")?.value || "";
  const status = qs("#quarantineStatusFilter")?.value || "all";
  const visible = quarantineItems.filter((item) => {
    const matchesStatus = status === "all" || item.status === status;
    const haystack = `${item.name} ${item.status} ${item.reason} ${item.original_path} ${item.sha256 || ""}`;
    return matchesStatus && textMatches(haystack, query);
  });
  if (!visible.length) {
    empty(list, "No quarantine records match this filter.");
    return;
  }
  list.replaceChildren();
  visible.forEach((item) => {
    const article = document.createElement("article");
    article.className = "quarantine-item";
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
        <small></small>
      </div>
      <div class="quarantine-actions"></div>
    `;
    qs("h4", article).textContent = `${item.name} - ${item.status}`;
    qs("p", article).textContent = item.reason;
    qs("small", article).textContent = `${item.original_path} - ${formatTime(item.created_at)} - ${item.sha256 || "hash unavailable"}`;
    const actions = qs(".quarantine-actions", article);
    if (item.status === "contained") {
      const restore = document.createElement("button");
      restore.className = "secondary-action";
      restore.type = "button";
      restore.textContent = "Restore";
      restore.addEventListener("click", (event) => withBusy(event.currentTarget, "Restoring", () => quarantineAction(item.id, "restore")));
      const del = document.createElement("button");
      del.className = "primary-action danger";
      del.type = "button";
      del.textContent = "Delete";
      del.addEventListener("click", async (event) => {
        const ok = window.confirm(`Permanently delete ${item.name} from quarantine?`);
        if (!ok) return;
        await withBusy(event.currentTarget, "Deleting", () => quarantineAction(item.id, "delete"));
      });
      actions.append(restore, del);
    }
    list.append(article);
  });
}

async function refreshStartup() {
  const list = qs("#startupList");
  empty(list, "Auditing registry Run keys, Startup folders, and scheduled tasks...");
  try {
    const rows = await withBusy(qs("#refreshStartup"), "Auditing", () => api("/api/startup-audit"));
    startupRows = rows || [];
    renderStartupRows();
  } catch (error) {
    empty(list, error.message);
  }
}

function renderStartupRows() {
  const list = qs("#startupList");
  renderMetrics(qs("#startupMetrics"), [
    { value: startupRows.length, label: "startup entries" },
    { value: startupRows.filter((row) => row.can_toggle !== false).length, label: "controllable" },
    { value: startupRows.filter((row) => row.can_toggle === false).length, label: "system protected" },
    { value: startupRows.filter((row) => !row.enabled).length, label: "disabled" }
  ]);
  if (!startupRows.length) {
    empty(list, "No startup entries found.");
    return;
  }
  const query = qs("#startupSearch")?.value || "";
  const filter = qs("#startupFilter")?.value || "all";
  const visible = startupRows.filter((row) => {
    const haystack = `${row.name} ${row.type} ${row.location} ${row.command} ${(row.findings || []).join(" ")}`;
    const matchesText = textMatches(haystack, query);
    const matchesFilter =
      filter === "all" ||
      (filter === "toggleable" && row.can_toggle !== false) ||
      (filter === "system" && row.can_toggle === false) ||
      (filter === "disabled" && !row.enabled) ||
      row.risk === filter;
    return matchesText && matchesFilter;
  });
  if (!visible.length) {
    empty(list, "No startup entries match this filter.");
    return;
  }
  list.replaceChildren();
  visible.forEach((row) => {
    const article = document.createElement("article");
    article.className = `finding-item ${riskClass(row.risk)}`;
    article.innerHTML = `
      <div>
        <h4></h4>
        <p></p>
        <small></small>
      </div>
      <button class="secondary-action" type="button"></button>
    `;
    qs("h4", article).textContent = `${row.risk.toUpperCase()} - ${row.name}`;
    qs("p", article).textContent = row.findings.join(" ");
    qs("small", article).textContent = `${row.type} - ${row.location} - ${row.command || "No command text"}`;
    const button = qs("button", article);
    button.textContent = row.enabled ? "Disable startup" : "Enable startup";
    if (row.can_toggle === false) {
      button.textContent = "System task";
      button.disabled = true;
      button.title = "Protected Windows scheduled task; shown for visibility only.";
      list.append(article);
      return;
    }
    button.addEventListener("click", async () => {
      const nextState = !row.enabled;
      const action = nextState ? "enable" : "disable";
      const ok = window.confirm(`${action[0].toUpperCase()}${action.slice(1)} startup for "${row.name}"?\n\nSome system-wide entries require Administrator rights.`);
      if (!ok) return;
      try {
        await withBusy(button, nextState ? "Enabling" : "Disabling", () => api("/api/startup-entry", {
          method: "POST",
          body: JSON.stringify({ entry: row, enabled: nextState })
        }));
        await refreshStartup();
        await refreshStatus();
      } catch (error) {
        window.alert(error.message);
      }
    });
    list.append(article);
  });
}

async function refreshBlocklists() {
  const list = qs("#blocklistList");
  try {
    const [data, blockedIps] = await Promise.all([api("/api/blocklists"), api("/api/blocked-ips")]);
    const rows = [
      ...(data.blocked_domains || []).map((value) => ({ type: "Domain", value, endpoint: "/api/unblock-domain", key: "domain" })),
      ...(data.blocked_hashes || []).map((value) => ({ type: "SHA-256", value, endpoint: "/api/unblock-hash", key: "sha256" })),
      ...(blockedIps || []).map((item) => ({ type: "Outbound IP", value: item.remote_address, endpoint: "/api/unblock-ip", key: "rule_name", ruleName: item.name }))
    ];
    if (!rows.length) {
      empty(list, "No local domains, hashes, or ClearGuard IP blocks are active.");
      return;
    }
    list.replaceChildren();
    rows.forEach((row) => {
      const article = document.createElement("article");
      article.className = "rule-item";
      article.innerHTML = `
        <div>
          <h4></h4>
          <p></p>
          <small></small>
        </div>
        <button class="secondary-action" type="button">Remove</button>
      `;
      qs("h4", article).textContent = row.value;
      qs("p", article).textContent = row.type;
      qs("small", article).textContent = row.type === "Outbound IP" ? "Windows Firewall rule" : "Local ClearGuard blocklist";
      qs("button", article).addEventListener("click", async () => {
        await withBusy(qs("button", article), "Removing", () => api(row.endpoint, { method: "POST", body: JSON.stringify({ [row.key]: row.ruleName || row.value }) }));
        await refreshBlocklists();
        await refreshBlocked();
      });
      list.append(article);
    });
  } catch (error) {
    empty(list, error.message);
  }
}

async function quarantineAction(id, action) {
  await api(`/api/quarantine/${encodeURIComponent(id)}`, {
    method: "POST",
    body: JSON.stringify({ action })
  });
  await refreshQuarantine();
  await refreshStatus();
}

async function checkUrl() {
  const box = qs("#urlResult");
  const url = qs("#urlInput").value.trim();
  box.textContent = "Checking URL locally...";
  try {
    const result = await withBusy(qs("#checkUrl"), "Checking", () => api("/api/investigate-url", {
      method: "POST",
      body: JSON.stringify({ url })
    }));
    box.innerHTML = `
      <strong>${result.risk.toUpperCase()} - ${result.host}</strong><br>
      Addresses: ${result.addresses.join(", ") || "none"}<br>
      ${result.findings.join(" ")}
    `;
    await refreshStatus();
  } catch (error) {
    box.textContent = error.message;
  }
}

async function updateSetting(key, value) {
  await api("/api/settings", {
    method: "POST",
    body: JSON.stringify({ [key]: value })
  });
  await refreshStatus();
}

async function defenderAction(endpoint, label) {
  const box = qs("#urlResult");
  box.textContent = `${label}...`;
  try {
    const button = endpoint.includes("update") ? qs("#updateDefender") : qs("#quickScan");
    const result = await withBusy(button, "Working", () => api(endpoint, { method: "POST", body: JSON.stringify({}) }));
    box.textContent = `${label} finished. ${result.detection_count ?? 0} detection(s).`;
    await refreshStatus();
  } catch (error) {
    box.textContent = error.message;
  }
}

async function addBlocklistItem(endpoint, payload, input) {
  const result = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
  input.value = "";
  await refreshBlocklists();
  await refreshBlocked();
  await refreshStatus();
  return result;
}

async function exportSecurityReport(button) {
  await withBusy(button, "Exporting", async () => {
    const report = await api("/api/report");
    downloadJson(`clearguard-report-${new Date().toISOString().slice(0, 10)}.json`, report);
  });
}

async function exportBlocklists(button) {
  await withBusy(button, "Exporting", async () => {
    const [blocklists, ips] = await Promise.all([api("/api/blocklists"), api("/api/blocked-ips")]);
    downloadJson(`clearguard-blocklists-${new Date().toISOString().slice(0, 10)}.json`, { ...blocklists, blocked_ips: ips });
  });
}

async function addProtectedPath(button) {
  const input = qs("#protectedPathInput");
  await withBusy(button, "Adding", async () => {
    await api("/api/protected-paths", { method: "POST", body: JSON.stringify({ action: "add", path: input.value.trim() }) });
    input.value = "";
    await refreshStatus();
  });
}

async function resetProtectedPaths(button) {
  const ok = window.confirm("Reset protected paths to Downloads, Desktop, and Documents if those folders exist?");
  if (!ok) return;
  await withBusy(button, "Resetting", async () => {
    await api("/api/protected-paths", { method: "POST", body: JSON.stringify({ action: "reset" }) });
    await refreshStatus();
  });
}

async function clearActivity(button) {
  const ok = window.confirm("Clear the local activity log? This does not change quarantine or rules.");
  if (!ok) return;
  await withBusy(button, "Clearing", async () => {
    await api("/api/activity-clear", { method: "POST", body: JSON.stringify({}) });
    await refreshStatus();
  });
}

async function purgeQuarantineHistory(button) {
  const ok = window.confirm("Remove restored/deleted quarantine history records? Contained files will stay in quarantine.");
  if (!ok) return;
  await withBusy(button, "Cleaning", async () => {
    await api("/api/quarantine-maintenance", { method: "POST", body: JSON.stringify({ action: "purge_inactive" }) });
    await refreshQuarantine();
    await refreshStatus();
  });
}

async function importBlocklists(button) {
  const input = qs("#bulkBlocklistInput");
  await withBusy(button, "Importing", async () => {
    try {
      const result = await api("/api/blocklist-import", { method: "POST", body: JSON.stringify({ text: input.value }) });
      input.value = "";
      qs("#rulesHelp").textContent = `Imported ${result.imported_domains.length} domain(s), ${result.imported_hashes.length} hash(es), and ${result.imported_ips.length} IP block(s). ${result.skipped.length} skipped.`;
      await refreshBlocklists();
      await refreshStatus();
    } catch (error) {
      qs("#rulesHelp").textContent = error.message;
    }
  });
}

qsa(".nav-item").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
qsa(".mode-button").forEach((button) => {
  button.addEventListener("click", async () => {
    await withBusy(button, "Saving", async () => {
      await api("/api/settings", { method: "POST", body: JSON.stringify({ mode: button.dataset.mode }) });
      await refreshStatus();
    });
  });
});
qs("#refreshOverview").addEventListener("click", (event) => withBusy(event.currentTarget, "Refreshing", refreshStatus));
qs("#overviewScan").addEventListener("click", () => switchView("scanner"));
qs("#exportReport").addEventListener("click", (event) => exportSecurityReport(event.currentTarget));
qs("#clearActivity").addEventListener("click", (event) => clearActivity(event.currentTarget));
qs("#scanDefault").addEventListener("click", (event) => withBusy(event.currentTarget, "Scanning", () => runScan("")));
qs("#scanPathButton").addEventListener("click", (event) => withBusy(event.currentTarget, "Scanning", () => runScan(qs("#scanPath").value.trim())));
qs("#addProtectedPath").addEventListener("click", (event) => addProtectedPath(event.currentTarget));
qs("#resetProtectedPaths").addEventListener("click", (event) => resetProtectedPaths(event.currentTarget));
qs("#scanFindingSearch").addEventListener("input", () => renderFindings());
qs("#scanRiskFilter").addEventListener("change", () => renderFindings());
qs("#refreshTraffic").addEventListener("click", refreshTraffic);
qs("#refreshBlocked").addEventListener("click", refreshBlocked);
qs("#trafficSearch").addEventListener("input", renderTrafficRows);
qs("#trafficRiskFilter").addEventListener("change", renderTrafficRows);
qs("#refreshQuarantine").addEventListener("click", refreshQuarantine);
qs("#purgeQuarantineHistory").addEventListener("click", (event) => purgeQuarantineHistory(event.currentTarget));
qs("#quarantineSearch").addEventListener("input", renderQuarantineItems);
qs("#quarantineStatusFilter").addEventListener("change", renderQuarantineItems);
qs("#refreshStartup").addEventListener("click", refreshStartup);
qs("#startupSearch").addEventListener("input", renderStartupRows);
qs("#startupFilter").addEventListener("change", renderStartupRows);
qs("#checkUrl").addEventListener("click", checkUrl);
qs("#defenderToggle").addEventListener("change", (event) => updateSetting("defender_enabled", event.target.checked));
qs("#realtimeToggle").addEventListener("change", (event) => updateSetting("realtime_enabled", event.target.checked));
qs("#notificationsToggle").addEventListener("change", (event) => updateSetting("notifications_enabled", event.target.checked));
qs("#testNotification").addEventListener("click", async () => {
  try {
    await withBusy(qs("#testNotification"), "Sending", () => api("/api/test-notification", { method: "POST", body: JSON.stringify({}) }));
  } catch (error) {
    window.alert(error.message);
  }
});
qs("#updateDefender").addEventListener("click", () => defenderAction("/api/defender-update", "Updating Defender definitions"));
qs("#quickScan").addEventListener("click", () => defenderAction("/api/defender-quick-scan", "Running Defender quick scan"));
qs("#downloadReportFromRules").addEventListener("click", (event) => exportSecurityReport(event.currentTarget));
qs("#exportBlocklists").addEventListener("click", (event) => exportBlocklists(event.currentTarget));
qs("#importBlocklists").addEventListener("click", (event) => importBlocklists(event.currentTarget));
qs("#addDomain").addEventListener("click", () => {
  const input = qs("#domainInput");
  input.value = sanitizeDomainInput(input.value);
  withBusy(qs("#addDomain"), "Blocking", async () => {
    try {
      const result = await addBlocklistItem("/api/block-domain", { domain: input.value }, input);
      qs("#rulesHelp").textContent = result.message || `Blocked ${result.domain}.`;
    } catch (error) {
      qs("#rulesHelp").textContent = error.message;
    }
  });
});
qs("#addIp").addEventListener("click", () => {
  const input = qs("#ipInput");
  withBusy(qs("#addIp"), "Blocking", async () => {
    try {
      const result = await addBlocklistItem("/api/block-ip", { remote_address: input.value.trim() }, input);
      qs("#rulesHelp").textContent = `Created Windows Firewall rule: ${result.rule}`;
    } catch (error) {
      qs("#rulesHelp").textContent = error.message;
    }
  });
});
qs("#addHash").addEventListener("click", () => {
  const input = qs("#hashInput");
  withBusy(qs("#addHash"), "Blocking", async () => {
    try {
      await addBlocklistItem("/api/block-hash", { sha256: input.value.trim() }, input);
      qs("#rulesHelp").textContent = "SHA-256 hash added to local file blocklist.";
    } catch (error) {
      qs("#rulesHelp").textContent = error.message;
    }
  });
});

refreshStatus();
setInterval(refreshStatus, 30000);
