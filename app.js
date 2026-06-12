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
}

function renderStatus(status) {
  currentStatus = status;
  qs("#trustScore").textContent = status.trust_score;
  qs("#trustCopy").textContent = trustCopy(status);
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
  renderActivity(status.activity || []);
}

function trustCopy(status) {
  if (status.trust_score >= 85) return "Healthy. No urgent local signal is currently dominating risk.";
  if (status.trust_score >= 75) return "Worth reviewing. One or more local signals need attention.";
  return "High attention. Review scan findings, traffic, and quarantine.";
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
  summary.textContent = "Scanning files...";
  findings.replaceChildren();
  try {
    const result = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({ path })
    });
    const risky = result.risky.length;
    summary.innerHTML = `
      <strong>${result.file_count} file(s) scanned</strong><br>
      ${risky} item(s) need review. Completed in ${result.duration_seconds}s.<br>
      Malware engine: ${result.defender?.available ? `${result.defender.ok ? "Defender scan completed" : "Defender scan had an issue"} (${result.defender.detection_count} detection(s))` : "Defender unavailable or disabled"}.<br>
      Target: ${result.target}
    `;
    if (!risky) {
      empty(findings, "No risky files found by local rules.");
    } else {
      renderFindings(result.risky);
    }
    await refreshStatus();
  } catch (error) {
    summary.textContent = error.message;
  }
}

function renderFindings(items) {
  const list = qs("#scanFindings");
  list.replaceChildren();
  items.forEach((item) => {
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
  const body = qs("#trafficTable");
  body.innerHTML = `<tr><td colspan="5">Reading live TCP connections...</td></tr>`;
  if (currentStatus) {
    qs("#trafficHelp").textContent = currentStatus.is_admin
      ? "ClearGuard is running with administrator rights, so firewall block rules can be created from here."
      : "ClearGuard is not running as Administrator. You can inspect traffic here, but creating Windows Firewall block rules requires elevation.";
  }
  try {
    const rows = await api("/api/network");
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="5">No established outbound TCP connections found.</td></tr>`;
      return;
    }
    body.replaceChildren();
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="risk-pill ${riskClass(row.risk)}"></span></td>
        <td></td>
        <td></td>
        <td></td>
        <td><button class="secondary-action" type="button">Block IP</button></td>
      `;
      tr.children[0].querySelector("span").textContent = row.risk;
      tr.children[1].textContent = `${row.process} (PID ${row.pid})`;
      tr.children[2].innerHTML = `<strong></strong><br><small></small>`;
      tr.children[2].querySelector("strong").textContent = row.host || row.remote_address;
      tr.children[2].querySelector("small").textContent = row.remote;
      tr.children[3].textContent = row.findings.join(" ");
      tr.querySelector("button").addEventListener("click", async () => {
        const ok = window.confirm(`Create a Windows Firewall block rule for ${row.remote_address}? This can break the app or website using that IP.`);
        if (!ok) return;
        try {
          await api("/api/block-ip", {
            method: "POST",
            body: JSON.stringify({ remote_address: row.remote_address })
          });
          await refreshStatus();
          await refreshBlocked();
        } catch (error) {
          window.alert(error.message);
        }
      });
      body.append(tr);
    });
    await refreshBlocked();
  } catch (error) {
    body.innerHTML = `<tr><td colspan="5">${error.message}</td></tr>`;
  }
}

async function refreshBlocked() {
  const list = qs("#blockedList");
  try {
    const rows = await api("/api/blocked-ips");
    if (!rows.length) {
      empty(list, "No enabled outbound Windows Firewall block rules with specific remote IPs were found.");
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
    if (!items.length) {
      empty(list, "No files are in quarantine.");
      return;
    }
    list.replaceChildren();
    items.forEach((item) => {
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
      qs("small", article).textContent = `${item.original_path} - ${formatTime(item.created_at)}`;
      const actions = qs(".quarantine-actions", article);
      if (item.status === "contained") {
        const restore = document.createElement("button");
        restore.className = "secondary-action";
        restore.type = "button";
        restore.textContent = "Restore";
        restore.addEventListener("click", () => quarantineAction(item.id, "restore"));
        const del = document.createElement("button");
        del.className = "primary-action danger";
        del.type = "button";
        del.textContent = "Delete";
        del.addEventListener("click", () => quarantineAction(item.id, "delete"));
        actions.append(restore, del);
      }
      list.append(article);
    });
  } catch (error) {
    empty(list, error.message);
  }
}

async function refreshStartup() {
  const list = qs("#startupList");
  empty(list, "Auditing registry Run keys, Startup folders, and scheduled tasks...");
  try {
    const rows = await api("/api/startup-audit");
    if (!rows.length) {
      empty(list, "No enabled startup entries found.");
      return;
    }
    list.replaceChildren();
    rows.forEach((row) => {
      const article = document.createElement("article");
      article.className = `finding-item ${riskClass(row.risk)}`;
      article.innerHTML = `
        <div>
          <h4></h4>
          <p></p>
          <small></small>
        </div>
      `;
      qs("h4", article).textContent = `${row.risk.toUpperCase()} - ${row.name}`;
      qs("p", article).textContent = row.findings.join(" ");
      qs("small", article).textContent = `${row.type} - ${row.location} - ${row.command}`;
      list.append(article);
    });
  } catch (error) {
    empty(list, error.message);
  }
}

async function refreshBlocklists() {
  const list = qs("#blocklistList");
  try {
    const data = await api("/api/blocklists");
    const rows = [
      ...(data.blocked_domains || []).map((value) => ({ type: "Domain", value, endpoint: "/api/unblock-domain", key: "domain" })),
      ...(data.blocked_hashes || []).map((value) => ({ type: "SHA-256", value, endpoint: "/api/unblock-hash", key: "sha256" }))
    ];
    if (!rows.length) {
      empty(list, "No local domains or hashes are blocked.");
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
      qs("small", article).textContent = "Local ClearGuard blocklist";
      qs("button", article).addEventListener("click", async () => {
        await api(row.endpoint, { method: "POST", body: JSON.stringify({ [row.key]: row.value }) });
        await refreshBlocklists();
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
    const result = await api("/api/investigate-url", {
      method: "POST",
      body: JSON.stringify({ url })
    });
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
    const result = await api(endpoint, { method: "POST", body: JSON.stringify({}) });
    box.textContent = `${label} finished. ${result.detection_count ?? 0} detection(s).`;
    await refreshStatus();
  } catch (error) {
    box.textContent = error.message;
  }
}

async function addBlocklistItem(endpoint, payload, input) {
  await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
  input.value = "";
  await refreshBlocklists();
  await refreshStatus();
}

qsa(".nav-item").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
qsa(".mode-button").forEach((button) => {
  button.addEventListener("click", async () => {
    await api("/api/settings", { method: "POST", body: JSON.stringify({ mode: button.dataset.mode }) });
    await refreshStatus();
  });
});
qs("#refreshOverview").addEventListener("click", refreshStatus);
qs("#scanDefault").addEventListener("click", () => runScan(""));
qs("#scanPathButton").addEventListener("click", () => runScan(qs("#scanPath").value.trim()));
qs("#refreshTraffic").addEventListener("click", refreshTraffic);
qs("#refreshBlocked").addEventListener("click", refreshBlocked);
qs("#refreshQuarantine").addEventListener("click", refreshQuarantine);
qs("#refreshStartup").addEventListener("click", refreshStartup);
qs("#checkUrl").addEventListener("click", checkUrl);
qs("#defenderToggle").addEventListener("change", (event) => updateSetting("defender_enabled", event.target.checked));
qs("#realtimeToggle").addEventListener("change", (event) => updateSetting("realtime_enabled", event.target.checked));
qs("#notificationsToggle").addEventListener("change", (event) => updateSetting("notifications_enabled", event.target.checked));
qs("#testNotification").addEventListener("click", async () => {
  try {
    await api("/api/test-notification", { method: "POST", body: JSON.stringify({}) });
  } catch (error) {
    window.alert(error.message);
  }
});
qs("#updateDefender").addEventListener("click", () => defenderAction("/api/defender-update", "Updating Defender definitions"));
qs("#quickScan").addEventListener("click", () => defenderAction("/api/defender-quick-scan", "Running Defender quick scan"));
qs("#addDomain").addEventListener("click", () => {
  const input = qs("#domainInput");
  addBlocklistItem("/api/block-domain", { domain: input.value.trim() }, input);
});
qs("#addHash").addEventListener("click", () => {
  const input = qs("#hashInput");
  addBlocklistItem("/api/block-hash", { sha256: input.value.trim() }, input);
});

refreshStatus();
setInterval(refreshStatus, 30000);
