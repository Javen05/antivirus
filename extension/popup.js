const risk = document.querySelector("#risk");
const host = document.querySelector("#host");
const findings = document.querySelector("#findings");

chrome.storage.local.get("lastResult", ({ lastResult }) => {
  if (!lastResult) {
    risk.textContent = "No page checked yet";
    host.textContent = "Browse to a website while the ClearGuard agent is running.";
    return;
  }
  risk.textContent = `${lastResult.risk.toUpperCase()} risk`;
  host.textContent = lastResult.host || lastResult.url || "Unknown destination";
  findings.replaceChildren();
  (lastResult.findings || []).forEach((finding) => {
    const li = document.createElement("li");
    li.textContent = finding;
    findings.append(li);
  });
});
