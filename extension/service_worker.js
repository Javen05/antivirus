const AGENT_URL = "http://127.0.0.1:5288/api/browser-check";
const riskyRanks = { low: 1, medium: 2, high: 3, critical: 4 };
const allowOnce = new Set();

async function checkUrl(tabId, url) {
  if (!url || !/^https?:\/\//i.test(url)) {
    return;
  }
  if (allowOnce.has(url)) {
    allowOnce.delete(url);
    return;
  }
  try {
    const response = await fetch(AGENT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const result = await response.json();
    await chrome.storage.local.set({ lastResult: { ...result, checkedAt: new Date().toISOString() } });

    const rank = riskyRanks[result.risk] || 1;
    const badgeText = rank >= 4 ? "!" : rank >= 3 ? "WARN" : rank >= 2 ? "?" : "";
    const badgeColor = rank >= 4 ? "#b83a3a" : rank >= 3 ? "#c47a13" : "#356f9f";
    await chrome.action.setBadgeText({ tabId, text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });

    if (rank >= 3) {
      await chrome.notifications.create(`clearguard-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `ClearGuard ${result.risk.toUpperCase()} website warning`,
        message: `${result.host}: ${result.findings.join(" ")}`
      });
      const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&risk=${encodeURIComponent(result.risk)}&host=${encodeURIComponent(result.host || "")}&why=${encodeURIComponent(result.findings.join(" "))}`);
      await chrome.tabs.update(tabId, { url: warningUrl });
    }
  } catch (error) {
    await chrome.storage.local.set({
      lastResult: {
        risk: "medium",
        host: "ClearGuard agent offline",
        findings: ["Start the ClearGuard local agent to enable website checks."],
        checkedAt: new Date().toISOString()
      }
    });
    await chrome.action.setBadgeText({ tabId, text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#61706a" });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    checkUrl(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  checkUrl(tabId, tab.url);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "allowOnce" && message.url) {
    allowOnce.add(message.url);
    sendResponse({ ok: true });
  }
});
