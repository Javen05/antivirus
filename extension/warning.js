const params = new URLSearchParams(location.search);
const originalUrl = params.get("url") || "";
const risk = params.get("risk") || "high";
const host = params.get("host") || originalUrl;
const why = params.get("why") || "ClearGuard found high-risk indicators for this page.";

document.querySelector("#title").textContent = `${risk.toUpperCase()} website warning`;
document.querySelector("#host").textContent = host;
document.querySelector("#why").textContent = why;
const continueLink = document.querySelector("#continueLink");
continueLink.href = originalUrl;
continueLink.addEventListener("click", async (event) => {
  event.preventDefault();
  await chrome.runtime.sendMessage({ type: "allowOnce", url: originalUrl });
  location.href = originalUrl;
});
