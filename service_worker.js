/**
 * Iffy‑Checker background service worker (Enhanced V3)
 * Handles automatic domain analysis, whitelisting, history logging, and stats.
 */

const IFFY_ROOT = "https://iffy.cert.hr";
const IFFY_VALIDATE = `${IFFY_ROOT}/validate`;

// In-memory cache for API responses (TTL 10 minutes)
const CACHE_TTL_MS = 10 * 60 * 1000;
const domainCache = new Map(); // domain -> { verdict, message, status_code, timestamp }

function getCachedResult(domain) {
  const cached = domainCache.get(domain);
  if (!cached) return null;
  if (Date.now() - cached.timestamp > CACHE_TTL_MS) {
    domainCache.delete(domain);
    return null;
  }
  return cached;
}

function setCachedResult(domain, result) {
  domainCache.set(domain, {
    verdict: result.verdict,
    message: result.message,
    status_code: result.status_code,
    timestamp: Date.now()
  });
  if (domainCache.size > 500) {
    const firstKey = domainCache.keys().next().value;
    domainCache.delete(firstKey);
  }
}

// Helper: Safely extract domain hostname
function getDomain(url) {
  if (!url || typeof url !== "string") return "";
  try {
    let toParse = url.trim();
    if (!/^https?:\/\//i.test(toParse)) {
      toParse = "https://" + toParse;
    }
    const urlObj = new URL(toParse);
    return urlObj.hostname.toLowerCase();
  } catch (e) {
    return url.trim().toLowerCase().split("/")[0].split(":")[0];
  }
}

// Helper: Normalize domain for whitelist comparison (strips www.)
function normalizeForWhitelist(domain) {
  if (!domain) return "";
  return domain.trim().toLowerCase().replace(/^www\./, "");
}

// Helper: Check if domain matches any item in the whitelist
function isWhitelisted(domain, whitelist) {
  if (!domain || !whitelist || !Array.isArray(whitelist)) return false;
  const cleanDomain = normalizeForWhitelist(domain);
  return whitelist.some(item => {
    const cleanItem = normalizeForWhitelist(item);
    return cleanDomain === cleanItem || cleanDomain.endsWith("." + cleanItem);
  });
}

// Helper: Safe Badge Operations to prevent unhandled runtime exceptions
function safeSetBadgeText(tabId, text) {
  if (!tabId) return;
  chrome.action.setBadgeText({ tabId, text }).catch(() => {
    // Tab might have been closed before async operation completed
  });
}

function safeSetBadgeBackgroundColor(tabId, color) {
  if (!tabId) return;
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {
    // Tab might have been closed before async operation completed
  });
}

function safeSetTitle(tabId, title) {
  if (!tabId) return;
  chrome.action.setTitle({ tabId, title }).catch(() => {
    // Tab might have been closed before async operation completed
  });
}

// Update Badge UI & Tooltip based on verdict
function updateUI(tabId, verdict, description) {
  if (!tabId) return;
  if (verdict === "paused") {
    safeSetBadgeText(tabId, "");
    safeSetTitle(tabId, "CERT Iffy: Zaštita je pauzirana");
    return;
  }

  if (verdict === "whitelisted") {
    safeSetBadgeText(tabId, "WHT");
    safeSetBadgeBackgroundColor(tabId, "#1a73e8"); // Blue
    safeSetTitle(tabId, `CERT Iffy: Dopuštena domena (${description || "Popis dopuštenih"})`);
  } else if (verdict === "safe") {
    safeSetBadgeText(tabId, "OK");
    safeSetBadgeBackgroundColor(tabId, "#0f9d58"); // Green
    safeSetTitle(tabId, `CERT Iffy: Stranica je sigurna (${description || "Nije na popisu lažnih trgovina"})`);
  } else if (verdict === "warning") {
    safeSetBadgeText(tabId, "WRN");
    safeSetBadgeBackgroundColor(tabId, "#d93025"); // Red
    safeSetTitle(tabId, `CERT Iffy UPOZORENJE: ${description || "Moguća lažna trgovina!"}`);
  } else {
    safeSetBadgeText(tabId, "ERR");
    safeSetBadgeBackgroundColor(tabId, "#808080"); // Gray
    safeSetTitle(tabId, `CERT Iffy: Pogreška pri provjeri (${description || "Nepoznata greška"})`);
  }
}

// Session state management for CERT Iffy
let hasSession = false;

async function ensureSession() {
  if (!hasSession) {
    try {
      await fetch(IFFY_ROOT, { credentials: "include" });
      hasSession = true;
    } catch (e) {
      // Ignore initial landing fetch failure; validate request will still attempt
    }
  }
}

// Core API scan: sends sanitized domain only to respect user privacy
async function fetchIffyApi(domain) {
  await ensureSession();

  let res;
  try {
    res = await fetch(IFFY_VALIDATE, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ match: domain })
    });
  } catch (networkErr) {
    hasSession = false;
    throw new Error(`Mrežna pogreška pri povezivanju sa servisom CERT Iffy: ${networkErr.message}`);
  }

  // Handle session expiration or invalid session
  if (!res.ok) {
    hasSession = false;
    await ensureSession();
    res = await fetch(IFFY_VALIDATE, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ match: domain })
    });
  }

  if (!res.ok) {
    throw new Error(`API returned status ${res.status}`);
  }

  const data = await res.json();

  // Retry once if server reports request was not received (session expired)
  if (data.message && data.message.includes("Poslužitelj nije zaprimio zahtjev")) {
    hasSession = false;
    await ensureSession();
    const retryRes = await fetch(IFFY_VALIDATE, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ match: domain })
    });
    if (retryRes.ok) {
      return await retryRes.json();
    }
  }

  return data;
}

// Full check logic wrapping API, Whitelist, Cache, History, Stats and Settings
async function checkUrlFull(url, forceCheck = false) {
  const domain = getDomain(url);
  if (!domain || (!url.startsWith("http:") && !url.startsWith("https:"))) {
    return {
      status_code: 400,
      message: "Interna stranica ili nepodržani protokol (provjera nije potrebna).",
      verdict: "error",
      domain: domain || "unknown",
      url: domain
    };
  }

  // Fetch extension state from storage
  const storage = await chrome.storage.local.get(["protectionEnabled", "whitelist"]);
  const protectionEnabled = storage.protectionEnabled !== false;
  const whitelist = storage.whitelist || [];

  // Check if whitelisted by user
  if (isWhitelisted(domain, whitelist)) {
    return {
      status_code: 200,
      message: "Siguran — domena je na popisu dopuštenih.",
      verdict: "whitelisted",
      domain,
      url: domain
    };
  }

  // If protection is paused and not a forced manual check, return paused
  if (!protectionEnabled && !forceCheck) {
    return {
      status_code: 200,
      message: "Automatska zaštita je pauzirana.",
      verdict: "paused",
      domain,
      url: domain
    };
  }

  // Check memory cache unless forced check requested
  if (!forceCheck) {
    const cached = getCachedResult(domain);
    if (cached) {
      return {
        status_code: cached.status_code,
        message: cached.message,
        verdict: cached.verdict,
        domain,
        url: domain
      };
    }
  }

  let verdict = "error";
  let message = "";
  let statusCode = 200;

  try {
    const data = await fetchIffyApi(domain);
    message = data.message || "";

    // Check for server validation errors
    if (message.includes("Unesena vrijednost nije URL") || message.includes("Poslužitelj nije zaprimio zahtjev")) {
      verdict = "error";
      statusCode = 400;
    } else if (data.exist === true) {
      // Domain identified in CERT-HR fraudulent store database
      verdict = "warning";
      statusCode = 200;
    } else if (data.exist === false) {
      // Domain not found in fake store database
      verdict = "safe";
      statusCode = 200;
    } else {
      // Fallback text check
      const msg = message.toLowerCase();
      if (msg.includes("nije prepoznao") || msg.includes("nije u bazi")) {
        verdict = "safe";
      } else {
        verdict = "warning";
      }
    }
  } catch (err) {
    statusCode = 500;
    message = err.message || "Pogreška pri povezivanju sa servisom CERT Iffy.";
    verdict = "error";
  }

  const result = {
    status_code: statusCode,
    message,
    verdict,
    domain,
    url: domain
  };

  // Cache safe and warning responses
  if (verdict === "safe" || verdict === "warning") {
    setCachedResult(domain, result);
  }

  // Update History & Stats (re-fetch live storage right before write to avoid race conditions)
  if (verdict === "safe" || verdict === "warning") {
    try {
      const liveData = await chrome.storage.local.get(["history", "stats"]);
      const history = liveData.history || [];
      const stats = liveData.stats || { scanned: 0, safe: 0, warnings: 0 };
      const now = Date.now();
      const lastItem = history[0];
      const isDuplicate = lastItem && lastItem.domain === domain && (now - lastItem.timestamp < 10000);

      if (!isDuplicate) {
        history.unshift({
          url: domain,
          domain,
          status_code: statusCode,
          message,
          verdict,
          timestamp: now
        });

        if (history.length > 100) {
          history.pop();
        }

        stats.scanned = (stats.scanned || 0) + 1;
        if (verdict === "safe") {
          stats.safe = (stats.safe || 0) + 1;
        } else if (verdict === "warning") {
          stats.warnings = (stats.warnings || 0) + 1;
        }

        await chrome.storage.local.set({ history, stats });
      }
    } catch (e) {
      // Non-critical storage error
    }
  }

  return result;
}

// Context Menu Setup and Storage Initialization
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "iffy-check",
      title: "Provjeri stranicu s Iffy",
      contexts: ["page", "link"]
    });
  });

  const storage = await chrome.storage.local.get(["protectionEnabled", "whitelist", "history", "stats"]);
  const updates = {};
  if (storage.protectionEnabled === undefined) updates.protectionEnabled = true;
  if (storage.whitelist === undefined) updates.whitelist = [];
  if (storage.history === undefined) updates.history = [];
  if (storage.stats === undefined) updates.stats = { scanned: 0, safe: 0, warnings: 0 };

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }
});

// Context-menu trigger
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "iffy-check" || info.menuItemId === "iffy‑check") {
    const urlToTest = info.linkUrl || info.pageUrl;
    if (!urlToTest) return;

    checkUrlFull(urlToTest, true).then((result) => {
      if (tab && tab.id) {
        updateUI(tab.id, result.verdict, result.message);
        chrome.tabs.sendMessage(tab.id, { type: "IFFY_RESULT", url: urlToTest, result }).catch(() => {});
      }
    });
  }
});

// Listener for manual triggers from the popup UI
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_URL") {
    checkUrlFull(msg.url, msg.forceCheck).then((result) => {
      if (msg.tabId) {
        updateUI(msg.tabId, result.verdict, result.message);
      }
      sendResponse(result);
    });
    return true; // Keep port open for async sendResponse
  }
});

// Automatically check on tab page navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    if (tab.url && /^https?:/i.test(tab.url)) {
      chrome.storage.local.get("protectionEnabled").then((res) => {
        const active = res.protectionEnabled !== false;
        if (!active) {
          updateUI(tabId, "paused");
          return;
        }
        checkUrlFull(tab.url, false).then((result) => {
          updateUI(tabId, result.verdict, result.message);
        });
      });
    } else if (tab.url && !/^https?:/i.test(tab.url)) {
      // Clear badge on internal pages (chrome://, file://, etc.)
      safeSetBadgeText(tabId, "");
      safeSetTitle(tabId, "CERT Iffy: Interna stranica preglednika");
    }
  }
});