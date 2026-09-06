/* global chrome */

// State variables
window.currentTabUrl = "";
window.currentTabDomain = "";
window.currentTabId = null;

// SVG Icon Definitions
const svgCheck = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="status-symbol"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
const svgWarning = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="status-symbol"><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
const svgInfo = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="status-symbol"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
const svgStar = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>`;
const svgClose = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
const svgTrash = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="trash-icon"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>`;

// Helper: Escape HTML to prevent XSS
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Helper: Safely extract domain/hostname
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

// Helper: Normalize user domain input (strips protocol, port, path, www.)
function normalizeDomain(input) {
  if (!input || typeof input !== "string") return "";
  let str = input.trim().toLowerCase();
  if (!/^https?:\/\//i.test(str)) {
    str = "https://" + str;
  }
  try {
    const urlObj = new URL(str);
    let hostname = urlObj.hostname.toLowerCase();
    if (hostname.startsWith("www.")) {
      hostname = hostname.substring(4);
    }
    return hostname;
  } catch (e) {
    return input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split(":")[0];
  }
}

// Set Header Protection Status Badge (Active / Paused)
function updateHeaderProtectionBadge(enabled) {
  const badge = document.getElementById("protectionStatusBadge");
  const text = badge.querySelector(".status-text");
  
  badge.className = "protection-status-badge";
  if (enabled) {
    badge.classList.add("active");
    text.textContent = "Zaštita aktivna";
  } else {
    badge.classList.add("paused");
    text.textContent = "Zaštita pauzirana";
  }
}

// Display Checking Spinner
function displayCheckingState(domain) {
  const shieldCard = document.getElementById("shieldCard");
  const shieldOverlay = document.getElementById("shieldOverlay");
  const verdictText = document.getElementById("statusVerdict");
  const domainText = document.getElementById("statusDomain");
  const descText = document.getElementById("statusDescription");
  const actionRow = document.getElementById("safetyActionRow");

  shieldCard.className = "shield-card status-checking";
  shieldOverlay.innerHTML = `<div class="spinner"></div>`;
  verdictText.textContent = "Provjera domene...";
  domainText.textContent = domain;
  descText.textContent = "Traženje adrese putem servisa CERT Iffy...";
  actionRow.style.display = "none";
}

// Display Internal Page State (browser internal URLs like chrome://, about:blank)
function displayInternalPageState(url) {
  const shieldCard = document.getElementById("shieldCard");
  const shieldOverlay = document.getElementById("shieldOverlay");
  const verdictText = document.getElementById("statusVerdict");
  const domainText = document.getElementById("statusDomain");
  const descText = document.getElementById("statusDescription");
  const actionRow = document.getElementById("safetyActionRow");

  shieldCard.className = "shield-card status-paused";
  shieldOverlay.innerHTML = svgInfo;
  verdictText.textContent = "Interna stranica";
  domainText.textContent = getDomain(url) || "Lokalno";
  descText.textContent = "Ovo je interna adresa preglednika (provjera sigurnosti internetskih trgovina nije potrebna).";
  actionRow.style.display = "none";
}

// Render Safety Verdict in Dashboard
function displaySafetyStatus(result) {
  const shieldCard = document.getElementById("shieldCard");
  const shieldOverlay = document.getElementById("shieldOverlay");
  const verdictText = document.getElementById("statusVerdict");
  const domainText = document.getElementById("statusDomain");
  const descText = document.getElementById("statusDescription");
  const actionRow = document.getElementById("safetyActionRow");
  const btnWhitelist = document.getElementById("btnWhitelistCurrent");

  domainText.textContent = result.domain;
  
  // Clear layout classes
  shieldCard.className = "shield-card";
  shieldOverlay.innerHTML = "";
  
  if (result.verdict === "safe") {
    shieldCard.classList.add("status-safe");
    shieldOverlay.innerHTML = svgCheck;
    verdictText.textContent = "Stranica je sigurna";
    descText.textContent = result.message || "Ova domena nije pronađena kao zlonamjerna adresa na servisu CERT Iffy.";
    actionRow.style.display = "flex";
    btnWhitelist.innerHTML = `${svgStar} <span>Vjeruj ovoj domeni</span>`;
    btnWhitelist.dataset.action = "add";
  } else if (result.verdict === "whitelisted") {
    shieldCard.classList.add("status-whitelisted");
    shieldOverlay.innerHTML = svgStar;
    verdictText.textContent = "Dopuštena domena";
    descText.textContent = "Označili ste ovu domenu kao pouzdanu. Automatske provjere su preskočene.";
    actionRow.style.display = "flex";
    btnWhitelist.innerHTML = `${svgClose} <span>Ukloni iz dopuštenih</span>`;
    btnWhitelist.dataset.action = "remove";
  } else if (result.verdict === "warning") {
    shieldCard.classList.add("status-warning");
    shieldOverlay.innerHTML = svgWarning;
    verdictText.textContent = "Upozorenje!";
    descText.textContent = result.message || "Pronađena sumnjiva domena na servisu CERT Iffy.";
    actionRow.style.display = "flex";
    btnWhitelist.innerHTML = `${svgStar} <span>Vjeruj ovoj domeni</span>`;
    btnWhitelist.dataset.action = "add";
  } else if (result.verdict === "paused") {
    shieldCard.classList.add("status-paused");
    shieldOverlay.innerHTML = svgInfo;
    verdictText.textContent = "Zaštita je pauzirana";
    descText.textContent = "Uključite automatsku zaštitu u postavkama kako biste omogućili skeniranje.";
    actionRow.style.display = "none";
  } else {
    shieldCard.classList.add("status-error");
    shieldOverlay.innerHTML = svgInfo;
    verdictText.textContent = "Pogreška pri provjeri";
    descText.textContent = result.message || "Nije moguće uspostaviti vezu s CERT Iffy poslužiteljem.";
    actionRow.style.display = "none";
  }
}

// Recheck current active page
function reCheckCurrentTab() {
  if (!window.currentTabUrl || !/^https?:/i.test(window.currentTabUrl)) return;
  displayCheckingState(window.currentTabDomain);
  chrome.runtime.sendMessage(
    { type: "CHECK_URL", url: window.currentTabUrl, forceCheck: true, tabId: window.currentTabId },
    (result) => {
      if (chrome.runtime.lastError || !result) {
        displaySafetyStatus({
          verdict: "error",
          domain: window.currentTabDomain,
          message: "Usluga provjere nije dostupna."
        });
      } else {
        displaySafetyStatus(result);
      }
    }
  );
}

// Render Check History Tab
function renderHistory() {
  chrome.storage.local.get("history", (res) => {
    const list = document.getElementById("historyList");
    const emptyState = document.getElementById("historyEmptyState");
    const history = res.history || [];
    
    list.innerHTML = "";
    if (history.length === 0) {
      emptyState.style.display = "flex";
      return;
    }
    emptyState.style.display = "none";

    history.forEach((item, index) => {
      const li = document.createElement("li");
      li.className = "history-item";
      
      let badgeClass = "hist-badge-gray";
      let iconSymbol = "?";
      
      if (item.verdict === "safe") {
        badgeClass = "hist-badge-green";
        iconSymbol = "✓";
      } else if (item.verdict === "warning") {
        badgeClass = "hist-badge-red";
        iconSymbol = "⚠";
      } else if (item.verdict === "whitelisted") {
        badgeClass = "hist-badge-blue";
        iconSymbol = "★";
      }

      const timeStr = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const safeDomain = escapeHtml(item.domain);
      const safeUrl = escapeHtml(item.url || item.domain);
      const safeTime = escapeHtml(timeStr);
      
      li.innerHTML = `
        <div class="hist-indicator ${badgeClass}">${iconSymbol}</div>
        <div class="hist-content">
          <div class="hist-domain" title="${safeUrl}">${safeDomain}</div>
          <div class="hist-time">${safeTime}</div>
        </div>
        <button class="btn-delete-history" data-index="${index}" title="Ukloni iz povijesti" aria-label="Ukloni ${safeDomain} iz povijesti">
          ${svgTrash}
        </button>
      `;
      list.appendChild(li);
    });

    // Delete single history item
    list.querySelectorAll(".btn-delete-history").forEach(btn => {
      btn.addEventListener("click", function(e) {
        e.stopPropagation();
        const idx = parseInt(this.dataset.index, 10);
        chrome.storage.local.get("history", (data) => {
          const listHist = data.history || [];
          listHist.splice(idx, 1);
          chrome.storage.local.set({ history: listHist }, () => {
            renderHistory();
          });
        });
      });
    });
  });
}

// Render Settings & Stats Tab
function renderSettingsAndStats() {
  chrome.storage.local.get(["protectionEnabled", "whitelist", "stats"], (res) => {
    // 1. Protection Toggle switch
    const toggle = document.getElementById("toggleProtection");
    const enabled = res.protectionEnabled !== false;
    toggle.checked = enabled;
    updateHeaderProtectionBadge(enabled);

    // 2. Statistics Values
    const stats = res.stats || { scanned: 0, safe: 0, warnings: 0 };
    document.getElementById("statScanned").textContent = stats.scanned || 0;
    document.getElementById("statSafe").textContent = stats.safe || 0;
    document.getElementById("statWarnings").textContent = stats.warnings || 0;

    // 3. Whitelist Manager List
    const whitelist = res.whitelist || [];
    const list = document.getElementById("whitelistList");
    const emptyState = document.getElementById("whitelistEmptyState");

    list.innerHTML = "";
    if (whitelist.length === 0) {
      emptyState.style.display = "block";
      return;
    }
    emptyState.style.display = "none";

    whitelist.forEach((domain) => {
      const safeDomain = escapeHtml(domain);
      const li = document.createElement("li");
      li.className = "whitelist-item";
      li.innerHTML = `
        <span class="whitelist-domain">${safeDomain}</span>
        <button class="btn-remove-whitelist" data-domain="${safeDomain}" title="Ukloni s popisa" aria-label="Ukloni ${safeDomain} s popisa">
          ${svgClose}
        </button>
      `;
      list.appendChild(li);
    });

    // Remove from Whitelist handler
    list.querySelectorAll(".btn-remove-whitelist").forEach(btn => {
      btn.addEventListener("click", function(e) {
        e.stopPropagation();
        const domain = this.dataset.domain;
        chrome.storage.local.get("whitelist", (data) => {
          let wl = data.whitelist || [];
          wl = wl.filter(d => d !== domain);
          chrome.storage.local.set({ whitelist: wl }, () => {
            renderSettingsAndStats();
            if (window.currentTabDomain === domain || normalizeDomain(window.currentTabDomain) === normalizeDomain(domain)) {
              reCheckCurrentTab();
            }
          });
        });
      });
    });
  });
}

// Add Domain to Whitelist helper
function addToWhitelist(domain) {
  if (!domain) return;
  const cleanDomain = normalizeDomain(domain);
  if (!cleanDomain) return;
  chrome.storage.local.get("whitelist", (res) => {
    const whitelist = res.whitelist || [];
    if (!whitelist.includes(cleanDomain)) {
      whitelist.push(cleanDomain);
      chrome.storage.local.set({ whitelist }, () => {
        renderSettingsAndStats();
        if (normalizeDomain(window.currentTabDomain) === cleanDomain) {
          reCheckCurrentTab();
        }
      });
    }
  });
}

// Remove Domain from Whitelist helper
function removeFromWhitelist(domain) {
  if (!domain) return;
  const cleanDomain = normalizeDomain(domain);
  chrome.storage.local.get("whitelist", (res) => {
    let whitelist = res.whitelist || [];
    whitelist = whitelist.filter(d => normalizeDomain(d) !== cleanDomain);
    chrome.storage.local.set({ whitelist }, () => {
      renderSettingsAndStats();
      if (normalizeDomain(window.currentTabDomain) === cleanDomain) {
        reCheckCurrentTab();
      }
    });
  });
}

// --- EVENT LISTENERS ---

// 1. Tab switching navigation
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", function() {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

    this.classList.add("active");
    const targetTabId = this.dataset.tab;
    document.getElementById(targetTabId).classList.add("active");

    if (targetTabId === "tab-history") {
      renderHistory();
    } else if (targetTabId === "tab-settings") {
      renderSettingsAndStats();
    }
  });
});

// 2. Main tab whitelist action button
document.getElementById("btnWhitelistCurrent").addEventListener("click", function() {
  if (!window.currentTabDomain) return;
  const action = this.dataset.action;
  if (action === "add") {
    addToWhitelist(window.currentTabDomain);
  } else {
    removeFromWhitelist(window.currentTabDomain);
  }
});

// 3. Clear History button
document.getElementById("btnClearHistory").addEventListener("click", () => {
  if (confirm("Poništiti svu povijest provjera?")) {
    chrome.storage.local.set({ history: [] }, () => {
      renderHistory();
    });
  }
});

// 4. Protection Switch toggle listener
document.getElementById("toggleProtection").addEventListener("change", function() {
  const active = this.checked;
  chrome.storage.local.set({ protectionEnabled: active }, () => {
    updateHeaderProtectionBadge(active);
    reCheckCurrentTab();
  });
});

// 5. Manual Check Form submit
document.getElementById("manualCheckForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const input = document.getElementById("manualCheckInput");
  const value = input.value.trim();
  if (!value) return;

  let url = value;
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  const testDomain = getDomain(url);
  if (!testDomain || testDomain.length < 3) return;

  window.currentTabUrl = url;
  window.currentTabDomain = testDomain;

  displayCheckingState(testDomain);
  
  chrome.runtime.sendMessage(
    { type: "CHECK_URL", url: url, forceCheck: true, tabId: window.currentTabId },
    (result) => {
      if (chrome.runtime.lastError || !result) {
        displaySafetyStatus({
          verdict: "error",
          domain: testDomain,
          message: "Pogreška pri ručnoj provjeri."
        });
      } else {
        displaySafetyStatus(result);
        input.value = "";
      }
    }
  );
});

// 6. Whitelist Manager Form submit
document.getElementById("whitelistAddForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const input = document.getElementById("whitelistAddInput");
  const value = input.value.trim();
  if (!value) return;

  const domain = normalizeDomain(value);
  if (domain) {
    addToWhitelist(domain);
    input.value = "";
  }
});

// 7. Open About & Privacy page
document.getElementById("rowAbout").addEventListener("click", () => {
  if (chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  } else {
    window.open(chrome.runtime.getURL("popup/about.html"));
  }
});

// --- POPUP INITIALIZATION ---
document.addEventListener("DOMContentLoaded", () => {
  // Query active tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];
    if (!activeTab || !activeTab.url) {
      displaySafetyStatus({
        verdict: "error",
        domain: "Nepoznato",
        message: "Nije moguće pročitati URL trenutne kartice."
      });
      return;
    }

    window.currentTabId = activeTab.id;

    // Check if it's an internal or non-web page (chrome://, about:blank, etc.)
    if (!/^https?:/i.test(activeTab.url)) {
      window.currentTabUrl = activeTab.url;
      window.currentTabDomain = "Interna stranica";
      displayInternalPageState(activeTab.url);
      return;
    }

    window.currentTabUrl = activeTab.url;
    window.currentTabDomain = getDomain(activeTab.url);

    // Initial check (checks settings internally)
    displayCheckingState(window.currentTabDomain);
    
    chrome.runtime.sendMessage(
      { type: "CHECK_URL", url: activeTab.url, forceCheck: false, tabId: window.currentTabId },
      (result) => {
        if (chrome.runtime.lastError || !result) {
          displaySafetyStatus({
            verdict: "error",
            domain: window.currentTabDomain,
            message: "Usluga provjere na servisu CERT Iffy nije dostupna."
          });
        } else {
          displaySafetyStatus(result);
        }
      }
    );
  });

  // Sync settings and badge
  renderSettingsAndStats();
});