/**
 * PHISH GUARD - Background Service Worker (Hybrid Threat Controller)
 * Manifest V3 Service Worker orchestrating tab monitoring, visual screenshot capture,
 * hybrid multi-modal backend communication, badge states, and warning interception.
 */

// Primary API Endpoint (Toggle between local development and cloud deployment)
const API_BASE_URL = "http://127.0.0.1:5000";
const CACHE_EXPIRY_MS = 5 * 60 * 1000;       // 5 minutes in-memory cache
const BYPASS_EXPIRY_MS = 60 * 60 * 1000;     // 1 hour temporary bypass window

// In-memory tab scan cache & bypass registers
const tabScanCache = new Map();
const temporaryBypasses = new Map();

/**
 * Validates whether a URL should be scanned
 */
function shouldScanUrl(url) {
  if (!url || typeof url !== "string") return false;
  const lower = url.toLowerCase();
  return (
    lower.startsWith("http://") ||
    lower.startsWith("https://")
  ) && !lower.includes("chrome://") && !lower.includes("chrome-extension://");
}

/**
 * Updates extension action badge text and background color
 */
function updateBadge(tabId, status, riskLevel) {
  let badgeText = "";
  let badgeColor = "#64748B";

  const upper = (status || "").toUpperCase();
  if (upper === "SAFE") {
    badgeText = "SAFE";
    badgeColor = "#10B981"; // Emerald
  } else if (upper === "SUSPICIOUS") {
    badgeText = "WARN";
    badgeColor = "#F59E0B"; // Amber
  } else if (upper === "PHISHING" || upper === "MALICIOUS") {
    badgeText = riskLevel === "Critical" ? "CRIT" : "DANG";
    badgeColor = "#EF4444"; // Crimson Red
  }

  try {
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  } catch (e) {
    // Tab might have been closed
  }
}

/**
 * Local heuristic scanner fallback when backend API is temporarily offline
 */
function localFallbackScan(url, html, forms) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const reasons = [];
    let isPhish = false;

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      reasons.push("Direct IP address used instead of domain name");
      isPhish = true;
    }

    if (/\.(xyz|top|tk|ml|ga|cf|gq|buzz|icu|club|cfd)$/.test(domain)) {
      reasons.push("High-risk Top-Level Domain detected");
      isPhish = true;
    }

    const brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase"];
    for (const b of brands) {
      if (domain.includes(b) && !domain.endsWith(`${b}.com`)) {
        reasons.push(`Brand spoofing indicator for '${b}'`);
        isPhish = true;
      }
    }

    const hasPassword = (forms || []).some((f) =>
      (f.inputs || []).some((i) => (i.type || "").toLowerCase() === "password")
    );
    if (hasPassword && isPhish) {
      reasons.push("Credential input form detected on unverified domain");
    }

    const decision = isPhish ? "PHISHING" : "SAFE";
    return {
      url,
      domain,
      prediction: decision,
      risk_level: isPhish ? "High" : "Low",
      confidence: isPhish ? 88.0 : 80.0,
      hybrid_score: isPhish ? 85.0 : 15.0,
      layer_scores: {
        url_score: isPhish ? 85.0 : 10.0,
        content_score: isPhish ? 60.0 : 10.0,
        form_score: hasPassword ? 50.0 : 0.0,
        javascript_score: 10.0,
        visual_score: isPhish ? 70.0 : 0.0,
        ssl_score: url.startsWith("https://") ? 0.0 : 35.0,
        reputation_score: isPhish ? 60.0 : 0.0,
        image_score: 10.0
      },
      scan_time_ms: 2.0,
      reasons,
      is_fallback: true
    };
  } catch (e) {
    return {
      url,
      prediction: "SAFE",
      risk_level: "Low",
      confidence: 50.0,
      hybrid_score: 10.0,
      layer_scores: {},
      scan_time_ms: 1.0,
      reasons: ["Local analysis completed"],
      is_fallback: true
    };
  }
}

/**
 * Sends multi-modal hybrid payload to Flask Backend
 */
async function sendHybridScanRequest(payload) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`${API_BASE_URL}/predict-hybrid`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const json = await response.json();
      return json.data;
    }
    throw new Error(`API returned HTTP ${response.status}`);
  } catch (error) {
    console.warn("[PhishGuard] Backend unreachable, falling back to local multi-layer heuristics:", error.message);
    return localFallbackScan(payload.url, payload.html, payload.forms);
  }
}

/**
 * Saves scan record to chrome.storage.local scan history
 */
async function recordToLocalHistory(scanResult) {
  try {
    const { localHistory = [] } = await chrome.storage.local.get("localHistory");
    const newEntry = {
      id: Date.now(),
      url: scanResult.url,
      domain: scanResult.domain,
      prediction: scanResult.prediction,
      confidence: scanResult.confidence,
      risk_level: scanResult.risk_level,
      hybrid_score: scanResult.hybrid_score || 0.0,
      scan_time_ms: scanResult.scan_time_ms,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    };

    const updated = [newEntry, ...localHistory.slice(0, 49)];
    await chrome.storage.local.set({ localHistory: updated });
  } catch (e) {
    console.error("[PhishGuard] Error updating local history:", e);
  }
}

/**
 * Executes hybrid scan combining Content Script data + Visual Screenshot
 */
async function executeHybridScan(tabId, windowId, pageData) {
  const url = pageData.url;
  if (!shouldScanUrl(url)) return;

  // Set scanning badge indicator
  chrome.action.setBadgeText({ tabId, text: "SCAN" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#3B82F6" });

  // 1. Capture Visible Tab Screenshot
  let screenshotBase64 = null;
  try {
    screenshotBase64 = await new Promise((resolve) => {
      chrome.tabs.captureVisibleTab(windowId, { format: "jpeg", quality: 60 }, (dataUrl) => {
        if (chrome.runtime.lastError || !dataUrl) {
          resolve(null);
        } else {
          resolve(dataUrl);
        }
      });
    });
  } catch (err) {
    screenshotBase64 = null;
  }

  // 2. Assemble Unified Multi-Modal Payload
  const hybridPayload = {
    url: pageData.url,
    html: pageData.html || "",
    forms: pageData.forms || [],
    scripts: pageData.scripts || [],
    images: pageData.images || [],
    screenshot: screenshotBase64,
    dom_metrics: pageData.dom_metrics || {},
    favicon_url: pageData.favicon_url || ""
  };

  // 3. Post to AI Backend
  const result = await sendHybridScanRequest(hybridPayload);
  tabScanCache.set(url, { timestamp: Date.now(), data: result });

  // 4. Update Badge
  updateBadge(tabId, result.prediction, result.risk_level);
  await recordToLocalHistory(result);

  // 5. Enforce Warning Redirection for Phishing Threats
  if (result.prediction === "PHISHING" || (result.prediction === "SUSPICIOUS" && result.risk_level === "Critical")) {
    const bypassTimestamp = temporaryBypasses.get(url);
    const isBypassed = bypassTimestamp && (Date.now() - bypassTimestamp < BYPASS_EXPIRY_MS);

    if (!isBypassed) {
      const warningUrl = chrome.runtime.getURL(
        `warning.html?targetUrl=${encodeURIComponent(url)}` +
        `&prediction=${encodeURIComponent(result.prediction)}` +
        `&risk=${encodeURIComponent(result.risk_level)}` +
        `&confidence=${encodeURIComponent(result.confidence)}` +
        `&hybrid_score=${encodeURIComponent(result.hybrid_score || 85.0)}` +
        `&matched_brand=${encodeURIComponent(result.matched_brand || "")}` +
        `&reasons=${encodeURIComponent(JSON.stringify(result.reasons || []))}`
      );
      chrome.tabs.update(tabId, { url: warningUrl });
    }
  }

  return result;
}

// ==========================================
// Event Listeners
// ==========================================

// Content Script sends extracted DOM/HTML data
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "PAGE_CONTENT_EXTRACTED") {
    if (sender.tab && sender.tab.id) {
      executeHybridScan(sender.tab.id, sender.tab.windowId, request.payload);
    }
  } else if (request.action === "GET_CURRENT_STATUS") {
    const cached = tabScanCache.get(request.url);
    if (cached) {
      sendResponse({ status: "success", data: cached.data });
    } else {
      // Query content script for fresh extraction
      if (sender.tab && sender.tab.id) {
        chrome.tabs.sendMessage(sender.tab.id, { action: "REQUEST_PAGE_CONTENT" }, (res) => {
          if (res && res.payload) {
            executeHybridScan(sender.tab.id, sender.tab.windowId, res.payload).then((result) => {
              sendResponse({ status: "success", data: result });
            });
          }
        });
        return true;
      }
    }
  } else if (request.action === "RESCAN_URL") {
    tabScanCache.delete(request.url);
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.id) {
        chrome.tabs.sendMessage(activeTab.id, { action: "REQUEST_PAGE_CONTENT" }, (res) => {
          if (res && res.payload) {
            executeHybridScan(activeTab.id, activeTab.windowId, res.payload).then((result) => {
              sendResponse({ status: "success", data: result });
            });
          }
        });
      }
    });
    return true;
  } else if (request.action === "ADD_BYPASS") {
    temporaryBypasses.set(request.url, Date.now());
    sendResponse({ status: "success" });
  } else if (request.action === "SUBMIT_REPORT") {
    fetch(`${API_BASE_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request.payload)
    })
      .then((res) => res.json())
      .then((data) => sendResponse(data))
      .catch((err) => sendResponse({ status: "error", message: err.message }));
    return true;
  }
});

// Update badge when user switches active tab
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && shouldScanUrl(tab.url)) {
      const cached = tabScanCache.get(tab.url);
      if (cached) {
        updateBadge(activeInfo.tabId, cached.data.prediction, cached.data.risk_level);
      }
    } else {
      chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
    }
  } catch (e) {
    // Ignore closed tabs
  }
});
