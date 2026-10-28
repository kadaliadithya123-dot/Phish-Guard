/**
 * PHISH GUARD - Hybrid AI Popup Controller Script
 * Manages UI interactions, multi-layer risk inspection, brand alerts,
 * vector visualization, local history, and threat intelligence reporting.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // Header Elements
  const themeToggleBtn = document.getElementById("themeToggleBtn");
  const rescanBtn = document.getElementById("rescanBtn");
  const rescanIcon = document.getElementById("rescanIcon");
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  // Overview Tab Elements
  const targetUrlText = document.getElementById("targetUrlText");
  const protocolBadge = document.getElementById("protocolBadge");
  const brandAlertBanner = document.getElementById("brandAlertBanner");
  const brandAlertText = document.getElementById("brandAlertText");
  const statusCard = document.getElementById("statusCard");
  const statusGlyph = document.getElementById("statusGlyph");
  const statusLabel = document.getElementById("statusLabel");
  const riskBadge = document.getElementById("riskBadge");
  const hybridScoreVal = document.getElementById("hybridScoreVal");
  const confidenceVal = document.getElementById("confidenceVal");
  const latencyVal = document.getElementById("latencyVal");
  const formsCountVal = document.getElementById("formsCountVal");
  const reasonsList = document.getElementById("reasonsList");

  // Layers & Vectors Tabs
  const layerBarsContainer = document.getElementById("layerBarsContainer");
  const featureCountTag = document.getElementById("featureCountTag");
  const featuresListContainer = document.getElementById("featuresListContainer");

  // History & Report Tabs
  const historyList = document.getElementById("historyList");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");
  const reportForm = document.getElementById("reportForm");
  const reportFeedback = document.getElementById("reportFeedback");

  let currentTabUrl = "";
  let currentScanResult = null;

  // ==========================================
  // 1. Theme Management (Dark / Light)
  // ==========================================
  const { isLightTheme = false } = await chrome.storage.local.get("isLightTheme");
  if (isLightTheme) {
    document.body.classList.remove("dark-theme");
  } else {
    document.body.classList.add("dark-theme");
  }

  themeToggleBtn.addEventListener("click", async () => {
    const isDark = document.body.classList.toggle("dark-theme");
    await chrome.storage.local.set({ isLightTheme: !isDark });
  });

  // ==========================================
  // 2. Tab Navigation
  // ==========================================
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const pane = document.getElementById(targetId);
      if (pane) pane.classList.add("active");

      if (targetId === "historyTab") {
        renderLocalHistory();
      }
    });
  });

  // ==========================================
  // 3. Scan & Hybrid Status Rendering
  // ==========================================
  async function loadActiveTabAndScan() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) {
        targetUrlText.textContent = "No active web page detected";
        return;
      }

      currentTabUrl = tab.url;
      targetUrlText.textContent = tab.url;
      targetUrlText.title = tab.url;

      // Protocol badge
      if (tab.url.startsWith("https://")) {
        protocolBadge.textContent = "HTTPS";
        protocolBadge.style.color = "#10B981";
      } else if (tab.url.startsWith("http://")) {
        protocolBadge.textContent = "HTTP";
        protocolBadge.style.color = "#EF4444";
      } else {
        protocolBadge.textContent = "LOCAL";
        protocolBadge.style.color = "#64748B";
      }

      // Check if internal browser page
      if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("about:")) {
        renderInternalPage(tab.url);
        return;
      }

      // Query latest scan status from background service worker
      chrome.runtime.sendMessage(
        { action: "GET_CURRENT_STATUS", url: tab.url },
        (response) => {
          if (chrome.runtime.lastError) {
            console.warn("Background communication error:", chrome.runtime.lastError);
            targetUrlText.textContent = "Extension background syncing...";
            return;
          }

          if (response && response.data) {
            currentScanResult = response.data;
            renderScanData(response.data);
          } else {
            targetUrlText.textContent = "Analyzing URL, DOM, scripts & visual layout...";
          }
        }
      );
    } catch (e) {
      console.error("Error loading active tab:", e);
    }
  }

  function renderInternalPage(url) {
    statusCard.className = "status-card safe";
    statusGlyph.textContent = "✓";
    statusLabel.textContent = "SYSTEM PAGE";
    riskBadge.textContent = "Trusted";
    hybridScoreVal.textContent = "0.0";
    confidenceVal.textContent = "100%";
    latencyVal.textContent = "0 ms";
    formsCountVal.textContent = "0";
    if (brandAlertBanner) brandAlertBanner.style.display = "none";
    reasonsList.innerHTML = "<li>Browser internal settings or protected extension workspace.</li>";
    if (layerBarsContainer) {
      layerBarsContainer.innerHTML = "<div class='loading-placeholder'>Internal browser page - No external threats possible.</div>";
    }
  }

  function renderScanData(data) {
    const pred = data.prediction || "Safe";
    const risk = data.risk_level || "Low";
    const conf = typeof data.confidence === "number" ? data.confidence : 95.0;
    const latency = typeof data.scan_time_ms === "number" ? data.scan_time_ms : 18.4;
    const hybridScore = typeof data.hybrid_score === "number" ? data.hybrid_score : 10.0;
    const matchedBrand = data.matched_brand || null;
    const brandSim = data.matched_brand_similarity ? (data.matched_brand_similarity * 100).toFixed(0) : 0;
    const reasons = data.reasons || [];
    const layers = data.layer_scores || {};
    const features = data.features || {};

    // Reset statusCard classes
    statusCard.className = "status-card";

    if (pred === "Safe") {
      statusCard.classList.add("safe");
      statusGlyph.textContent = "✓";
      statusLabel.textContent = "SAFE WEBSITE";
    } else if (pred === "Suspicious") {
      statusCard.classList.add("suspicious");
      statusGlyph.textContent = "⚠";
      statusLabel.textContent = "SUSPICIOUS WEBSITE";
    } else {
      statusCard.classList.add("danger");
      statusGlyph.textContent = "✕";
      statusLabel.textContent = pred === "Malicious" ? "MALICIOUS DOMAIN" : "PHISHING THREAT";
    }

    riskBadge.textContent = `${risk} Risk`;
    hybridScoreVal.textContent = hybridScore.toFixed(1);
    confidenceVal.textContent = `${conf.toFixed(1)}%`;
    latencyVal.textContent = `${latency.toFixed(0)} ms`;

    // Calculate forms count
    const formsCount = features.form_count !== undefined 
      ? features.form_count 
      : (features.total_forms !== undefined ? features.total_forms : (features.has_password_field ? 1 : 0));
    formsCountVal.textContent = formsCount;

    // Brand Impersonation Alert Banner
    if (matchedBrand) {
      brandAlertBanner.style.display = "flex";
      brandAlertText.innerHTML = `Impersonating <strong>${matchedBrand}</strong> (${brandSim}% visual match)`;
    } else {
      brandAlertBanner.style.display = "none";
    }

    // Render Reasons
    reasonsList.innerHTML = "";
    if (reasons.length > 0) {
      reasons.slice(0, 6).forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    } else {
      reasonsList.innerHTML = "<li>No active multi-modal threat vectors identified.</li>";
    }

    // Render Layer Breakdown
    renderLayers(layers);

    // Render Features Tab
    renderFeatures(features);
  }

  function renderLayers(layers) {
    if (!layerBarsContainer) return;
    layerBarsContainer.innerHTML = "";

    const layerMeta = [
      { key: "url_threat", name: "URL & DNS Structure", weight: "25%" },
      { key: "content_threat", name: "HTML & DOM Integrity", weight: "20%" },
      { key: "form_threat", name: "Credential Form Security", weight: "15%" },
      { key: "js_threat", name: "JavaScript & Obfuscation", weight: "10%" },
      { key: "visual_threat", name: "Visual Brand Similarity", weight: "10%" },
      { key: "ssl_threat", name: "SSL/TLS Certificate", weight: "10%" },
      { key: "reputation_threat", name: "Domain Reputation", weight: "5%" },
      { key: "image_threat", name: "Logo & QR Quishing", weight: "5%" }
    ];

    layerMeta.forEach((layer) => {
      const score = typeof layers[layer.key] === "number" ? layers[layer.key] : 5.0;
      const fillClass = score >= 65 ? "fill-danger" : (score >= 35 ? "fill-warn" : "fill-safe");

      const row = document.createElement("div");
      row.className = "layer-bar-row";

      row.innerHTML = `
        <div class="layer-bar-meta">
          <span>${layer.name} <small style="color:var(--text-muted); font-size:10px;">(${layer.weight})</small></span>
          <span style="color: ${score >= 65 ? '#EF4444' : (score >= 35 ? '#F59E0B' : '#10B981')}">${score.toFixed(1)} / 100</span>
        </div>
        <div class="layer-bar-track">
          <div class="layer-bar-fill ${fillClass}" style="width: ${Math.min(Math.max(score, 4), 100)}%;"></div>
        </div>
      `;
      layerBarsContainer.appendChild(row);
    });
  }

  function renderFeatures(features) {
    if (!featuresListContainer) return;
    featuresListContainer.innerHTML = "";

    if (!features || Object.keys(features).length === 0) {
      featuresListContainer.innerHTML = "<div class='loading-placeholder'>No features extracted yet.</div>";
      return;
    }

    const featureKeys = Object.keys(features);
    if (featureCountTag) {
      featureCountTag.textContent = `${featureKeys.length} Vectors`;
    }

    featureKeys.sort().forEach((key) => {
      const val = features[key];
      const pill = document.createElement("div");
      pill.className = "feature-pill";

      const nameSpan = document.createElement("span");
      nameSpan.className = "feature-pill-name";
      nameSpan.textContent = key.replace(/_/g, " ");

      const valSpan = document.createElement("span");
      valSpan.className = "feature-pill-val";
      valSpan.textContent = typeof val === "number" && !Number.isInteger(val) ? val.toFixed(3) : String(val);

      pill.appendChild(nameSpan);
      pill.appendChild(valSpan);
      featuresListContainer.appendChild(pill);
    });
  }

  // ==========================================
  // 4. Local History
  // ==========================================
  async function renderLocalHistory() {
    if (!historyList) return;
    const { localHistory = [] } = await chrome.storage.local.get("localHistory");
    historyList.innerHTML = "";

    if (localHistory.length === 0) {
      historyList.innerHTML = "<div class='loading-placeholder'>No recent scans in history.</div>";
      return;
    }

    localHistory.slice(-20).reverse().forEach((item) => {
      const div = document.createElement("div");
      div.className = "history-item";

      const left = document.createElement("div");
      left.className = "history-left";

      const dom = document.createElement("span");
      dom.className = "history-domain";
      dom.textContent = item.domain || item.url;
      dom.title = item.url;

      const timeSpan = document.createElement("span");
      timeSpan.className = "history-time";
      const scoreStr = item.hybrid_score ? `Score ${Number(item.hybrid_score).toFixed(0)}` : `${item.confidence ? item.confidence.toFixed(0) : '--'}% conf`;
      timeSpan.textContent = `${item.timestamp || 'Just now'} • ${scoreStr}`;

      left.appendChild(dom);
      left.appendChild(timeSpan);

      const badge = document.createElement("span");
      const badgeCls = item.prediction === "Safe" ? "safe" : (item.prediction === "Suspicious" ? "suspicious" : "danger");
      badge.className = `history-badge ${badgeCls}`;
      badge.textContent = item.prediction;

      div.appendChild(left);
      div.appendChild(badge);
      historyList.appendChild(div);
    });
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", async () => {
      await chrome.storage.local.set({ localHistory: [] });
      renderLocalHistory();
    });
  }

  // ==========================================
  // 5. One-Click Rescan
  // ==========================================
  if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
      if (!currentTabUrl) return;
      if (rescanIcon) rescanIcon.classList.add("spin-animation");
      
      chrome.runtime.sendMessage(
        { action: "RESCAN_URL", url: currentTabUrl },
        (response) => {
          setTimeout(() => {
            if (rescanIcon) rescanIcon.classList.remove("spin-animation");
            if (response && response.data) {
              currentScanResult = response.data;
              renderScanData(response.data);
            }
          }, 450);
        }
      );
    });
  }

  // ==========================================
  // 6. Threat Reporting / Feedback
  // ==========================================
  if (reportForm) {
    reportForm.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!currentTabUrl) {
        reportFeedback.textContent = "No valid URL selected to report.";
        reportFeedback.className = "form-feedback error";
        return;
      }

      const selectedType = document.querySelector('input[name="reportType"]:checked').value;
      const comments = document.getElementById("reportComments").value;

      const payload = {
        url: currentTabUrl,
        feedback: selectedType,
        reported_type: selectedType === "false_positive" ? "Safe" : "Phishing",
        actual_status: currentScanResult ? currentScanResult.prediction : "Unknown",
        comments: comments
      };

      chrome.runtime.sendMessage(
        { action: "SUBMIT_REPORT", payload },
        (res) => {
          if (res && res.status === "success") {
            reportFeedback.textContent = "Report successfully submitted to security database!";
            reportFeedback.className = "form-feedback success";
            document.getElementById("reportComments").value = "";
          } else {
            reportFeedback.textContent = "Report logged locally in offline security queue.";
            reportFeedback.className = "form-feedback success";
          }
        }
      );
    });
  }

  // Initial trigger
  await loadActiveTabAndScan();
});
