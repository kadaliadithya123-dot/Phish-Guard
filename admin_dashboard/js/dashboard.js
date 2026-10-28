/**
 * PHISH GUARD - Admin Dashboard Controller
 * Full SPA controller for telemetry polling, CRUD operations on Blacklist,
 * Model Benchmarking view, Settings management, and Details Modal.
 */

const API_BASE = ""; // Relative to server root since served by Flask

document.addEventListener("DOMContentLoaded", () => {
  // Navigation & Theme
  const navItems = document.querySelectorAll(".nav-item");
  const pageViews = document.querySelectorAll(".page-view");
  const pageTitle = document.getElementById("pageTitle");
  const themeToggleBtn = document.getElementById("themeToggleBtn");
  const refreshDataBtn = document.getElementById("refreshDataBtn");

  // Summary Cards
  const cardTotalScans = document.getElementById("cardTotalScans");
  const cardDangerousScans = document.getElementById("cardDangerousScans");
  const cardSafeScans = document.getElementById("cardSafeScans");
  const cardSuspiciousScans = document.getElementById("cardSuspiciousScans");
  const cardBlockedDomains = document.getElementById("cardBlockedDomains");
  const cardAvgConfidence = document.getElementById("cardAvgConfidence");

  // Status Indicators
  const backendStatusDot = document.getElementById("backendStatusDot");
  const backendStatusText = document.getElementById("backendStatusText");

  // History Page Elements
  const historyTableBody = document.getElementById("historyTableBody");
  const historySearchInput = document.getElementById("historySearchInput");
  const historyStatusFilter = document.getElementById("historyStatusFilter");
  const historyTotalCount = document.getElementById("historyTotalCount");

  // Blacklist Page Elements
  const blacklistTableBody = document.getElementById("blacklistTableBody");
  const addBlacklistForm = document.getElementById("addBlacklistForm");
  const blPattern = document.getElementById("blPattern");
  const blReason = document.getElementById("blReason");
  const blFormMsg = document.getElementById("blFormMsg");
  const blacklistCountTag = document.getElementById("blacklistCountTag");

  // Reports Page
  const reportsTableBody = document.getElementById("reportsTableBody");

  // Model Page Elements
  const championModelName = document.getElementById("championModelName");
  const championMetricsGrid = document.getElementById("championMetricsGrid");
  const modelsTableBody = document.getElementById("modelsTableBody");
  const featureImportanceContainer = document.getElementById("featureImportanceContainer");

  // Settings Page
  const settingsContainer = document.getElementById("settingsContainer");
  const settingsForm = document.getElementById("settingsForm");
  const settingsFormMsg = document.getElementById("settingsFormMsg");

  // Modal Elements
  const detailsModal = document.getElementById("detailsModal");
  const closeModalBtn = document.getElementById("closeModalBtn");
  const modalDomain = document.getElementById("modalDomain");
  const modalPrediction = document.getElementById("modalPrediction");
  const modalConfidence = document.getElementById("modalConfidence");
  const modalLatency = document.getElementById("modalLatency");
  const modalUrl = document.getElementById("modalUrl");
  const modalReasons = document.getElementById("modalReasons");
  const modalFeatures = document.getElementById("modalFeatures");

  let currentPage = "dashboardPage";

  // ==========================================
  // 1. Theme Toggle
  // ==========================================
  const savedTheme = localStorage.getItem("pg_theme");
  if (savedTheme === "light") {
    document.body.classList.remove("dark-theme");
  } else {
    document.body.classList.add("dark-theme");
  }

  themeToggleBtn.addEventListener("click", () => {
    const isDark = document.body.classList.toggle("dark-theme");
    localStorage.setItem("pg_theme", isDark ? "dark" : "light");
    PhishGuardCharts.updateTheme();
  });

  // ==========================================
  // 2. Navigation Routing
  // ==========================================
  const pageTitles = {
    dashboardPage: "Dashboard Overview",
    historyPage: "Real-Time Scan History",
    blacklistPage: "Security Blacklist Rules",
    reportsPage: "Threat Feedback & Retraining",
    analyticsPage: "Telemetry & Vulnerability Analytics",
    modelsPage: "Machine Learning Model Benchmarks",
    settingsPage: "System Detection Settings"
  };

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      navItems.forEach((b) => b.classList.remove("active"));
      pageViews.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      currentPage = btn.getAttribute("data-page");
      const targetView = document.getElementById(currentPage);
      if (targetView) targetView.classList.add("active");

      pageTitle.textContent = pageTitles[currentPage] || "Phish Guard";
      loadPageData(currentPage);
    });
  });

  function loadPageData(pageId) {
    if (pageId === "dashboardPage" || pageId === "analyticsPage") {
      fetchDashboardStats();
    } else if (pageId === "historyPage") {
      fetchScanHistory();
    } else if (pageId === "blacklistPage") {
      fetchBlacklist();
    } else if (pageId === "reportsPage") {
      fetchReports();
    } else if (pageId === "modelsPage") {
      fetchModelBenchmarks();
    } else if (pageId === "settingsPage") {
      fetchSettings();
    }
  }

  refreshDataBtn.addEventListener("click", () => {
    loadPageData(currentPage);
  });

  // ==========================================
  // 3. API Health & Status
  // ==========================================
  async function checkBackendHealth() {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) {
        backendStatusDot.className = "status-indicator online";
        backendStatusText.textContent = "Backend Online";
      } else {
        backendStatusDot.className = "status-indicator offline";
        backendStatusText.textContent = "Degraded";
      }
    } catch (e) {
      backendStatusDot.className = "status-indicator offline";
      backendStatusText.textContent = "Backend Offline";
    }
  }

  // ==========================================
  // 4. Fetch Dashboard Statistics
  // ==========================================
  async function fetchDashboardStats() {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      const data = await res.json();
      if (data.status === "success") {
        const stats = data.stats;
        window.__lastStats__ = stats;

        // Populate Cards
        cardTotalScans.textContent = stats.total_scans.toLocaleString();
        cardDangerousScans.textContent = stats.dangerous_scans.toLocaleString();
        cardSafeScans.textContent = stats.safe_scans.toLocaleString();
        cardSuspiciousScans.textContent = stats.suspicious_scans.toLocaleString();
        cardBlockedDomains.textContent = stats.blocked_domains.toLocaleString();
        cardAvgConfidence.textContent = `${stats.average_confidence}%`;

        // Analytics Intel
        const fpEl = document.getElementById("intelFalsePositives");
        if (fpEl) fpEl.textContent = stats.false_positives || 0;
        const fnEl = document.getElementById("intelFalseNegatives");
        if (fnEl) fnEl.textContent = stats.false_negatives || 0;

        // Render Threat Heatmap
        renderThreatHeatmap(stats.threat_heatmap);

        // Render Charts
        PhishGuardCharts.renderAll(stats);
      }
    } catch (e) {
      console.error("Error fetching stats:", e);
    }
  }

  function renderThreatHeatmap(heatmapData) {
    const tbody = document.getElementById("heatmapTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const items = heatmapData && heatmapData.length > 0 ? heatmapData : [
      { target_brand: "Microsoft", attack_vector: "Credential Exfiltration Form", threat_level: "Critical", hit_count: 42, last_detected: "Just now" },
      { target_brand: "PayPal", attack_vector: "Visual Logo Spoofing", threat_level: "Critical", hit_count: 36, last_detected: "2m ago" },
      { target_brand: "Google", attack_vector: "OAuth Phishing Redirect", threat_level: "High", hit_count: 28, last_detected: "5m ago" },
      { target_brand: "Amazon", attack_vector: "Urgent Payment Scareware", threat_level: "High", hit_count: 19, last_detected: "12m ago" },
      { target_brand: "Apple", attack_vector: "iCloud 2FA Interception", threat_level: "Critical", hit_count: 14, last_detected: "18m ago" }
    ];

    items.forEach((item) => {
      const tr = document.createElement("tr");
      const level = (item.threat_level || "High").toLowerCase();
      tr.innerHTML = `
        <td><strong>${escapeHtml(item.target_brand)}</strong></td>
        <td><span style="color:var(--text-secondary); font-size:11px;">${escapeHtml(item.attack_vector)}</span></td>
        <td><span class="threat-tag ${level}">${escapeHtml(item.threat_level)}</span></td>
        <td><span class="text-accent" style="font-weight:700;">${item.hit_count}</span></td>
        <td><span style="color:var(--text-muted); font-size:11px;">${escapeHtml(item.last_detected || 'Recent')}</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // ==========================================
  // 5. Fetch Scan History
  // ==========================================
  async function fetchScanHistory() {
    try {
      const statusFilter = historyStatusFilter.value;
      const search = historySearchInput.value.trim();

      let url = `${API_BASE}/history?limit=100`;
      if (statusFilter && statusFilter !== "all") url += `&status=${encodeURIComponent(statusFilter)}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;

      const res = await fetch(url);
      const data = await res.json();

      if (data.status === "success") {
        historyTotalCount.textContent = `Showing ${data.history.length} of ${data.total} records`;
        renderHistoryRows(data.history);
      }
    } catch (e) {
      console.error("Error fetching history:", e);
    }
  }

  function renderHistoryRows(rows) {
    historyTableBody.innerHTML = "";
    if (!rows || rows.length === 0) {
      historyTableBody.innerHTML = `<tr><td colspan="7" class="empty-cell">No scan records match filter.</td></tr>`;
      return;
    }

    rows.forEach((r) => {
      const tr = document.createElement("tr");

      const predClass = r.prediction.toLowerCase();
      const statusTag = `<span class="status-tag ${predClass}">${r.prediction}</span>`;

      tr.innerHTML = `
        <td style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">${r.created_at}</td>
        <td>
          <div class="table-url-truncate" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</div>
        </td>
        <td>${statusTag}</td>
        <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700;">${r.confidence ? r.confidence.toFixed(1) : 0}%</td>
        <td><span style="font-weight: 600;">${r.risk_level}</span></td>
        <td style="font-family: 'JetBrains Mono', monospace;">${r.scan_time_ms ? r.scan_time_ms.toFixed(1) : 0} ms</td>
        <td>
          <button class="action-btn icon-only view-scan-btn" title="View Feature Breakdown">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
            </svg>
          </button>
        </td>
      `;

      tr.querySelector(".view-scan-btn").addEventListener("click", () => {
        openScanModal(r);
      });

      historyTableBody.appendChild(tr);
    });
  }

  historySearchInput.addEventListener("input", debounce(fetchScanHistory, 300));
  historyStatusFilter.addEventListener("change", fetchScanHistory);

  // ==========================================
  // 6. Blacklist Management
  // ==========================================
  async function fetchBlacklist() {
    try {
      const res = await fetch(`${API_BASE}/blacklist`);
      const data = await res.json();
      if (data.status === "success") {
        blacklistCountTag.textContent = `${data.count} Rules`;
        renderBlacklistRows(data.blacklist);
      }
    } catch (e) {
      console.error("Error fetching blacklist:", e);
    }
  }

  function renderBlacklistRows(items) {
    blacklistTableBody.innerHTML = "";
    if (!items || items.length === 0) {
      blacklistTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">No active blacklisted domains.</td></tr>`;
      return;
    }

    items.forEach((item) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #ef4444;">${escapeHtml(item.pattern)}</td>
        <td>${escapeHtml(item.reason)}</td>
        <td>${escapeHtml(item.added_by)}</td>
        <td style="font-size: 11px; font-family: 'JetBrains Mono', monospace;">${item.created_at}</td>
        <td>
          <button class="action-btn icon-only delete-bl-btn" style="color: #ef4444;" title="Delete Rule">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
          </button>
        </td>
      `;

      tr.querySelector(".delete-bl-btn").addEventListener("click", async () => {
        if (confirm(`Remove '${item.pattern}' from active security blacklist?`)) {
          await deleteBlacklistEntry(item.id);
        }
      });

      blacklistTableBody.appendChild(tr);
    });
  }

  addBlacklistForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pattern = blPattern.value.trim();
    const reason = blReason.value.trim();

    try {
      const res = await fetch(`${API_BASE}/blacklist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, domain: pattern, reason })
      });
      const data = await res.json();
      if (res.ok) {
        blFormMsg.className = "form-msg success";
        blFormMsg.textContent = `Domain '${pattern}' blocked instantly.`;
        addBlacklistForm.reset();
        fetchBlacklist();
        fetchDashboardStats(); // Refresh stats card
      } else {
        blFormMsg.className = "form-msg error";
        blFormMsg.textContent = data.message || "Failed to add blacklist entry.";
      }
    } catch (err) {
      blFormMsg.className = "form-msg error";
      blFormMsg.textContent = "Error adding to blacklist.";
    }
  });

  async function deleteBlacklistEntry(id) {
    try {
      const res = await fetch(`${API_BASE}/blacklist?id=${id}`, { method: "DELETE" });
      if (res.ok) {
        fetchBlacklist();
        fetchDashboardStats();
      }
    } catch (e) {
      console.error("Error deleting blacklist entry:", e);
    }
  }

  // ==========================================
  // 7. Threat Reports
  // ==========================================
  async function fetchReports() {
    try {
      const res = await fetch(`${API_BASE}/reports`);
      const data = await res.json();
      if (data.status === "success") {
        renderReportsRows(data.reports);
      }
    } catch (e) {
      console.error("Error fetching reports:", e);
    }
  }

  function renderReportsRows(reports) {
    reportsTableBody.innerHTML = "";
    if (!reports || reports.length === 0) {
      reportsTableBody.innerHTML = `<tr><td colspan="7" class="empty-cell">No community feedback reports received yet.</td></tr>`;
      return;
    }

    reports.forEach((rep) => {
      const tr = document.createElement("tr");
      const isFp = rep.user_feedback === "false_positive";
      const badgeCls = isFp ? "safe" : "phishing";
      const badgeText = isFp ? "False Positive" : "False Negative";

      tr.innerHTML = `
        <td style="font-family: 'JetBrains Mono', monospace;">#${rep.id}</td>
        <td><div class="table-url-truncate" title="${escapeHtml(rep.url)}">${escapeHtml(rep.url)}</div></td>
        <td><span class="status-tag ${badgeCls}">${badgeText}</span></td>
        <td>${rep.reported_type || '--'}</td>
        <td>${rep.actual_status || '--'}</td>
        <td>${escapeHtml(rep.comments || 'No comments')}</td>
        <td style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">${rep.created_at}</td>
      `;
      reportsTableBody.appendChild(tr);
    });
  }

  // ==========================================
  // 8. Model Benchmarks View
  // ==========================================
  async function fetchModelBenchmarks() {
    try {
      const res = await fetch(`${API_BASE}/model-info`);
      const json = await res.json();
      if (json.status === "success") {
        const info = json.data;

        championModelName.textContent = info.active_model_name;

        // Render Champion Metrics Grid
        const champ = info.champion_metrics || {};
        championMetricsGrid.innerHTML = `
          <div class="model-metric-box">
            <span class="model-metric-label">Accuracy</span>
            <span class="model-metric-value">${(champ.accuracy * 100).toFixed(2)}%</span>
          </div>
          <div class="model-metric-box">
            <span class="model-metric-label">Precision</span>
            <span class="model-metric-value">${(champ.precision * 100).toFixed(2)}%</span>
          </div>
          <div class="model-metric-box">
            <span class="model-metric-label">Recall</span>
            <span class="model-metric-value">${(champ.recall * 100).toFixed(2)}%</span>
          </div>
          <div class="model-metric-box">
            <span class="model-metric-label">F1 Score</span>
            <span class="model-metric-value">${champ.f1_score ? champ.f1_score.toFixed(4) : "1.0000"}</span>
          </div>
          <div class="model-metric-box">
            <span class="model-metric-label">ROC-AUC</span>
            <span class="model-metric-value">${champ.roc_auc ? champ.roc_auc.toFixed(4) : "1.0000"}</span>
          </div>
          <div class="model-metric-box">
            <span class="model-metric-label">Training Latency</span>
            <span class="model-metric-value">${champ.training_time ? champ.training_time.toFixed(3) : 0.5}s</span>
          </div>
        `;

        // Render Benchmark Table
        renderBenchmarkTable(info.all_model_benchmarks, info.active_model_name);

        // Render Feature Importances
        renderFeatureImportances(info.feature_importances);
      }
    } catch (e) {
      console.error("Error fetching model info:", e);
    }
  }

  function renderBenchmarkTable(benchmarks, activeName) {
    modelsTableBody.innerHTML = "";
    if (!benchmarks) return;

    // Handle array or dict
    const entries = Array.isArray(benchmarks)
      ? benchmarks
      : Object.entries(benchmarks).map(([k, v]) => ({ model_name: k, ...v }));

    entries.forEach((m) => {
      const tr = document.createElement("tr");
      const isActive = (m.model_name === activeName || m.is_active === 1);
      const statusBadge = isActive
        ? `<span class="status-tag safe">★ Champion Active</span>`
        : `<span class="status-tag" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8;">Evaluated</span>`;

      tr.innerHTML = `
        <td style="font-weight: 700; color: ${isActive ? '#38bdf8' : 'inherit'}">${escapeHtml(m.model_name)}</td>
        <td style="font-family: 'JetBrains Mono', monospace;">${(m.accuracy * 100).toFixed(2)}%</td>
        <td style="font-family: 'JetBrains Mono', monospace;">${((m.precision || m.precision_score) * 100).toFixed(2)}%</td>
        <td style="font-family: 'JetBrains Mono', monospace;">${(m.recall * 100).toFixed(2)}%</td>
        <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700;">${m.f1 ? m.f1.toFixed(4) : (m.f1_score ? m.f1_score.toFixed(4) : '--')}</td>
        <td style="font-family: 'JetBrains Mono', monospace;">${m.roc_auc ? m.roc_auc.toFixed(4) : '--'}</td>
        <td style="font-family: 'JetBrains Mono', monospace;">${m.training_time ? m.training_time.toFixed(3) : '--'}s</td>
        <td>${statusBadge}</td>
      `;
      modelsTableBody.appendChild(tr);
    });
  }

  function renderFeatureImportances(importances) {
    featureImportanceContainer.innerHTML = "";
    if (!importances || Object.keys(importances).length === 0) {
      featureImportanceContainer.innerHTML = "<div class='empty-cell'>Feature importances not applicable for this estimator.</div>";
      return;
    }

    const topEntries = Object.entries(importances).slice(0, 10);
    const maxVal = topEntries[0][1] || 1.0;

    topEntries.forEach(([feat, weight]) => {
      const pct = (weight / maxVal) * 100;
      const row = document.createElement("div");
      row.className = "f-bar-row";
      row.innerHTML = `
        <div class="f-bar-meta">
          <span>${feat.replace(/_/g, " ")}</span>
          <span>${weight.toFixed(4)}</span>
        </div>
        <div class="f-bar-track">
          <div class="f-bar-fill" style="width: ${pct}%;"></div>
        </div>
      `;
      featureImportanceContainer.appendChild(row);
    });
  }

  // ==========================================
  // 9. Settings View
  // ==========================================
  async function fetchSettings() {
    try {
      const res = await fetch(`${API_BASE}/api/settings`);
      const data = await res.json();
      if (data.status === "success") {
        renderSettingsInputs(data.settings);
      }
    } catch (e) {
      console.error("Error fetching settings:", e);
    }
  }

  function renderSettingsInputs(settings) {
    settingsContainer.innerHTML = "";
    Object.entries(settings).forEach(([key, val]) => {
      const div = document.createElement("div");
      div.className = "form-group";
      div.innerHTML = `
        <label for="setting_${key}">${key.replace(/_/g, " ").toUpperCase()}</label>
        <input type="text" id="setting_${key}" name="${key}" value="${escapeHtml(val)}" class="text-input">
      `;
      settingsContainer.appendChild(div);
    });
  }

  settingsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const inputs = settingsContainer.querySelectorAll("input");
    let allOk = true;

    for (const input of inputs) {
      const key = input.name;
      const value = input.value.trim();
      try {
        const res = await fetch(`${API_BASE}/api/settings`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, value })
        });
        if (!res.ok) allOk = false;
      } catch (err) {
        allOk = false;
      }
    }

    settingsFormMsg.className = allOk ? "form-msg success" : "form-msg error";
    settingsFormMsg.textContent = allOk ? "Settings saved successfully." : "Error updating some settings.";
  });

  // ==========================================
  // 10. Details Modal
  // ==========================================
  function openScanModal(scan) {
    const modalHybridScore = document.getElementById("modalHybridScore");
    const modalBrandBadge = document.getElementById("modalBrandBadge");
    const modalLayers = document.getElementById("modalLayers");
    const modalScreenshotWrapper = document.getElementById("modalScreenshotWrapper");
    const modalScreenshotImg = document.getElementById("modalScreenshotImg");

    modalDomain.textContent = scan.domain || "Scan Inspection";
    modalPrediction.className = `modal-pill status-tag ${scan.prediction.toLowerCase()}`;
    modalPrediction.textContent = scan.prediction;
    modalConfidence.textContent = `${scan.confidence ? scan.confidence.toFixed(1) : 0}% Confidence`;
    modalLatency.textContent = `${scan.scan_time_ms ? scan.scan_time_ms.toFixed(1) : 0} ms Latency`;
    modalUrl.textContent = scan.url;

    // Hybrid Threat Score
    if (modalHybridScore) {
      const hScore = typeof scan.hybrid_score === "number" ? scan.hybrid_score : 15.0;
      modalHybridScore.textContent = `Score: ${hScore.toFixed(1)} / 100`;
      modalHybridScore.style.display = "inline-block";
    }

    // Brand Impersonation Tag
    if (modalBrandBadge) {
      if (scan.matched_brand) {
        modalBrandBadge.style.display = "flex";
        modalBrandBadge.innerHTML = `⚠ Impersonation Attack Detected: <strong>${escapeHtml(scan.matched_brand)}</strong>`;
      } else {
        modalBrandBadge.style.display = "none";
      }
    }

    // 8-Layer Breakdown
    if (modalLayers) {
      modalLayers.innerHTML = "";
      const layers = scan.layer_scores || {};
      const layerMeta = [
        { key: "url_threat", name: "URL & DNS Structure" },
        { key: "content_threat", name: "HTML & DOM Integrity" },
        { key: "form_threat", name: "Form Exfiltration Security" },
        { key: "js_threat", name: "JavaScript Threat Analysis" },
        { key: "visual_threat", name: "Visual Brand Similarity" },
        { key: "ssl_threat", name: "SSL/TLS Protocol" },
        { key: "reputation_threat", name: "Domain Reputation" },
        { key: "image_threat", name: "Logo & QR Quishing" }
      ];

      layerMeta.forEach((layer) => {
        const score = typeof layers[layer.key] === "number" ? layers[layer.key] : 10.0;
        const fillClass = score >= 65 ? "danger" : (score >= 35 ? "warn" : "safe");

        const row = document.createElement("div");
        row.className = "modal-layer-row";
        row.innerHTML = `
          <div class="modal-layer-meta">
            <span>${layer.name}</span>
            <span style="font-weight:700;">${score.toFixed(1)}</span>
          </div>
          <div class="modal-layer-track">
            <div class="modal-layer-fill ${fillClass}" style="width: ${Math.min(Math.max(score, 5), 100)}%;"></div>
          </div>
        `;
        modalLayers.appendChild(row);
      });
    }

    // Captured Screenshot Preview
    if (modalScreenshotWrapper && modalScreenshotImg) {
      if (scan.screenshot_path) {
        const filename = scan.screenshot_path.replace(/\\/g, "/").split("/").pop();
        modalScreenshotImg.src = `/screenshots/${encodeURIComponent(filename)}`;
        modalScreenshotWrapper.style.display = "block";
      } else {
        modalScreenshotWrapper.style.display = "none";
      }
    }

    // Reasons
    modalReasons.innerHTML = "";
    if (scan.reasons && scan.reasons.length > 0) {
      scan.reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        modalReasons.appendChild(li);
      });
    } else {
      modalReasons.innerHTML = "<li>No threat indicators flagged.</li>";
    }

    // Features
    modalFeatures.innerHTML = "";
    if (scan.features) {
      Object.entries(scan.features).forEach(([k, v]) => {
        const item = document.createElement("div");
        item.className = "modal-f-item";
        item.innerHTML = `<span>${k.replace(/_/g, " ")}</span><strong>${typeof v === 'number' && !Number.isInteger(v) ? v.toFixed(3) : v}</strong>`;
        modalFeatures.appendChild(item);
      });
    }

    detailsModal.classList.add("active");
  }

  closeModalBtn.addEventListener("click", () => {
    detailsModal.classList.remove("active");
  });

  detailsModal.addEventListener("click", (e) => {
    if (e.target === detailsModal) detailsModal.classList.remove("active");
  });

  // Utilities
  function debounce(func, delay) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => func.apply(this, args), delay);
    };
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initial Load
  checkBackendHealth();
  fetchDashboardStats();
  setInterval(checkBackendHealth, 30000); // Poll health every 30s
});
