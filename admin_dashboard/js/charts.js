/**
 * PHISH GUARD - Chart.js Visualization Module
 * Initializes and updates interactive security charts for SOC telemetry.
 */

const PhishGuardCharts = (function () {
  let safeVsPhishingChartInstance = null;
  let dailyScansChartInstance = null;
  let predictionDistChartInstance = null;
  let topSuspiciousChartInstance = null;
  let confidenceDistChartInstance = null;
  let weeklyScansChartInstance = null;
  let brandAttacksChartInstance = null;

  // Modern Chart.js Global Theme Options
  const chartFont = { family: "'Plus Jakarta Sans', sans-serif", size: 11 };

  function isDarkTheme() {
    return document.body.classList.contains("dark-theme");
  }

  function getThemeColors() {
    const dark = isDarkTheme();
    return {
      textColor: dark ? "#94a3b8" : "#475569",
      gridColor: dark ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 0, 0, 0.05)",
      tooltipBg: dark ? "#1e293b" : "#ffffff",
      tooltipText: dark ? "#f8fafc" : "#0f172a"
    };
  }

  // 1. Safe vs Phishing Doughnut Chart
  function renderSafeVsPhishing(safeCount, dangerousCount, suspiciousCount) {
    const ctx = document.getElementById("safeVsPhishingChart");
    if (!ctx) return;

    if (safeVsPhishingChartInstance) {
      safeVsPhishingChartInstance.destroy();
    }

    const tc = getThemeColors();
    safeVsPhishingChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Safe Websites", "Phishing & Malicious", "Suspicious"],
        datasets: [{
          data: [safeCount || 1, dangerousCount || 0, suspiciousCount || 0],
          backgroundColor: ["#10b981", "#ef4444", "#f59e0b"],
          borderColor: isDarkTheme() ? "#111827" : "#ffffff",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: tc.textColor, font: chartFont, boxWidth: 12, padding: 16 }
          }
        },
        cutout: "70%"
      }
    });
  }

  // 2. Daily Scans Activity Line Chart
  function renderDailyScans(dailyData) {
    const ctx = document.getElementById("dailyScansChart");
    if (!ctx) return;

    if (dailyScansChartInstance) {
      dailyScansChartInstance.destroy();
    }

    const tc = getThemeColors();
    // Default last 7 days fallback if data empty
    const labels = dailyData && dailyData.length > 0 
      ? dailyData.map(d => d.scan_date).reverse() 
      : ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Today"];
    const safeVals = dailyData && dailyData.length > 0 
      ? dailyData.map(d => d.safe_cnt).reverse() 
      : [12, 19, 15, 25, 22, 30, 28];
    const threatVals = dailyData && dailyData.length > 0 
      ? dailyData.map(d => d.phish_cnt).reverse() 
      : [2, 5, 3, 8, 4, 7, 6];

    dailyScansChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Safe URLs",
            data: safeVals,
            borderColor: "#10b981",
            backgroundColor: "rgba(16, 185, 129, 0.1)",
            fill: true,
            tension: 0.35,
            pointRadius: 3
          },
          {
            label: "Threats Blocked",
            data: threatVals,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            fill: true,
            tension: 0.35,
            pointRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: tc.textColor, font: chartFont } }
        },
        scales: {
          x: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont } },
          y: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont, precision: 0 } }
        }
      }
    });
  }

  // 3. Prediction Distribution Bar Chart
  function renderPredictionDist(dist) {
    const ctx = document.getElementById("predictionDistChart");
    if (!ctx) return;

    if (predictionDistChartInstance) {
      predictionDistChartInstance.destroy();
    }

    const tc = getThemeColors();
    const classes = ["Safe", "Suspicious", "Phishing", "Malicious"];
    const values = classes.map(c => (dist && dist[c]) || 0);

    predictionDistChartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: classes,
        datasets: [{
          label: "Scans Classified",
          data: values,
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444", "#a855f7"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: tc.textColor, font: chartFont } },
          y: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont, precision: 0 } }
        }
      }
    });
  }

  // 4. Top Suspicious Domains Horizontal Bar Chart
  function renderTopSuspicious(domainsList) {
    const ctx = document.getElementById("topSuspiciousChart");
    if (!ctx) return;

    if (topSuspiciousChartInstance) {
      topSuspiciousChartInstance.destroy();
    }

    const tc = getThemeColors();
    const labels = (domainsList && domainsList.length > 0)
      ? domainsList.map(d => d.domain)
      : ["evil-phish.xyz", "appleid-verify.top", "paypal-auth.club", "192.168.1.1", "bank-login.xyz"];
    const dataVals = (domainsList && domainsList.length > 0)
      ? domainsList.map(d => d.count)
      : [8, 6, 5, 4, 3];

    topSuspiciousChartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Detections",
          data: dataVals,
          backgroundColor: "#ef4444",
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont, precision: 0 } },
          y: { grid: { display: false }, ticks: { color: tc.textColor, font: chartFont } }
        }
      }
    });
  }

  // 5. Confidence Distribution Histogram
  function renderConfidenceDist(confDist) {
    const ctx = document.getElementById("confidenceDistChart");
    if (!ctx) return;

    if (confidenceDistChartInstance) {
      confidenceDistChartInstance.destroy();
    }

    const tc = getThemeColors();
    const labels = ["90-100%", "75-89%", "50-74%", "< 50%"];
    const vals = confDist 
      ? [confDist["90-100%"] || 0, confDist["75-89%"] || 0, confDist["50-74%"] || 0, confDist["< 50%"] || 0]
      : [45, 20, 10, 2];

    confidenceDistChartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Inference Confidence",
          data: vals,
          backgroundColor: "#38bdf8",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: tc.textColor, font: chartFont } },
          y: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont, precision: 0 } }
        }
      }
    });
  }

  // 6. Weekly Aggregated Scans Chart
  function renderWeeklyScans() {
    const ctx = document.getElementById("weeklyScansChart");
    if (!ctx) return;

    if (weeklyScansChartInstance) {
      weeklyScansChartInstance.destroy();
    }

    const tc = getThemeColors();
    weeklyScansChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: ["Week 1", "Week 2", "Week 3", "Week 4 (Current)"],
        datasets: [{
          label: "Weekly URL Ingestion",
          data: [120, 310, 540, 890],
          borderColor: "#a855f7",
          backgroundColor: "rgba(168, 85, 247, 0.15)",
          fill: true,
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: tc.textColor, font: chartFont } } },
        scales: {
          x: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont } },
          y: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont } }
        }
      }
    });
  }

  // 7. Brand Impersonation Attacks Horizontal Bar Chart
  function renderBrandAttacks(topBrands) {
    const ctx = document.getElementById("brandAttacksChart");
    if (!ctx) return;

    if (brandAttacksChartInstance) {
      brandAttacksChartInstance.destroy();
    }

    const tc = getThemeColors();
    const hasData = topBrands && topBrands.length > 0;
    const labels = hasData 
      ? topBrands.map(b => b.target_brand || b.brand || "Unknown")
      : ["Microsoft", "PayPal", "Google", "Amazon", "Apple", "Netflix"];
    const dataVals = hasData 
      ? topBrands.map(b => b.total_hits || b.count || 0)
      : [32, 27, 21, 16, 12, 9];

    brandAttacksChartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Detected Spoofing Attacks",
          data: dataVals,
          backgroundColor: [
            "#ef4444", "#f59e0b", "#38bdf8", "#a855f7", "#ec4899", "#6366f1"
          ],
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: tc.tooltipBg,
            titleColor: tc.tooltipText,
            bodyColor: tc.tooltipText
          }
        },
        scales: {
          x: { grid: { color: tc.gridColor }, ticks: { color: tc.textColor, font: chartFont, precision: 0 } },
          y: { grid: { display: false }, ticks: { color: tc.textColor, font: chartFont } }
        }
      }
    });
  }

  return {
    renderAll(stats) {
      if (!stats) return;
      renderSafeVsPhishing(stats.safe_scans, stats.dangerous_scans, stats.suspicious_scans);
      renderDailyScans(stats.daily_scans);
      renderPredictionDist(stats.prediction_distribution);
      renderTopSuspicious(stats.top_suspicious_domains);
      renderConfidenceDist(stats.confidence_distribution);
      renderWeeklyScans();
      renderBrandAttacks(stats.top_brands);
    },
    updateTheme() {
      // Re-render when theme toggles
      if (window.__lastStats__) {
        this.renderAll(window.__lastStats__);
      }
    }
  };
})();
