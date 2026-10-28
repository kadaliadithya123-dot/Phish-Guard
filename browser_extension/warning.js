/**
 * PHISH GUARD - Warning Page Controller Script
 * Parses URL threat parameters, displays multi-modal detection indicators,
 * handles brand impersonation alert, safe navigation retreat, temporary bypass, and false positive reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get("targetUrl") || "Unknown Destination";
  const prediction = urlParams.get("prediction") || "PHISHING";
  const risk = urlParams.get("risk") || "Critical";
  const confidence = urlParams.get("confidence") || "99.0";
  const hybridScore = urlParams.get("hybrid_score") || "94.0";
  const matchedBrand = urlParams.get("matched_brand") || "";
  let reasons = [];

  try {
    reasons = JSON.parse(urlParams.get("reasons") || "[]");
  } catch (e) {
    reasons = ["Suspicious domain structure and deceptive pattern markers."];
  }

  // Populate DOM elements
  const targetUrlDisplay = document.getElementById("targetUrlDisplay");
  const threatClassification = document.getElementById("threatClassification");
  const riskLevelDisplay = document.getElementById("riskLevelDisplay");
  const hybridScoreDisplay = document.getElementById("hybridScoreDisplay");
  const confidenceDisplay = document.getElementById("confidenceDisplay");
  const brandSpoofBox = document.getElementById("brandSpoofBox");
  const brandSpoofText = document.getElementById("brandSpoofText");
  const warningReasonsList = document.getElementById("warningReasonsList");
  const reportStatusMsg = document.getElementById("reportStatusMsg");
  const educationalPanel = document.getElementById("educationalPanel");

  targetUrlDisplay.textContent = targetUrl;
  threatClassification.textContent = `${risk.toUpperCase()} HYBRID THREAT BLOCKED`;
  riskLevelDisplay.textContent = risk;
  hybridScoreDisplay.textContent = `${parseFloat(hybridScore).toFixed(1)} / 100`;
  confidenceDisplay.textContent = `${parseFloat(confidence).toFixed(1)}%`;

  // Brand Impersonation Alert
  if (matchedBrand) {
    brandSpoofBox.style.display = "flex";
    brandSpoofText.innerHTML = `Identified visual brand spoofing attack mimicking <strong>${matchedBrand}</strong>`;
  } else {
    brandSpoofBox.style.display = "none";
  }

  // Render Reasons
  warningReasonsList.innerHTML = "";
  if (reasons.length > 0) {
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      warningReasonsList.appendChild(li);
    });
  } else {
    warningReasonsList.innerHTML = "<li>Identified as credential phishing attack via multi-modal AI classification.</li>";
  }

  // 1. Back to Safety
  document.getElementById("goBackBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // 2. Continue Anyway (Temporary Bypass)
  document.getElementById("continueAnywayBtn").addEventListener("click", () => {
    const confirmed = confirm(
      "SECURITY WARNING: Continuing may lead to credential harvesting, credit card theft, or session takeover.\n\nAre you sure you want to proceed?"
    );
    if (confirmed) {
      chrome.runtime.sendMessage(
        { action: "ADD_BYPASS", url: targetUrl },
        () => {
          window.location.href = targetUrl;
        }
      );
    }
  });

  // 3. Report False Positive
  document.getElementById("reportFpBtn").addEventListener("click", () => {
    chrome.runtime.sendMessage(
      {
        action: "SUBMIT_REPORT",
        payload: {
          url: targetUrl,
          feedback: "false_positive",
          reported_type: "Safe",
          actual_status: prediction,
          comments: "Reported directly from Warning blocking screen."
        }
      },
      (res) => {
        reportStatusMsg.textContent = "✓ False positive report submitted to threat database. Thank you!";
      }
    );
  });

  // 4. Learn More Toggle
  document.getElementById("learnMoreBtn").addEventListener("click", () => {
    educationalPanel.classList.toggle("visible");
  });
});
