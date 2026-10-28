# 🛡️ PHISH GUARD 2.0
### Next-Generation Hybrid AI-Based Browser Security System for Real-Time Phishing Detection

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/framework-Flask%203.1-green.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ml-scikit--learn-orange.svg)](https://scikit-learn.org/)
[![Chrome Extension](https://img.shields.io/badge/manifest-V3-brightgreen.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PHISH GUARD 2.0** is an enterprise-grade, hybrid cybersecurity system designed to detect and block phishing attacks in real time. Unlike conventional security tools that inspect *only the URL string*, PHISH GUARD analyzes **BOTH the URL and webpage content** (DOM structure, login forms, JavaScript behavior, visual screenshot layouts, SSL certificates, and domain reputation) before making a classification decision (`SAFE`, `SUSPICIOUS`, `PHISHING`).

---

## 🌟 Key Architecture & Capabilities

```
  Chrome Extension (Manifest V3)
             │
             ├── Collect URL & DNS metadata
             ├── Collect HTML source & DOM structure
             ├── Collect Login Forms, Inputs & Action URLs
             ├── Collect JavaScript scripts & Behaviors
             ├── Collect Image metadata & Favicons
             └── Capture Viewport Screenshot (Base64 JPEG)
             │
             ▼
      Flask REST API (/predict-hybrid)
             │
             ├── 10 Modular Specialized Feature Extractors (101 Vectors)
             ├── Machine Learning Benchmark Model (Random Forest 97.0% Accuracy)
             └── Hybrid Risk Fusion Engine (8-Layer Weighted Fusion + Critical Overrides)
             │
             ▼
       Verdicts: SAFE  |  SUSPICIOUS  |  PHISHING
```

### 1. 8-Layer Security Inspection Model
1. **URL & DNS Structure (25% Weight):** 42 structural, lexical, entropy, brand keyword, and TLD indicators (`feature_extractors/url_feature_extractor.py`).
2. **HTML & DOM Content (20% Weight):** Scareware detection, hidden zero-pixel iframes, cryptominers, fake alert popups, clipboard hijacking, and disabled right-click (`content_analyzer/html_content_analyzer.py`).
3. **Login Form Security (15% Weight):** Password inputs, credit card fields, OTP tokens, HTTP action downgrades, and cross-domain credential exfiltration (`form_analyzer/form_security_analyzer.py`).
4. **JavaScript Threat Analysis (10% Weight):** `eval()`, `document.write()`, Base64 decoding, Dean Edwards packers, and client-side keylogger hooks (`javascript_analyzer/js_threat_analyzer.py`).
5. **Visual AI & Brand Matching (10% Weight):** Viewport perceptual difference hashing (`dHash`) and RGB color palette distance against top impersonated brands: Google, Microsoft, PayPal, Apple, Amazon, Netflix, Chase, Binance (`visual_similarity/visual_comparator.py`).
6. **SSL/TLS Inspection (10% Weight):** Socket handshakes, self-signed detection, expiration, and mixed content (`ssl_checker/ssl_inspector.py`).
7. **Domain Reputation (5% Weight):** Dynamic DNS detection (`duckdns.org`, `no-ip.biz`), DNS resolution, and local blacklists (`domain_reputation/reputation_engine.py`).
8. **Asset & Image Analysis (5% Weight):** Favicon origin mismatches, brand logo hotlinking, and QR code quishing (`image_analyzer/image_asset_analyzer.py`, `email_detector/email_exfiltration_detector.py`).

### 2. Defense-in-Depth Non-Linear Overrides
The **Hybrid Risk Engine** (`risk_engine/hybrid_risk_engine.py`) enforces deterministic non-linear override rules to defeat stealthy phishing attacks:
* **Rule A (Blacklist):** Verified blacklisted domain $\rightarrow \text{Score} = 100.0 \rightarrow \text{PHISHING}$.
* **Rule B (Cross-Domain Credential Post):** Password/CC form submitting to unauthorized external origin $\rightarrow \text{Score} \ge 88.0 \rightarrow \text{PHISHING}$.
* **Rule C (Brand Spoofing with Login):** Visual or lexical brand clone on unauthorized hostname $\rightarrow \text{Score} \ge 85.0 \rightarrow \text{PHISHING}$.
* **Rule D (Raw IP Hostname):** IP address soliciting credentials $\rightarrow \text{Score} \ge 90.0 \rightarrow \text{PHISHING}$.
* **Rule E (Top Whitelisted Domain):** Clean high-authority domain $\rightarrow \text{Score} \le 10.0 \rightarrow \text{SAFE}$.

---

## 🏆 Machine Learning Benchmark Results

Trained on a balanced 101-feature multi-modal dataset ($N=3,000$ samples across 8 ML algorithms):

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Champion)** | **97.00%** | **96.71%** | **97.32%** | **97.01%** | **0.9934** | **0.320s** |
| **Extra Trees** | 96.67% | 96.69% | 96.64% | 96.67% | 0.9931 | 0.228s |
| **Voting Ensemble** | 96.17% | 95.71% | 96.64% | 96.17% | 0.9926 | 0.941s |
| **AdaBoost** | 94.67% | 94.95% | 94.30% | 94.62% | 0.9859 | 0.174s |
| **Gradient Boosting** | 94.67% | 94.35% | 94.97% | 94.66% | 0.9840 | 0.817s |
| **Decision Tree** | 93.83% | 93.36% | 94.30% | 93.83% | 0.9383 | 0.024s |
| **K-Nearest Neighbors** | 87.83% | 89.44% | 85.57% | 87.46% | 0.9575 | 0.007s |
| **Gaussian Naive Bayes** | 83.17% | 84.14% | 81.54% | 82.82% | 0.9238 | 0.007s |

*ROC Curves and Confusion Matrix plots are saved in `models/roc_curves.png` and `models/hybrid_confusion_matrix.png`.*

---

## 📁 Modular Directory Structure

```
PHISH-GUARD/
├── backend/                       # Flask REST API, model service & database controllers
│   ├── app.py                     # API server (/predict-hybrid, /export-scans, /stats)
│   ├── model_service.py           # Hybrid multi-modal predictor orchestrator
│   └── database_manager.py        # SQLite multi-modal schema & telemetry logger
├── browser_extension/             # Chrome Manifest V3 Browser Extension
│   ├── manifest.json              # Extension manifest (tabs, scripting, host_permissions)
│   ├── content.js                 # Extracts HTML, DOM tree, forms, scripts, images
│   ├── background.js              # Captures screenshot, queries API, manages badges
│   ├── popup.html / css / js      # Hybrid score gauge, 8 layer bars, brand spoof alert
│   └── warning.html / css / js    # Full-screen block page with bypass & threat breakdown
├── admin_dashboard/               # Security Operations Center (SOC) Web App
│   ├── index.html                 # Threat heatmap, brand attack chart, scan inspector
│   ├── css/dashboard.css          # Dark/light responsive cybersecurity styling
│   └── js/ (dashboard.js, charts.js) # Chart.js visualizations & CSV export
├── feature_extractors/            # 42 URL lexical, structural, and entropy features
├── content_analyzer/              # HTML DOM, invisible CSS, scareware, and cryptominers
├── form_analyzer/                 # Password, CC, OTP, and cross-domain action auditing
├── javascript_analyzer/           # eval(), document.write(), keylogger, and packer detector
├── visual_similarity/             # Viewport screenshot dHash & RGB brand matching
├── ocr_detector/                  # Optical character urgency & threat text heuristic
├── ssl_checker/                   # Socket-level TLS certificate and cipher validation
├── domain_reputation/             # Disposable DynDNS, DNS resolution, and threat feeds
├── image_analyzer/                # Favicon origin matching and QR quishing inspection
├── email_detector/                # Form mailto: and webhook data exfiltration detector
├── risk_engine/                   # Multi-layer weighted risk fusion and non-linear overrides
├── models/                        # Serialized hybrid models, ROC curves, confusion matrix
├── dataset/                       # 101-feature synthetic training matrix (3,000 samples)
├── database/                      # SQLite relational database (phishguard.db)
├── documentation/                 # Technical reports, user guide, and HYBRID_ARCHITECTURE.md
├── screenshots/                   # Audit storage for captured webpage screenshots
├── tests/                         # Automated test suite (34 unit & integration tests)
└── requirements.txt               # Python runtime dependencies
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Environment Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/kadaliadithya123-dot/PHISH-GUARD-.git
cd PHISH-GUARD-
pip install -r requirements.txt
```

### 2. Run the Hybrid Backend Server
```bash
python backend/app.py
```
* Server runs on `http://127.0.0.1:5000`
* SOC Dashboard available at `http://127.0.0.1:5000/dashboard`

### 3. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in top right).
3. Click **Load unpacked**.
4. Select the `browser_extension/` directory inside this project.
5. The **PHISH GUARD** shield logo will appear in your Chrome toolbar.

### 4. Run the Test Suite
```bash
python -m unittest discover -s tests -p "test_*.py"
```
*All 34 unit and integration tests will execute and verify system integrity.*

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/predict-hybrid` | `POST` | Primary multi-modal inspection (receives URL, HTML, forms, scripts, screenshot) |
| `/predict` | `POST` | Backward-compatible URL-only prediction |
| `/health` | `GET` | System health, model readiness, and database status |
| `/stats` | `GET` | SOC telemetry, threat heatmap, brand attacks, and daily scan counts |
| `/history` | `GET` | Paginated scan audit history with search and filter |
| `/export-scans` | `GET` | Downloads audit scan history as a CSV file |
| `/model-info` | `GET` | Champion model metrics, ROC-AUC, and feature importances |
| `/blacklist` | `GET/POST/DELETE`| Blacklist rule management for custom blocking |

---

## 📄 Academic Project Details
* **Project Name:** PHISH GUARD – Next-Generation Hybrid Phishing Detection System
* **Domain:** Cybersecurity, Artificial Intelligence, Browser Extension Security
* **Technologies:** Python 3.12+, Flask, Scikit-learn, PIL/NumPy, Chrome Manifest V3, Chart.js, SQLite.
* **Documentation:** Detailed engineering paper located at `documentation/HYBRID_ARCHITECTURE.md`.
