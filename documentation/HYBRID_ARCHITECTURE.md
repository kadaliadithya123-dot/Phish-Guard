# PHISH GUARD 2.0: Next-Generation Hybrid AI-Based Phishing & Malicious Web Security Architecture

**Author:** Cybersecurity & Machine Learning Engineering Research Group  
**Project:** PHISH GUARD – Academic Final-Year Engineering Project  
**System Classification:** Real-Time Multi-Modal Threat Inspection System  
**Version:** 2.0.0 Hybrid Edition  

---

## 1. Executive Summary

Legacy phishing countermeasures rely predominantly on static URL reputation feeds or lexical machine learning filters. While lexical models identify obvious synthetic domains (such as excessive Shannon entropy, brand typosquatting, or high hyphen counts), modern adversaries routinely evade URL-only filters by utilizing:
1. **Legitimate cloud infrastructures & reverse proxies** (e.g. `*.pages.dev`, `*.firebaseapp.com`, `*.blob.core.windows.net`, or Azure App Services).
2. **Shortened links & multi-hop redirects** that disguise the final payload.
3. **Dynamic Single Page Applications (SPAs)** that inject credential harvesting elements via obfuscated JavaScript only upon real user interaction.
4. **Perceptually identical cloned interfaces** mimicking major banking, enterprise, and social identity providers (Google, Microsoft, Apple, PayPal, Netflix).

**PHISH GUARD 2.0** solves this fundamental blindspot by transitioning from a single-modality URL detector into a **Hybrid Multi-Modal Phishing Intelligence Engine**. It analyzes **BOTH** the URL anatomy and the rendered client-side webpage characteristics—including the DOM tree, login forms, JavaScript behaviors, visual layouts, SSL certificates, and domain authority—before rendering a final classification (`SAFE`, `SUSPICIOUS`, `PHISHING`).

---

## 2. Multi-Modal System Architecture

```
+-----------------------------------------------------------------------------------+
|                           BROWSER CLIENT (Chrome MV3)                             |
|                                                                                   |
|  [Tab Navigation / MutationObserver]                                             |
|          |                                                                        |
|          +--> content.js: Extracts DOM Tree, Forms, Scripts, Images               |
|          +--> background.js: Captures Viewport Screenshot (JPEG Base64)          |
+-----------------------------------------------------------------------------------+
                                       |
                                       | POST /predict-hybrid (JSON Payload)
                                       v
+-----------------------------------------------------------------------------------+
|                        FLASK BACKEND & HYBRID AI ENGINE                           |
|                                                                                   |
|  +---------------------------+       +-----------------------------------------+  |
|  | 1. URL Feature Extractor  |       | 2. HTML & DOM Content Analyzer          |  |
|  | (42 Lexical/Entropy Feats)|       | (Scareware, Iframes, Hidden Elements)   |  |
|  +---------------------------+       +-----------------------------------------+  |
|  +---------------------------+       +-----------------------------------------+  |
|  | 3. Form Security Analyzer |       | 4. JavaScript Threat Analyzer           |  |
|  | (Password, OTP, CC, Action)|      | (eval, packers, keyloggers, base64)     |  |
|  +---------------------------+       +-----------------------------------------+  |
|  +---------------------------+       +-----------------------------------------+  |
|  | 5. Visual AI Comparator   |       | 6. OCR Text Urgency Analyzer            |  |
|  | (dHash, RGB Palettes)     |       | (Scareware urgency heuristic)           |  |
|  +---------------------------+       +-----------------------------------------+  |
|  +---------------------------+       +-----------------------------------------+  |
|  | 7. SSL & Protocol Checker |       | 8. Domain Reputation Engine             |  |
|  | (TLS, Expiry, Self-Signed)|       | (DynDNS, DNS resolves, Blacklist)      |  |
|  +---------------------------+       +-----------------------------------------+  |
|  +---------------------------+       +-----------------------------------------+  |
|  | 9. Image Asset Analyzer   |       | 10. Email Exfiltration Detector         |  |
|  | (Favicon, QR Quishing)    |       | (mailto: forms, webhook relays)         |  |
|  +---------------------------+       +-----------------------------------------+  |
|                                                                                   |
|         |                                      |                                  |
|         v                                      v                                  |
|  +---------------------------+       +-----------------------------------------+  |
|  | Multi-Layer Threat Scores |       | Machine Learning Model Ensemble         |  |
|  | (8 Security Layers: 0-100)|       | (101 Features -> Scaler -> Classifier)  |  |
|  +---------------------------+       +-----------------------------------------+  |
|                 \                                 /                               |
|                  v                               v                                |
|        +---------------------------------------------------+                      |
|        |           HYBRID RISK FUSION ENGINE               |                      |
|        | - Multi-Layer Weighted Linear Fusion              |                      |
|        | - Defense-in-Depth Non-Linear Security Overrides  |                      |
|        +---------------------------------------------------+                      |
|                                  |                                                |
|                                  v                                                |
|             Classification: SAFE | SUSPICIOUS | PHISHING                          |
|             Hybrid Score: 0.0 - 100.0 | Confidence Score                          |
+-----------------------------------------------------------------------------------+
                                   |
                                   v
             [Browser Notification / Full Warning Screen / Extension UI]
```

---

## 3. The 8 Security Analysis Layers

### Layer 1: URL & DNS Structure (Weight: 25%)
- **Directory:** `feature_extractors/url_feature_extractor.py`
- **Features Extracted:** 42 distinct lexical and structural vectors including URL length, domain length, path length, dot count, hyphen count, subdomain depth, Shannon entropy, brand keyword presence, IP address in hostname, URL shortening patterns, and TLD reputation risk.

### Layer 2: HTML & DOM Integrity (Weight: 20%)
- **Directory:** `content_analyzer/html_content_analyzer.py`
- **Capabilities:** Analyzes the rendered HTML source using BeautifulSoup. Detects invisible CSS deceptive text, hidden zero-pixel iframes, external link ratios, meta-refresh auto-redirects, browser fingerprinting scripts, CoinHive/CryptoLoot web miners, fake alert popups, clipboard hijacking (`navigator.clipboard.writeText`), and context menu disabling (`oncontextmenu="return false"`).

### Layer 3: Credential Form Security (Weight: 15%)
- **Directory:** `form_analyzer/form_security_analyzer.py`
- **Capabilities:** Inspects `<form>` descriptors, action targets, and `<input>` elements. Detects password fields, credit card numbers, CVVs, expiration dates, OTP/2FA verification codes, empty or `javascript:` form actions, cross-domain credential exfiltration (where input fields are sent to an external domain distinct from the visited origin), and insecure HTTP form submissions on HTTPS pages.

### Layer 4: JavaScript Behavioral Inspection (Weight: 10%)
- **Directory:** `javascript_analyzer/js_threat_analyzer.py`
- **Capabilities:** Evaluates client-side scripts for dynamic execution and evasion techniques: `eval()`, `document.write()`, `Function()` constructor, Base64 unpacking (`atob`), Dean Edwards packer strings (`eval(function(p,a,c,k,e,d)...)`), keystroke interception listeners (`keydown`/`keypress`), credential interception hooks, and `history.pushState` manipulation.

### Layer 5: Visual Brand AI & Layout Similarity (Weight: 10%)
- **Directory:** `visual_similarity/visual_comparator.py`
- **Capabilities:** Analyzes real-time viewport screenshots captured by `chrome.tabs.captureVisibleTab`. Utilizes difference hashing (`dHash`) and RGB color palette distance metrics across major impersonated targets (Google, Microsoft, PayPal, Apple, Amazon, Netflix, Chase Bank, Binance). If a webpage visually mimics an authentic brand layout while running on an unauthorized hostname, a visual spoofing alert is flagged.

### Layer 6: SSL & Protocol Inspector (Weight: 10%)
- **Directory:** `ssl_checker/ssl_inspector.py`
- **Capabilities:** Performs active socket-level TLS handshakes. Inspects certificate authority validity, certificate expiration dates, self-signed certificates, TLS version deprecation, and mixed HTTP/HTTPS content.

### Layer 7: Domain Reputation & Threat Feeds (Weight: 5%)
- **Directory:** `domain_reputation/reputation_engine.py`
- **Capabilities:** Checks DNS resolvability, dynamic DNS providers (e.g., `duckdns.org`, `no-ip.biz`, `ngrok.io`), known top-traffic whitelisted authority domains, and SQLite blacklist rule matches.

### Layer 8: Image Assets & Quishing Detector (Weight: 5%)
- **Directory:** `image_analyzer/image_asset_analyzer.py` & `email_detector/email_exfiltration_detector.py`
- **Capabilities:** Evaluates hotlinked brand logos, favicon origins, and QR code markers (Quishing) that attempt to redirect mobile users away from desktop inspection.

---

## 4. Hybrid Risk Fusion Engine

The decision engine combines multi-layer threat intensities with defensive override rules:

### A. Linear Weighted Fusion
$$\text{Score}_{\text{base}} = \sum_{i=1}^{8} w_i \cdot \text{Threat}_i$$

Where weights $w_i$ satisfy $\sum w_i = 1.0$:
- URL Threat: $0.25$
- Content HTML Threat: $0.20$
- Form Threat: $0.15$
- JavaScript Threat: $0.10$
- Visual AI Threat: $0.10$
- SSL/TLS Threat: $0.10$
- Domain Reputation Threat: $0.05$
- Image & Quishing Threat: $0.05$

### B. Non-Linear Defense-in-Depth Overrides
A strictly weighted average could allow an attacker with a clean URL to exfiltrate credentials. To eliminate this risk, the engine enforces non-linear override rules:
1. **Active Blacklist Override:** If domain is on the SOC blacklist $\rightarrow \text{Score} = 100.0 \rightarrow \text{PHISHING}$.
2. **Cross-Domain Credential Exfiltration:** If a form contains a password/credit-card input and submits to an external domain $\rightarrow \text{Score} \ge 88.0 \rightarrow \text{PHISHING}$.
3. **Brand Impersonation with Login:** If visual or URL brand similarity matches an official institution on an unauthorized domain while soliciting credentials $\rightarrow \text{Score} \ge 85.0 \rightarrow \text{PHISHING}$.
4. **Raw IP Address with Authentication:** If hostname is an IPv4/IPv6 address soliciting credentials $\rightarrow \text{Score} \ge 90.0 \rightarrow \text{PHISHING}$.
5. **High-Threat URL Override:** If lexical URL analysis or ML confidence produces a threat score $\ge 75.0 \rightarrow \text{Score} \ge 75.0 \rightarrow \text{PHISHING}$.
6. **Whitelisted Authority Domain:** Verified top domains without injection $\rightarrow \text{Score} \le 10.0 \rightarrow \text{SAFE}$.

### C. Decision Thresholds
- **$\text{Score} < 40.0$**: **`SAFE`** (Green badge, normal navigation)
- **$40.0 \le \text{Score} < 75.0$**: **`SUSPICIOUS`** (Yellow badge, user caution advised)
- **$\text{Score} \ge 75.0$**: **`PHISHING`** (Red badge, warning screen triggered)

---

## 5. Machine Learning Benchmarking Results

The hybrid pipeline evaluated 8 machine learning models on a balanced 101-feature multi-modal dataset ($N=3,000$ samples):

| Model Name | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** *(Champion)* | **97.00%** | **96.71%** | **97.32%** | **97.01%** | **0.9934** | **0.320s** |
| **Extra Trees** | 96.67% | 96.69% | 96.64% | 96.67% | 0.9931 | 0.228s |
| **Voting Ensemble** | 96.17% | 95.71% | 96.64% | 96.17% | 0.9926 | 0.941s |
| **AdaBoost** | 94.67% | 94.95% | 94.30% | 94.62% | 0.9859 | 0.174s |
| **Gradient Boosting** | 94.67% | 94.35% | 94.97% | 94.66% | 0.9840 | 0.817s |
| **Decision Tree** | 93.83% | 93.36% | 94.30% | 93.83% | 0.9383 | 0.024s |
| **K-Nearest Neighbors** | 87.83% | 89.44% | 85.57% | 87.46% | 0.9575 | 0.007s |
| **Gaussian Naive Bayes** | 83.17% | 84.14% | 81.54% | 82.82% | 0.9238 | 0.007s |

---

## 6. Verification and Test Coverage

The test suite in `tests/` executes 34 unit and integration tests with 100% passing status:
- `TestHTMLContentAnalyzer`: Verifies DOM parsing, cryptominer signatures, hidden text, and scareware alerts.
- `TestFormSecurityAnalyzer`: Verifies password input, OTP detection, and cross-domain action exfiltration.
- `TestJavaScriptThreatAnalyzer`: Verifies `eval()`, `document.write()`, Base64 decoding, and keylogger detection.
- `TestVisualComparator`: Verifies perceptual dHash comparison and brand color matching.
- `TestHybridRiskEngine`: Verifies weighted score fusion and critical non-linear overrides.
- `TestHybridAPIEndpoints`: Verifies `/predict-hybrid`, `/predict`, `/export-scans`, `/health`, `/stats`, and `/blacklist`.
- **Inference Latency:** Average single-scan execution is $\approx 172.4\text{ ms}$, operating well beneath real-time browser performance budgets.
