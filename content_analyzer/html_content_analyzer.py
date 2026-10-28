"""
PHISH GUARD - Hybrid AI Browser Security System
Module: content_analyzer.html_content_analyzer

Performs deep structural, lexical, and behavioral inspection on webpage HTML content.
Analyzes hidden elements, iframes, links, scripts, CSS obfuscation, canvas fingerprinting,
and scareware indicators.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup

SCAREWARE_PHRASES = [
    "critical alert", "virus detected", "account suspended", "security alert",
    "call microsoft support", "identity theft", "hacked", "immediate action required",
    "unauthorized access", "system infected", "toll-free", "your computer has been locked",
    "financial freeze", "suspended account", "kyc expired", "wallet compromised"
]

CRYPTOMINER_SIGNATURES = [
    "coinhive", "cryptoloot", "webminer", "monerominer", "coin-hive",
    "miner.js", "cryptonight", "deepminer", "jsecoin"
]

FINGERPRINTING_SIGNATURES = [
    "todataurl", "getimagedata", "measuretext", "webglrenderingcontext",
    "audiofingerprint", "enumerateDevices"
]


class HTMLContentAnalyzer:
    """Analyzes raw HTML source code and DOM components extracted by browser extension."""

    def __init__(self):
        pass

    def analyze_html(
        self,
        html_content: str,
        base_url: str = "",
        dom_metrics: Dict[str, Any] = None
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Extracts structural, lexical, and evasive features from HTML.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        dom_metrics = dom_metrics or {}
        html = html_content or ""
        soup = BeautifulSoup(html, "html.parser")
        base_domain = urlparse(base_url).netloc.lower() if base_url else ""

        # 1. Page Title Analysis
        title_tag = soup.find("title")
        title_text = title_tag.get_text().strip() if title_tag else ""
        title_len = len(title_text)
        has_empty_title = 1.0 if not title_text else 0.0

        # 2. Link Distribution (Internal vs External vs Empty)
        links = soup.find_all("a", href=True)
        total_links = len(links)
        internal_links = 0
        external_links = 0
        empty_links = 0

        for a in links:
            href = a.get("href", "").strip().lower()
            if not href or href == "#" or href.startswith("javascript:"):
                empty_links += 1
                continue
            if href.startswith(("http://", "https://")):
                link_domain = urlparse(href).netloc.lower()
                if base_domain and link_domain and link_domain != base_domain:
                    external_links += 1
                else:
                    internal_links += 1
            else:
                internal_links += 1

        external_link_ratio = (external_links / max(1, total_links))
        empty_link_ratio = (empty_links / max(1, total_links))

        # 3. Iframes & Invisible Elements
        iframes = soup.find_all("iframe")
        iframe_count = len(iframes)
        invisible_iframes = 0
        for ifr in iframes:
            style = (ifr.get("style", "") + " " + ifr.get("class", [""])[0] if isinstance(ifr.get("class"), list) else "").lower()
            width = ifr.get("width", "100")
            height = ifr.get("height", "100")
            if (
                "display:none" in style
                or "visibility:hidden" in style
                or "opacity:0" in style
                or width in ["0", "1", "0px", "1px"]
                or height in ["0", "1", "0px", "1px"]
            ):
                invisible_iframes += 1

        # 4. Scripts & Inlining
        script_tags = soup.find_all("script")
        total_scripts = len(script_tags)
        inline_scripts = sum(1 for s in script_tags if not s.get("src"))
        external_scripts = total_scripts - inline_scripts

        # Combined script text for behavioral scanning
        raw_script_text = " ".join([s.get_text() for s in script_tags]).lower()

        # 5. Evasive CSS & Hidden Text
        hidden_elements_count = 0
        for tag in soup.find_all(True):
            style = tag.get("style", "").lower()
            if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                hidden_elements_count += 1

        # 6. Meta Tags & Auto Redirects
        meta_refresh = 1.0 if soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}) else 0.0
        meta_count = len(soup.find_all("meta"))

        # 7. Scareware / Urgent Phishing Language
        page_text = soup.get_text().lower()
        matched_scareware = [phrase for phrase in SCAREWARE_PHRASES if phrase in page_text]
        scareware_detected = 1.0 if matched_scareware else 0.0

        # 8. Cryptominers & Fingerprinting in Source
        has_cryptominer = 1.0 if any(sig in raw_script_text for sig in CRYPTOMINER_SIGNATURES) else 0.0
        has_fingerprinting = 1.0 if sum(1 for sig in FINGERPRINTING_SIGNATURES if sig in raw_script_text) >= 2 else 0.0

        # 9. Anti-Analysis & Interaction Interception
        has_disabled_rightclick = 1.0 if (
            "oncontextmenu=\"return false\"" in html.lower()
            or "event.button == 2" in raw_script_text
            or dom_metrics.get("context_menu_disabled", False)
        ) else 0.0

        has_clipboard_hijack = 1.0 if (
            "navigator.clipboard.writetext" in raw_script_text
            or "addeventlistener('copy'" in raw_script_text
            or dom_metrics.get("clipboard_intercepted", False)
        ) else 0.0

        has_fake_popup = 1.0 if ("window.open" in raw_script_text and "popup" in raw_script_text) else 0.0

        # 10. Form & Password elements count
        num_forms = len(soup.find_all("form"))
        num_password_inputs = len(soup.find_all("input", attrs={"type": re.compile(r"password", re.I)}))

        # 11. Base64 scripts or data URIs
        base64_scripts_count = float(len(re.findall(r"data:text/javascript;base64,", html, re.I)))

        # 12. Content Threat Score (0.0 to 100.0)
        content_score = 0.0
        if scareware_detected:
            content_score += 35.0
        if invisible_iframes > 0:
            content_score += 25.0
        if has_cryptominer:
            content_score += 30.0
        if meta_refresh:
            content_score += 20.0
        if has_disabled_rightclick:
            content_score += 15.0
        if has_clipboard_hijack:
            content_score += 15.0
        if external_link_ratio > 0.6 and total_links > 5:
            content_score += 15.0
        if empty_link_ratio > 0.4 and total_links > 3:
            content_score += 15.0
        if num_password_inputs > 0 and base_domain and not base_url.startswith("https://"):
            content_score += 25.0
        if base64_scripts_count > 0:
            content_score += 15.0

        content_score = min(100.0, content_score)

        # Compile features dictionary
        features: Dict[str, float] = {
            "title_length": float(title_len),
            "has_empty_title": has_empty_title,
            "total_links": float(total_links),
            "internal_links": float(internal_links),
            "external_links": float(external_links),
            "external_link_ratio": round(float(external_link_ratio), 4),
            "empty_link_ratio": round(float(empty_link_ratio), 4),
            "iframe_count": float(iframe_count),
            "invisible_iframes": float(invisible_iframes),
            "total_scripts": float(total_scripts),
            "inline_scripts": float(inline_scripts),
            "external_scripts": float(external_scripts),
            "hidden_elements_count": float(hidden_elements_count),
            "meta_count": float(meta_count),
            "has_meta_refresh": meta_refresh,
            "scareware_detected": scareware_detected,
            "has_cryptominer": has_cryptominer,
            "has_fingerprinting": has_fingerprinting,
            "has_disabled_rightclick": has_disabled_rightclick,
            "has_clipboard_hijack": has_clipboard_hijack,
            "has_fake_popup": has_fake_popup,
            "content_num_forms": float(num_forms),
            "content_num_passwords": float(num_password_inputs),
            "base64_scripts_count": base64_scripts_count,
            "content_threat_score": round(content_score, 2)
        }

        # Detection Reasons
        reasons: List[str] = []
        if scareware_detected:
            reasons.append(f"Scareware alert text found: '{matched_scareware[0]}'")
        if invisible_iframes > 0:
            reasons.append(f"Detected {invisible_iframes} hidden/invisible iframe(s) commonly used for drive-by injection")
        if has_cryptominer:
            reasons.append("Browser cryptominer signature identified in webpage scripts")
        if meta_refresh:
            reasons.append("Automated client-side meta-refresh redirect detected")
        if has_disabled_rightclick:
            reasons.append("Website actively disables right-click context menu to prevent source inspection")
        if has_clipboard_hijack:
            reasons.append("Suspicious clipboard API manipulation detected")
        if empty_link_ratio > 0.4 and total_links > 3:
            reasons.append(f"Abnormally high ratio of dummy/empty hyperlinks ({empty_link_ratio * 100:.0f}%)")
        if external_link_ratio > 0.6 and total_links > 5:
            reasons.append("Page links predominantly point to external third-party domains")

        metadata: Dict[str, Any] = {
            "title": title_text,
            "total_links": total_links,
            "matched_scareware": matched_scareware,
            "content_threat_score": content_score
        }

        return features, reasons, metadata
