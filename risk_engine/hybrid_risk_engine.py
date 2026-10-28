"""
PHISH GUARD - Hybrid AI Browser Security System
Module: risk_engine.hybrid_risk_engine

Multi-Layer Weighted Risk Fusion Engine combining:
- URL AI Analysis (25%)
- Content HTML Analysis (20%)
- Form Security Analysis (15%)
- JavaScript Behavioral Analysis (10%)
- Visual & Brand AI Analysis (10%)
- SSL & Protocol Analysis (10%)
- Domain Reputation Analysis (5%)
- Image & Asset Analysis (5%)

Applies defense-in-depth non-linear overrides to classify websites as:
SAFE, SUSPICIOUS, or PHISHING.
"""

from typing import Any, Dict, List, Tuple

# Default Layer Weights (Sum = 1.0)
DEFAULT_WEIGHTS = {
    "url": 0.25,
    "content": 0.20,
    "form": 0.15,
    "javascript": 0.10,
    "visual": 0.10,
    "ssl": 0.10,
    "reputation": 0.05,
    "image": 0.05
}

# Decision Thresholds
THRESHOLD_SAFE = 40.0       # < 40.0 is SAFE
THRESHOLD_PHISHING = 75.0   # >= 75.0 is PHISHING, otherwise SUSPICIOUS


class HybridRiskEngine:
    """Combines multi-modal threat scores and enforces non-linear security overrides."""

    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or DEFAULT_WEIGHTS

    def evaluate(
        self,
        url_threat_score: float,
        content_threat_score: float,
        form_threat_score: float,
        js_threat_score: float,
        visual_threat_score: float,
        ssl_threat_score: float,
        reputation_threat_score: float,
        image_threat_score: float,
        critical_flags: Dict[str, bool] = None,
        all_reasons: List[str] = None
    ) -> Dict[str, Any]:
        """
        Fuses all layer threat scores (each 0.0 to 100.0) into a unified hybrid verdict.
        Returns:
            {
               "decision": "SAFE" | "SUSPICIOUS" | "PHISHING",
               "risk_level": "Low" | "Medium" | "High" | "Critical",
               "hybrid_score": float (0-100),
               "confidence": float (0-100),
               "layer_scores": dict,
               "reasons": list of str,
               "is_critical_override": bool
            }
        """
        critical_flags = critical_flags or {}
        all_reasons = all_reasons or []

        # 1. Base Weighted Score Calculation
        weighted_score = (
            (url_threat_score * self.weights["url"]) +
            (content_threat_score * self.weights["content"]) +
            (form_threat_score * self.weights["form"]) +
            (js_threat_score * self.weights["javascript"]) +
            (visual_threat_score * self.weights["visual"]) +
            (ssl_threat_score * self.weights["ssl"]) +
            (reputation_threat_score * self.weights["reputation"]) +
            (image_threat_score * self.weights["image"])
        )
        hybrid_score = round(max(0.0, min(100.0, weighted_score)), 2)

        # 2. Defense-in-Depth Non-Linear Overrides
        is_override = False
        override_reason = None

        # Rule A: Active Blacklist
        if critical_flags.get("is_blacklisted", False):
            hybrid_score = 100.0
            is_override = True
            override_reason = "CRITICAL OVERRIDE: Domain matches verified security blacklist"

        # Rule B: Cross-Domain Credential Exfiltration
        elif critical_flags.get("cross_domain_credential_post", False):
            hybrid_score = max(hybrid_score, 88.0)
            is_override = True
            override_reason = "CRITICAL OVERRIDE: Form exfiltrates credentials to an external unauthorized domain"

        # Rule C: Brand Impersonation with Login Form on Untrusted Host
        elif critical_flags.get("brand_impersonation_with_login", False):
            hybrid_score = max(hybrid_score, 85.0)
            is_override = True
            override_reason = "CRITICAL OVERRIDE: Unauthorized brand login form detected"

        # Rule D: Raw IP Address with Password Form or suspicious path
        elif critical_flags.get("ip_with_login", False) or critical_flags.get("is_ip_suspicious", False):
            hybrid_score = max(hybrid_score, 90.0)
            is_override = True
            override_reason = "CRITICAL OVERRIDE: Raw IP address soliciting sensitive paths or credentials"

        # Rule E: High Threat URL lexical / ML override (handles URL-only scans and brand spoofing domains)
        elif url_threat_score >= 70.0:
            hybrid_score = max(hybrid_score, url_threat_score)
            is_override = True
            override_reason = "CRITICAL OVERRIDE: Lexical brand impersonation or high-confidence URL phishing markers"

        elif url_threat_score >= 45.0:
            hybrid_score = max(hybrid_score, url_threat_score)

        # Rule F: Verified Top Whitelisted Domain without injection
        elif critical_flags.get("is_top_domain", False) and url_threat_score < 15.0 and content_threat_score < 20.0:
            hybrid_score = min(hybrid_score, 10.0)

        # 3. Decision Classification
        if hybrid_score >= THRESHOLD_PHISHING:
            decision = "PHISHING"
            risk_level = "Critical" if hybrid_score >= 88.0 else "High"
            confidence = round(max(75.0, hybrid_score), 1)
        elif hybrid_score >= THRESHOLD_SAFE:
            decision = "SUSPICIOUS"
            risk_level = "Medium"
            confidence = round(hybrid_score, 1)
        else:
            decision = "SAFE"
            risk_level = "Low"
            confidence = round(max(70.0, 100.0 - hybrid_score), 1)

        # Prepend override reason if triggered
        final_reasons = list(all_reasons)
        if override_reason and override_reason not in final_reasons:
            final_reasons.insert(0, override_reason)

        if not final_reasons:
            if decision == "SAFE":
                final_reasons.append("Multi-layer analysis verified clean HTML structure, SSL encryption, and legitimate domain reputation")
            else:
                final_reasons.append("Composite multi-layer signals indicate elevated phishing probability")

        layer_scores = {
            "url_score": round(url_threat_score, 1),
            "content_score": round(content_threat_score, 1),
            "form_score": round(form_threat_score, 1),
            "javascript_score": round(js_threat_score, 1),
            "visual_score": round(visual_threat_score, 1),
            "ssl_score": round(ssl_threat_score, 1),
            "reputation_score": round(reputation_threat_score, 1),
            "image_score": round(image_threat_score, 1)
        }

        return {
            "decision": decision,
            "risk_level": risk_level,
            "hybrid_score": hybrid_score,
            "confidence": confidence,
            "layer_scores": layer_scores,
            "reasons": final_reasons[:6],  # Top 6 concise reasons for display
            "is_critical_override": is_override
        }
