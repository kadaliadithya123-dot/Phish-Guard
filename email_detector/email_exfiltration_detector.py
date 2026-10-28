"""
PHISH GUARD - Hybrid AI Browser Security System
Module: email_detector.email_exfiltration_detector

Detects credential exfiltration via mailto: links, Webhook relays
(Telegram bots, Discord webhooks), and third-party email form processors (Formspree, EmailJS).
"""

import re
from typing import Any, Dict, List, Tuple

WEBHOOK_RELAYS = [
    "api.telegram.org/bot", "discord.com/api/webhooks", "hooks.slack.com",
    "formspree.io", "emailjs.com", "formkeep.com", "formsubmit.co"
]


class EmailExfiltrationDetector:
    """Identifies attempts to relay harvested credentials via mailto or third-party webhooks."""

    def __init__(self):
        pass

    def detect_exfiltration(
        self,
        html_content: str,
        forms_data: List[Dict[str, Any]] = None
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Analyzes HTML and form actions for email/webhook exfiltration targets.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        html = (html_content or "").lower()
        forms_data = forms_data or []

        has_mailto_form = 0.0
        has_webhook_relay = 0.0
        matched_relays = []

        # 1. Form Action Check
        for f in forms_data:
            action = (f.get("action") or "").lower()
            if action.startswith("mailto:"):
                has_mailto_form = 1.0
            for relay in WEBHOOK_RELAYS:
                if relay in action:
                    has_webhook_relay = 1.0
                    matched_relays.append(relay)

        # 2. General HTML search
        for relay in WEBHOOK_RELAYS:
            if relay in html and relay not in matched_relays:
                has_webhook_relay = 1.0
                matched_relays.append(relay)

        has_mailto_links = 1.0 if "href=\"mailto:" in html or "href='mailto:" in html else 0.0

        # Score calculation
        score = 0.0
        if has_webhook_relay:
            score += 55.0
        if has_mailto_form:
            score += 45.0

        score = min(100.0, score)

        features: Dict[str, float] = {
            "has_mailto_form": has_mailto_form,
            "has_webhook_relay": has_webhook_relay,
            "has_mailto_links": has_mailto_links,
            "email_threat_score": round(score, 2)
        }

        reasons: List[str] = []
        if has_webhook_relay:
            reasons.append(f"Direct credential exfiltration webhook endpoint detected ({', '.join(set(matched_relays))})")
        if has_mailto_form:
            reasons.append("Form directly exfiltrates submitted data via client mailto: protocol")

        metadata: Dict[str, Any] = {
            "email_threat_score": score,
            "matched_relays": list(set(matched_relays))
        }

        return features, reasons, metadata
