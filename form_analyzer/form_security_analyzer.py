"""
PHISH GUARD - Hybrid AI Browser Security System
Module: form_analyzer.form_security_analyzer

Analyzes login, banking, and credential-harvesting forms on visited webpages.
Inspects form action targets, cross-domain submission, password inputs,
credit card inputs, OTP fields, and deceptive overlay forms.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

CC_NAME_PATTERNS = [
    r"card[-_]?num", r"cc[-_]?num", r"credit[-_]?card", r"card[-_]?no",
    r"cvv", r"cvc", r"exp[-_]?date", r"cardholder"
]

OTP_PATTERNS = [
    r"otp", r"token", r"2fa", r"auth[-_]?code", r"security[-_]?code",
    r"verification[-_]?code", r"sms[-_]?code"
]


class FormSecurityAnalyzer:
    """Evaluates security posture and credential harvesting indicators of webpage forms."""

    def __init__(self):
        pass

    def analyze_forms(
        self,
        forms_data: List[Dict[str, Any]],
        current_url: str = ""
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Analyzes a list of form descriptors collected by the content script.
        forms_data is a list of dicts:
            {
               "action": str,
               "method": str,
               "inputs": [
                   {"type": str, "name": str, "id": str, "placeholder": str}
               ]
            }
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        forms_data = forms_data or []
        current_domain = urlparse(current_url).netloc.lower() if current_url else ""
        current_is_https = current_url.lower().startswith("https://") if current_url else False

        total_forms = len(forms_data)
        has_password_field = 0.0
        has_credit_card_field = 0.0
        has_otp_field = 0.0
        has_email_field = 0.0
        total_inputs = 0
        hidden_inputs = 0
        external_action_count = 0
        empty_action_count = 0
        http_action_on_https = 0.0
        suspicious_method_count = 0

        for f in forms_data:
            action = (f.get("action") or "").strip().lower()
            method = (f.get("method") or "get").strip().lower()
            inputs = f.get("inputs") or []

            total_inputs += len(inputs)
            form_has_password = False

            # Inspect inputs
            for inp in inputs:
                itype = (inp.get("type") or "text").lower()
                iname = (inp.get("name") or "").lower()
                iid = (inp.get("id") or "").lower()
                iplaceholder = (inp.get("placeholder") or "").lower()
                combined_ident = f"{iname} {iid} {iplaceholder}"

                if itype == "password" or "password" in combined_ident or "passwd" in combined_ident:
                    has_password_field = 1.0
                    form_has_password = True

                if any(re.search(pat, combined_ident) for pat in CC_NAME_PATTERNS):
                    has_credit_card_field = 1.0

                if any(re.search(pat, combined_ident) for pat in OTP_PATTERNS):
                    has_otp_field = 1.0

                if itype == "email" or "email" in combined_ident or "user" in combined_ident or "login" in combined_ident:
                    has_email_field = 1.0

                if itype == "hidden":
                    hidden_inputs += 1

            # Analyze Action target
            if not action or action == "#" or action.startswith("javascript:") or action == "about:blank":
                empty_action_count += 1
            elif action.startswith(("http://", "https://")):
                action_domain = urlparse(action).netloc.lower()
                if current_domain and action_domain and action_domain != current_domain:
                    external_action_count += 1
                if current_is_https and action.startswith("http://"):
                    http_action_on_https = 1.0

            # Method checks: password sent via GET
            if form_has_password and method == "get":
                suspicious_method_count += 1

        # Form Threat Score Calculation (0.0 to 100.0)
        form_score = 0.0
        if has_password_field:
            form_score += 20.0
        if has_credit_card_field:
            form_score += 35.0
        if has_otp_field:
            form_score += 25.0
        if external_action_count > 0:
            form_score += 40.0
        if http_action_on_https:
            form_score += 30.0
        if suspicious_method_count > 0:
            form_score += 25.0
        if empty_action_count > 0 and has_password_field:
            form_score += 20.0

        form_score = min(100.0, form_score)

        features: Dict[str, float] = {
            "total_forms": float(total_forms),
            "has_password_field": has_password_field,
            "has_credit_card_field": has_credit_card_field,
            "has_otp_field": has_otp_field,
            "has_email_field": has_email_field,
            "total_inputs": float(total_inputs),
            "hidden_inputs": float(hidden_inputs),
            "external_action_count": float(external_action_count),
            "empty_action_count": float(empty_action_count),
            "http_action_on_https": http_action_on_https,
            "suspicious_method_count": float(suspicious_method_count),
            "form_threat_score": round(form_score, 2)
        }

        reasons: List[str] = []
        if external_action_count > 0:
            reasons.append(f"Cross-domain credential exfiltration: Form posts user input to external domain")
        if has_credit_card_field:
            reasons.append("Webpage solicits sensitive credit card / banking details (CVV/Card Number)")
        if has_password_field and empty_action_count > 0:
            reasons.append("Password input detected inside form with dummy or empty action target (#)")
        if http_action_on_https:
            reasons.append("Form downgrades security: transmits credentials over unencrypted HTTP")
        if has_otp_field:
            reasons.append("Solicitation of One-Time Password (OTP) or Multi-Factor Authentication tokens")
        if suspicious_method_count > 0:
            reasons.append("Password transmitted via plaintext GET parameter in URL")

        metadata: Dict[str, Any] = {
            "form_threat_score": form_score,
            "has_password": bool(has_password_field),
            "has_credit_card": bool(has_credit_card_field),
            "has_otp": bool(has_otp_field),
            "external_action": external_action_count > 0
        }

        return features, reasons, metadata
