"""
PHISH GUARD - Hybrid AI Browser Security System
Module: ocr_detector.ocr_text_analyzer

Detects embedded phishing text, security warnings, and urgency phrases inside
images and webpage screenshots to defeat text-in-image evasion techniques.
"""

import base64
import io
import re
from typing import Any, Dict, List, Tuple
from PIL import Image

URGENT_OCR_PHRASES = [
    "verify account", "update payment", "login immediately", "expired account",
    "bank verification", "free gift", "lottery", "urgent", "limited time",
    "account suspended", "security alert", "confirm identity", "wallet disconnected",
    "unauthorized login", "24 hours to verify", "avoid suspension"
]


class OCRTextAnalyzer:
    """Analyzes text embedded within webpage images, banners, and screenshot captures."""

    def __init__(self):
        pass

    def analyze_image_text(
        self,
        screenshot_base64: str = None,
        extracted_text_hints: List[str] = None
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Inspects text found in image assets or optical text extracts.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        extracted_text_hints = extracted_text_hints or []
        combined_text = " ".join(extracted_text_hints).lower()

        # Check for urgent / phishing phrases
        matched_phrases = []
        for phrase in URGENT_OCR_PHRASES:
            if phrase in combined_text:
                matched_phrases.append(phrase)

        phrase_count = len(matched_phrases)
        has_urgent_ocr = 1.0 if phrase_count > 0 else 0.0

        ocr_score = min(100.0, phrase_count * 30.0)

        features: Dict[str, float] = {
            "ocr_urgent_phrase_count": float(phrase_count),
            "ocr_has_urgency": has_urgent_ocr,
            "ocr_threat_score": round(ocr_score, 2)
        }

        reasons: List[str] = []
        if has_urgent_ocr:
            reasons.append(f"Visual text analysis detected deceptive urgency phrases: '{', '.join(matched_phrases[:3])}'")

        metadata: Dict[str, Any] = {
            "ocr_threat_score": ocr_score,
            "matched_phrases": matched_phrases
        }

        return features, reasons, metadata
