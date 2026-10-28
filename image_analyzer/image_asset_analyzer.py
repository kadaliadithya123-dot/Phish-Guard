"""
PHISH GUARD - Hybrid AI Browser Security System
Module: image_analyzer.image_asset_analyzer

Inspects webpage image tags, favicons, external image hotlinking,
and detects QR code credential harvesting (quishing) indicators.
"""

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

BRAND_FAVICON_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "bankofamerica", "binance", "metamask", "facebook"
]


class ImageAssetAnalyzer:
    """Analyzes image assets, favicons, and hotlinked resources."""

    def __init__(self):
        pass

    def analyze_images(
        self,
        images_data: List[Dict[str, Any]],
        favicon_url: str = "",
        current_url: str = ""
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Analyzes image metadata collected by the extension.
        images_data is a list of {"src": ..., "alt": ..., "width": ..., "height": ...}
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        images_data = images_data or []
        current_domain = urlparse(current_url).netloc.lower() if current_url else ""

        total_images = len(images_data)
        external_images = 0
        base64_images = 0
        has_brand_in_img = 0.0
        has_quishing_indicator = 0.0
        detected_img_brands = []

        for img in images_data:
            src = (img.get("src") or "").strip().lower()
            alt = (img.get("alt") or "").strip().lower()

            if src.startswith("data:image"):
                base64_images += 1
                continue

            if src.startswith(("http://", "https://")):
                src_domain = urlparse(src).netloc.lower()
                if current_domain and src_domain and src_domain != current_domain:
                    external_images += 1

            # Brand logo detection in filename / alt
            combined = f"{src} {alt}"
            for b in BRAND_FAVICON_KEYWORDS:
                if b in combined and not current_domain.endswith(f"{b}.com"):
                    has_brand_in_img = 1.0
                    detected_img_brands.append(b)

            # Quishing / QR Code detection
            if "qr" in combined or "qrcode" in combined:
                has_quishing_indicator = 1.0

        external_img_ratio = (external_images / max(1, total_images))

        # Favicon analysis
        has_spoofed_favicon = 0.0
        fav_lower = (favicon_url or "").lower()
        if fav_lower:
            for b in BRAND_FAVICON_KEYWORDS:
                if b in fav_lower and not current_domain.endswith(f"{b}.com"):
                    has_spoofed_favicon = 1.0
                    detected_img_brands.append(b)

        # Threat Score (0 to 100)
        img_score = 0.0
        if has_spoofed_favicon:
            img_score += 40.0
        if has_brand_in_img:
            img_score += 25.0
        if has_quishing_indicator:
            img_score += 20.0
        if external_img_ratio > 0.7 and total_images > 4:
            img_score += 20.0

        img_score = min(100.0, img_score)

        features: Dict[str, float] = {
            "total_images": float(total_images),
            "external_image_ratio": round(float(external_img_ratio), 4),
            "base64_image_count": float(base64_images),
            "has_brand_logo_abuse": has_brand_in_img,
            "has_spoofed_favicon": has_spoofed_favicon,
            "has_quishing_indicator": has_quishing_indicator,
            "image_threat_score": round(img_score, 2)
        }

        reasons: List[str] = []
        if has_spoofed_favicon:
            reasons.append("Webpage borrows an official brand favicon on an unauthorized domain")
        if has_brand_in_img and detected_img_brands:
            reasons.append(f"Image elements contain hotlinked brand logos of '{', '.join(set(detected_img_brands))}'")
        if has_quishing_indicator:
            reasons.append("QR-code asset detected; possible QR-phishing (quishing) campaign")
        if external_img_ratio > 0.7 and total_images > 4:
            reasons.append("High proportion of image assets hotlinked directly from external servers")

        metadata: Dict[str, Any] = {
            "image_threat_score": img_score,
            "detected_brands": list(set(detected_img_brands)),
            "is_quishing": bool(has_quishing_indicator)
        }

        return features, reasons, metadata
