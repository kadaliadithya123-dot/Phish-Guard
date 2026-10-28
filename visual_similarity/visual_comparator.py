"""
PHISH GUARD - Hybrid AI Browser Security System
Module: visual_similarity.visual_comparator

Computer Vision and Perceptual Hashing module for webpage screenshots.
Detects visually copied login interfaces, cloned brand palettes,
and layout impersonation (Google, Microsoft, PayPal, Apple, Amazon, Netflix, Banks).
"""

import base64
import io
import math
import os
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image

# Reference Brand Signatures (Dominant Colors & Reference Hashes)
BRAND_PROFILES = {
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "accounts.google.com"],
        "dominant_colors": [(66, 133, 244), (234, 67, 53), (251, 188, 5), (52, 168, 83)],  # Blue, Red, Yellow, Green
        "ref_hash": "d1c080e0e0e0f0f0"
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "login.microsoftonline.com", "live.com"],
        "dominant_colors": [(242, 80, 34), (127, 186, 0), (0, 164, 239), (255, 185, 0)],
        "ref_hash": "f0e0c08080c0e0f0"
    },
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com"],
        "dominant_colors": [(0, 48, 135), (0, 121, 193), (255, 255, 255)],  # PayPal Navy & Cyan
        "ref_hash": "a0c0e0f0f0e0c0a0"
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com"],
        "dominant_colors": [(0, 0, 0), (245, 245, 247), (255, 255, 255)],
        "ref_hash": "e0e0e0e0e0e0e0e0"
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "dominant_colors": [(229, 9, 20), (20, 20, 20), (0, 0, 0)],  # Netflix Red & Black
        "ref_hash": "000000ffff000000"
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": ["chase.com"],
        "dominant_colors": [(17, 110, 189), (255, 255, 255), (33, 33, 33)],
        "ref_hash": "c0c0c0f0f0c0c0c0"
    },
    "binance": {
        "name": "Binance",
        "official_domains": ["binance.com"],
        "dominant_colors": [(243, 186, 47), (30, 32, 38), (14, 16, 20)],  # Binance Gold & Dark
        "ref_hash": "0f0f0ff0f0ff0f0f"
    }
}


def calculate_dhash(image: Image.Image, hash_size: int = 8) -> str:
    """Calculates Difference Hash (dHash) of PIL image."""
    resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = np.array(resized)
    difference = pixels[:, 1:] > pixels[:, :-1]
    decimal_value = 0
    hex_string = []
    for index, value in enumerate(difference.flatten()):
        if value:
            decimal_value += 2 ** (index % 8)
        if (index % 8) == 7:
            hex_string.append(hex(decimal_value)[2:].rjust(2, "0"))
            decimal_value = 0
    return "".join(hex_string)


def hamming_distance(hash1: str, hash2: str) -> int:
    """Computes Hamming distance between two hexadecimal hash strings."""
    if len(hash1) != len(hash2):
        return 64
    dist = 0
    for h1, h2 in zip(hash1, hash2):
        n1 = int(h1, 16)
        n2 = int(h2, 16)
        dist += bin(n1 ^ n2).count("1")
    return dist


def color_palette_similarity(image: Image.Image, target_colors: List[Tuple[int, int, int]]) -> float:
    """Measures presence and dominance of specific brand color palette in screenshot."""
    img_rgb = image.convert("RGB").resize((64, 64))
    pixels = np.array(img_rgb).reshape(-1, 3)
    matches = 0
    for p in pixels:
        for tc in target_colors:
            # Euclidean distance in RGB space
            dist = math.sqrt(sum((float(a) - float(b)) ** 2 for a, b in zip(p, tc)))
            if dist < 45.0:  # Color proximity threshold
                matches += 1
                break
    return round(matches / len(pixels), 4)


class VisualComparator:
    """Compares webpage screenshots against known brand templates and layout structures."""

    def __init__(self, screenshots_dir: str = None):
        self.screenshots_dir = screenshots_dir

    def analyze_screenshot(
        self,
        screenshot_base64: Optional[str],
        current_url: str = "",
        save_to_disk: bool = True
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Analyzes screenshot data URL from the extension.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        features: Dict[str, float] = {
            "screenshot_provided": 0.0,
            "visual_similarity_score": 0.0,
            "brand_color_match_ratio": 0.0,
            "visual_threat_score": 0.0
        }
        reasons: List[str] = []
        metadata: Dict[str, Any] = {
            "matched_brand": None,
            "screenshot_path": None,
            "visual_threat_score": 0.0
        }

        if not screenshot_base64:
            return features, reasons, metadata

        try:
            # Strip data URI prefix if present
            if "," in screenshot_base64:
                header, encoded = screenshot_base64.split(",", 1)
            else:
                encoded = screenshot_base64

            image_data = base64.b64decode(encoded)
            img = Image.open(io.BytesIO(image_data))
            features["screenshot_provided"] = 1.0

            # Compute dHash
            screenshot_hash = calculate_dhash(img)

            # Save screenshot to disk if configured
            screenshot_rel_path = None
            if save_to_disk and self.screenshots_dir:
                os.makedirs(self.screenshots_dir, exist_ok=True)
                filename = f"scan_{abs(hash(current_url)) % 1000000}_{screenshot_hash[:8]}.jpg"
                save_path = os.path.join(self.screenshots_dir, filename)
                img.convert("RGB").save(save_path, "JPEG", quality=75)
                screenshot_rel_path = f"screenshots/{filename}"
                metadata["screenshot_path"] = screenshot_rel_path

            # Clean current domain for legitimate verification
            from urllib.parse import urlparse
            current_domain = urlparse(current_url).netloc.lower() if current_url else ""

            best_brand = None
            highest_threat_score = 0.0
            highest_color_ratio = 0.0

            for brand_key, profile in BRAND_PROFILES.items():
                is_official = any(current_domain.endswith(dom) for dom in profile["official_domains"])

                # If current website is ALREADY official domain, it's not impersonating
                if is_official:
                    continue

                # Measure color palette presence
                color_ratio = color_palette_similarity(img, profile["dominant_colors"])
                if color_ratio > highest_color_ratio:
                    highest_color_ratio = color_ratio

                # Measure perceptual hash distance
                hash_dist = hamming_distance(screenshot_hash, profile["ref_hash"])
                # Normalized similarity (0 to 1)
                hash_sim = max(0.0, 1.0 - (hash_dist / 64.0))

                # Composite visual copy score
                visual_threat = (color_ratio * 60.0) + (hash_sim * 40.0)
                if visual_threat > highest_threat_score and (color_ratio > 0.22 or hash_sim > 0.65):
                    highest_threat_score = visual_threat
                    best_brand = profile["name"]

            visual_threat_score = min(100.0, highest_threat_score)
            features["visual_similarity_score"] = round(visual_threat_score / 100.0, 4)
            features["brand_color_match_ratio"] = round(highest_color_ratio, 4)
            features["visual_threat_score"] = round(visual_threat_score, 2)

            if best_brand and visual_threat_score > 35.0:
                reasons.append(f"Visual AI detected layout & color palette cloning of '{best_brand}' on an unauthorized domain")
                metadata["matched_brand"] = best_brand

            metadata["visual_threat_score"] = visual_threat_score
            return features, reasons, metadata

        except Exception as e:
            # Graceful error tolerance
            metadata["error"] = str(e)
            return features, reasons, metadata
