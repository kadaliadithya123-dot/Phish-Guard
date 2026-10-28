"""
PHISH GUARD - Hybrid AI Browser Security System
Module: backend.model_service

Hybrid Multi-Modal Predictor Service orchestrating:
- URL Feature Extraction (42 vectors)
- HTML & DOM Content Analysis
- Form & Credential Security Analysis
- JavaScript Behavioral Inspection
- Visual Perceptual & Computer Vision Matching
- Optical Text / Urgency Keyword Scanning
- SSL/TLS Socket Probing
- Domain Reputation & Dynamic DNS Checks
- Image & Favicon Hotlink Analysis
- Multi-Layer Weighted Risk Fusion Engine
"""

import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# Path configuration
BACKEND_DIR = os.path.dirname(__file__)
BASE_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
sys.path.append(BASE_DIR)

from feature_extractors.url_feature_extractor import extract_url_features, get_url_feature_names
from content_analyzer.html_content_analyzer import HTMLContentAnalyzer
from form_analyzer.form_security_analyzer import FormSecurityAnalyzer
from javascript_analyzer.js_threat_analyzer import JavaScriptThreatAnalyzer
from visual_similarity.visual_comparator import VisualComparator
from ocr_detector.ocr_text_analyzer import OCRTextAnalyzer
from ssl_checker.ssl_inspector import SSLInspector
from domain_reputation.reputation_engine import DomainReputationEngine
from image_analyzer.image_asset_analyzer import ImageAssetAnalyzer
from email_detector.email_exfiltration_detector import EmailExfiltrationDetector
from risk_engine.hybrid_risk_engine import HybridRiskEngine

import database_manager
from logger import setup_logger
from security_utils import validate_and_sanitize_url

logger = setup_logger("phishguard.model_service")

MODELS_DIR = os.path.join(BASE_DIR, "models")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")


class HybridPhishGuardPredictor:
    """Orchestrates multi-modal security analysis across URL, HTML, Forms, JS, Visual, SSL, and Reputation."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(HybridPhishGuardPredictor, cls).__new__(cls)
            cls._instance.is_initialized = False
        return cls._instance

    def __init__(self):
        if self.is_initialized:
            return
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.feature_names = []

        # Sub-analyzers
        self.html_analyzer = HTMLContentAnalyzer()
        self.form_analyzer = FormSecurityAnalyzer()
        self.js_analyzer = JavaScriptThreatAnalyzer()
        self.visual_comparator = VisualComparator(screenshots_dir=SCREENSHOTS_DIR)
        self.ocr_analyzer = OCRTextAnalyzer()
        self.ssl_inspector = SSLInspector(timeout=2.0)
        self.reputation_engine = DomainReputationEngine()
        self.image_analyzer = ImageAssetAnalyzer()
        self.email_detector = EmailExfiltrationDetector()
        self.risk_engine = HybridRiskEngine()

        self.load_artifacts()
        self.is_initialized = True

    def load_artifacts(self) -> bool:
        """Loads trained hybrid ML model, scaler, and metadata from disk."""
        try:
            model_file = os.path.join(MODELS_DIR, "hybrid_model.pkl")
            if not os.path.exists(model_file):
                model_file = os.path.join(MODELS_DIR, "model.pkl")

            scaler_file = os.path.join(MODELS_DIR, "hybrid_scaler.pkl")
            if not os.path.exists(scaler_file):
                scaler_file = os.path.join(MODELS_DIR, "scaler.pkl")

            meta_file = os.path.join(MODELS_DIR, "hybrid_metadata.json")
            if not os.path.exists(meta_file):
                meta_file = os.path.join(MODELS_DIR, "metadata.json")

            if os.path.exists(model_file) and os.path.exists(scaler_file):
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                logger.info(f"Loaded Hybrid Machine Learning model from {os.path.basename(model_file)}.")
            else:
                logger.warning("ML artifacts not found. Operating with Multi-Layer Risk Engine.")

            if os.path.exists(meta_file):
                with open(meta_file, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.feature_names = self.metadata.get("feature_names", [])

            return True
        except Exception as e:
            logger.error(f"Error loading model artifacts: {e}", exc_info=True)
            return False

    def predict_hybrid(
        self,
        raw_url: str,
        html_content: str = "",
        forms_data: List[Dict[str, Any]] = None,
        scripts_data: Any = None,
        images_data: List[Dict[str, Any]] = None,
        screenshot_base64: Optional[str] = None,
        dom_metrics: Dict[str, Any] = None,
        favicon_url: str = "",
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Executes full multi-modal hybrid threat analysis:
        1. URL feature extraction & ML inference
        2. HTML & DOM structural analysis
        3. Form & credential harvesting analysis
        4. JavaScript behavioral inspection
        5. Visual layout & color palette matching
        6. OCR text scanning
        7. SSL/TLS socket verification
        8. Domain reputation & DNS checks
        9. Multi-Layer Risk Scoring Engine & Non-linear Overrides
        10. Database telemetry logging
        """
        start_time = time.perf_counter()

        # Step 1: Validate and sanitize URL
        is_valid, sanitized_url, err_msg = validate_and_sanitize_url(raw_url)
        if not is_valid:
            return {
                "success": False,
                "error": err_msg,
                "url": raw_url,
                "prediction": "SAFE",
                "risk_level": "None"
            }

        # Step 2: Extract URL Features (42 vectors)
        url_feats, url_reasons, url_meta = extract_url_features(sanitized_url)
        domain = url_meta.get("domain", "")

        # Step 3: Check Blacklist (Instant deterministic check)
        blacklisted, bl_reason = database_manager.is_blacklisted(domain, sanitized_url)

        # Step 4: Content HTML Analysis
        content_feats, content_reasons, content_meta = self.html_analyzer.analyze_html(
            html_content=html_content,
            base_url=sanitized_url,
            dom_metrics=dom_metrics
        )

        # Step 5: Form Security Analysis
        form_feats, form_reasons, form_meta = self.form_analyzer.analyze_forms(
            forms_data=forms_data or [],
            current_url=sanitized_url
        )

        # Step 6: JavaScript Behavioral Analysis
        js_feats, js_reasons, js_meta = self.js_analyzer.analyze_scripts(
            scripts_data=scripts_data or []
        )

        # Step 7: Visual & Brand AI Analysis
        visual_feats, visual_reasons, visual_meta = self.visual_comparator.analyze_screenshot(
            screenshot_base64=screenshot_base64,
            current_url=sanitized_url,
            save_to_disk=True
        )

        # Step 8: OCR Text Scanning
        ocr_feats, ocr_reasons, ocr_meta = self.ocr_analyzer.analyze_image_text(
            screenshot_base64=screenshot_base64,
            extracted_text_hints=[content_meta.get("title", "")]
        )

        # Step 9: SSL/TLS Socket Inspection
        ssl_feats, ssl_reasons, ssl_meta = self.ssl_inspector.inspect_ssl(
            target_url=sanitized_url,
            page_resources_http_count=int(content_feats.get("empty_links", 0))
        )

        # Step 10: Domain Reputation Analysis
        rep_feats, rep_reasons, rep_meta = self.reputation_engine.evaluate_reputation(
            target_url=sanitized_url,
            is_in_blacklist=blacklisted,
            blacklist_reason=bl_reason
        )

        # Step 11: Image Asset Analysis
        img_feats, img_reasons, img_meta = self.image_analyzer.analyze_images(
            images_data=images_data or [],
            favicon_url=favicon_url,
            current_url=sanitized_url
        )

        # Step 12: Email & Webhook Exfiltration Detection
        email_feats, email_reasons, email_meta = self.email_detector.detect_exfiltration(
            html_content=html_content,
            forms_data=forms_data or []
        )

        # Step 13: Machine Learning Model Inference on URL + Content Feature Vector
        ml_phishing_probability = 0.0
        if self.model is not None and self.scaler is not None and self.feature_names:
            try:
                # Combine all extracted features
                combined_features = {}
                combined_features.update(url_feats)
                combined_features.update(content_feats)
                combined_features.update(form_feats)
                combined_features.update(js_feats)
                combined_features.update(img_feats)

                # Build row matching feature_names
                feature_row = [combined_features.get(col, 0.0) for col in self.feature_names]
                scaled_vec = self.scaler.transform(pd.DataFrame([feature_row], columns=self.feature_names))

                if hasattr(self.model, "predict_proba"):
                    proba = self.model.predict_proba(scaled_vec)[0]
                    ml_phishing_probability = float(proba[1])
                else:
                    pred = self.model.predict(scaled_vec)[0]
                    ml_phishing_probability = 1.0 if pred == 1 else 0.0
            except Exception as e:
                logger.error(f"Inference warning: {e}")
                ml_phishing_probability = 0.5
        else:
            ml_phishing_probability = 0.5

        # Compute URL Layer Threat Score (0 to 100)
        url_threat_score = max(
            url_feats.get("brand_impersonation", 0) * 85.0,
            url_feats.get("has_ip_address", 0) * 80.0,
            ml_phishing_probability * 100.0
        )
        if url_feats.get("tld_risk_score", 0) == 1.0:
            url_threat_score = max(url_threat_score, 45.0)

        # Consolidate all reasons
        consolidated_reasons = (
            url_reasons + content_reasons + form_reasons +
            js_reasons + visual_reasons + ocr_reasons +
            ssl_reasons + rep_reasons + img_reasons + email_reasons
        )

        # Critical Non-Linear Flags
        critical_flags = {
            "is_blacklisted": blacklisted,
            "cross_domain_credential_post": form_meta.get("external_action", False) and form_meta.get("has_password", False),
            "brand_impersonation_with_login": (url_feats.get("brand_impersonation", 0) == 1.0 or visual_meta.get("matched_brand") is not None) and form_meta.get("has_password", False),
            "ip_with_login": url_feats.get("has_ip_address", 0) == 1.0 and form_meta.get("has_password", False),
            "is_ip_suspicious": url_feats.get("has_ip_address", 0) == 1.0,
            "is_top_domain": rep_feats.get("rep_is_top_domain", 0) == 1.0
        }

        # Step 14: Multi-Layer Risk Engine Evaluation
        verdict = self.risk_engine.evaluate(
            url_threat_score=url_threat_score,
            content_threat_score=content_meta.get("content_threat_score", content_feats.get("content_threat_score", 0.0)),
            form_threat_score=form_meta.get("form_threat_score", form_feats.get("form_threat_score", 0.0)),
            js_threat_score=js_meta.get("js_threat_score", js_feats.get("js_threat_score", 0.0)),
            visual_threat_score=visual_meta.get("visual_threat_score", visual_feats.get("visual_threat_score", 0.0)),
            ssl_threat_score=ssl_meta.get("ssl_threat_score", ssl_feats.get("ssl_threat_score", 0.0)),
            reputation_threat_score=rep_meta.get("reputation_threat_score", rep_feats.get("domain_reputation_threat_score", 0.0)),
            image_threat_score=img_meta.get("image_threat_score", img_feats.get("image_threat_score", 0.0)),
            critical_flags=critical_flags,
            all_reasons=consolidated_reasons
        )

        scan_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        html_hash = hashlib.sha256(html_content.encode("utf-8")).hexdigest()[:16] if html_content else ""

        # Step 15: Telemetry Logging to SQLite Database
        try:
            database_manager.log_hybrid_scan(
                url=sanitized_url,
                domain=domain,
                prediction=verdict["decision"],
                confidence=verdict["confidence"],
                risk_level=verdict["risk_level"],
                hybrid_score=verdict["hybrid_score"],
                layer_scores=verdict["layer_scores"],
                scan_time_ms=scan_time_ms,
                reasons=verdict["reasons"],
                features={**url_feats, **content_feats, **form_feats, **js_feats},
                html_hash=html_hash,
                screenshot_path=visual_meta.get("screenshot_path", ""),
                client_ip=client_ip
            )

            # Record threat hit in heatmap if brand matched or phishing
            matched_brand = visual_meta.get("matched_brand") or (url_meta.get("detected_brands", [None])[0] if url_meta.get("detected_brands") else None)
            if matched_brand and verdict["decision"] in ["PHISHING", "SUSPICIOUS"]:
                database_manager.record_threat_hit(
                    target_brand=matched_brand,
                    attack_vector="Credential Harvesting" if form_meta.get("has_password") else "Brand Impersonation",
                    threat_level=verdict["risk_level"]
                )
        except Exception as e:
            logger.error(f"Error persisting hybrid scan history: {e}")

        # Assemble unified response payload
        return {
            "success": True,
            "url": sanitized_url,
            "domain": domain,
            "prediction": verdict["decision"],
            "risk_level": verdict["risk_level"],
            "confidence": verdict["confidence"],
            "hybrid_score": verdict["hybrid_score"],
            "layer_scores": verdict["layer_scores"],
            "reasons": verdict["reasons"],
            "scan_time_ms": scan_time_ms,
            "html_hash": html_hash,
            "screenshot_path": visual_meta.get("screenshot_path"),
            "matched_brand": visual_meta.get("matched_brand") or (url_meta.get("detected_brands", [None])[0] if url_meta.get("detected_brands") else None),
            "is_blacklisted": blacklisted,
            "metadata": {
                "url_meta": url_meta,
                "content_meta": content_meta,
                "form_meta": form_meta,
                "visual_meta": visual_meta,
                "ssl_meta": ssl_meta,
                "reputation_meta": rep_meta
            }
        }

    def predict_url(self, raw_url: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """Backwards compatible URL-only entry point."""
        res = self.predict_hybrid(
            raw_url=raw_url,
            html_content="",
            forms_data=[],
            scripts_data=[],
            images_data=[],
            client_ip=client_ip
        )
        # Normalize prediction casing for legacy clients/tests
        p = res.get("prediction", "SAFE").upper()
        if p == "SAFE":
            res["prediction"] = "Safe"
        elif p == "PHISHING":
            res["prediction"] = "Phishing"
        elif p == "SUSPICIOUS":
            res["prediction"] = "Suspicious"
        elif p == "MALICIOUS":
            res["prediction"] = "Malicious"
        return res

    def get_model_information(self) -> Dict[str, Any]:
        """Returns details about active champion model, ROC-AUC, and multi-model benchmarks."""
        benchmarks = database_manager.get_model_benchmarks()
        active_name = self.metadata.get("active_model_name", "Random Forest")
        return {
            "active_model_name": active_name,
            "feature_count": self.metadata.get("feature_count", len(self.feature_names)),
            "feature_names": self.feature_names,
            "champion_metrics": self.metadata.get("champion_metrics", {}),
            "feature_importances": self.metadata.get("feature_importances", {}),
            "all_model_benchmarks": benchmarks or self.metadata.get("all_model_benchmarks", {}),
            "created_at": self.metadata.get("created_at", "N/A"),
            "status": "online" if self.model is not None else "degraded (rule engine active)"
        }


# Global singleton instance
predictor_service = HybridPhishGuardPredictor()
