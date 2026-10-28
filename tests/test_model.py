"""
Integration and Inference Tests for PHISH GUARD Machine Learning Models
Verifies artifact existence, latency benchmarking, and prediction accuracy.
"""

import os
import sys
import time
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from model_service import predictor_service


class TestModelService(unittest.TestCase):

    def test_artifacts_loaded(self):
        """Verifies that model.pkl and scaler.pkl are loaded in memory."""
        self.assertIsNotNone(predictor_service.model)
        self.assertIsNotNone(predictor_service.scaler)
        self.assertGreater(len(predictor_service.metadata), 0)

    def test_latency_performance(self):
        """Ensures inference execution is under 500 ms performance budget."""
        test_url = "https://www.wikipedia.org"
        start = time.perf_counter()
        res = predictor_service.predict_url(test_url)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        self.assertLess(elapsed_ms, 500.0, f"Inference took {elapsed_ms}ms, exceeding budget.")
        self.assertTrue(res["success"])
        self.assertIn("scan_time_ms", res)
        print(f"\n[Bench] Latency for single URL scan: {elapsed_ms:.2f} ms")

    def test_safe_url_classification(self):
        """Tests that a legitimate site receives 'Safe' prediction and 'Low' risk."""
        res = predictor_service.predict_url("https://www.apple.com/iphone")
        self.assertTrue(res["success"])
        self.assertEqual(res["prediction"], "Safe")
        self.assertEqual(res["risk_level"], "Low")
        self.assertGreaterEqual(res["confidence"], 75.0)

    def test_phishing_url_classification(self):
        """Tests that an obvious credential phishing URL is flagged as Phishing/Malicious."""
        res = predictor_service.predict_url("http://paypal-verification-alert-account.xyz/login.php")
        self.assertTrue(res["success"])
        self.assertIn(res["prediction"], ["Phishing", "Malicious"])
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(res["confidence"], 75.0)

    def test_ip_address_url_classification(self):
        """Tests that an IP-based URL is flagged with Critical risk."""
        res = predictor_service.predict_url("http://192.0.2.1/admin/login")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "Critical")
        self.assertIn(res["prediction"], ["Phishing", "Malicious"])

    def test_model_info_endpoint_data(self):
        """Validates that model information returns valid metrics."""
        info = predictor_service.get_model_information()
        self.assertIn("active_model_name", info)
        self.assertIn("champion_metrics", info)
        self.assertGreaterEqual(info["feature_count"], 30)


if __name__ == "__main__":
    unittest.main()
