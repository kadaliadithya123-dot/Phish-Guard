"""
PHISH GUARD - Hybrid AI Browser Security System
Module: ssl_checker.ssl_inspector

Inspects SSL/TLS certificate validity, certificate authority (CA),
self-signed indicators, expiration, TLS version, and mixed-content risks.
"""

import datetime
import socket
import ssl
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


class SSLInspector:
    """Probes and analyzes SSL/TLS certificates and transport security."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def inspect_ssl(
        self,
        target_url: str,
        page_resources_http_count: int = 0
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Inspects SSL certificate for the given target URL.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        hostname = parsed.netloc.split(":")[0]
        port = parsed.port or 443
        is_https = parsed.scheme.lower() == "https"

        features: Dict[str, float] = {
            "ssl_is_https": 1.0 if is_https else 0.0,
            "ssl_cert_valid": 0.0,
            "ssl_is_self_signed": 0.0,
            "ssl_days_until_expiry": 0.0,
            "ssl_cert_age_days": 0.0,
            "ssl_mixed_content_detected": 1.0 if page_resources_http_count > 0 and is_https else 0.0,
            "ssl_threat_score": 0.0
        }
        reasons: List[str] = []
        metadata: Dict[str, Any] = {
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "tls_version": None,
            "ssl_threat_score": 0.0
        }

        if not is_https:
            features["ssl_threat_score"] = 40.0
            reasons.append("Webpage is served over unencrypted HTTP protocol")
            metadata["ssl_threat_score"] = 40.0
            return features, reasons, metadata

        # Probe TLS socket
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    metadata["tls_version"] = tls_version

                    features["ssl_cert_valid"] = 1.0

                    # Parse expiration & start dates
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    fmt = "%b %d %H:%M:%S %Y %Z"

                    now = datetime.datetime.now(datetime.timezone.utc)
                    if not_after:
                        valid_to = datetime.datetime.strptime(not_after, fmt).replace(tzinfo=datetime.timezone.utc)
                        days_left = (valid_to - now).days
                        features["ssl_days_until_expiry"] = float(max(0, days_left))
                        metadata["valid_to"] = str(valid_to)

                    if not_before:
                        valid_from = datetime.datetime.strptime(not_before, fmt).replace(tzinfo=datetime.timezone.utc)
                        cert_age = (now - valid_from).days
                        features["ssl_cert_age_days"] = float(max(0, cert_age))
                        metadata["valid_from"] = str(valid_from)

                    # Extract Issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))
                    metadata["issuer"] = issuer_org

                    # Threat scoring
                    score = 0.0
                    # Very short lived or newly generated certificate (< 3 days old)
                    if features["ssl_cert_age_days"] < 3:
                        score += 15.0
                    # Expiring within 48 hours
                    if 0 < features["ssl_days_until_expiry"] < 2:
                        score += 20.0
                    if features["ssl_mixed_content_detected"]:
                        score += 20.0

                    features["ssl_threat_score"] = round(score, 2)
                    metadata["ssl_threat_score"] = round(score, 2)

        except ssl.SSLCertVerificationError as e:
            # Self-signed or expired or invalid hostname
            features["ssl_is_self_signed"] = 1.0
            features["ssl_threat_score"] = 65.0
            reasons.append("Invalid or untrusted self-signed SSL/TLS certificate")
            metadata["ssl_threat_score"] = 65.0
            metadata["error"] = str(e)
        except Exception as e:
            # Timeout or socket error - non-fatal fallback
            features["ssl_threat_score"] = 10.0
            metadata["error"] = str(e)

        if features["ssl_mixed_content_detected"]:
            reasons.append("Mixed content detected: unencrypted HTTP assets loaded over HTTPS connection")

        return features, reasons, metadata
