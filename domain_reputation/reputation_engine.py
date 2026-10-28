"""
PHISH GUARD - Hybrid AI Browser Security System
Module: domain_reputation.reputation_engine

Computes domain trust, registrar indicators, abuse risk scores,
and detects abuse of dynamic DNS or cloud worker proxies.
"""

import socket
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# Free dynamic DNS, tunneling, and serverless hosting domains frequently abused by phishing
DISPOSABLE_CLOUD_HOSTS = {
    "duckdns.org", "no-ip.org", "ngrok.io", "ngrok-free.app", "serveo.net",
    "localtunnel.me", "firebaseapp.com", "pages.dev", "workers.dev",
    "web.app", "herokuapp.com", "netlify.app", "vercel.app", "github.io"
}

TOP_ESTABLISHED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "github.com", "wikipedia.org", "python.org", "mozilla.org", "cloudflare.com",
    "paypal.com", "chase.com", "bankofamerica.com", "netflix.com", "youtube.com"
}


class DomainReputationEngine:
    """Evaluates domain trust scores and checks for disposable hosting abuse."""

    def __init__(self):
        pass

    def evaluate_reputation(
        self,
        target_url: str,
        is_in_blacklist: bool = False,
        blacklist_reason: str = None
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Calculates domain reputation metrics and abuse risk.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        hostname = parsed.netloc.split(":")[0].lower()
        parts = hostname.split(".")

        registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        # 1. Disposable / Cloud Worker Abuse Check
        is_cloud_worker_abuse = 0.0
        for host in DISPOSABLE_CLOUD_HOSTS:
            if hostname.endswith(host) and hostname != host:
                is_cloud_worker_abuse = 1.0
                break

        # 2. Established Whitelist Check
        is_top_domain = 1.0 if registered_domain in TOP_ESTABLISHED_DOMAINS else 0.0

        # 3. DNS Resolvability
        dns_active = 1.0
        try:
            socket.gethostbyname(hostname)
        except Exception:
            dns_active = 0.0

        # 4. Blacklist Check
        is_blacklisted = 1.0 if is_in_blacklist else 0.0

        # Reputation Score (0 to 100, where 100 is maximum maliciousness)
        score = 0.0
        if is_blacklisted:
            score = 100.0
        else:
            if is_cloud_worker_abuse:
                score += 45.0
            if not dns_active:
                score += 35.0
            if is_top_domain:
                score = 0.0

        score = min(100.0, score)

        features: Dict[str, float] = {
            "rep_is_blacklisted": is_blacklisted,
            "rep_is_cloud_worker_abuse": is_cloud_worker_abuse,
            "rep_is_top_domain": is_top_domain,
            "rep_dns_active": dns_active,
            "domain_reputation_threat_score": round(score, 2)
        }

        reasons: List[str] = []
        if is_blacklisted:
            reasons.append(f"Domain is listed on the active security blacklist: {blacklist_reason or 'Known threat'}")
        if is_cloud_worker_abuse:
            reasons.append(f"Hosted on disposable cloud tunnel or worker domain ({registered_domain}) frequently used for evasion")
        if not dns_active:
            reasons.append("Hostname failed authoritative DNS resolution probe")

        metadata: Dict[str, Any] = {
            "domain": hostname,
            "registered_domain": registered_domain,
            "is_blacklisted": bool(is_blacklisted),
            "domain_reputation_threat_score": score
        }

        return features, reasons, metadata
