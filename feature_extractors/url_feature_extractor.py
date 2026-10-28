"""
PHISH GUARD - Hybrid AI Browser Security System
Module: feature_extractors.url_feature_extractor

Extracts 40+ lexical, structural, statistical, and security features from URLs.
"""

import math
import re
import socket
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

# Target brands frequently abused in phishing
TARGET_BRANDS = [
    "google", "microsoft", "apple", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "x", "github", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank", "binance",
    "coinbase", "metamask", "outlook", "yahoo", "dropbox", "adobe",
    "steam", "roblox", "ebay", "walmart", "irs", "gov", "usps"
]

# Sensitive authentication / threat keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "confirm", "confirmation", "password",
    "credential", "wallet", "recover", "authenticate", "auth", "validation",
    "support", "billing", "invoice", "payment", "alert", "notification",
    "suspended", "unlock", "ebayisapi", "webscr", "securelogin", "claim",
    "reward", "bonus", "free", "kyc", "portal", "session", "token"
]

# High-risk Top-Level Domains (TLDs)
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "fit", "icu", "click", "rest", "cam", "loan", "men",
    "stream", "download", "racing", "win", "bid", "vip", "monster",
    "casa", "surf", "cfd", "sbs", "country", "kim", "party", "science"
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st",
    "tiny.cc", "bc.vc", "rb.gy", "trib.al", "s.id", "v.gd", "qr.net"
}

# Suspicious downloadable extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".apk", ".bat", ".vbs", ".cmd", ".ps1", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".dmg"
}

COMMON_TLDS = {"com", "org", "net", "edu", "gov", "mil", "co", "io", "info", "biz"}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of string (bits per symbol)."""
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob_dist])
    return round(entropy, 4)


def is_ip_address(domain: str) -> bool:
    """Verifies whether hostname is an IPv4 or IPv6 address."""
    clean_domain = domain.split(":")[0].strip()
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, clean_domain):
        parts = clean_domain.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    if ":" in clean_domain and re.match(r"^[0-9a-fA-F:]+$", clean_domain):
        return True
    return False


def detect_homoglyphs(domain: str) -> bool:
    """Identifies lookalike substitutions and mixed scripts."""
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return True

    clean = domain.lower()
    patterns = [
        r"p[a@]yp[a@][1l]",
        r"g[0o]{2}gle",
        r"m[i1]cr[0o]s[0o]ft",
        r"[a@][p1]{2}le",
        r"[a@]m[a@]z[0o]n",
        r"netfl[i1]x",
        r"f[a@]ceb[0o]{2}k",
        r"b[i1]n[a@]nce"
    ]
    for pat in patterns:
        if re.search(pat, clean):
            if any(b in re.sub(r"[^a-z]", "", clean) for b in TARGET_BRANDS):
                if re.search(r"[0-9]", clean):
                    return True
    return False


def extract_url_features(raw_url: str) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
    """
    Extracts 40+ numerical features and human-readable threat reasons from a URL.
    Returns:
        (features_dict, reasons_list, metadata_dict)
    """
    url = (raw_url or "").strip()
    if not url.startswith(("http://", "https://")):
        parsed = urlparse("http://" + url)
        has_scheme = False
    else:
        parsed = urlparse(url)
        has_scheme = True

    scheme = parsed.scheme.lower() if has_scheme else ""
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    domain = netloc.split(":")[0] if ":" in netloc else netloc
    domain_parts = domain.split(".") if domain else []
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []
    num_subdomains = len(subdomains)

    # 1. Length metrics
    url_len = len(url)
    dom_len = len(domain)
    path_len = len(path)
    query_len = len(query)
    frag_len = len(fragment)

    # 2. Character counts
    count_dots = url.count(".")
    count_hyphens = url.count("-")
    count_underscore = url.count("_")
    count_slash = url.count("/")
    count_question = url.count("?")
    count_equal = url.count("=")
    count_at = url.count("@")
    count_amp = url.count("&")
    count_excl = url.count("!")
    count_tilde = url.count("~")
    count_percent = url.count("%")
    count_plus = url.count("+")
    count_digits = sum(c.isdigit() for c in url)
    count_letters = sum(c.isalpha() for c in url)
    digit_ratio = (count_digits / max(1, count_letters))

    # 3. Protocol & Port
    has_https = 1.0 if scheme == "https" else 0.0
    has_http = 1.0 if scheme == "http" else 0.0
    has_port = 1.0 if (":" in netloc and not is_ip_address(domain)) else 0.0

    # 4. Hostname characteristics
    has_ip = 1.0 if is_ip_address(domain) else 0.0
    has_punycode = 1.0 if "xn--" in domain else 0.0
    has_homoglyphs = 1.0 if detect_homoglyphs(domain) else 0.0
    is_shortened = 1.0 if (domain in SHORTENER_DOMAINS or any(domain.endswith("." + s) for s in SHORTENER_DOMAINS)) else 0.0
    tld_risk = 1.0 if tld in HIGH_RISK_TLDS else 0.0
    consecutive_hyphens = 1.0 if "--" in domain else 0.0

    # 5. TLD in subdomain / deceptive hierarchy
    tld_in_sub = 0.0
    for ct in COMMON_TLDS:
        if f".{ct}." in domain:
            tld_in_sub = 1.0
            break

    # 6. Path anomalies
    has_double_slash_path = 1.0 if "//" in path else 0.0
    has_dangerous_ext = 1.0 if any(path.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS) else 0.0

    # 7. Query parameters
    params = parse_qs(query) if query else {}
    num_params = float(len(params))

    # 8. Entropy
    url_entropy = calculate_entropy(url)
    dom_entropy = calculate_entropy(domain)
    path_entropy = calculate_entropy(path)

    # 9. Keywords & Brand impersonation
    url_lower = url.lower()
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    kw_count = float(len(matched_kws))

    brand_spoofed = 0.0
    detected_brands = []
    registered_dom = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

    for brand in TARGET_BRANDS:
        if brand in url_lower:
            is_legit_domain = any(
                registered_dom == f"{brand}.{kt}" or registered_dom == f"{brand}.co.{kt}"
                for kt in ["com", "org", "net", "io", "co", "uk", "de", "fr", "ca", "jp", "au", "in", "us"]
            )
            if not is_legit_domain:
                if (brand in domain and registered_dom != f"{brand}.com") or (brand in path):
                    brand_spoofed = 1.0
                    detected_brands.append(brand)

    # 10. DNS Resolution check (fast non-blocking probe)
    dns_resolvable = 1.0
    resolved_ip = ""
    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        dns_resolvable = 0.0

    # 11. Popularity / Alexa proxy heuristic
    domain_length_ratio = float(dom_len / max(1, url_len))
    path_length_ratio = float(path_len / max(1, url_len))

    # Compile the 42 features dictionary
    features: Dict[str, float] = {
        "url_length": float(url_len),
        "domain_length": float(dom_len),
        "path_length": float(path_len),
        "query_length": float(query_len),
        "fragment_length": float(frag_len),
        "count_dots": float(count_dots),
        "count_hyphens": float(count_hyphens),
        "count_underscore": float(count_underscore),
        "count_slash": float(count_slash),
        "count_question": float(count_question),
        "count_equal": float(count_equal),
        "count_at": float(count_at),
        "count_amp": float(count_amp),
        "count_excl": float(count_excl),
        "count_tilde": float(count_tilde),
        "count_percent": float(count_percent),
        "count_plus": float(count_plus),
        "count_digits": float(count_digits),
        "count_letters": float(count_letters),
        "digit_to_letter_ratio": round(float(digit_ratio), 4),
        "count_subdomains": float(num_subdomains),
        "has_https": has_https,
        "has_http": has_http,
        "has_port": has_port,
        "has_ip_address": has_ip,
        "has_punycode": has_punycode,
        "has_homoglyphs": has_homoglyphs,
        "is_shortened_url": is_shortened,
        "tld_risk_score": tld_risk,
        "consecutive_hyphens": consecutive_hyphens,
        "tld_in_subdomain": tld_in_sub,
        "has_double_slash_path": has_double_slash_path,
        "has_dangerous_ext": has_dangerous_ext,
        "num_parameters": num_params,
        "url_entropy": url_entropy,
        "domain_entropy": dom_entropy,
        "path_entropy": path_entropy,
        "suspicious_keywords_count": kw_count,
        "brand_impersonation": brand_spoofed,
        "dns_resolvable": dns_resolvable,
        "domain_length_ratio": round(domain_length_ratio, 4),
        "path_length_ratio": round(path_length_ratio, 4)
    }

    # Reasons list
    reasons: List[str] = []
    if has_ip == 1.0:
        reasons.append("Raw IP address used as hostname instead of a registered domain")
    if brand_spoofed == 1.0 and detected_brands:
        reasons.append(f"Brand impersonation detected: deceptive use of '{', '.join(set(detected_brands))}'")
    if has_punycode == 1.0:
        reasons.append("Punycode (IDN) detected; potential homograph character spoofing")
    if has_homoglyphs == 1.0:
        reasons.append("Lookalike character substitutions detected in domain syntax")
    if is_shortened == 1.0:
        reasons.append("URL shortening service masks actual destination")
    if tld_risk == 1.0:
        reasons.append(f"Domain uses high-abuse Top-Level Domain (.{tld})")
    if count_at > 0:
        reasons.append("Contains '@' symbol designed to mislead browser routing")
    if has_double_slash_path == 1.0:
        reasons.append("Double slash '//' found in URL path; potential open redirect")
    if tld_in_sub == 1.0:
        reasons.append("Deceptive subdomain contains embedded TLD (e.g., brand.com.attacker)")
    if num_subdomains >= 3:
        reasons.append(f"Excessive subdomain nesting depth ({num_subdomains} subdomains)")
    if dom_entropy > 4.2:
        reasons.append(f"High domain entropy ({dom_entropy:.2f}); indicative of DGA botnet generation")
    if has_dangerous_ext == 1.0:
        reasons.append("Direct link to an executable or dangerous archive payload")
    if kw_count >= 2:
        reasons.append(f"Multiple credential/security keywords detected: {', '.join(matched_kws[:3])}")
    if has_https == 0.0:
        reasons.append("Insecure HTTP protocol without transport-layer encryption")

    metadata: Dict[str, Any] = {
        "domain": domain,
        "tld": tld,
        "scheme": scheme,
        "num_subdomains": num_subdomains,
        "detected_brands": list(set(detected_brands)),
        "suspicious_keywords": matched_kws,
        "is_ip": bool(has_ip),
        "is_shortened": bool(is_shortened),
        "resolved_ip": resolved_ip
    }

    return features, reasons, metadata


def get_url_feature_names() -> List[str]:
    """Returns ordered list of feature names matching the 42 numerical features."""
    return [
        "url_length", "domain_length", "path_length", "query_length", "fragment_length",
        "count_dots", "count_hyphens", "count_underscore", "count_slash", "count_question",
        "count_equal", "count_at", "count_amp", "count_excl", "count_tilde", "count_percent",
        "count_plus", "count_digits", "count_letters", "digit_to_letter_ratio", "count_subdomains",
        "has_https", "has_http", "has_port", "has_ip_address", "has_punycode", "has_homoglyphs",
        "is_shortened_url", "tld_risk_score", "consecutive_hyphens", "tld_in_subdomain",
        "has_double_slash_path", "has_dangerous_ext", "num_parameters", "url_entropy",
        "domain_entropy", "path_entropy", "suspicious_keywords_count", "brand_impersonation",
        "dns_resolvable", "domain_length_ratio", "path_length_ratio"
    ]
