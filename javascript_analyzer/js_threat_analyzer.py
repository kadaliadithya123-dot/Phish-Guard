"""
PHISH GUARD - Hybrid AI Browser Security System
Module: javascript_analyzer.js_threat_analyzer

Inspects inline and external JavaScript code for malicious behaviors:
eval(), document.write(), Base64 decoding, credential exfiltration,
clipboard hijacking, keylogging, and packers/obfuscation.
"""

import re
from typing import Any, Dict, List, Tuple


class JavaScriptThreatAnalyzer:
    """Detects malicious JavaScript constructs, obfuscation, and data exfiltration patterns."""

    def __init__(self):
        pass

    def analyze_scripts(
        self,
        scripts_data: List[Dict[str, Any]] or str
    ) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """
        Analyzes script texts and script tags.
        scripts_data can be a list of strings, a list of dicts with {"src": ..., "content": ...},
        or raw script text.
        Returns:
            (features_dict, reasons_list, metadata_dict)
        """
        if isinstance(scripts_data, list):
            combined_code = ""
            for item in scripts_data:
                if isinstance(item, dict):
                    combined_code += " " + (item.get("content") or "")
                elif isinstance(item, str):
                    combined_code += " " + item
        elif isinstance(scripts_data, str):
            combined_code = scripts_data
        else:
            combined_code = ""

        code_lower = combined_code.lower()

        # 1. Dynamic Evaluation & Injection
        has_eval = 1.0 if re.search(r"\beval\s*\(", combined_code) else 0.0
        has_doc_write = 1.0 if re.search(r"document\.(write|writeln)\s*\(", combined_code) else 0.0
        has_func_constructor = 1.0 if re.search(r"new\s+Function\s*\(", combined_code) else 0.0

        # 2. Base64 & Hex Decoding
        has_atob = 1.0 if re.search(r"\batob\s*\(", combined_code) else 0.0
        has_unescape = 1.0 if re.search(r"\b(unescape|decodeuricomponent)\s*\(", code_lower) else 0.0

        # Large hex escape sequences (e.g., \x61\x62\x63...)
        hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", combined_code))
        has_heavy_hex = 1.0 if hex_escapes > 15 else 0.0

        # 3. Packer / Obfuscator Signatures
        has_js_packer = 1.0 if "eval(function(p,a,c,k,e,d)" in code_lower or "eval(function(p,a,c,k,e,r)" in code_lower else 0.0
        has_obfuscated_vars = 1.0 if len(re.findall(r"_0x[a-f0-9]{4,8}", combined_code)) > 5 else 0.0

        # 4. Keylogging Behaviors
        has_keylogging = 1.0 if (
            re.search(r"addeventlistener\s*\(\s*['\"](keydown|keypress|keyup)['\"]", code_lower)
            or "onkeydown" in code_lower
            or "onkeypress" in code_lower
        ) else 0.0

        # 5. Credential Interception on Submit
        has_credential_interceptor = 1.0 if (
            re.search(r"addeventlistener\s*\(\s*['\"]submit['\"]", code_lower)
            and ("password" in code_lower or "value" in code_lower)
        ) else 0.0

        # 6. Exfiltration & Beaconing
        has_fetch_beacon = 1.0 if (
            re.search(r"\b(fetch|sendbeacon)\s*\(", code_lower)
            or re.search(r"new\s+xmlhttprequest\s*\(", code_lower)
        ) else 0.0

        # 7. Navigation & History Manipulation
        has_location_replace = 1.0 if re.search(r"location\.(replace|assign)\s*\(", code_lower) else 0.0
        has_history_tamper = 1.0 if re.search(r"history\.(pushstate|replacestate)\s*\(", code_lower) else 0.0
        has_window_opener_exploit = 1.0 if "window.opener" in code_lower and "null" in code_lower else 0.0

        # 8. Clipboard Tampering
        has_clipboard_write = 1.0 if "navigator.clipboard.writetext" in code_lower else 0.0

        # JavaScript Threat Score Calculation (0.0 to 100.0)
        js_score = 0.0
        if has_js_packer:
            js_score += 40.0
        if has_obfuscated_vars or has_heavy_hex:
            js_score += 30.0
        if has_keylogging:
            js_score += 35.0
        if has_credential_interceptor:
            js_score += 30.0
        if has_eval:
            js_score += 20.0
        if has_atob and has_doc_write:
            js_score += 25.0
        if has_clipboard_write:
            js_score += 15.0
        if has_location_replace:
            js_score += 10.0

        js_score = min(100.0, js_score)

        features: Dict[str, float] = {
            "js_has_eval": has_eval,
            "js_has_doc_write": has_doc_write,
            "js_has_func_constructor": has_func_constructor,
            "js_has_atob": has_atob,
            "js_has_heavy_hex": has_heavy_hex,
            "js_has_packer": has_js_packer,
            "js_has_obfuscated_vars": has_obfuscated_vars,
            "js_has_keylogging": has_keylogging,
            "js_has_credential_interceptor": has_credential_interceptor,
            "js_has_fetch_beacon": has_fetch_beacon,
            "js_has_location_replace": has_location_replace,
            "js_has_history_tamper": has_history_tamper,
            "js_has_window_opener_exploit": has_window_opener_exploit,
            "js_has_clipboard_write": has_clipboard_write,
            "js_threat_score": round(js_score, 2)
        }

        reasons: List[str] = []
        if has_js_packer:
            reasons.append("Heavily packed/obfuscated JavaScript packer routine detected")
        if has_keylogging:
            reasons.append("Client-side keylogging event listener (intercepting keystrokes)")
        if has_credential_interceptor:
            reasons.append("JavaScript intercepts form submission to extract user credentials")
        if has_obfuscated_vars or has_heavy_hex:
            reasons.append("High entropy variable names or heavy hexadecimal string obfuscation")
        if has_eval:
            reasons.append("Dynamic code evaluation using eval() detected")
        if has_clipboard_write:
            reasons.append("JavaScript attempts automated clipboard hijacking")

        metadata: Dict[str, Any] = {
            "js_threat_score": js_score,
            "is_obfuscated": bool(has_js_packer or has_obfuscated_vars or has_heavy_hex),
            "is_keylogger": bool(has_keylogging)
        }

        return features, reasons, metadata
