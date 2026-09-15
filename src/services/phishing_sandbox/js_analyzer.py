import re
from typing import Dict, Any, List

JS_SUSPICIOUS_PATTERNS = {
    "evalOrDynamicExecution": [
        r"\beval\s*\(", r"\bFunction\s*\(", r"\bsetTimeout\s*\(\s*['\"`]", r"\bsetInterval\s*\(\s*['\"`]"
    ],
    "obfuscationAndEncoding": [
        r"\\x[0-9a-fA-F]{2}", r"\\u[0-9a-fA-F]{4}", r"\batob\s*\(", r"\bunescape\s*\(",
        r"\bString\.fromCharCode\s*\(", r"\b_0x[a-f0-9]+"
    ],
    "credentialCollectionAndKeylogging": [
        r"\baddEventListener\s*\(\s*['\"]keydown['\"]", r"\baddEventListener\s*\(\s*['\"]keypress['\"]",
        r"\.value\s*==\s*['\"]password['\"]", r"document\.forms\[.*?\]\.submit",
        r"navigator\.credentials\.get", r"input\[type=['\"]password['\"]"
    ],
    "browserFingerprinting": [
        r"\.toDataURL\s*\(", r"\bWebGLRenderingContext\b", r"\bAudioContext\b",
        r"navigator\.userAgentData", r"screen\.colorDepth", r"navigator\.hardwareConcurrency"
    ],
    "cryptoMining": [
        r"coinhive", r"cryptonight", r"minr\.js", r"webminepool", r"deepminer"
    ],
    "forcedRedirectAndDownloads": [
        r"window\.location\.replace\s*\(", r"top\.location\.href\s*=", r"document\.location\s*=",
        r"\.setAttribute\s*\(\s*['\"]download['\"]", r"URL\.createObjectURL\s*\("
    ]
}

def analyze_javascript_behaviors(html_or_js: str) -> Dict[str, Any]:
    """
    Statically inspect embedded and inline JavaScript for malicious/suspicious behaviors:
    - Code Obfuscation & packing
    - Keylogging & form credential harvesting
    - Browser fingerprinting
    - Crypto-jacking & WebAssembly miners
    - Forced downloads & redirects
    """
    code = html_or_js or ""
    detected_categories = []
    indicators = []
    category_scores = {}

    for cat, patterns in JS_SUSPICIOUS_PATTERNS.items():
        matches_found = []
        for pat in patterns:
            hits = re.findall(pat, code, re.IGNORECASE)
            if hits:
                matches_found.append({"pattern": pat, "count": len(hits)})

        if matches_found:
            detected_categories.append(cat)
            category_scores[cat] = sum(m["count"] for m in matches_found)
            indicators.append({
                "category": cat,
                "matches": matches_found
            })

    has_obfuscation = "obfuscationAndEncoding" in detected_categories or "evalOrDynamicExecution" in detected_categories
    has_keylogging = "credentialCollectionAndKeylogging" in detected_categories
    has_crypto = "cryptoMining" in detected_categories

    risk_score = 0
    if has_obfuscation:
        risk_score += 35
    if has_keylogging:
        risk_score += 45
    if has_crypto:
        risk_score += 50
    if "forcedRedirectAndDownloads" in detected_categories:
        risk_score += 20
    if "browserFingerprinting" in detected_categories:
        risk_score += 15

    risk_score = min(100, risk_score)

    return {
        "jsRiskScore": risk_score,
        "hasObfuscatedCode": has_obfuscation,
        "hasKeyloggingHooks": has_keylogging,
        "hasCryptoMiningSignatures": has_crypto,
        "detectedCategories": detected_categories,
        "indicators": indicators
    }
