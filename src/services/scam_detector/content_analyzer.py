import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

DECEPTIVE_DISCOUNT_KEYWORDS = [
    "80% off", "90% off", "70% off", "blowout sale", "replica", "factory clearance",
    "free giveaway", "claim your prize", "limited stock hurry", "exclusive discount"
]

CRYPTO_FINANCIAL_FRAUD_KEYWORDS = [
    "crypto investment", "100% guarantee", "double your deposit", "risk free profit",
    "guaranteed returns", "bitcoin giveaway", "send 0.1 btc receive 1 btc", "mining pool profit",
    "daily roi", "cloud mining profit", "instant withdrawal guarantee"
]

IRREVERSIBLE_PAYMENT_METHODS = [
    "western union", "moneygram", "send bitcoin", "usdt trc20", "gift card payment",
    "apple gift card", "steam card payment", "zelle to personal", "cashapp only"
]

OBFUSCATED_JS_PATTERNS = [
    (r'eval\s*\(', "eval() Dynamic Code Execution"),
    (r'unescape\s*\(', "unescape() String Obfuscation"),
    (r'document\.write\s*\(unescape', "Document Write Obfuscation"),
    (r'coinhive|cryptonight|miner\.start', "Crypto-Mining Script Signature"),
    (r'atob\s*\(', "Base64 Dynamic Decoding (atob)"),
    (r'fromCharCode', "String fromCharCode Character Masking"),
    (r'window\[["\']\\x[0-9a-fA-F]+["\']\]', "Hex Encoded Window Property Access")
]

def analyze_page_content_and_behavior(html: str, target_domain: str) -> dict:
    """
    Audits DOM elements, credential forms, obfuscated JavaScript, deceptive commercial claims,
    and payment red flags.
    """
    soup = BeautifulSoup(html or "", 'html.parser')
    body_text = soup.body.get_text().lower() if soup.body else (html or "").lower()

    result = {
        "title": soup.title.string.strip() if soup.title and soup.title.string else "Untitled Target",
        "hasLoginForms": False,
        "passwordFieldsCount": 0,
        "formsDiscovered": [],
        "externalFormAction": False,
        "suspiciousJsPatterns": [],
        "deceptiveDiscountFound": [],
        "financialFraudKeywords": [],
        "irreversiblePaymentDemands": [],
        "hasFreeWebmailSupport": False,
        "hasContactInfo": False,
        "hasPolicyPages": False,
        "iframesCount": 0,
        "hiddenElementsCount": 0,
        "indicators": []
    }

    # 1. Forms & Password / Credential Harvesting Analysis
    forms = soup.find_all("form")
    for f in forms:
        action = (f.get("action") or "").strip()
        method = (f.get("method") or "GET").upper()
        inputs = f.find_all("input")
        pwd_inputs = [i for i in inputs if i.get("type", "").lower() == "password"]
        
        is_ext = False
        if action.startswith(('http://', 'https://')):
            f_host = urlparse(action).hostname or ""
            if f_host.startswith("www."): f_host = f_host[4:]
            if f_host and f_host != target_domain:
                is_ext = True
                result["externalFormAction"] = True
                result["indicators"].append(f"External Form Action Target: Login/Form credentials submitted to third-party host [{f_host}].")

        if pwd_inputs:
            result["hasLoginForms"] = True
            result["passwordFieldsCount"] += len(pwd_inputs)

        result["formsDiscovered"].append({
            "action": action or "(Same Page)",
            "method": method,
            "inputsCount": len(inputs),
            "hasPassword": len(pwd_inputs) > 0,
            "isExternal": is_ext
        })

    # 2. Obfuscated JavaScript & Crypto-Mining Analysis
    scripts = soup.find_all("script")
    script_content = " ".join([s.get_text() for s in scripts if s.get_text()])
    
    for pattern, desc in OBFUSCATED_JS_PATTERNS:
        if re.search(pattern, script_content, re.I):
            result["suspiciousJsPatterns"].append(desc)
            result["indicators"].append(f"Suspicious JavaScript Pattern: Detected {desc}.")

    # 3. Deceptive Discounts & Marketing Pressure
    for kw in DECEPTIVE_DISCOUNT_KEYWORDS:
        if kw in body_text:
            result["deceptiveDiscountFound"].append(kw)
    if result["deceptiveDiscountFound"]:
        result["indicators"].append(f"Deceptive Commercial Pressure: Found promotional discount lures [{', '.join(result['deceptiveDiscountFound'][:3])}].")

    # 4. Financial Fraud & Unrealistic ROI Claims
    for kw in CRYPTO_FINANCIAL_FRAUD_KEYWORDS:
        if kw in body_text:
            result["financialFraudKeywords"].append(kw)
    if result["financialFraudKeywords"]:
        result["indicators"].append(f"High-Risk Financial Guarantees: Found speculative promises [{', '.join(result['financialFraudKeywords'][:3])}].")

    # 5. Irreversible Payment Demands
    for kw in IRREVERSIBLE_PAYMENT_METHODS:
        if kw in body_text:
            result["irreversiblePaymentDemands"].append(kw)
    if result["irreversiblePaymentDemands"]:
        result["indicators"].append(f"Irreversible Payment Demands: Site requests non-refundable payment [{', '.join(result['irreversiblePaymentDemands'])}].")

    # 6. Contact & Free Webmail Accountability
    free_webmails = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@protonmail.com"]
    for wm in free_webmails:
        if wm in body_text:
            result["hasFreeWebmailSupport"] = True
            result["indicators"].append(f"Free Webmail for Business: Official contact address uses free personal email [{wm}] rather than enterprise domain.")
            break

    contact_words = ["contact us", "support@", "help@", "phone:", "tel:", "customer service", "office address"]
    result["hasContactInfo"] = any(w in body_text for w in contact_words)

    policy_words = ["privacy policy", "terms of service", "terms and conditions", "refund policy", "return policy"]
    result["hasPolicyPages"] = any(w in body_text for w in policy_words)

    # 7. DOM Traps (iFrames and Hidden Elements)
    result["iframesCount"] = len(soup.find_all("iframe"))
    result["hiddenElementsCount"] = len(soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden', re.I)))

    return result
