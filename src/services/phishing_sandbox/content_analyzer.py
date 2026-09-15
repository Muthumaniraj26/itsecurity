import re
import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any, List

SUSPICIOUS_PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "login to continue",
    "unauthorized access", "account suspended", "update payment method",
    "unusual activity detected", "security alert", "password expired",
    "billing problem", "urgent response required", "wallet recovery phrase",
    "sign in with microsoft", "apple id verification", "enter one-time passcode"
]

async def analyze_sandboxed_content(url: str, custom_html: str = None) -> Dict[str, Any]:
    """
    Fetch and analyze webpage content in a safe sandboxed environment:
    - HTML structure & title
    - Form analysis (Login, Password, Payment, OTP, Hidden fields, Action URLs)
    - Iframes & External script dependencies
    - Phishing keyword triggers
    """
    html_content = custom_html or ""
    status_code = 200
    headers = {}

    if not custom_html:
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecIntel-Sandbox/2.0"}
            ) as client:
                res = await client.get(url)
                html_content = res.text
                status_code = res.status_code
                headers = dict(res.headers)
        except Exception as e:
            return {
                "fetchSuccess": False,
                "error": str(e),
                "title": "",
                "hasLoginForm": False,
                "hasPasswordFields": False,
                "hasPaymentForm": False,
                "hasOtpField": False,
                "externalIframes": 0,
                "externalScripts": 0,
                "hiddenForms": 0,
                "suspiciousKeywords": [],
                "formsSummary": []
            }

    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Page Title
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    # 2. Form & Credential Harvest Inspection
    forms = soup.find_all("form")
    has_login = False
    has_password = False
    has_payment = False
    has_otp = False
    hidden_forms = 0
    forms_summary = []

    for f in forms:
        action = f.get("action", "")
        method = f.get("method", "GET").upper()

        inputs = f.find_all("input")
        pwd_inputs = [i for i in inputs if i.get("type", "").lower() == "password"]
        text_inputs = [i for i in inputs if i.get("type", "").lower() in ("text", "email", "tel", "")]
        hidden_inputs = [i for i in inputs if i.get("type", "").lower() == "hidden"]

        # Payment field heuristic
        card_keywords = ["card", "cc", "cvv", "cvc", "exp", "expiry", "cardnumber"]
        is_payment = any(any(k in (i.get("name", "") + " " + i.get("id", "")).lower() for k in card_keywords) for i in inputs)

        # OTP field heuristic
        otp_keywords = ["otp", "code", "passcode", "2fa", "mfa", "token", "verification"]
        is_otp = any(any(k in (i.get("name", "") + " " + i.get("id", "")).lower() for k in otp_keywords) for i in inputs)

        is_form_hidden = "hidden" in f.get("class", []) or "display:none" in f.get("style", "").replace(" ", "").lower()
        if is_form_hidden:
            hidden_forms += 1

        if pwd_inputs:
            has_password = True
            has_login = True
        if is_payment:
            has_payment = True
        if is_otp:
            has_otp = True

        forms_summary.append({
            "action": action,
            "method": method,
            "passwordFieldsCount": len(pwd_inputs),
            "textFieldsCount": len(text_inputs),
            "hiddenFieldsCount": len(hidden_inputs),
            "isPaymentForm": is_payment,
            "isOtpForm": is_otp,
            "isExternalAction": bool(action.startswith("http://") or action.startswith("https://"))
        })

    # 3. Iframes & Scripts
    iframes = soup.find_all("iframe")
    external_iframes = 0
    for ifr in iframes:
        src = ifr.get("src", "")
        if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
            external_iframes += 1

    scripts = soup.find_all("script")
    external_scripts = 0
    for s in scripts:
        src = s.get("src", "")
        if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
            external_scripts += 1

    # 4. Text & Phishing Keywords
    body_text = soup.get_text(separator=" ", strip=True).lower()
    matched_keywords = [kw for kw in SUSPICIOUS_PHISHING_KEYWORDS if kw in body_text]

    return {
        "fetchSuccess": True,
        "statusCode": status_code,
        "title": title,
        "bodySnippet": body_text[:600],
        "hasLoginForm": has_login,
        "hasPasswordFields": has_password,
        "hasPaymentForm": has_payment,
        "hasOtpField": has_otp,
        "totalForms": len(forms),
        "hiddenForms": hidden_forms,
        "formsSummary": forms_summary,
        "externalIframes": external_iframes,
        "externalScripts": external_scripts,
        "suspiciousKeywords": matched_keywords,
        "contentType": headers.get("content-type", "")
    }
