import pytest
from src.services.phishing_sandbox.url_normalizer import normalize_url
from src.services.phishing_sandbox.phishing_detector import detect_phishing_domain_similarity
from src.services.phishing_sandbox.brand_intel import analyze_brand_impersonation
from src.services.phishing_sandbox.risk_engine import compute_url_risk_score
from src.services.phishing_sandbox.auth_indicators import extract_authentication_harvest_vectors
from src.services.phishing_sandbox.download_malware_analyzer import analyze_download_payload

def test_url_normalizer_components():
    url = "https://login.example.com:443/account?id=123&utm_source=tracker#section"
    res = normalize_url(url)
    assert res["scheme"] == "https"
    assert res["domain"] == "login.example.com"
    assert res["baseDomain"] == "example.com"
    assert res["port"] == 443
    assert res["path"] == "/account"
    assert "utm_source" in res["strippedTrackingParams"]
    assert "utm_source" not in res["cleanUrl"]

def test_homoglyph_and_brand_impersonation():
    suspicious_url = "https://secure-login-portal.paypal-verification-update.net/auth"
    norm = normalize_url(suspicious_url)
    brand_res = analyze_brand_impersonation(norm["domain"], norm["cleanUrl"])
    assert brand_res["isBrandImpersonationDetected"] is True
    assert "PayPal" in brand_res["targetedBrand"]

def test_auth_harvesting_detection():
    html = "Please enter your 12-word seed phrase or private key to recover your wallet."
    forms_summary = [
        {"passwordFieldsCount": 1, "textFieldsCount": 1, "isPaymentForm": True, "isOtpForm": True}
    ]
    auth_res = extract_authentication_harvest_vectors(html, forms_summary)
    assert auth_res["hasCredentialHarvesting"] is True
    assert auth_res["harvestTargets"]["password"] is True
    assert auth_res["harvestTargets"]["cryptoSeedPhrase"] is True
    assert auth_res["harvestTargets"]["creditCardOrCvv"] is True

def test_risk_scoring_rubric():
    norm = normalize_url("http://192.168.1.1/login.php.exe")
    rep = {"isDirectIpHost": True, "reputationLevel": "HIGH RISK"}
    phish = {"isPhishingSuspect": True, "homoglyphs": {"hasHomoglyphs": True}}
    brand = {"isBrandImpersonationDetected": True, "targetedBrand": "PayPal"}
    dom = {"ageDays": 2, "isNewlyRegistered": True}
    redirect = {"isSuspiciousRedirectChain": True, "totalHops": 3}
    content = {"hasPasswordFields": True, "hasPaymentForm": True, "hasOtpField": True}
    js = {"jsRiskScore": 50, "hasObfuscatedCode": True}
    dl = {"isDownloadTriggered": True, "isExecutablePayload": True}
    ssl = {"hasSsl": False, "isValid": False}
    auth = {"hasCredentialHarvesting": True, "harvestVectorCount": 3}

    score_res = compute_url_risk_score(
        normalizer_data=norm,
        reputation_data=rep,
        domain_data=dom,
        phishing_data=phish,
        brand_data=brand,
        content_data=content,
        redirect_data=redirect,
        js_data=js,
        download_data=dl,
        ssl_data=ssl,
        auth_data=auth
    )
    assert score_res["totalScore"] >= 70
    assert score_res["classification"] in ["CRITICAL", "HIGH"]
