from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from src.services.phishing_sandbox.url_normalizer import normalize_url, expand_short_url
from src.services.phishing_sandbox.reputation_intel import check_url_reputation
from src.services.phishing_sandbox.domain_engine import analyze_domain_infrastructure
from src.services.phishing_sandbox.phishing_detector import detect_phishing_domain_similarity
from src.services.phishing_sandbox.brand_intel import analyze_brand_impersonation
from src.services.phishing_sandbox.content_analyzer import analyze_sandboxed_content
from src.services.phishing_sandbox.redirect_analyzer import trace_redirect_chain
from src.services.phishing_sandbox.js_analyzer import analyze_javascript_behaviors
from src.services.phishing_sandbox.download_malware_analyzer import analyze_download_payload
from src.services.phishing_sandbox.ssl_engine import analyze_ssl_certificate
from src.services.phishing_sandbox.auth_indicators import extract_authentication_harvest_vectors
from src.services.phishing_sandbox.risk_engine import compute_url_risk_score
from src.services.phishing_sandbox.ai_analyst import run_ai_threat_analyst
from src.services.threat_digest.router import extract_llm_headers

router = APIRouter(prefix="/api", tags=["Phishing Sandbox & Deep URL Inspection"])

class UrlScanRequest(BaseModel):
    url: str
    scanLevel: Optional[str] = "deep"  # "fast", "deep", "advanced"

@router.post("/scan-url")
async def scan_url_deep_sandbox(data: UrlScanRequest, request: Request):
    """
    Comprehensive 16-Module Deep Sandbox Inspection:
    1. URL Input & Normalization & Shortener expansion
    2. Threat Intelligence & Reputation Feeds
    3. Domain RDAP, DNS & IP Geolocation
    4. Phishing Heuristics & Homoglyph Detection
    5. Brand Impersonation Recognition
    6. Sandboxed Web Content & Form Audits
    7. Safe Redirect Chain Tracer
    8. JavaScript Static Behavioral Analysis
    9. Download & Malware Payload Inspection
    10. SSL/TLS Certificate Analysis
    11. Credential & Asset Harvesting Vectors
    12. Empirical Risk Scoring (0 - 100)
    13. Multi-LLM AI Threat Analyst Investigation
    """
    try:
        raw_url = data.url.strip()
        if not raw_url:
            raise HTTPException(status_code=400, detail="URL cannot be empty.")

        opts = extract_llm_headers(request)

        # 1. URL Normalization
        normalizer_result = normalize_url(raw_url)
        if not normalizer_result.get("valid"):
            raise HTTPException(status_code=400, detail=normalizer_result.get("error", "Invalid URL."))

        target_url = normalizer_result["cleanUrl"]
        target_domain = normalizer_result["domain"]
        target_subdomains = normalizer_result["subdomains"]

        # If shortener detected, expand
        shortener_info = {}
        if normalizer_result.get("isShortUrl"):
            shortener_info = await expand_short_url(target_url)
            if shortener_info.get("isExpanded") and shortener_info.get("finalUrl"):
                target_url = shortener_info["finalUrl"]

        # 2. Threat Intelligence Reputation
        reputation_result = check_url_reputation(target_url, target_domain)

        # 3. Domain & DNS Infrastructure
        domain_result = await analyze_domain_infrastructure(target_domain)

        # 4. Phishing Detection (Levenshtein, Jaro-Winkler, Homoglyphs)
        phishing_result = detect_phishing_domain_similarity(target_domain, target_subdomains)

        # 5. Sandboxed Web Content Analysis
        content_result = await analyze_sandboxed_content(target_url)

        # 6. Brand Impersonation Analysis
        brand_result = analyze_brand_impersonation(target_domain, target_url, content_result.get("title", ""))

        # 7. Safe Multi-Hop Redirect Trace
        redirect_result = await trace_redirect_chain(target_url)

        # 8. JavaScript Behavior Analysis
        js_result = analyze_javascript_behaviors(content_result.get("bodySnippet", ""))

        # 9. Download & Malware Payload Analysis
        download_result = analyze_download_payload(
            target_url,
            content_result.get("contentType", ""),
            content_result.get("contentDisposition", "")
        )

        # 10. SSL/TLS Certificate Handshake
        ssl_result = analyze_ssl_certificate(target_domain, normalizer_result.get("port", 443))

        # 11. Authentication & Credential Harvesting Indicators
        auth_result = extract_authentication_harvest_vectors(
            content_result.get("bodySnippet", ""),
            content_result.get("formsSummary", [])
        )

        # 12. Empirical Risk Scoring Engine
        risk_result = compute_url_risk_score(
            normalizer_data=normalizer_result,
            reputation_data=reputation_result,
            domain_data=domain_result,
            phishing_data=phishing_result,
            brand_data=brand_result,
            content_data=content_result,
            redirect_data=redirect_result,
            js_data=js_result,
            download_data=download_result,
            ssl_data=ssl_result,
            auth_data=auth_result
        )

        # Assemble full scan report
        full_report = {
            "url": target_url,
            "rawInputUrl": raw_url,
            "domain": target_domain,
            "normalizer": normalizer_result,
            "shortener": shortener_info,
            "reputationIntelligence": reputation_result,
            "domainAnalysis": domain_result,
            "phishingDetection": phishing_result,
            "brandImpersonation": brand_result,
            "contentAnalysis": content_result,
            "redirectAnalysis": redirect_result,
            "javascriptAnalysis": js_result,
            "downloadMalwareAnalysis": download_result,
            "sslTlsAnalysis": ssl_result,
            "authHarvestVectors": auth_result,
            "riskScoring": risk_result
        }

        # 13. AI Threat Analyst Synthesis
        ai_analyst_result = await run_ai_threat_analyst(full_report, **opts)
        full_report["aiAnalystVerdict"] = ai_analyst_result

        return full_report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deep sandbox URL scan failed: {str(e)}")

@router.post("/scan-url/normalize")
async def normalize_url_endpoint(data: UrlScanRequest):
    """Utility endpoint to dissect and normalize any URL."""
    norm = normalize_url(data.url)
    if norm.get("isShortUrl"):
        exp = await expand_short_url(norm["cleanUrl"])
        norm["expansion"] = exp
    return norm
