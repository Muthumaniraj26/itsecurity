import asyncio
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.services.threat_digest.router import extract_llm_headers
from src.services.scam_detector.domain_intel import (
    normalize_domain_and_url,
    fetch_rdap_whois,
    query_dns_records,
    check_email_security_protections,
    fetch_ip_geolocation,
    enumerate_subdomains
)
from src.services.scam_detector.ssl_analyzer import inspect_ssl_tls_certificate
from src.services.scam_detector.web_security import (
    inspect_web_security_and_headers,
    scan_common_ports
)
from src.services.scam_detector.phishing_typosquatting import analyze_phishing_and_typosquatting
from src.services.scam_detector.threat_intelligence import (
    check_dnsbl_blacklist,
    evaluate_threat_intelligence
)
from src.services.scam_detector.content_analyzer import analyze_page_content_and_behavior
from src.services.scam_detector.risk_engine import compute_comprehensive_domain_risk
from src.services.scam_detector.ai_analyst import generate_ai_domain_security_report
from src.services.scraper.url_scraper import scrape_url_info

router = APIRouter(prefix="/api", tags=["Domain Security & Scam Intelligence"])

class DomainScanInput(BaseModel):
    url: str

@router.post("/detect-scam")
@router.post("/domain-audit")
async def audit_domain_security(data: DomainScanInput, request: Request):
    """
    Comprehensive 10-Module Domain Threat Intelligence & Website Scam Audit.
    Executes deep DNS, WHOIS, SSL/TLS, Security Headers, Phishing/Typosquatting,
    Infrastructure Geolocation, Content Analysis, and AI Threat Synthesis.
    """
    try:
        raw_target = data.url.strip()
        if not raw_target:
            raise ValueError("Target domain or URL cannot be empty.")

        domain, normalized_url = normalize_domain_and_url(raw_target)
        opts = extract_llm_headers(request)

        # 1. Parallel Core Telemetry Gathering
        rdap_task = fetch_rdap_whois(domain)
        dns_task = asyncio.get_event_loop().run_in_executor(None, lambda: query_dns_records(domain))
        ssl_task = asyncio.get_event_loop().run_in_executor(None, lambda: inspect_ssl_tls_certificate(domain))
        web_task = inspect_web_security_and_headers(domain, normalized_url)
        subdomains_task = enumerate_subdomains(domain)
        scraper_task = scrape_url_info(normalized_url)

        rdap_info, dns_records, ssl_info, web_sec_info, subdomains, scraped_raw = await asyncio.gather(
            rdap_task, dns_task, ssl_task, web_task, subdomains_task, scraper_task,
            return_exceptions=False
        )

        # 2. Extract Primary IP & Run Infrastructure Probing
        primary_ip = (dns_records.get("A") or [""])[0]
        geo_task = fetch_ip_geolocation(primary_ip)
        ports_task = scan_common_ports(domain)
        dnsbl_task = check_dnsbl_blacklist(primary_ip, domain)

        geo_info, open_ports, dnsbl_results = await asyncio.gather(
            geo_task, ports_task, dnsbl_task,
            return_exceptions=False
        )

        # 3. Email Authentication & DNS Defense Posture
        email_sec = check_email_security_protections(
            domain,
            dns_records.get("TXT", []),
            dns_records.get("MX", [])
        )

        # 4. Phishing & Brand Impersonation / Typosquatting Analysis
        phishing_info = analyze_phishing_and_typosquatting(domain, normalized_url)

        # 5. Threat Intelligence & Blacklist Synthesis
        threat_intel = evaluate_threat_intelligence(domain, primary_ip, dnsbl_results)

        # 6. Content & Behavioral DOM Analysis
        content_info = analyze_page_content_and_behavior(
            scraped_raw.get("pageMetadata", {}).get("bodySnippet", "") + " " + scraped_raw.get("pageMetadata", {}).get("title", ""),
            domain
        )
        if scraped_raw.get("pageMetadata", {}).get("hasPasswordFields"):
            content_info["hasLoginForms"] = True
        if scraped_raw.get("pageMetadata", {}).get("emptyOrExternalForm"):
            content_info["externalFormAction"] = True

        # 7. Multi-Factor 6-Pillar Risk Engine
        risk_evaluation = compute_comprehensive_domain_risk(
            domain=domain,
            domain_info=rdap_info,
            phishing_info=phishing_info,
            threat_intel=threat_intel,
            ssl_info=ssl_info,
            web_security=web_sec_info,
            email_sec=email_sec,
            content_info=content_info
        )

        # 8. Real-Time AI Security Analyst Executive Synthesis
        ai_report = await generate_ai_domain_security_report(
            domain=domain,
            url=normalized_url,
            risk_summary=risk_evaluation,
            domain_info=rdap_info,
            dns_info=dns_records,
            ssl_info=ssl_info,
            web_security=web_sec_info,
            email_sec=email_sec,
            phishing_info=phishing_info,
            threat_intel=threat_intel,
            content_info=content_info,
            geo_info=geo_info,
            **opts
        )

        # Construct Unified Domain Intelligence Report
        response_data = {
            "domain": domain,
            "url": normalized_url,
            "scannedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "riskScore": risk_evaluation["riskScore"],
            "trustScore": risk_evaluation["trustScore"],
            "riskLevel": risk_evaluation["riskLevel"],
            "threatClassification": risk_evaluation["threatClassification"],
            "redFlags": risk_evaluation["redFlags"],
            "trustSignals": risk_evaluation["trustSignals"],
            "breakdown": risk_evaluation["breakdown"],
            "domainIntelligence": {
                "domain": domain,
                "registrar": rdap_info.get("registrar"),
                "createdDate": rdap_info.get("createdDate"),
                "expiresDate": rdap_info.get("expiresDate"),
                "updatedDate": rdap_info.get("updatedDate"),
                "ageDays": rdap_info.get("ageDays"),
                "daysUntilExpiry": rdap_info.get("daysUntilExpiry"),
                "status": rdap_info.get("status", []),
                "privacyProtected": rdap_info.get("privacyProtected", False),
                "nameservers": dns_records.get("nameservers", [])
            },
            "dnsIntelligence": dns_records,
            "subdomains": subdomains,
            "emailSecurity": email_sec,
            "sslIntelligence": ssl_info,
            "webSecurity": web_sec_info,
            "openPorts": open_ports,
            "infrastructure": geo_info,
            "phishingRadar": phishing_info,
            "threatIntelligence": threat_intel,
            "contentAnalysis": content_info,
            "aiReport": ai_report
        }

        # Backwards compatible key for older UI components
        response_data["scraped"] = scraped_raw
        response_data["analysis"] = {
            "scamProbability": risk_evaluation["riskScore"],
            "trustScore": risk_evaluation["trustScore"],
            "redFlags": risk_evaluation["redFlags"],
            "riskSignalsText": ai_report.get("executiveSummary", ""),
            "assessmentText": ai_report.get("technicalVerdict", "")
        }

        return response_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Domain Security Audit failed: {str(e)}")
