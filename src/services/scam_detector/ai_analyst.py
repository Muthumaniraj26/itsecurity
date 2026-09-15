import json
from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm

async def generate_ai_domain_security_report(
    domain: str,
    url: str,
    risk_summary: dict,
    domain_info: dict,
    dns_info: dict,
    ssl_info: dict,
    web_security: dict,
    email_sec: dict,
    phishing_info: dict,
    threat_intel: dict,
    content_info: dict,
    geo_info: dict,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> dict:
    """
    AI Security Analyst synthesis layer that correlates technical telemetry
    and produces an executive risk report with actionable intelligence.
    """
    evidence_payload = {
        "domain": domain,
        "url": url,
        "riskScore": risk_summary["riskScore"],
        "trustScore": risk_summary["trustScore"],
        "riskLevel": risk_summary["riskLevel"],
        "threatClassification": risk_summary["threatClassification"],
        "domainAgeDays": domain_info.get("ageDays"),
        "registrar": domain_info.get("registrar"),
        "ip": geo_info.get("ip"),
        "country": geo_info.get("country"),
        "asn": geo_info.get("asn"),
        "isBrandImpersonation": phishing_info.get("isBrandImpersonation"),
        "impersonatedBrand": phishing_info.get("impersonatedBrand"),
        "suspiciousTokens": phishing_info.get("suspiciousTokensFound"),
        "sslHealth": ssl_info.get("health"),
        "sslIssuer": ssl_info.get("issuer", {}).get("organization"),
        "sslDaysActive": ssl_info.get("daysActive"),
        "headerGrade": web_security.get("securityHeaders", {}).get("grade"),
        "missingHeaders": web_security.get("securityHeaders", {}).get("missingHeaders"),
        "spfPolicy": email_sec.get("spf", {}).get("policy"),
        "dmarcPolicy": email_sec.get("dmarc", {}).get("policy"),
        "blacklistsListed": threat_intel.get("blacklistsListed"),
        "hasLoginForms": content_info.get("hasLoginForms"),
        "externalFormAction": content_info.get("externalFormAction"),
        "financialFraudKeywords": content_info.get("financialFraudKeywords"),
        "deceptiveDiscountFound": content_info.get("deceptiveDiscountFound"),
        "freeWebmailSupport": content_info.get("hasFreeWebmailSupport"),
        "redFlags": risk_summary.get("redFlags", [])
    }

    prompt = f"""
You are an expert Principal Cyber Threat Intelligence Analyst and Anti-Fraud Investigator.
Review the following correlated telemetry gathered from real-time DNS, RDAP, TLS, HTTP security headers, and behavioral DOM inspection:

TARGET TELEMETRY:
{json.dumps(evidence_payload, indent=2)}

Synthesize this data into a definitive Executive Security Assessment. Correlate multiple signals (e.g. fresh domain + brand keyword + external form action + missing DMARC = credential harvesting).
Explain WHY the risk score was generated based on verifiable evidence.

You MUST respond strictly with raw JSON matching this schema:
{{
  "executiveSummary": "Concise 2-3 sentence overview of the domain's risk posture and verified intent.",
  "threatActorIntent": "e.g. Active Credential Harvesting / High-Yield Investment Fraud / Counterfeit E-Commerce Storefront / Legitimate Corporate Service",
  "confidenceScore": 95,
  "keyCorrelatedFindings": [
    "First correlated finding connecting multiple telemetry points",
    "Second finding explaining infrastructure or authentication posture",
    "Third finding on brand abuse or deceptive mechanics"
  ],
  "technicalVerdict": "High-confidence assessment string detailing whether users or organizations should block, monitor, or trust this domain.",
  "recommendedActions": [
    "Immediate action for end-users (e.g. Do not submit credentials)",
    "Action for enterprise SOC (e.g. Add domain to perimeter DNS sinkhole)",
    "Action for abuse mitigation (e.g. Report to hosting provider or registrar)"
  ]
}}
"""
    try:
        raw_response = await call_multi_llm(prompt, provider, user_api_key, model_name, base_url)
        return parse_json_response(raw_response)
    except Exception as e:
        print(f"AI Domain Report synthesis notice ({provider}): {e}")
        # Deterministic Fallback Synthesis
        return {
            "executiveSummary": f"Domain {domain} exhibits a {risk_summary['riskLevel']} risk rating (Score: {risk_summary['riskScore']}/100) classified as '{risk_summary['threatClassification']}'. Telemetry identifies {len(risk_summary.get('redFlags', []))} primary risk flags across infrastructure, domain age, and authentication hygiene.",
            "threatActorIntent": risk_summary["threatClassification"],
            "confidenceScore": 92 if risk_summary["riskScore"] >= 70 or risk_summary["riskScore"] <= 20 else 80,
            "keyCorrelatedFindings": risk_summary.get("redFlags", [])[:4] or [f"Domain evaluated as {risk_summary['riskLevel']} with standard baseline security."],
            "technicalVerdict": f"{'BLOCK & ISOLATE: High likelihood of malicious or deceptive operations.' if risk_summary['riskScore'] >= 70 else ('MONITOR & EXERCISE CAUTION: Elevated risk indicators present.' if risk_summary['riskScore'] >= 40 else 'SAFE TO PROCEED: Verified enterprise domain with standard security compliance.')}",
            "recommendedActions": [
                "Do not submit sensitive credentials, financial details, or API keys if risk score is elevated.",
                "Enforce strict DNS and SPF/DMARC email security policies to prevent domain spoofing.",
                "Deploy HTTPS Strict-Transport-Security (HSTS) and Content-Security-Policy (CSP) headers."
            ]
        }
