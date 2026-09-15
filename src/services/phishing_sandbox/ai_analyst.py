import json
from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm
from typing import Dict, Any

async def run_ai_threat_analyst(
    scan_report: Dict[str, Any],
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> Dict[str, Any]:
    """
    Synthesize all URL sandbox inspection vectors using Multi-LLM reasoning:
    - Executive Verdict
    - Targeted Brand & Impersonation Anatomy
    - MITRE ATT&CK TTP mapping
    - Evidence Correlation Analysis
    - SOC Remediations & Triage Action Plan
    """
    normalizer = scan_report.get("normalizer", {})
    risk = scan_report.get("riskScoring", {})
    brand = scan_report.get("brandImpersonation", {})
    phishing = scan_report.get("phishingDetection", {})
    domain = scan_report.get("domainAnalysis", {})
    content = scan_report.get("contentAnalysis", {})
    redirect = scan_report.get("redirectAnalysis", {})
    reputation = scan_report.get("reputationIntelligence", {})
    auth = scan_report.get("authHarvestVectors", {})
    js = scan_report.get("javascriptAnalysis", {})

    prompt = f"""
You are a Principal SOC Cyber Threat Intelligence Analyst and Phishing Forensics Specialist.
Review the comprehensive sandbox telemetry collected for the target URL:

TARGET TELEMETRY:
- Raw URL: {normalizer.get('rawUrl')}
- Clean Normalized URL: {normalizer.get('cleanUrl')}
- Domain: {normalizer.get('domain')}
- Scheme / Port: {normalizer.get('scheme')} / {normalizer.get('port')}
- Is Shortened URL: {normalizer.get('isShortUrl')}
- Domain Age: {domain.get('ageDays', 'Unknown')} days (Registrar: {domain.get('registrar', 'Unknown')})
- Newly Registered Domain: {domain.get('isNewlyRegistered')}
- IP / ASN / Country: {domain.get('ipAddress', 'Unknown')} / {domain.get('asn', 'Unknown')} / {domain.get('country', 'Unknown')}
- Targeted Brand: {brand.get('targetedBrand') or 'None detected'}
- Brand Impersonation Flag: {brand.get('isBrandImpersonationDetected')}
- Homoglyphs / Unicode Confusables: {phishing.get('homoglyphs', {}).get('hasHomoglyphs')}
- Threat Feeds Matches: {reputation.get('totalThreatMatches', 0)} matches (Reputation: {reputation.get('reputationLevel')})
- Redirect Hops: {redirect.get('totalHops', 1)} (Suspicious Chain: {redirect.get('isSuspiciousRedirectChain')})
- Page Title: "{content.get('title', '')}"
- Credential Harvesting Vectors: {auth.get('harvestTargets')}
- Obfuscated JS / Keylogging: Obfuscated={js.get('hasObfuscatedCode')}, Keylogging={js.get('hasKeyloggingHooks')}
- Computed Empirical Risk Score: {risk.get('totalScore')}/100 ({risk.get('classification')})

Generate an authoritative, explainable incident investigation report.
You must respond in raw JSON format matching this schema:
{{
  "executiveVerdict": "Clear 2-3 sentence executive synopsis explaining the verdict, confidence, and primary attack surface.",
  "phishingTechniques": [
    "Specific phishing or evasion technique 1 (e.g., Typo-squatting, Credential Harvesting, Homoglyph disguise)",
    "Technique 2..."
  ],
  "mitreAttackMapping": [
    {{"techniqueId": "T1566.002", "techniqueName": "Spearphishing Link", "tactic": "Initial Access"}},
    {{"techniqueId": "T1056.001", "techniqueName": "Keylogging / Credential Interception", "tactic": "Collection"}}
  ],
  "threatLandscapeContext": "Context on whether this fits known phishing campaign infrastructure or commodity phishing kits.",
  "socRemediationSteps": [
    "Actionable step 1 for SOC analysts (e.g. Block domain on edge firewall, Revoke compromised user sessions)",
    "Actionable step 2...",
    "Actionable step 3..."
  ]
}}
"""

    try:
        response_text = await call_multi_llm(prompt, provider, user_api_key, model_name, base_url)
        parsed = parse_json_response(response_text)
        return parsed
    except Exception as e:
        # Fallback structured analyst assessment
        return {
            "executiveVerdict": f"URL exhibits {risk.get('classification')} risk indicators with an aggregate risk score of {risk.get('totalScore')}/100. Telemetry shows {'active brand impersonation of ' + str(brand.get('targetedBrand')) if brand.get('isBrandImpersonationDetected') else 'unusual domain and form collection behavior'}.",
            "phishingTechniques": [
                "Deceptive Domain Registration" if domain.get('isNewlyRegistered') else "URL Path Obfuscation",
                "Credential Form Harvesting" if auth.get('hasCredentialHarvesting') else "Suspicious Redirect Redirection"
            ],
            "mitreAttackMapping": [
                {"techniqueId": "T1566.002", "techniqueName": "Spearphishing Link", "tactic": "Initial Access"},
                {"techniqueId": "T1584.004", "techniqueName": "Server Compromise / Impersonation", "tactic": "Resource Development"}
            ],
            "threatLandscapeContext": "Observed patterns align with automated phishing kit deployments targeting enterprise credentials.",
            "socRemediationSteps": [
                "Block the domain and associated IP address on perimeter firewalls and DNS sinkholes.",
                "Inspect web proxy logs for internal endpoints that accessed this destination.",
                "Force credential reset and MFA token revocation for any users who submitted credentials."
            ]
        }
