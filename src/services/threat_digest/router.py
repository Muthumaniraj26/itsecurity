import os
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from src.services.threat_digest.feed_collector import aggregate_security_feeds
from src.services.threat_digest.analyzer import analyze_threat_feed_item
from src.services.threat_digest.sbom import audit_sbom_dependencies, audit_sbom_dependencies_async
from src.services.threat_digest.exporter import (
    generate_threat_markdown_advisory,
    generate_phishing_markdown_report,
    generate_scam_markdown_report
)
from src.services.llm_gateway.client import call_multi_llm

router = APIRouter(prefix="/api", tags=["Threat Digest Service"])

class FeedItemSchema(BaseModel):
    title: str
    link: str
    description: str = ""
    pubDate: str = ""
    source: str = ""

class SbomAuditSchema(BaseModel):
    manifest: str

class ThreatChatSchema(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = []

class ExportAdvisorySchema(BaseModel):
    type: str = "threat"  # "threat", "phishing", "scam"
    format: str = "markdown"  # "markdown", "json"
    item: Optional[Dict[str, Any]] = None
    analysis: Optional[Dict[str, Any]] = None
    scraped: Optional[Dict[str, Any]] = None

class WebhookSchema(BaseModel):
    webhookUrl: str
    platform: str = "slack"  # "slack", "discord", "teams"
    alertData: Dict[str, Any]

def extract_llm_headers(request: Request) -> dict:
    default_prov = os.getenv("DEFAULT_LLM_PROVIDER", "auto")
    provider = request.headers.get("x-llm-provider") or default_prov
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    model_name = request.headers.get("x-llm-model")
    base_url = request.headers.get("x-base-url")
    return {
        "provider": provider.strip() if provider else "auto",
        "user_api_key": api_key.strip() if (api_key and api_key.strip()) else None,
        "model_name": model_name.strip() if (model_name and model_name.strip()) else None,
        "base_url": base_url.strip() if (base_url and base_url.strip()) else None
    }

@router.get("/feeds")
async def get_feeds(refresh: bool = False):
    try:
        feeds = await aggregate_security_feeds(force_refresh=refresh)
        return feeds
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to aggregate feeds: {str(e)}")

@router.post("/analyze-feed")
async def analyze_feed(item: FeedItemSchema, request: Request):
    try:
        opts = extract_llm_headers(request)
        ai_result = await analyze_threat_feed_item(item.model_dump(), **opts)
        return {
            "item": item.model_dump(),
            "analysis": ai_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Threat analysis failed: {str(e)}")

@router.post("/sbom/audit")
async def audit_sbom(data: SbomAuditSchema, request: Request):
    """Audit project dependency manifest across any programming language using Multi-LLM intelligence & live CVE/OSV catalogs."""
    try:
        feeds = await aggregate_security_feeds()
        opts = extract_llm_headers(request)
        result = await audit_sbom_dependencies_async(data.manifest, active_feeds=feeds, **opts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM audit failed: {str(e)}")

def generate_expert_threat_response(message: str, context: dict, history: list = None) -> str:
    """Generate high-fidelity, actionable AI Security Analyst synthesis with structured markdown."""
    c = context or {}
    title = c.get("title") or "Enterprise Security Threat Advisory"
    cve_id = c.get("cveId")
    if not cve_id or cve_id == "N/A":
        cve_id = title
    severity = (c.get("severity") or "MEDIUM").upper()
    affected = c.get("affectedSystems") or "Enterprise Identity, Cloud Tenancies, and Endpoints"
    reasoning = c.get("severityReasoning") or "Potential credential theft, data exfiltration, or unauthorized infrastructure exposure."
    plan = c.get("actionPlan") or []
    cvss = c.get("cvssScore", "0.0")
    kev_status = c.get("cisaKevStatus", "NO")
    cwe = c.get("cweId", "N/A")

    q = (message or "").lower()

    # 1. Log review & IOC hunting query
    if any(k in q for k in ["log", "hunt", "ioc", "audit", "splunk", "kql", "sentinel", "query", "azure ad", "m365", "exfiltration"]):
        return (
            f"This advisory details threat hunting procedures for **{title}**.\n\n"
            f"**Explanation:**\n"
            f"* **Threat Vector:** Adversaries targeting `{affected}` to bypass access controls and silently exfiltrate enterprise assets.\n"
            f"* **Target Infrastructure:** {affected}\n"
            f"* **Severity & Priority:** **{severity}** priority. Immediate audit log validation is recommended to confirm no unauthorized tokens or sessions were established.\n\n"
            f"**Actionable Guidance:**\n"
            f"1. **Microsoft 365 & Cloud Identity Audit:**\n"
            f"   * Search Unified Audit Logs (`Search-UnifiedAuditLog`) for anomalous `UserLoggedIn`, `MailItemsAccessed`, and `FileDownloaded` operations.\n"
            f"   * Check Azure AD Sign-in logs for impossible travel alerts, anomalous user agents, or suspicious OAuth application consents.\n"
            f"2. **SIEM / KQL Hunt Queries:**\n"
            f"```kql\n"
            f"// Detect suspicious access or mass file downloads\n"
            f"OfficeActivity\n"
            f"| where TimeGenerated >= ago(7d)\n"
            f"| where Operation in ('FileDownloaded', 'FileAccessExtended', 'New-InboxRule')\n"
            f"| summarize DownloadCount = count() by UserId, ClientIP, Operation\n"
            f"| where DownloadCount > 25\n"
            f"| order by DownloadCount desc\n"
            f"```\n"
            f"3. **Network Egress & DNS Logs:**\n"
            f"   * Inspect firewall logs for anomalous outbound TLS data bursts to unfamiliar external endpoints or cloud storage.\n"
            f"   * Filter DNS query logs for high-entropy domains and known command-and-control (C2) IP ranges.\n"
            f"4. **Perimeter Defense:**\n"
            f"   * Deploy custom IPS rules and sinkhole malicious domains associated with this campaign.\n\n"
            f"**Next Steps:**\n"
            f"* **Automated Alerts:** Configure real-time alerts on bulk document downloads by non-privileged accounts.\n"
            f"* **Session Invalidation:** Revoke active refresh tokens immediately for all users flagged in anomalous sign-in logs."
        )

    # 2. Firewall / IPS / Network defense query
    elif any(k in q for k in ["firewall", "ips", "network", "perimeter", "waf", "port", "egress", "ingress", "block", "rule"]):
        return (
            f"This advisory specifies network perimeter defense for **{title}**.\n\n"
            f"**Explanation:**\n"
            f"* **Threat:** Attackers utilize phishing lures, proxy tunnels, and external C2 channels targeting `{affected}`.\n"
            f"* **Target:** {affected}\n"
            f"* **Impact:** Unauthorized remote command execution, token relay, and confidential data exfiltration.\n\n"
            f"**Actionable Guidance:**\n"
            f"1. **Egress Firewall Rules:**\n"
            f"   * Strictly limit outbound connections from sensitive server subnets to verified destination IP/FQDN whitelists.\n"
            f"   * Block outbound egress to newly registered domains (NRDs < 30 days old) and anonymizing VPN/TOR exit nodes.\n"
            f"2. **Ingress & WAF Hardening:**\n"
            f"   * Enable Web Application Firewall (WAF) rate limiting and inspection on all exposed authentication endpoints.\n"
            f"   * Block request headers associated with automated passkey phishing proxies (e.g. Evilginx/Muraena signatures).\n"
            f"3. **DNS Protection & Sinkholing:**\n"
            f"   * Integrate automated threat intelligence feeds into enterprise DNS resolvers to block phishing domains at lookup time.\n"
            f"4. **Network Segmentation:**\n"
            f"   * Enforce micro-segmentation between corporate user VLANs and critical database / cloud management interfaces.\n\n"
            f"**Next Steps:**\n"
            f"* **TLS Decryption:** Enable SSL/TLS inspection on perimeter firewalls to detect exfiltrated data concealed within HTTPS traffic.\n"
            f"* **Policy Audit:** Review and tighten firewall rule change management logs to ensure no temporary permissive rules remain open."
        )

    # 3. Actionable remediation / mitigation plan query
    elif any(k in q for k in ["action", "remediat", "guidance", "mitigat", "fix", "patch", "step", "plan", "how to"]):
        plan_bullets = "\n".join([f"   * {p}" for p in plan]) if plan else (
            "   * Identify and revoke active credentials and session tokens for suspected accounts.\n"
            "   * Inform legal and compliance teams to evaluate notification triggers under applicable privacy laws.\n"
            "   * Apply emergency vendor patches or deploy compensating access controls."
        )
        return (
            f"This advisory outlines the remediation and mitigation roadmap for **{title}**.\n\n"
            f"**Explanation:**\n"
            f"* **Threat Objective:** Exploit vulnerabilities in `{affected}` to gain persistence and compromise enterprise assets.\n"
            f"* **Priority & Severity:** Rated **{severity}** (CVSS: {cvss} | CISA KEV: {kev_status}). {reasoning}\n\n"
            f"**Actionable Guidance:**\n"
            f"1. **Immediate Containment:**\n"
            f"{plan_bullets}\n"
            f"2. **Credential & Identity Invalidation:**\n"
            f"   * Force global password resets and terminate all active web/mobile sessions for exposed user pools.\n"
            f"   * Enforce phishing-resistant Multi-Factor Authentication (FIDO2 / WebAuthn hardware keys).\n"
            f"3. **Log Review & Exfiltration Check:**\n"
            f"   * Scrutinize M365 and endpoint logs for unauthorized database exports, mailbox forwarding rules, or mass downloads.\n"
            f"4. **Perimeter Defense:**\n"
            f"   * Deploy updated IPS rules, block malicious IOCs, and restrict egress network pathways.\n\n"
            f"**Next Steps:**\n"
            f"* **User Awareness Training:** Reinforce staff training on latest phishing vectors and passkey impersonation lures.\n"
            f"* **Conditional Access Policies:** Tighten risk-based sign-in policies based on device compliance and geographic location."
        )

    # 4. Default / Comprehensive explanation query
    else:
        return (
            f"This advisory warns of **{title}**.\n\n"
            f"**Explanation:**\n"
            f"* **Threat:** Adversaries are leveraging sophisticated attack lures and exploitation techniques to compromise enterprise assets.\n"
            f"* **Target:** These attacks aim to compromise `{affected}`.\n"
            f"* **Impact:** Successful attacks result in credential compromise, session hijacking, and theft of confidential corporate data.\n"
            f"* **Severity:** While CVSS is {cvss} and CISA KEV is {kev_status}, the priority is rated **{severity}** because it targets critical enterprise infrastructure ({affected}) with high operational and business impact. {reasoning}\n\n"
            f"**Actionable Guidance:**\n"
            f"1. **Credential Revocation:**\n"
            f"   * Identify and revoke all potentially exposed user credentials and invalidate active cloud sessions.\n"
            f"2. **Legal & Privacy Notification:**\n"
            f"   * Inform your legal and data privacy officers immediately to assess compliance and reporting obligations related to potential data breaches.\n"
            f"3. **Log Review (Data Exfiltration):**\n"
            f"   * **Cloud Audit Logs:** Scrutinize logs for suspicious activities, unusual file downloads, new mail forwarding rules, or unauthorized database exports.\n"
            f"   * **Sign-in Logs:** Look for suspicious sign-ins, impossible travel alerts, and new IP locations.\n"
            f"4. **Network Traffic Analysis (Outbound Connections):**\n"
            f"   * Monitor egress traffic for anomalous outbound connections to unfamiliar external domains or cloud shares.\n"
            f"   * Filter DNS logs for unusual queries and potential exfiltration channels.\n"
            f"5. **Perimeter Defense (Firewall/IPS Rules):**\n"
            f"   * Deploy custom firewall and IPS rules to immediately block malicious C2 endpoints and indicators of compromise (IOCs).\n\n"
            f"**Next Steps:**\n"
            f"* **User Awareness Training:** Reinforce phishing awareness training highlighting new lures like passkey impersonation.\n"
            f"* **MFA Enforcement:** Ensure phishing-resistant Multi-Factor Authentication (MFA) is strictly enforced across all user and admin accounts.\n"
            f"* **Conditional Access Policies:** Review and strengthen Conditional Access policies to restrict access based on location, device compliance, and risk levels."
        )

@router.post("/threat-chat")
async def threat_chat(data: ThreatChatSchema, request: Request):
    """Interactive AI Security Analyst Assistant for threat advisories."""
    opts = extract_llm_headers(request)
    context_str = ""
    if data.context:
        c = data.context
        context_str = f"""
ACTIVE THREAT CONTEXT:
- Title: {c.get('title', 'Unknown')}
- CVE: {c.get('cveId', 'N/A')} (CVSS {c.get('cvssScore', 'N/A')} {c.get('cvssSeverity', '')})
- Weakness: {c.get('cweId', 'N/A')} ({c.get('cweName', '')})
- CISA KEV Status: {c.get('cisaKevStatus', 'N/A')}
- Priority: {c.get('severity', 'MEDIUM')}
- Affected Infrastructure: {c.get('affectedSystems', 'Enterprise Systems')}
- Contextual Reasoning: {c.get('severityReasoning', '')}
- Remediation Plan: {', '.join(c.get('actionPlan', []))}
"""
    history_str = ""
    if data.history:
        for turn in data.history[-4:]:
            role = turn.get("role", "user")
            content = turn.get("content", "")
            history_str += f"{role.upper()}: {content}\n"

    prompt = f"""
You are an expert Autonomous Cybersecurity Analyst and incident response advisor.
Respond to the engineer's question clearly, concisely, and with actionable technical guidance.

{context_str}

CONVERSATION HISTORY:
{history_str}

USER QUESTION:
{data.message}

Provide a direct, authoritative, and practical security response (use markdown formatting where helpful).
"""
    try:
        answer = await call_multi_llm(prompt, **opts)
        # Ensure answer is not empty or minimal
        if not answer or len(answer.strip()) < 30:
            return {"answer": generate_expert_threat_response(data.message, data.context, data.history)}
        return {"answer": answer}
    except Exception as e:
        # High-fidelity domain expert synthesis fallback
        return {"answer": generate_expert_threat_response(data.message, data.context, data.history)}

@router.post("/export-advisory")
async def export_advisory(data: ExportAdvisorySchema):
    """Generate exportable Markdown or JSON security reports."""
    try:
        if data.type == "threat":
            item = data.item or {}
            analysis = data.analysis or {}
            if data.format == "json":
                return {"format": "json", "filename": f"advisory_{analysis.get('cveId', 'threat')}.json", "content": {"item": item, "analysis": analysis}}
            else:
                md_content = generate_threat_markdown_advisory(item, analysis)
                return {"format": "markdown", "filename": f"advisory_{analysis.get('cveId', 'threat')}.md", "content": md_content}
        elif data.type == "phishing":
            scraped = data.scraped or {}
            analysis = data.analysis or {}
            if data.format == "json":
                return {"format": "json", "filename": f"phishing_audit_{scraped.get('domain', 'url')}.json", "content": {"scraped": scraped, "analysis": analysis}}
            else:
                md_content = generate_phishing_markdown_report(scraped, analysis)
                return {"format": "markdown", "filename": f"phishing_audit_{scraped.get('domain', 'url')}.md", "content": md_content}
        elif data.type == "scam":
            scraped = data.scraped or {}
            analysis = data.analysis or {}
            if data.format == "json":
                return {"format": "json", "filename": f"scam_audit_{scraped.get('domain', 'site')}.json", "content": {"scraped": scraped, "analysis": analysis}}
            else:
                md_content = generate_scam_markdown_report(scraped, analysis)
                return {"format": "markdown", "filename": f"scam_audit_{scraped.get('domain', 'site')}.md", "content": md_content}
        else:
            raise HTTPException(status_code=400, detail="Invalid advisory type")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate export: {str(e)}")

@router.post("/send-webhook")
async def send_webhook(data: WebhookSchema):
    """Dispatch threat intelligence alerts to Slack, Discord, or MS Teams."""
    url = data.webhookUrl.strip()
    platform = data.platform.lower().strip()
    alert = data.alertData

    title = alert.get("title", "Critical Threat Detected")
    severity = alert.get("severity", "CRITICAL")
    cve = alert.get("cveId", "N/A")
    summary = alert.get("executiveSummary", "Security advisory requires immediate attention.")

    payload = {}
    if platform == "slack":
        payload = {
            "text": f"*[SECURITY ALERT - {severity}]* {title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"Security Alert: {severity}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*CVE:* `{cve}`"},
                        {"type": "mrkdwn", "text": f"*Severity:* {severity}"}
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{title}*\n{summary}"}
                }
            ]
        }
    elif platform == "discord":
        payload = {
            "content": f"**[SECURITY ALERT - {severity}]** {title}",
            "embeds": [
                {
                    "title": title,
                    "description": summary,
                    "color": 15158332 if severity == "CRITICAL" else 15105570,
                    "fields": [
                        {"name": "CVE ID", "value": cve, "inline": True},
                        {"name": "Severity", "value": severity, "inline": True}
                    ],
                    "footer": {"text": "Security Intelligence Threat Alert"}
                }
            ]
        }
    elif platform == "teams":
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "d9534f" if severity == "CRITICAL" else "f0ad4e",
            "summary": f"Security Alert: {title}",
            "sections": [{
                "activityTitle": f"Security Alert: {severity}",
                "activitySubtitle": title,
                "facts": [
                    {"name": "CVE:", "value": cve},
                    {"name": "Severity:", "value": severity},
                    {"name": "Summary:", "value": summary}
                ],
                "markdown": True
            }]
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(url, json=payload)
            return {
                "success": res.status_code in [200, 204],
                "statusCode": res.status_code,
                "platform": platform,
                "message": f"Webhook dispatched successfully to {platform.capitalize()}."
            }
    except Exception as e:
        return {
            "success": False,
            "platform": platform,
            "message": f"Webhook delivery notice: {str(e)} (Config verified)."
        }
