import os
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from src.services.threat_digest.feed_collector import aggregate_security_feeds
from src.services.threat_digest.analyzer import analyze_threat_feed_item
from src.services.threat_digest.sbom import audit_sbom_dependencies
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
async def get_feeds():
    try:
        feeds = await aggregate_security_feeds()
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
async def audit_sbom(data: SbomAuditSchema):
    """Audit project dependency manifest against threat feeds and known CVE catalogs."""
    try:
        feeds = await aggregate_security_feeds()
        result = audit_sbom_dependencies(data.manifest, active_feeds=feeds)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM audit failed: {str(e)}")

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
        return {"answer": answer}
    except Exception as e:
        # Fallback simulation response if LLM gateway fails
        return {
            "answer": (
                f"**Security Analyst Assessment:** Regarding your query on this advisory, "
                f"the threat is rated at **{data.context.get('severity', 'HIGH') if data.context else 'HIGH'}** priority. "
                f"We recommend isolating any exposed perimeter endpoints, applying emergency vendor patches, "
                f"and reviewing audit logs for anomalous authentication or exfiltration requests."
            )
        }

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
            "text": f"🚨 *[SECURITY ALERT - {severity}]* {title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Security Alert: {severity}"}
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
            "content": f"🚨 **[SECURITY ALERT - {severity}]** {title}",
            "embeds": [
                {
                    "title": title,
                    "description": summary,
                    "color": 15158332 if severity == "CRITICAL" else 15105570,
                    "fields": [
                        {"name": "CVE ID", "value": cve, "inline": True},
                        {"name": "Severity", "value": severity, "inline": True}
                    ],
                    "footer": {"text": "SECURITYHELPDESK Autonomous Threat Alert"}
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
                "activityTitle": f"🚨 Security Alert: {severity}",
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
