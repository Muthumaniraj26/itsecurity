import json
from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm
from src.services.threat_digest.tools import run_security_investigation_tools

def get_simulated_threat_analysis(title: str, summary: str) -> dict:
    """Heuristic simulation fallback for threat feed analysis."""
    content = (title + " " + (summary or "")).lower()
    
    category = "Vulnerabilities & Patches"
    compliance = ["SOC 2"]
    remediation = "Apply latest security patches from vendor immediately."

    if "ransomware" in content or "lockbit" in content or "encrypt" in content:
        category = "Ransomware"
        compliance.extend(["GDPR", "ISO 27001"])
        remediation = "Check offline backup viability. Isolate affected network segments. Roll out endpoint protection rules."
    elif "leak" in content or "breach" in content or "data" in content or "exposed" in content:
        category = "Data Breach & Privacy"
        compliance.extend(["GDPR", "HIPAA"])
        remediation = "Revoke exposed credentials. Notify legal & data privacy officers. Review logs for unauthorized database exports."
    elif "compliance" in content or "regulation" in content or "law" in content or "audit" in content:
        category = "Compliance Regulation"
        compliance.extend(["GDPR", "PCI DSS", "HIPAA", "SOC 2"])
        remediation = "Conduct internal compliance gap assessment. Audit security access controls and data retention logs."

    compliance = list(set(compliance))
    tool_results = run_security_investigation_tools({"title": title, "description": summary, "source": "Security Advisory"})

    return {
        "executiveSummary": f"AI Summary of threat alert regarding \"{title}\". {category} advisory requiring immediate security review.",
        "category": category,
        "severity": tool_results["contextualPriority"],
        "severityReasoning": tool_results["priorityReasoning"],
        "affectedSystems": tool_results["orgAssetName"],
        "cveId": tool_results["cveId"],
        "isCve": tool_results["isCve"],
        "incidentCategory": tool_results["incidentCategory"],
        "cisaKevStatus": tool_results["cisaKevStatus"],
        "cvssScore": tool_results["cvssScore"],
        "cvssSeverity": tool_results["cvssSeverity"],
        "cvssVector": tool_results["cvssVector"],
        "cweId": tool_results["cweId"],
        "cweName": tool_results["cweName"],
        "mitreTtp": tool_results["mitreTtp"],
        "orgAssetMatch": tool_results["orgAssetMatch"],
        "orgAssetName": tool_results["orgAssetName"],
        "internetExposed": tool_results["internetExposed"],
        "investigationTrail": tool_results["investigationTrail"],
        "complianceImpact": compliance,
        "actionPlan": [
            remediation,
            "Perform network traffic analysis to detect any anomalous outbound connections.",
            "Deploy custom firewall / IPS rules to block known exploit payloads."
        ]
    }

async def analyze_threat_feed_item(
    item: dict,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> dict:
    """Analyze a threat feed item by executing deterministic tools and synthesizing with LLM."""
    tool_results = run_security_investigation_tools(item)
    
    prompt = f"""
    You are an Autonomous AI Security Analyst Agent performing organization-specific threat intelligence.
    
    DETERMINISTIC INVESTIGATION TOOL RESULTS:
    - Extracted CVE: {tool_results['cveId']} (Is Formal CVE: {tool_results['isCve']})
    - Threat/Incident Category: {tool_results['incidentCategory']}
    - CISA KEV Exploitation Status: {tool_results['cisaKevStatus']}
    - Threat Impact / CVSS Metric: {tool_results['cvssScore']} ({tool_results['cvssSeverity']}) Vector: {tool_results['cvssVector']}
    - Root Weakness Enumeration: {tool_results['cweId']} - {tool_results['cweName']}
    - MITRE ATT&CK TTP: {tool_results['mitreTtp']['id']} - {tool_results['mitreTtp']['name']} ({tool_results['mitreTtp']['tactic']})
    - Organization Asset Inventory Match: {tool_results['orgAssetMatch']} (Target Asset: {tool_results['orgAssetName']})
    - Internet Exposed Asset: {tool_results['internetExposed']}
    - Contextual Priority Score: {tool_results['contextualPriority']} ({tool_results['priorityReasoning']})

    FEED ITEM TO SYNTHESIZE:
    Feed Title: "{item['title']}"
    Feed Summary: "{item.get('description', 'No description provided')}"
    Feed Link: "{item['link']}"

    You must reply in raw JSON format (no markdown blocks, just the JSON object itself). The JSON must match the following schema exactly:
    {{
      "executiveSummary": "Concise 2-sentence summary of what happened, who is affected, and why it matters.",
      "category": "One of: Ransomware, Data Breach & Privacy, Vulnerabilities & Patches, Compliance Regulation, Threat Actor Campaign",
      "severity": "{tool_results['contextualPriority']}",
      "severityReasoning": "{tool_results['priorityReasoning']}",
      "affectedSystems": "{tool_results['orgAssetName']}",
      "cveId": "{tool_results['cveId']}",
      "isCve": {str(tool_results['isCve']).lower()},
      "incidentCategory": "{tool_results['incidentCategory']}",
      "cisaKevStatus": "{tool_results['cisaKevStatus']}",
      "cvssScore": {tool_results['cvssScore']},
      "cvssSeverity": "{tool_results['cvssSeverity']}",
      "cweId": "{tool_results['cweId']}",
      "cweName": "{tool_results['cweName']}",
      "mitreTtp": {json.dumps(tool_results['mitreTtp'])},
      "orgAssetMatch": "{tool_results['orgAssetMatch']}",
      "orgAssetName": "{tool_results['orgAssetName']}",
      "internetExposed": "{tool_results['internetExposed']}",
      "investigationTrail": {json.dumps(tool_results['investigationTrail'])},
      "complianceImpact": ["GDPR", "HIPAA", "SOC 2", "PCI DSS"],
      "actionPlan": ["Step 1...", "Step 2...", "Step 3...", "Step 4..."]
    }}
    """
    try:
        response_text = await call_multi_llm(prompt, provider, user_api_key, model_name, base_url)
        parsed = parse_json_response(response_text)
        parsed["cveId"] = tool_results["cveId"]
        parsed["isCve"] = tool_results["isCve"]
        parsed["incidentCategory"] = tool_results["incidentCategory"]
        parsed["cisaKevStatus"] = tool_results["cisaKevStatus"]
        parsed["cvssScore"] = tool_results["cvssScore"]
        parsed["cvssSeverity"] = tool_results["cvssSeverity"]
        parsed["cvssVector"] = tool_results["cvssVector"]
        parsed["cweId"] = tool_results["cweId"]
        parsed["cweName"] = tool_results["cweName"]
        parsed["mitreTtp"] = tool_results["mitreTtp"]
        parsed["orgAssetMatch"] = tool_results["orgAssetMatch"]
        parsed["orgAssetName"] = tool_results["orgAssetName"]
        parsed["internetExposed"] = tool_results["internetExposed"]
        parsed["investigationTrail"] = tool_results["investigationTrail"]
        if not parsed.get("severity"):
            parsed["severity"] = tool_results["contextualPriority"]
        return parsed
    except Exception as e:
        print(f"Multi-LLM threat analysis failed ({provider}): {e}")
        return get_simulated_threat_analysis(item["title"], item.get("description", ""))
