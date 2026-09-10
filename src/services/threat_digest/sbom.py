import re
import json
from src.services.threat_digest.tools import get_cisa_kev_catalog

# Known Vulnerability Catalog for Common Enterprise Packages
KNOWN_VULN_DB = {
    "log4j": {
        "cve": "CVE-2021-44228",
        "severity": "CRITICAL",
        "affected": "<2.17.1",
        "title": "Log4Shell Remote Code Execution in Apache Log4j",
        "remediation": "Upgrade log4j to >=2.17.1 or replace with SLF4J loggers immediately."
    },
    "urllib3": {
        "cve": "CVE-2023-45803",
        "severity": "HIGH",
        "affected": "<2.0.7",
        "title": "HTTP Request Smuggling via Chunked Stripping in urllib3",
        "remediation": "Upgrade urllib3 to >=2.0.7 or latest 2.x release."
    },
    "requests": {
        "cve": "CVE-2023-32681",
        "severity": "MEDIUM",
        "affected": "<2.31.0",
        "title": "Proxy-Authorization Header Leakage on HTTPS Redirect",
        "remediation": "Upgrade requests to >=2.31.0."
    },
    "aiohttp": {
        "cve": "CVE-2024-23829",
        "severity": "HIGH",
        "affected": "<3.9.2",
        "title": "HTTP Parser Request Smuggling / Security Bypass",
        "remediation": "Upgrade aiohttp to >=3.9.2."
    },
    "jinja2": {
        "cve": "CVE-2024-22195",
        "severity": "MEDIUM",
        "affected": "<3.1.3",
        "title": "HTML Attribute Cross-Site Scripting (XSS) via xmlattr Filter",
        "remediation": "Upgrade jinja2 to >=3.1.3."
    },
    "django": {
        "cve": "CVE-2024-45231",
        "severity": "HIGH",
        "affected": "<4.2.16",
        "title": "Potential Denial of Service Vulnerability in email validation",
        "remediation": "Upgrade Django to >=4.2.16, >=5.0.9, or latest LTS."
    },
    "jsonwebtoken": {
        "cve": "CVE-2022-23529",
        "severity": "HIGH",
        "affected": "<9.0.0",
        "title": "Insecure Key Retrieval Remote Code Execution in jsonwebtoken",
        "remediation": "Upgrade jsonwebtoken to >=9.0.0."
    },
    "axios": {
        "cve": "CVE-2023-45857",
        "severity": "HIGH",
        "affected": "<1.6.0",
        "title": "Cross-Site Request Forgery / SSRF Data Leakage in Axios",
        "remediation": "Upgrade axios to >=1.6.0 or latest release."
    },
    "lodash": {
        "cve": "CVE-2021-23337",
        "severity": "HIGH",
        "affected": "<4.17.21",
        "title": "Prototype Pollution / Command Injection via template",
        "remediation": "Upgrade lodash to >=4.17.21."
    },
    "moment": {
        "cve": "CVE-2022-31129",
        "severity": "HIGH",
        "affected": "<2.29.4",
        "title": "Pathological Regular Expression Denial of Service (ReDoS)",
        "remediation": "Upgrade moment to >=2.29.4 or migrate to date-fns/Luxon."
    },
    "paramiko": {
        "cve": "CVE-2023-48795",
        "severity": "HIGH",
        "affected": "<3.4.0",
        "title": "Terrapin Attack: Prefix Truncation in SSH protocol",
        "remediation": "Upgrade paramiko to >=3.4.0."
    },
    "pillow": {
        "cve": "CVE-2023-4863",
        "severity": "CRITICAL",
        "affected": "<10.0.1",
        "title": "Heap Buffer Overflow in WebP Image Processing",
        "remediation": "Upgrade Pillow to >=10.0.1."
    }
}

def parse_dependency_manifest(content: str) -> list:
    """Extracts package name and version specs from requirements.txt or package.json."""
    content = content.strip()
    packages = []

    # 1. Try parsing JSON (package.json)
    if content.startswith("{") and "dependencies" in content:
        try:
            data = json.loads(content)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}
            for pkg, ver in all_deps.items():
                packages.append({
                    "name": pkg.lower().strip(),
                    "version": str(ver).replace("^", "").replace("~", "").strip(),
                    "ecosystem": "npm"
                })
            return packages
        except Exception:
            pass

    # 2. Parse Line-by-Line (requirements.txt or simple manifest)
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Match python package==1.2.3 or package>=1.2.3
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([><=~^!]+)?\s*([0-9a-zA-Z_\-\.]+)?', line)
        if match:
            pkg_name = match.group(1).lower().strip()
            operator = match.group(2) or "=="
            version = match.group(3) or "latest"
            packages.append({
                "name": pkg_name,
                "version": version,
                "operator": operator,
                "ecosystem": "pypi"
            })

    return packages

def audit_sbom_dependencies(manifest_content: str, active_feeds: list = None) -> dict:
    """
    Audits an uploaded Software Bill of Materials (SBOM) or manifest against:
    1. Known enterprise vulnerability catalog (KNOWN_VULN_DB).
    2. CISA KEV Exploitation catalog.
    3. Active ingested threat feed alerts.
    """
    dependencies = parse_dependency_manifest(manifest_content)
    if not dependencies:
        return {
            "totalDependencies": 0,
            "vulnerableCount": 0,
            "riskLevel": "SAFE",
            "matchedVulnerabilities": [],
            "cleanDependencies": [],
            "summary": "No valid packages identified. Please provide a valid requirements.txt or package.json."
        }

    cisa_catalog = get_cisa_kev_catalog()
    vulnerable_matches = []
    clean_deps = []

    for dep in dependencies:
        name = dep["name"]
        ver = dep.get("version", "unknown")
        matched = False

        # Check in Known Vulnerability DB
        if name in KNOWN_VULN_DB:
            vuln_info = KNOWN_VULN_DB[name]
            cve_id = vuln_info["cve"]
            is_cisa_kev = cve_id in cisa_catalog

            vulnerable_matches.append({
                "package": name,
                "version": ver,
                "cveId": cve_id,
                "severity": "CRITICAL" if is_cisa_kev else vuln_info["severity"],
                "cisaKev": is_cisa_kev,
                "affectedConstraint": vuln_info["affected"],
                "title": vuln_info["title"],
                "remediation": vuln_info["remediation"],
                "source": "Known Vulnerability Catalog"
            })
            matched = True

        # Cross-reference with live ingested threat feeds
        if active_feeds and not matched:
            for feed in active_feeds:
                f_title = feed.get("title", "").lower()
                f_desc = feed.get("description", "").lower()
                if f" {name} " in f" {f_title} " or f" {name} " in f" {f_desc} ":
                    cve_match = re.search(r'cve-\d{4}-\d{4,}', f_title + " " + f_desc, re.I)
                    extracted_cve = cve_match.group(0).upper() if cve_match else "CVE-PENDING"
                    vulnerable_matches.append({
                        "package": name,
                        "version": ver,
                        "cveId": extracted_cve,
                        "severity": "HIGH",
                        "cisaKev": extracted_cve in cisa_catalog,
                        "affectedConstraint": "Current advisory alert",
                        "title": f"Active Security Advisory: {feed.get('title')}",
                        "remediation": "Audit module usage and upgrade to the vendor-patched release.",
                        "source": f"Live Feed Alert ({feed.get('source', 'Security Advisory')})"
                    })
                    matched = True
                    break

        if not matched:
            clean_deps.append(f"{name} ({ver})")

    # Determine overall SBOM risk level
    v_count = len(vulnerable_matches)
    if any(v["severity"] == "CRITICAL" or v.get("cisaKev") for v in vulnerable_matches):
        risk_level = "CRITICAL"
    elif any(v["severity"] == "HIGH" for v in vulnerable_matches):
        risk_level = "HIGH"
    elif v_count > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "SAFE"

    summary_text = (
        f"Audited {len(dependencies)} dependencies across project manifests. "
        f"Identified {v_count} vulnerable packages requiring mitigation. "
        f"Overall dependency risk posture is rated [{risk_level}]."
    )

    return {
        "totalDependencies": len(dependencies),
        "vulnerableCount": v_count,
        "riskLevel": risk_level,
        "matchedVulnerabilities": vulnerable_matches,
        "cleanDependencies": clean_deps,
        "summary": summary_text
    }
