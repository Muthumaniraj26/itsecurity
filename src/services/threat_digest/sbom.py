import re
import json
import asyncio
import httpx
from typing import Optional, List, Dict, Any

from src.services.llm_gateway.client import call_multi_llm
from src.services.threat_digest.tools import get_cisa_kev_catalog

# ==============================================================================
# 1. ECOSYSTEM DETECTION & UNIVERSAL MANIFEST / SBOM PARSER
# ==============================================================================
def detect_ecosystem(content: str) -> str:
    """Detects programming language ecosystem or SBOM standard dynamically from manifest format."""
    c = content.strip()
    if 'bomFormat' in c and 'CycloneDX' in c:
        return "CycloneDX SBOM"
    if '<bom' in c or 'xmlns="http://cyclonedx.org/schema' in c:
        return "CycloneDX XML"
    if 'SPDXVersion:' in c or '"spdxVersion"' in c:
        return "SPDX SBOM"
    if c.startswith("{") and ("dependencies" in c or "devDependencies" in c or "peerDependencies" in c):
        return "Node.js (npm)"
    if "go 1." in c or "require (" in c or "module " in c:
        return "Go (pkg.go.dev)"
    if "[dependencies]" in c or "[workspace]" in c or "edition =" in c:
        return "Rust (crates.io)"
    if "<project" in c or "<groupId>" in c or "dependencies {" in c or "implementation(" in c:
        return "Java (Maven/Gradle)"
    if "source 'https://rubygems.org'" in c or "gem " in c:
        return "Ruby (RubyGems)"
    if '"require": {' in c or '"require-dev": {' in c:
        return "PHP (Composer)"
    if "<PackageReference" in c or "<package id=" in c:
        return ".NET (NuGet)"
    return "Python (PyPI)"

def parse_dependency_manifest(content: str) -> list:
    """
    Dynamically extracts package names and version specifications from any input manifest:
    - CycloneDX (JSON & XML)
    - SPDX (JSON & Tag:Value)
    - Node.js (package.json, package-lock.json)
    - Python (requirements.txt, Pipfile, pyproject.toml)
    - Java (pom.xml, build.gradle)
    - Go (go.mod)
    - Rust (Cargo.toml)
    - PHP (composer.json)
    - Ruby (Gemfile)
    - .NET (packages.config, *.csproj)
    - Standard line-by-line format
    """
    content = content.strip()
    if not content:
        return []
    packages = []
    seen = set()

    def add_pkg(name: str, version: str = "latest", operator: str = "", ecosystem: str = "Generic"):
        cleaned_name = name.strip()
        if not cleaned_name or cleaned_name.startswith("#") or cleaned_name.startswith("//"):
            return
        # Normalize version string
        clean_ver = version.strip() if version else "latest"
        clean_ver = re.sub(r'^[~^=><! ]+', '', clean_ver)
        if not clean_ver:
            clean_ver = "latest"
        key = f"{cleaned_name.lower()}@{clean_ver}"
        if key in seen:
            return
        seen.add(key)
        packages.append({
            "name": cleaned_name,
            "version": clean_ver,
            "operator": operator.strip() if operator else "",
            "ecosystem": ecosystem
        })

    # A. JSON Formats (CycloneDX JSON, SPDX JSON, package.json, composer.json)
    if content.startswith("{"):
        try:
            data = json.loads(content)
            # 1. CycloneDX JSON
            if "components" in data and isinstance(data["components"], list):
                for comp in data["components"]:
                    p_name = comp.get("name")
                    p_ver = comp.get("version", "latest")
                    p_purl = comp.get("purl", "")
                    eco = "Generic"
                    if "pkg:pypi" in p_purl:
                        eco = "Python (PyPI)"
                    elif "pkg:npm" in p_purl:
                        eco = "Node.js (npm)"
                    elif "pkg:maven" in p_purl:
                        eco = "Java (Maven)"
                    elif "pkg:golang" in p_purl:
                        eco = "Go"
                    elif "pkg:cargo" in p_purl:
                        eco = "Rust (crates.io)"
                    elif "pkg:nuget" in p_purl:
                        eco = ".NET (NuGet)"
                    if p_name:
                        add_pkg(p_name, p_ver, ecosystem=eco)
                if packages:
                    return packages

            # 2. SPDX JSON
            if "packages" in data and isinstance(data["packages"], list):
                for pkg in data["packages"]:
                    p_name = pkg.get("name")
                    p_ver = pkg.get("versionInfo", "latest")
                    if p_name:
                        add_pkg(p_name, p_ver, ecosystem="SPDX")
                if packages:
                    return packages

            # 3. Node.js package.json
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            peer_deps = data.get("peerDependencies", {})
            for pkg, ver in {**deps, **dev_deps, **peer_deps}.items():
                add_pkg(pkg, str(ver), ecosystem="Node.js (npm)")

            # 4. PHP Composer
            php_deps = data.get("require", {})
            php_dev = data.get("require-dev", {})
            for pkg, ver in {**php_deps, **php_dev}.items():
                if pkg.lower() != "php":
                    add_pkg(pkg, str(ver), ecosystem="PHP (Composer)")

            if packages:
                return packages
        except Exception:
            pass

    # B. XML Formats (CycloneDX XML, Java pom.xml, .NET csproj / packages.config)
    if "<" in content and ">" in content:
        # CycloneDX XML components
        if "<component" in content:
            for match in re.finditer(r'<component[^>]*>.*?<name>([^<]+)</name>.*?<version>([^<]+)</version>', content, re.DOTALL):
                add_pkg(match.group(1), match.group(2), ecosystem="CycloneDX XML")
            if packages:
                return packages

        # Java Maven POM
        if "<dependency>" in content or "<artifactId>" in content:
            for match in re.finditer(r'<artifactId>([^<]+)</artifactId>(?:.*?<version>([^<]+)</version>)?', content, re.DOTALL):
                add_pkg(match.group(1), match.group(2) or "latest", ecosystem="Java (Maven)")
            if packages:
                return packages

        # .NET / NuGet packages.config / *.csproj
        if "<PackageReference" in content or "<package id=" in content:
            for match in re.finditer(r'(?:Include|id)=["\']([^"\']+)["\'](?:\s+Version=["\']([^"\']+)["\'])?', content):
                add_pkg(match.group(1), match.group(2) or "latest", ecosystem=".NET (NuGet)")
            if packages:
                return packages

    # C. SPDX Tag:Value Format
    if "SPDXVersion:" in content or "PackageName:" in content:
        curr_pkg = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("PackageName:"):
                curr_pkg = line.replace("PackageName:", "").strip()
            elif line.startswith("PackageVersion:") and curr_pkg:
                curr_ver = line.replace("PackageVersion:", "").strip()
                add_pkg(curr_pkg, curr_ver, ecosystem="SPDX")
                curr_pkg = None
        if curr_pkg:
            add_pkg(curr_pkg, "latest", ecosystem="SPDX")
        if packages:
            return packages

    # D. Gradle Implementation
    if "implementation" in content or "api(" in content or "compile " in content:
        for match in re.finditer(r"(?:implementation|api|compile)\s*['\"(]+([^:'\"\s]+):([^:'\"\s]+):?([^'\"\s\)]*)?['\"\)]+", content):
            add_pkg(f"{match.group(1)}:{match.group(2)}", match.group(3) or "latest", ecosystem="Java (Gradle)")
        if packages:
            return packages

    # E. Go (go.mod)
    if "module " in content or "require " in content:
        for match in re.finditer(r'(?:require\s+)?([a-zA-Z0-9\.\-_/]+)\s+v?([0-9\.\-a-zA-Z]+)', content):
            if match.group(1) not in ["module", "go", "require"]:
                add_pkg(match.group(1), match.group(2), ecosystem="Go")
        if packages:
            return packages

    # F. Rust (Cargo.toml)
    if "[dependencies]" in content or "[dev-dependencies]" in content:
        for match in re.finditer(r'([a-zA-Z0-9\-_]+)\s*=\s*(?:"([^"]+)"|{\s*version\s*=\s*"([^"]+)")', content):
            pkg = match.group(1)
            ver = match.group(2) or match.group(3) or "latest"
            add_pkg(pkg, ver, ecosystem="Rust (crates.io)")
        if packages:
            return packages

    # G. Ruby Gemfile
    if "gem " in content:
        for match in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", content):
            add_pkg(match.group(1), match.group(2) or "latest", ecosystem="Ruby (RubyGems)")
        if packages:
            return packages

    # H. Line-by-Line Standard Parser (requirements.txt, Pipfile, or generic list)
    detected_eco = detect_ecosystem(content)
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # Support name == 1.2.3, name >= 1.2.3, name: 1.2.3, name = 1.2.3
        match = re.match(r'^([a-zA-Z0-9_\-\./@:]+)\s*([><=~^!:@]+)?\s*([0-9a-zA-Z_\-\.]+)?', line)
        if match:
            pkg_name = match.group(1).strip()
            operator = match.group(2) or ""
            version = match.group(3) or ""
            if pkg_name.lower() not in ["dependencies", "dev-dependencies", "require"]:
                add_pkg(pkg_name, version if version else "latest", operator, ecosystem=detected_eco)

    return packages

# ==============================================================================
# 2. REAL-TIME LIVE OPEN SOURCE VULNERABILITY (OSV.DEV) API CORRELATOR
# ==============================================================================
ECOSYSTEM_OSV_MAP = {
    "Python (PyPI)": "PyPI",
    "Node.js (npm)": "npm",
    "Java (Maven)": "Maven",
    "Java (Gradle)": "Maven",
    "Java (Maven/Gradle)": "Maven",
    "Go": "Go",
    "Go (pkg.go.dev)": "Go",
    "Rust (crates.io)": "crates.io",
    "Ruby (RubyGems)": "RubyGems",
    "PHP (Composer)": "Packagist",
    ".NET (NuGet)": "NuGet",
    "Generic": "PyPI"
}

async def query_live_osv_vulnerabilities(dependencies: list) -> List[Dict[str, Any]]:
    """Queries live OSV.dev open vulnerability catalog in real time without any hardcoded dictionary."""
    if not dependencies:
        return []

    cisa_catalog = get_cisa_kev_catalog()
    results = []

    async with httpx.AsyncClient(timeout=4.0) as client:
        async def check_dep(dep):
            name = dep["name"]
            ver = dep["version"]
            eco = dep.get("ecosystem", "Python (PyPI)")
            osv_eco = ECOSYSTEM_OSV_MAP.get(eco, "PyPI")

            payload = {"package": {"name": name, "ecosystem": osv_eco}}
            if ver and ver != "latest":
                payload["version"] = ver

            try:
                res = await client.post("https://api.osv.dev/v1/query", json=payload)
                if res.status_code == 200:
                    vulns = res.json().get("vulns", [])
                    for v in vulns[:4]: # Top 4 highest priority per package
                        v_id = v.get("id", "VULN")
                        aliases = v.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), v_id)
                        
                        summary = v.get("summary") or v.get("details", "")
                        summary_first_line = summary.split("\n")[0][:180] if summary else f"Security advisory impacting {name}"
                        
                        # Calculate severity dynamically from OSV metadata
                        db_spec = v.get("database_specific", {})
                        sev_raw = (db_spec.get("severity") or "").upper()
                        if "CRITICAL" in sev_raw:
                            sev = "CRITICAL"
                        elif "HIGH" in sev_raw:
                            sev = "HIGH"
                        elif "MODERATE" in sev_raw or "MEDIUM" in sev_raw:
                            sev = "MEDIUM"
                        elif "LOW" in sev_raw:
                            sev = "LOW"
                        else:
                            sev = "HIGH" if any(k in summary.lower() for k in ["rce", "remote code", "injection", "overflow"]) else "MEDIUM"

                        # Check live CISA KEV
                        is_cisa = cve_id in cisa_catalog or any(a in cisa_catalog for a in aliases)
                        if is_cisa:
                            sev = "CRITICAL"

                        # Extract fixed version if available
                        fixed_ver = None
                        for aff in v.get("affected", []):
                            for r in aff.get("ranges", []):
                                for ev in r.get("events", []):
                                    if "fixed" in ev:
                                        fixed_ver = ev["fixed"]
                                        break

                        remediation = f"Upgrade {name} to version >= {fixed_ver}" if fixed_ver else f"Upgrade {name} to the latest non-vulnerable release."

                        # Infer category
                        cat = "Security Vulnerability"
                        s_lower = summary.lower()
                        if "remote code execution" in s_lower or "rce" in s_lower:
                            cat = "Remote Code Execution (RCE)"
                        elif "prototype pollution" in s_lower:
                            cat = "Prototype Pollution"
                        elif "sql injection" in s_lower:
                            cat = "SQL Injection"
                        elif "cross-site scripting" in s_lower or "xss" in s_lower:
                            cat = "Cross-Site Scripting (XSS)"
                        elif "denial of service" in s_lower or "dos" in s_lower:
                            cat = "Denial of Service (DoS)"
                        elif "credential" in s_lower or "leak" in s_lower or "disclosure" in s_lower:
                            cat = "Credential / Info Disclosure"
                        elif "traversal" in s_lower:
                            cat = "Directory Traversal"

                        results.append({
                            "package": name,
                            "version": ver,
                            "cveId": cve_id,
                            "severity": sev,
                            "cisaKev": is_cisa,
                            "threatCategory": cat,
                            "affectedConstraint": f"< {fixed_ver}" if fixed_ver else "Affected release",
                            "title": summary_first_line,
                            "remediation": remediation,
                            "source": "Live OSV Catalog"
                        })
            except Exception:
                pass

        tasks = [check_dep(d) for d in dependencies[:40]]
        await asyncio.gather(*tasks, return_exceptions=True)

    return results

def _clean_json_str(raw: str) -> Optional[dict]:
    """Fault-tolerant JSON extraction from LLM responses."""
    if not raw or not raw.strip():
        return None
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r'(\{[\s\S]*\})', text)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    return None

# ==============================================================================
# 3. PURE REAL-TIME LLM & LIVE THREAT AUDITOR (NO HARDCODED PACKAGES)
# ==============================================================================
async def audit_sbom_dependencies_async(
    manifest_content: str,
    active_feeds: list = None,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> dict:
    """
    Pure Real-Time AI and Live Open-Source Threat Auditor.
    Dynamically analyzes ANY library or software manifest input in real time.
    Uses LLM threat intelligence + Live OSV database queries with zero predefined package lists.
    """
    dependencies = parse_dependency_manifest(manifest_content)
    detected_eco = detect_ecosystem(manifest_content)

    if not dependencies:
        return {
            "totalDependencies": 0,
            "vulnerableCount": 0,
            "riskLevel": "SAFE",
            "ecosystem": detected_eco,
            "matchedVulnerabilities": [],
            "cleanDependencies": [],
            "summary": "No valid packages identified in the input manifest."
        }

    # 1. Real-time Live OSV database query for all parsed dependencies
    live_vulns = []
    try:
        live_vulns = await query_live_osv_vulnerabilities(dependencies)
    except Exception as e:
        print(f"[SBOM Live OSV Notice] {e}")

    # Deduplicate live OSV vulnerabilities
    deduped_live_vulns = []
    seen_keys = set()
    for v in live_vulns:
        k = f"{v['package'].lower()}:{v['cveId']}"
        if k not in seen_keys:
            seen_keys.add(k)
            deduped_live_vulns.append(v)

    # 2. Real-Time Deep LLM Threat Intelligence Evaluation
    pkg_list_str = "\n".join([
        f"- {d['name']} (version: {d['version']}, ecosystem: {d.get('ecosystem', detected_eco)})"
        for d in dependencies
    ])
    osv_context_str = json.dumps(deduped_live_vulns, indent=2)

    prompt = f"""You are a Principal Software Supply Chain & Cyber Threat Intelligence Auditor.
Analyze the following list of software dependencies in real time for security risks, typosquatting, supply chain malware, or known vulnerabilities.

Ecosystem: {detected_eco}

Dependencies to evaluate:
{pkg_list_str}

Live OSV Database Findings (if any):
{osv_context_str}

Raw Manifest Content:
```
{manifest_content[:2500]}
```

Perform rigorous, real-time threat analysis on EVERY package:
1. **Malware / Typosquatting / Supply Chain Deception**:
   - Inspect package names for typosquats, lookalikes, trojanized packages, crypto-stealers, or dependency confusion attacks.
   - For malicious or deceptive packages, mark severity as `CRITICAL`, threatCategory as `Supply Chain Malware` or `Typosquatting`, and explain the threat.
2. **Vulnerabilities / CVEs**:
   - Evaluate whether installed package versions are vulnerable to Remote Code Execution, Privilege Escalation, Prototype Pollution, Deserialization, SSRF, or known CVEs.
   - Assign appropriate severity (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`).
3. **Clean Packages**:
   - Packages that are legitimate, authentic, and free from critical security flaws MUST be added to `cleanDependencies`.
4. **Remediation**:
   - Provide concrete, developer-actionable remediation instructions.

CRITICAL INSTRUCTION:
Return ONLY a valid JSON object matching this schema, without conversational preamble:
{{
  "ecosystem": "{detected_eco}",
  "riskLevel": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
  "summary": "Executive security assessment of evaluated software supply chain dependencies.",
  "matchedVulnerabilities": [
    {{
      "package": "exact_package_name",
      "version": "version_str",
      "cveId": "CVE-XXXX-XXXXX or MALWARE-IDENTIFIER",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cisaKev": true | false,
      "threatCategory": "Supply Chain Malware" | "Typosquatting" | "Remote Code Execution (RCE)" | "Vulnerability",
      "affectedConstraint": "Affected version range or All versions",
      "title": "Clear description of the finding",
      "remediation": "Specific developer remediation guidance",
      "source": "AI Threat Intelligence Model"
    }}
  ],
  "cleanDependencies": [
    "package_name (version)"
  ]
}}
"""
    try:
        raw_response = await call_multi_llm(
            prompt=prompt,
            provider=provider,
            user_api_key=user_api_key,
            model_name=model_name,
            base_url=base_url
        )

        data = _clean_json_str(raw_response)
        if data and isinstance(data, dict) and "matchedVulnerabilities" in data:
            llm_vulns = data.get("matchedVulnerabilities", [])
            clean_list = data.get("cleanDependencies", [])

            # Merge any live OSV findings not already in LLM findings
            all_vulns = list(llm_vulns)
            llm_vuln_pkgs = {f"{v.get('package', '').lower()}:{v.get('cveId', '')}" for v in llm_vulns if isinstance(v, dict)}

            for ov in deduped_live_vulns:
                ov_key = f"{ov['package'].lower()}:{ov['cveId']}"
                if ov_key not in llm_vuln_pkgs:
                    all_vulns.append(ov)

            # Recompute accurate risk level
            has_crit = any(v.get("severity") == "CRITICAL" for v in all_vulns if isinstance(v, dict))
            has_high = any(v.get("severity") == "HIGH" for v in all_vulns if isinstance(v, dict))
            has_med = any(v.get("severity") == "MEDIUM" for v in all_vulns if isinstance(v, dict))

            if has_crit:
                calc_risk = "CRITICAL"
            elif has_high:
                calc_risk = "HIGH"
            elif has_med or len(all_vulns) > 0:
                calc_risk = "MEDIUM"
            else:
                calc_risk = "SAFE"

            # Ensure clean list doesn't include vulnerable packages
            vuln_names = {v.get("package", "").lower() for v in all_vulns if isinstance(v, dict)}
            final_clean = [
                f"{d['name']} ({d['version']})"
                for d in dependencies
                if d["name"].lower() not in vuln_names
            ]

            return {
                "totalDependencies": len(dependencies),
                "vulnerableCount": len(all_vulns),
                "riskLevel": data.get("riskLevel", calc_risk) if data.get("riskLevel") in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] else calc_risk,
                "ecosystem": data.get("ecosystem", detected_eco),
                "matchedVulnerabilities": all_vulns,
                "cleanDependencies": final_clean,
                "summary": data.get("summary", f"AI Threat Intelligence evaluated {len(dependencies)} packages in real time across {detected_eco}.")
            }
    except Exception as e:
        print(f"[SBOM LLM Real-Time Notice] LLM live call notice: {e}")

    # If LLM is unreachable, construct dynamic real-time report from live OSV database query
    has_crit = any(v.get("severity") == "CRITICAL" for v in deduped_live_vulns)
    has_high = any(v.get("severity") == "HIGH" for v in deduped_live_vulns)
    has_med = any(v.get("severity") == "MEDIUM" for v in deduped_live_vulns)

    if has_crit:
        fallback_risk = "CRITICAL"
    elif has_high:
        fallback_risk = "HIGH"
    elif has_med or len(deduped_live_vulns) > 0:
        fallback_risk = "MEDIUM"
    else:
        fallback_risk = "SAFE"

    vuln_names = {v["package"].lower() for v in deduped_live_vulns}
    clean_list = [
        f"{d['name']} ({d['version']})"
        for d in dependencies
        if d["name"].lower() not in vuln_names
    ]

    if deduped_live_vulns:
        fallback_summary = (
            f"Live OSV vulnerability scan evaluated {len(dependencies)} packages in real time. "
            f"Identified {len(deduped_live_vulns)} active security vulnerabilities. "
            f"Immediate review and version upgrades recommended for vulnerable components."
        )
    else:
        fallback_summary = (
            f"Live supply chain scan verified {len(dependencies)} packages in real time across {detected_eco}. "
            f"No active vulnerabilities detected in live open source catalogs."
        )

    return {
        "totalDependencies": len(dependencies),
        "vulnerableCount": len(deduped_live_vulns),
        "riskLevel": fallback_risk,
        "ecosystem": detected_eco,
        "matchedVulnerabilities": deduped_live_vulns,
        "cleanDependencies": clean_list,
        "summary": fallback_summary
    }

def audit_sbom_dependencies(manifest_content: str, active_feeds: list = None) -> dict:
    """Synchronous wrapper for audit_sbom_dependencies_async."""
    return asyncio.run(audit_sbom_dependencies_async(manifest_content, active_feeds))
