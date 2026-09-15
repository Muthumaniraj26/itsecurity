import os
import sys
import asyncio
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.services.threat_digest.sbom import audit_sbom_dependencies_async

async def run_live_tests():
    print("==================================================")
    print("   LIVE DYNAMIC REAL-TIME SBOM AUDITOR TESTS      ")
    print("==================================================\n")

    # TEST 1: Arbitrary Real-World Python Manifest
    print("--- LIVE TEST 1: Python Libraries (Real-time Live OSV & AI) ---")
    manifest_py = """requests==2.25.0
urllib3==1.26.4
fastapi>=0.110.0
pydantic>=2.6.0"""
    res1 = await audit_sbom_dependencies_async(manifest_py)
    print(f"Ecosystem Detected: {res1.get('ecosystem')}")
    print(f"Total Packages: {res1.get('totalDependencies')} | Vulnerabilities: {res1.get('vulnerableCount')} | Risk: {res1.get('riskLevel')}")
    print(f"Executive Summary: {res1.get('summary')}")
    print("Vulnerabilities Identified in Real Time:")
    for v in res1.get("matchedVulnerabilities", []):
        print(f"  - [{v.get('severity')}] {v.get('package')} ({v.get('version')}) -> {v.get('cveId')} | {v.get('title')[:60]}...")
    print(f"Verified Clean Packages: {res1.get('cleanDependencies')}\n")

    # TEST 2: Arbitrary Node.js Manifest
    print("--- LIVE TEST 2: Node.js npm Libraries (Real-time Live OSV & AI) ---")
    manifest_node = json.dumps({
        "dependencies": {
            "lodash": "4.17.19",
            "express": "4.17.1",
            "cors": "^2.8.5"
        }
    }, indent=2)
    res2 = await audit_sbom_dependencies_async(manifest_node)
    print(f"Ecosystem Detected: {res2.get('ecosystem')}")
    print(f"Total Packages: {res2.get('totalDependencies')} | Vulnerabilities: {res2.get('vulnerableCount')} | Risk: {res2.get('riskLevel')}")
    for v in res2.get("matchedVulnerabilities", []):
        print(f"  - [{v.get('severity')}] {v.get('package')} ({v.get('version')}) -> {v.get('cveId')} | {v.get('title')[:60]}...")
    print(f"Verified Clean Packages: {res2.get('cleanDependencies')}\n")

    # TEST 3: Arbitrary / Newly Introduced Custom Libraries
    print("--- LIVE TEST 3: Arbitrary Custom / Newly Introduced Library Names ---")
    manifest_custom = """my-internal-telemetry==1.0.0
secure-auth-broker>=2.1.0
requests2==0.0.1
fake-crypto-wallet==1.0.0"""
    res3 = await audit_sbom_dependencies_async(manifest_custom)
    print(f"Ecosystem Detected: {res3.get('ecosystem')}")
    print(f"Total Packages: {res3.get('totalDependencies')} | Vulnerabilities: {res3.get('vulnerableCount')} | Risk: {res3.get('riskLevel')}")
    print(f"Executive Summary: {res3.get('summary')}")
    for v in res3.get("matchedVulnerabilities", []):
        print(f"  - [{v.get('severity')}] {v.get('package')} ({v.get('version')}) -> {v.get('cveId')} ({v.get('threatCategory')})")
    print(f"Verified Clean Packages: {res3.get('cleanDependencies')}\n")

    print("==================================================")
    print("   ALL DYNAMIC LIVE AUDIT RUNS COMPLETED [OK]     ")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_live_tests())
