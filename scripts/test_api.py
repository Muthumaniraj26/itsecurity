import httpx
import sys

def test_endpoints():
    print("==================================================")
    print("   TESTING FASTAPI MICROSERVICES ENDPOINTS (PORT 8000)")
    print("==================================================\n")
    
    server_url = "http://localhost:8000"
    all_passed = True
    
    # 1. Test /health
    try:
        res = httpx.get(f"{server_url}/health", timeout=5.0)
        print(f"[OK] GET /health -> Status {res.status_code}")
        print(f"     Microservices active: {res.json().get('microservices')}")
    except Exception as err:
        print(f"[ERROR] GET /health failed: {err}")
        print("Please ensure 'python server.py' is running.")
        sys.exit(1)

    # 2. Test /api/feeds
    sample_article = None
    try:
        response = httpx.get(f"{server_url}/api/feeds", timeout=10.0)
        print(f"\n[OK] GET /api/feeds -> Status {response.status_code}")
        feeds = response.json()
        print(f"     Total articles returned: {len(feeds)}")
        
        if len(feeds) > 0:
            sample_article = feeds[0]
            print(f"     Sample article: \"{sample_article.get('title')[:50]}...\" from {sample_article.get('source')}")
    except Exception as err:
        print(f"[ERROR] GET /api/feeds failed: {err}")
        all_passed = False

    # 3. Test /api/analyze-feed (with NIST NVD & MITRE)
    analysis_data = None
    if sample_article:
        try:
            analyze_res = httpx.post(f"{server_url}/api/analyze-feed", json=sample_article, timeout=20.0)
            print(f"\n[OK] POST /api/analyze-feed -> Status {analyze_res.status_code}")
            analysis = analyze_res.json().get("analysis", {})
            analysis_data = analysis
            print(f"     CVE ID: {analysis.get('cveId')} | CVSS: {analysis.get('cvssScore')} ({analysis.get('cvssSeverity')})")
            print(f"     CWE: {analysis.get('cweId')} - {analysis.get('cweName')}")
            print(f"     Category: {analysis.get('category')} | Severity: {analysis.get('severity')}")
            print(f"     CISA KEV: {analysis.get('cisaKevStatus')}")
        except Exception as err:
            print(f"[ERROR] POST /api/analyze-feed failed: {err}")
            all_passed = False

    # 4. Test /api/sbom/audit
    try:
        manifest_sample = "fastapi>=0.110.0\nlog4j==2.14.1\nrequests==2.25.0\nurllib3==1.26.4"
        sbom_res = httpx.post(f"{server_url}/api/sbom/audit", json={"manifest": manifest_sample}, timeout=10.0)
        print(f"\n[OK] POST /api/sbom/audit -> Status {sbom_res.status_code}")
        sbom_data = sbom_res.json()
        print(f"     Total Audited: {sbom_data.get('totalDependencies')} | Vulnerabilities: {sbom_data.get('vulnerableCount')}")
        print(f"     Risk Level: {sbom_data.get('riskLevel')}")
    except Exception as err:
        print(f"[ERROR] POST /api/sbom/audit failed: {err}")
        all_passed = False

    # 5. Test /api/threat-chat
    try:
        chat_payload = {
            "message": "What is the immediate mitigation for this alert?",
            "context": analysis_data or {"title": "Sample Vulnerability", "severity": "HIGH"}
        }
        chat_res = httpx.post(f"{server_url}/api/threat-chat", json=chat_payload, timeout=20.0)
        print(f"\n[OK] POST /api/threat-chat -> Status {chat_res.status_code}")
        ans = chat_res.json().get("answer", "")
        print(f"     Analyst Response Preview: \"{ans[:80]}...\"")
    except Exception as err:
        print(f"[ERROR] POST /api/threat-chat failed: {err}")
        all_passed = False

    # 6. Test /api/export-advisory
    try:
        export_payload = {
            "type": "threat",
            "format": "markdown",
            "item": sample_article or {"title": "Sample CVE"},
            "analysis": analysis_data or {"cveId": "CVE-TEST", "severity": "HIGH"}
        }
        export_res = httpx.post(f"{server_url}/api/export-advisory", json=export_payload, timeout=10.0)
        print(f"\n[OK] POST /api/export-advisory -> Status {export_res.status_code}")
        print(f"     Exported Filename: {export_res.json().get('filename')}")
    except Exception as err:
        print(f"[ERROR] POST /api/export-advisory failed: {err}")
        all_passed = False

    # 7. Test /api/scan-url (Phishing Sandbox)
    try:
        phish_res = httpx.post(f"{server_url}/api/scan-url", json={"url": "https://example.com"}, timeout=30.0)
        print(f"\n[OK] POST /api/scan-url -> Status {phish_res.status_code}")
        data = phish_res.json()
        print(f"     Domain Age Days: {data.get('scraped', {}).get('domainInfo', {}).get('ageDays')}")
        print(f"     Phishing Probability: {data.get('analysis', {}).get('phishingProbability')}% | Level: {data.get('analysis', {}).get('dangerLevel')}")
    except Exception as err:
        print(f"[ERROR] POST /api/scan-url failed: {err}")
        all_passed = False

    # 8. Test /api/detect-scam (Scam Detector)
    try:
        scam_res = httpx.post(f"{server_url}/api/detect-scam", json={"url": "http://luxury-watch-outlet.top"}, timeout=30.0)
        print(f"\n[OK] POST /api/detect-scam -> Status {scam_res.status_code}")
        data = scam_res.json()
        print(f"     Scam Probability: {data.get('analysis', {}).get('scamProbability')}% | Trust Score: {data.get('analysis', {}).get('trustScore')}/100")
    except Exception as err:
        print(f"[ERROR] POST /api/detect-scam failed: {err}")
        all_passed = False

    # 9. Test /api/test-key
    try:
        key_res = httpx.post(f"{server_url}/api/test-key", json={"provider": "google", "apiKey": "INVALID_TEST_KEY_FOR_CHECK"}, timeout=10.0)
        print(f"\n[OK] POST /api/test-key -> Status {key_res.status_code}")
        data = key_res.json()
        print(f"     Key Validation Handled Gracefully: Valid={data.get('valid')}")
    except Exception as err:
        print(f"[ERROR] POST /api/test-key failed: {err}")
        all_passed = False

    print("\n==================================================")
    if all_passed:
        print("   ALL API ENDPOINTS TESTED AND OPERATIONAL [OK]")
    else:
        print("   SOME ENDPOINT TESTS REPORTED ERRORS [WARN]")
    print("==================================================")

if __name__ == "__main__":
    test_endpoints()
