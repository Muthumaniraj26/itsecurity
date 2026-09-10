import os
import json
import httpx
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

async def run_diagnostics():
    print('==================================================')
    print('         SECURITY HELPDESK SYSTEM DIAGNOSTICS         ')
    print('==================================================\n')

    all_passed = True

    # 1. Auditing Security Ingestion Feeds
    print('1. Auditing Security Ingestion Feeds...')
    try:
        feeds_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'feeds.json')
        with open(feeds_path, 'r', encoding='utf-8') as f:
            feeds = json.load(f)
        print(f"   [OK] config/feeds.json read successfully. Registered sources: {len(feeds)}")

        async with httpx.AsyncClient(timeout=4.0) as client:
            for feed in feeds:
                try:
                    response = await client.get(feed['url'])
                    print(f"   [OK] Ingested \"{feed['name']}\" -> Status {response.status_code}")
                except Exception as err:
                    print(f"   [ERROR] Ingest Failed for \"{feed['name']}\": {err}")
                    all_passed = False
    except Exception as err:
        print(f"   [ERROR] Configuration Load Error: {err}")
        all_passed = False

    # 2. Testing RDAP WHOIS Connectivity
    print('\n2. Testing RDAP WHOIS Connectivity...')
    try:
        test_domain = 'google.com'
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.get(f"https://rdap.org/domain/{test_domain}", headers={"Accept": "application/json"}, follow_redirects=True)
            if response.status_code == 200 and response.json().get('objectClassName') == 'domain':
                print("   [OK] RDAP lookup operational. Test query \"google.com\" passed.")
            else:
                raise ValueError(f"Unexpected response status: {response.status_code}")
    except Exception as err:
        print(f"   [ERROR] RDAP connection failed (Lookup might fail, fallbacks will be used): {err}")
        all_passed = False

    # 3. Auditing Gemini AI Agent Integration
    print('\n3. Auditing Gemini AI Agent Integration...')
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        print('   [WARN] No GEMINI_API_KEY found in .env.')
        print('   [INFO] System running in Simulation Mode (fallback prompts cached).')
    else:
        try:
            genai.configure(api_key=key)
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content('Say standard verification string: "API Active"')
            print(f"   [OK] Gemini API Connection active. Response: \"{response.text.strip()}\"")
        except Exception as err:
            print(f"   [ERROR] Gemini API Call Failed: {err}")
            all_passed = False

    print('\n==================================================')
    if all_passed:
        print('   DIAGNOSTIC STATUS: ALL INTEGRATIONS ACTIVE [OK]')
    else:
        print('   DIAGNOSTIC STATUS: COMPLETED WITH WARNINGS [WARN]')
        print('   Please check the network warnings above.')
    print('==================================================')

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_diagnostics())
