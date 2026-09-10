import os
import ssl
import socket
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

def normalize_url(url_str: str) -> str:
    url_str = url_str.strip()
    if not url_str.lower().startswith(('http://', 'https://')):
        url_str = 'http://' + url_str
    return url_str

def get_direct_ssl_info(hostname: str, port: int = 443) -> dict:
    """
    Direct socket TLS certificate inspection.
    Bypasses HTTP WAFs/Cloudflare because it only performs a cryptographic handshake.
    """
    result = {"issuer": "Unknown", "validTo": None, "hasSsl": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["hasSsl"] = True
                
                # Extract Issuer organization
                issuer_items = cert.get("issuer", ())
                for rdn in issuer_items:
                    for key, val in rdn:
                        if key == "organizationName":
                            result["issuer"] = val
                
                result["validTo"] = cert.get("notAfter")
    except Exception:
        pass
    return result

async def get_domain_age_info(domain: str) -> dict:
    """
    Queries official RDAP database (ICANN/Verisign).
    Does NOT touch Cloudflare WAF.
    """
    result = {
        "createdDate": None,
        "registrar": "Unknown",
        "ageDays": None
    }
    
    parts = domain.split('.')
    if len(parts) < 2:
        return result

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/json"},
                follow_redirects=True
            )
            
            if response.status_code == 404:
                result["registrar"] = "Unregistered / Unknown"
                return result
            
            if response.status_code != 200:
                return result

            rdap_data = response.json()
            created_date = None
            registrar = "Unknown"

            # Parse events to find registration/creation date
            events = rdap_data.get("events", [])
            if isinstance(events, list):
                creation_event = next((e for e in events if e.get("eventAction") == "registration"), None)
                last_update_event = next((e for e in events if e.get("eventAction") == "last update"), None)
                
                target_event = creation_event or last_update_event
                if target_event and target_event.get("eventDate"):
                    try:
                        date_str = target_event["eventDate"].replace('Z', '+00:00')
                        if '.' in date_str:
                            base_part, tz_part = date_str.split('+')
                            base_part = base_part.split('.')[0]
                            date_str = f"{base_part}+{tz_part}"
                        created_date = datetime.fromisoformat(date_str)
                    except Exception:
                        pass

            # Parse entities to find registrar
            entities = rdap_data.get("entities", [])
            if isinstance(entities, list):
                registrar_entity = next((e for e in entities if "registrar" in e.get("roles", [])), None)
                if registrar_entity and isinstance(registrar_entity.get("vcardArray"), list):
                    vcard_items = registrar_entity["vcardArray"][1]
                    fn_item = next((item for item in vcard_items if item[0] == "fn"), None)
                    if fn_item and len(fn_item) > 3:
                        registrar = fn_item[3]

            result["registrar"] = registrar
            if created_date:
                result["createdDate"] = created_date.isoformat()
                created_date_naive = created_date.replace(tzinfo=None)
                diff = datetime.utcnow() - created_date_naive
                result["ageDays"] = max(0, diff.days)

    except Exception as e:
        result["error"] = str(e)
        result["registrar"] = "Lookup Timeout / Unknown"

    return result

async def scrape_url_info(raw_url: str) -> dict:
    """
    Cloud-Resilient URL Security Inspector.
    - Anti-tarpit timeouts (connect 3s, read 4s).
    - Modern Chrome 128 Client Hints (Sec-CH-UA) to avoid bot triggers.
    - 512KB payload streaming limits.
    - Direct TLS socket certificate extraction.
    - RDAP domain age verification.
    """
    url_str = normalize_url(raw_url)
    try:
        parsed_url = urlparse(url_str)
    except Exception:
        raise ValueError("Invalid URL format")

    domain = parsed_url.hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]

    is_https = parsed_url.scheme == "https"

    result = {
        "url": url_str,
        "domain": domain,
        "isHttps": is_https,
        "scrapedAt": datetime.utcnow().isoformat() + "Z",
        "wafDetected": False,
        "sslCert": {"issuer": "Unknown", "validTo": None},
        "pageMetadata": {
            "title": "",
            "hasPasswordFields": False,
            "hasInputFields": False,
            "inputsCount": 0,
            "totalLinks": 0,
            "externalLinks": 0,
            "suspiciousKeywordsFound": [],
            "bodySnippet": ""
        },
        "domainInfo": {
            "registrar": "Unknown",
            "createdDate": None,
            "ageDays": None
        }
    }

    # 1. Fetch domain registration age info (RDAP)
    result["domainInfo"] = await get_domain_age_info(domain)

    # 2. Extract direct SSL Certificate details via TLS socket
    if is_https and domain:
        ssl_info = get_direct_ssl_info(domain, parsed_url.port or 443)
        result["sslCert"] = ssl_info

    # 3. HTTP Page Inspection with Modern Browser Headers & Strict Anti-Hanging Limits
    proxy = os.getenv("CRAWLER_PROXY") or None
    transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None

    # Granular timeouts: connect 3s, read 4s, pool 3s (prevents cloud tarpit hanging)
    timeout_config = httpx.Timeout(connect=3.0, read=4.0, write=3.0, pool=3.0)

    # Modern Chrome 128 Windows 11 Headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout_config,
            follow_redirects=True,
            max_redirects=5,
            transport=transport
        ) as client:
            # Stream response to cap maximum download to 512 KB (prevents RAM exhaustion)
            async with client.stream("GET", url_str, headers=headers) as response:
                body_chunks = []
                bytes_downloaded = 0
                max_bytes = 512 * 1024  # 512 KB cap

                async for chunk in response.aiter_bytes():
                    body_chunks.append(chunk)
                    bytes_downloaded += len(chunk)
                    if bytes_downloaded >= max_bytes:
                        break

                raw_content = b"".join(body_chunks)
                html = raw_content.decode("utf-8", errors="replace")

                # Detect Cloudflare / WAF challenge pages gracefully
                server_header = response.headers.get("server", "").lower()
                if response.status_code in [403, 503] or "cloudflare" in server_header or "cf-ray" in response.headers:
                    if "just a moment" in html.lower() or "challenge-platform" in html.lower():
                        result["wafDetected"] = True
                        result["pageMetadata"]["title"] = "Protected by Cloudflare / Security WAF"
                        result["pageMetadata"]["bodySnippet"] = "Target domain is behind active Cloudflare/WAF challenge shield."

                soup = BeautifulSoup(html, 'html.parser')

                # Page Title
                if not result["wafDetected"]:
                    result["pageMetadata"]["title"] = soup.title.string.strip() if soup.title and soup.title.string else "Untitled Page"

                # Inputs Analysis
                inputs = soup.find_all("input")
                result["pageMetadata"]["inputsCount"] = len(inputs)
                if inputs:
                    result["pageMetadata"]["hasInputFields"] = True
                    for ipt in inputs:
                        if ipt.get("type", "").lower() == "password":
                            result["pageMetadata"]["hasPasswordFields"] = True

                # Form Handler & Action Analysis (UCI Phishing Feature 16 & 17)
                forms = soup.find_all("form")
                empty_or_ext_form = False
                for form in forms:
                    action = (form.get("action") or "").strip()
                    if not action or action.lower() in ["about:blank", "#", "javascript:void(0)"]:
                        empty_or_ext_form = True
                    elif action.startswith(('http://', 'https://')):
                        form_host = urlparse(action).hostname or ""
                        if form_host.startswith("www."): form_host = form_host[4:]
                        if form_host and form_host != domain:
                            empty_or_ext_form = True
                result["pageMetadata"]["emptyOrExternalForm"] = empty_or_ext_form
                result["pageMetadata"]["hasMailto"] = bool(re.search(r'mailto:', html, re.I))

                # Script, Link, and DOM Tricks (UCI Phishing Features 10, 15, 21, 23)
                result["pageMetadata"]["hasIframe"] = bool(soup.find_all("iframe"))
                result["pageMetadata"]["hasRightClickDisabled"] = bool(re.search(r'event\.button\s*==\s*2|contextmenu\s*=\s*["\']?return\s+false', html, re.I))

                # External Script/Link Ratio
                scripts = soup.find_all(["script", "link"])
                ext_scripts = 0
                for s in scripts:
                    src = s.get("src") or s.get("href") or ""
                    if src.startswith(('http://', 'https://')):
                        s_host = urlparse(src).hostname or ""
                        if s_host.startswith("www."): s_host = s_host[4:]
                        if s_host and s_host != domain:
                            ext_scripts += 1
                result["pageMetadata"]["externalScriptsRatio"] = (ext_scripts / len(scripts)) if scripts else 0.0

                # Links Analysis
                links = soup.find_all("a")
                result["pageMetadata"]["totalLinks"] = len(links)
                
                external_links_count = 0
                for lk in links:
                    href = lk.get("href")
                    if href:
                        try:
                            if href.startswith(('http://', 'https://')):
                                lk_domain = urlparse(href).hostname or ""
                                if lk_domain.startswith("www."):
                                    lk_domain = lk_domain[4:]
                                if lk_domain != domain:
                                    external_links_count += 1
                        except Exception:
                            pass
                
                result["pageMetadata"]["externalLinks"] = external_links_count

                # Suspicious Keywords in page body text
                body_text = soup.body.get_text().lower() if soup.body else ""
                suspect_keywords = [
                    'login', 'verify', 'account', 'secure', 'bank', 'update', 'password',
                    'suspend', 'urgent', 'action required', 'billing', 'signin', 'credential',
                    'recovery', 'official', 'gift card', 'winner', 'claim reward'
                ]

                found_keywords = [kw for kw in suspect_keywords if kw in body_text]
                result["pageMetadata"]["suspiciousKeywordsFound"] = found_keywords

                # Lexical URL Features (matching UCI ML Phishing dataset)
                shortening_pattern = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|tiny\.cc|cutt\.us|bitly\.com|rb\.gy'
                result["pageMetadata"]["isShortUrl"] = bool(re.search(shortening_pattern, url_str, re.I))
                result["pageMetadata"]["hasAtSymbol"] = "@" in url_str
                result["pageMetadata"]["hasDoubleSlashRedirect"] = url_str.find("//", 8) != -1
                result["pageMetadata"]["hasHttpsInDomain"] = "https" in domain.lower()
                result["pageMetadata"]["urlLength"] = len(url_str)
                result["pageMetadata"]["hasNonStandardPort"] = bool(parsed_url.port and parsed_url.port not in [80, 443])

                # Clean Snippet for AI processing
                clean_text = ' '.join(body_text.split())
                if not result["wafDetected"]:
                    result["pageMetadata"]["bodySnippet"] = clean_text[:1500]

    except Exception as e:
        result["error"] = f"Network Ingestion Notice: {str(e)}"
        if not result["pageMetadata"]["title"]:
            result["pageMetadata"]["title"] = "Target Host Unreachable / Filtered"

    return result
