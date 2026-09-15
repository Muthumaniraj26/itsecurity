import re
import urllib.parse
import unicodedata
import httpx
from typing import Dict, Any, List

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "bit.do", "bl.ink", "shorte.st",
    "v.gd", "qr.net", "1url.com", "t2mio.com", "s.id", "soo.gd", "trib.al"
}

# Tracking query parameters to strip for normalization
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "zanpid", "yclid",
    "_hsenc", "_hsmi", "mc_cid", "mc_eid", "igshid", "ref", "source"
}

def is_punycode(domain: str) -> bool:
    """Check if domain contains Punycode/IDN encoded labels."""
    return any(part.startswith("xn--") for part in domain.split("."))

def normalize_url(raw_url: str) -> Dict[str, Any]:
    """
    Comprehensive URL Input & Normalization engine:
    - URL validation
    - URL decoding & percent-encoding analysis
    - Lowercase/uppercase normalization
    - Punycode / IDN conversion
    - Tracking parameters removal
    - Component extraction (Scheme, Domain, Port, Path, Query, Fragment, Subdomains)
    """
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return {"valid": False, "error": "Empty URL provided."}

    # Ensure scheme is present for parsing
    has_explicit_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw_url))
    working_url = raw_url if has_explicit_scheme else f"http://{raw_url}"

    try:
        parsed = urllib.parse.urlparse(working_url)
    except Exception as e:
        return {"valid": False, "error": f"Invalid URL syntax: {str(e)}"}

    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc

    # Extract userinfo, host, and port
    userinfo = None
    if "@" in netloc:
        userinfo, netloc = netloc.split("@", 1)

    port = parsed.port
    host = parsed.hostname or ""

    # Check for Unicode IDN / Punycode conversion
    unicode_host = host
    punycode_host = host
    try:
        unicode_host = host.encode("utf-8").decode("idna")
    except Exception:
        pass

    try:
        punycode_host = host.encode("idna").decode("ascii")
    except Exception:
        pass

    has_punycode = is_punycode(punycode_host) or (unicode_host != host)

    # Subdomain and base domain extraction
    domain_parts = unicode_host.split(".")
    subdomains = []
    base_domain = unicode_host
    tld = ""

    if len(domain_parts) >= 2:
        # Simple multi-part TLD handling (e.g. .co.uk, .com.au)
        multi_tlds = {"co.uk", "com.au", "co.in", "net.au", "org.uk", "gov.uk", "edu.au", "ac.uk"}
        last_two = ".".join(domain_parts[-2:]).lower()
        last_three = ".".join(domain_parts[-3:]).lower() if len(domain_parts) >= 3 else ""

        if last_three in multi_tlds and len(domain_parts) >= 4:
            base_domain = ".".join(domain_parts[-4:])
            subdomains = domain_parts[:-4]
            tld = last_three
        elif last_two in multi_tlds and len(domain_parts) >= 3:
            base_domain = ".".join(domain_parts[-3:])
            subdomains = domain_parts[:-3]
            tld = last_two
        else:
            base_domain = ".".join(domain_parts[-2:])
            subdomains = domain_parts[:-2]
            tld = domain_parts[-1]
    elif len(domain_parts) == 1:
        base_domain = domain_parts[0]
        tld = ""

    # Path & Query parameters
    raw_path = parsed.path or "/"
    try:
        decoded_path = urllib.parse.unquote(raw_path)
    except Exception:
        decoded_path = raw_path

    # Percent encoding depth check
    percent_encoding_count = raw_path.count("%") + (parsed.query or "").count("%")
    double_encoded = "%25" in raw_url.lower()

    # Query params analysis and tracking param stripping
    query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    clean_query_dict = {k: v for k, v in query_dict.items() if k.lower() not in TRACKING_PARAMS}
    clean_query_str = urllib.parse.urlencode(clean_query_dict, doseq=True)

    # Reconstructed clean canonical URL
    clean_netloc = punycode_host
    if port and ((scheme == "http" and port != 80) or (scheme == "https" and port != 443)):
        clean_netloc = f"{clean_netloc}:{port}"

    clean_url = urllib.parse.urlunparse((
        scheme,
        clean_netloc,
        raw_path,
        "",
        clean_query_str,
        parsed.fragment
    ))

    # Shortener check
    is_shortener = host.lower() in URL_SHORTENERS or any(host.lower().endswith("." + s) for s in URL_SHORTENERS)

    return {
        "valid": True,
        "rawUrl": raw_url,
        "cleanUrl": clean_url,
        "scheme": scheme,
        "isHttps": scheme == "https",
        "domain": unicode_host,
        "punycodeDomain": punycode_host,
        "hasPunycode": has_punycode,
        "baseDomain": base_domain,
        "subdomains": subdomains,
        "tld": tld,
        "port": port or (443 if scheme == "https" else 80),
        "path": raw_path,
        "decodedPath": decoded_path,
        "query": parsed.query,
        "queryParams": query_dict,
        "cleanedQueryParams": clean_query_dict,
        "strippedTrackingParams": [k for k in query_dict.keys() if k.lower() in TRACKING_PARAMS],
        "fragment": parsed.fragment,
        "hasUserinfo": bool(userinfo),
        "userinfo": userinfo,
        "hasAtSymbol": "@" in raw_url,
        "percentEncodingCount": percent_encoding_count,
        "isDoubleEncoded": double_encoded,
        "isShortUrl": is_shortener
    }

async def expand_short_url(url: str, max_hops: int = 3) -> Dict[str, Any]:
    """Safely expand shortened URL by following redirects."""
    hops = []
    current_url = url
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            for _ in range(max_hops):
                res = await client.head(current_url)
                hops.append({"url": current_url, "status": res.status_code})
                if res.status_code in (301, 302, 303, 307, 308) and "location" in res.headers:
                    current_url = urllib.parse.urljoin(current_url, res.headers["location"])
                else:
                    break
        return {
            "isExpanded": len(hops) > 1,
            "finalUrl": current_url,
            "expansionHops": hops
        }
    except Exception as e:
        return {
            "isExpanded": False,
            "finalUrl": url,
            "expansionHops": hops,
            "error": str(e)
        }
