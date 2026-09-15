import re
from urllib.parse import urlparse

TARGETED_BRANDS = [
    {"name": "PayPal", "domain": "paypal.com", "keywords": ["paypal", "paypa1", "pay-pal", "paypol"]},
    {"name": "Apple / iCloud", "domain": "apple.com", "keywords": ["apple", "icloud", "appie", "app-le", "appleid"]},
    {"name": "Microsoft / Office 365", "domain": "microsoft.com", "keywords": ["microsoft", "office365", "micros0ft", "msft", "outlook", "live.com"]},
    {"name": "Google / Gmail", "domain": "google.com", "keywords": ["google", "g00gle", "gmail", "goog1e"]},
    {"name": "Amazon", "domain": "amazon.com", "keywords": ["amazon", "amaz0n", "amzn", "prime-amazon"]},
    {"name": "Netflix", "domain": "netflix.com", "keywords": ["netflix", "netf1ix", "net-flix"]},
    {"name": "Chase Bank", "domain": "chase.com", "keywords": ["chase", "chasebank", "chase-secure"]},
    {"name": "Bank of America", "domain": "bankofamerica.com", "keywords": ["bankofamerica", "bofa", "bofa-online"]},
    {"name": "Binance / Crypto", "domain": "binance.com", "keywords": ["binance", "binanse", "binance-us"]},
    {"name": "Coinbase", "domain": "coinbase.com", "keywords": ["coinbase", "c0inbase", "coin-base"]},
    {"name": "Meta / Facebook / Instagram", "domain": "meta.com", "keywords": ["facebook", "faceb00k", "instagram", "meta-verify", "fb-security"]},
    {"name": "DHL Express", "domain": "dhl.com", "keywords": ["dhl", "dhl-parcel", "dhl-tracking"]},
    {"name": "FedEx", "domain": "fedex.com", "keywords": ["fedex", "fed-ex", "fedex-delivery"]},
    {"name": "USPS Postal", "domain": "usps.com", "keywords": ["usps", "usps-tracking", "usps-parcel"]}
]

HOMOGLYPH_MAP = {
    'o': ['0', 'o', 'ó', 'ö'],
    'l': ['1', 'i', 'l', '|'],
    'i': ['1', 'l', 'í', '!'],
    'e': ['3', 'e', 'é'],
    'a': ['4', '@', 'a', 'á'],
    's': ['5', '$', 's'],
    't': ['7', 't', '+'],
    'm': ['rn', 'nn', 'm'],
    'w': ['vv', 'w']
}

SUSPICIOUS_PHISHING_TOKENS = [
    "login", "verify", "verification", "secure", "security", "update", "billing",
    "account", "auth", "portal", "confirm", "wallet", "airdrop", "claim", "recover",
    "restore", "suspended", "banking", "webscr", "signin", "passcode", "identity"
]

def generate_typosquat_variants(domain_base: str, tld: str) -> list[dict]:
    """Generates potential lookalike and typosquat domains for brand protection."""
    variants = []
    
    # 1. Character replacement (Homoglyphs)
    for i, ch in enumerate(domain_base):
        if ch in HOMOGLYPH_MAP:
            for sub in HOMOGLYPH_MAP[ch]:
                if sub != ch:
                    variant_name = domain_base[:i] + sub + domain_base[i+1:]
                    variants.append({
                        "domain": f"{variant_name}.{tld}",
                        "technique": "Homoglyph Substitution",
                        "similarity": "High"
                    })

    # 2. Hyphenation insertion
    if len(domain_base) > 4:
        for i in range(2, len(domain_base) - 1):
            variant_name = domain_base[:i] + "-" + domain_base[i:]
            variants.append({
                "domain": f"{variant_name}.{tld}",
                "technique": "Hyphen Injection",
                "similarity": "High"
            })

    # 3. Transposition (swapping adjacent chars)
    for i in range(len(domain_base) - 1):
        swapped = list(domain_base)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        variant_name = "".join(swapped)
        if variant_name != domain_base:
            variants.append({
                "domain": f"{variant_name}.{tld}",
                "technique": "Character Transposition",
                "similarity": "Medium"
            })

    # Deduplicate and return top 12
    seen = set()
    unique_variants = []
    for v in variants:
        if v["domain"] not in seen and v["domain"] != f"{domain_base}.{tld}":
            seen.add(v["domain"])
            unique_variants.append(v)
            if len(unique_variants) >= 12:
                break

    return unique_variants

def analyze_phishing_and_typosquatting(domain: str, url: str) -> dict:
    """
    Detects brand impersonation, lookalike domains, phishing keyword density,
    and homoglyph camouflage.
    """
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    domain_base = parts[0] if len(parts) > 1 else domain_lower
    tld = ".".join(parts[1:]) if len(parts) > 1 else "com"

    result = {
        "isBrandImpersonation": False,
        "impersonatedBrand": None,
        "isLookalikeDomain": False,
        "matchedKeywords": [],
        "suspiciousTokensFound": [],
        "hasHomoglyphs": False,
        "phishingRiskScore": 0,
        "lookalikeVariants": generate_typosquat_variants(domain_base, tld),
        "indicators": []
    }

    # 1. Detect Brand Impersonation
    for brand in TARGETED_BRANDS:
        if domain_lower == brand["domain"]:
            # Legitimate official domain
            continue

        for kw in brand["keywords"]:
            # Check if brand keyword appears inside a non-official domain name
            if kw in domain_lower:
                result["isBrandImpersonation"] = True
                result["impersonatedBrand"] = brand["name"]
                result["phishingRiskScore"] += 45
                result["indicators"].append(f"Brand Impersonation: Domain contains targeted trademark [{brand['name']}] but is NOT an official domain.")
                break
        if result["isBrandImpersonation"]:
            break

    # 2. Detect Suspicious Phishing Tokens in Domain / URL
    combined_target = f"{domain_lower} {url.lower()}"
    found_tokens = []
    for token in SUSPICIOUS_PHISHING_TOKENS:
        if re.search(r'[\-_/.]' + token + r'[\-_/.]|' + token, combined_target):
            found_tokens.append(token)

    result["suspiciousTokensFound"] = list(set(found_tokens))
    if len(result["suspiciousTokensFound"]) >= 2:
        result["phishingRiskScore"] += 25
        result["indicators"].append(f"Phishing Token Combination: Detected high-risk security lures [{', '.join(result['suspiciousTokensFound'])}].")
    elif len(result["suspiciousTokensFound"]) == 1:
        result["phishingRiskScore"] += 10

    # 3. Detect Punycode / IDN Homograph Camouflage (e.g. xn--)
    if "xn--" in domain_lower:
        result["hasHomoglyphs"] = True
        result["phishingRiskScore"] += 35
        result["indicators"].append("Internationalized Domain Name (Punycode): Uses 'xn--' prefix to camouflage non-Latin homoglyphs.")

    # 4. Multi-subdomain Phishing Obfuscation (e.g. login.paypal.com.verify-user.xyz)
    if domain_lower.count('.') >= 3:
        result["phishingRiskScore"] += 15
        result["indicators"].append(f"Deep Subdomain Nesting: Domain contains {domain_lower.count('.')} dot-separated levels often used to disguise brand names.")

    result["phishingRiskScore"] = min(result["phishingRiskScore"], 100)
    return result
