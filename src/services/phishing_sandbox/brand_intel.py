from typing import Dict, Any, List, Optional

# Brand Intelligence Database containing verified official root domains and keywords
BRAND_INTELLIGENCE_DB = {
    "microsoft": {
        "name": "Microsoft Corporation",
        "officialDomains": ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "azure.com", "windows.net", "msn.com", "bing.com", "outlook.com"],
        "keywords": ["microsoft", "office365", "m365", "outlook", "onedrive", "sharepoint", "azure", "msft", "win-security"],
        "commonLures": ["password-reset", "account-suspended", "session-verify", "document-share", "voicemail-notification"]
    },
    "apple": {
        "name": "Apple Inc.",
        "officialDomains": ["apple.com", "icloud.com", "itunes.com", "appleid.apple.com"],
        "keywords": ["apple", "icloud", "appleid", "itunes", "find-my-iphone"],
        "commonLures": ["id-locked", "unauthorized-sign-in", "receipt-confirmation", "findmy-device"]
    },
    "google": {
        "name": "Google LLC",
        "officialDomains": ["google.com", "gmail.com", "youtube.com", "googlemail.com", "accounts.google.com", "drive.google.com", "workspace.google.com"],
        "keywords": ["google", "gmail", "google-workspace", "gdrive", "youtube"],
        "commonLures": ["security-alert", "recover-password", "storage-full", "device-sync"]
    },
    "paypal": {
        "name": "PayPal Holdings, Inc.",
        "officialDomains": ["paypal.com", "paypal-community.com", "paypal-corp.com"],
        "keywords": ["paypal", "pay-pal", "paypal-service", "paypal-billing"],
        "commonLures": ["unusual-activity", "account-restricted", "confirm-identity", "invoice-received"]
    },
    "amazon": {
        "name": "Amazon.com, Inc.",
        "officialDomains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "aws.amazon.com", "primevideo.com"],
        "keywords": ["amazon", "prime", "aws", "amzn", "amazon-delivery"],
        "commonLures": ["order-delayed", "billing-problem", "lock-account", "prime-renewal"]
    },
    "netflix": {
        "name": "Netflix, Inc.",
        "officialDomains": ["netflix.com"],
        "keywords": ["netflix", "nflx", "netflix-streaming"],
        "commonLures": ["membership-on-hold", "payment-declined", "update-billing"]
    },
    "meta": {
        "name": "Meta Platforms (Facebook/Instagram)",
        "officialDomains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com", "fb.com"],
        "keywords": ["facebook", "instagram", "whatsapp", "meta-business", "copyright-infringement"],
        "commonLures": ["copyright-violation", "appeal-decision", "account-disabled", "business-manager-suspended"]
    },
    "chase": {
        "name": "JPMorgan Chase & Co.",
        "officialDomains": ["chase.com", "jpmorgan.com"],
        "keywords": ["chase", "jpmorgan", "chase-bank", "chase-online"],
        "commonLures": ["wire-transfer-review", "fraud-detection", "verify-card", "online-banking-access"]
    },
    "binance": {
        "name": "Binance Holdings Ltd",
        "officialDomains": ["binance.com", "binance.us"],
        "keywords": ["binance", "bnb-chain", "binance-wallet"],
        "commonLures": ["withdrawal-request", "kyc-verification", "airdrop-claim"]
    },
    "dhl": {
        "name": "DHL Express",
        "officialDomains": ["dhl.com", "dhl-express.com"],
        "keywords": ["dhl", "dhl-parcel", "dhl-tracking"],
        "commonLures": ["parcel-delivery-fee", "address-correction", "customs-duty-unpaid"]
    }
}

def analyze_brand_impersonation(domain: str, url: str, page_title: str = "") -> Dict[str, Any]:
    """
    Analyze if the given URL is actively impersonating a recognized high-profile enterprise brand:
    - Identifies target brand
    - Compares domain with verified official domain list
    - Detects deceptive keywords & impersonation markers
    """
    domain_lower = domain.lower()
    url_lower = url.lower()
    title_lower = (page_title or "").lower()

    detected_brand_key = None
    target_brand_info = None
    is_impersonating = False
    indicators = []

    for key, info in BRAND_INTELLIGENCE_DB.items():
        # Check if brand keywords or brand name appears in domain or URL
        brand_in_domain = any(k in domain_lower for k in info["keywords"])
        brand_in_title = any(k in title_lower for k in info["keywords"])
        brand_in_url = any(k in url_lower for k in info["keywords"])

        if brand_in_domain or brand_in_title or brand_in_url:
            detected_brand_key = key
            target_brand_info = info

            # Check if current domain is an official domain of the brand
            is_official = any(domain_lower == off or domain_lower.endswith("." + off) for off in info["officialDomains"])

            if not is_official:
                is_impersonating = True
                if brand_in_domain:
                    indicators.append(f"Target brand '{info['name']}' keyword explicitly embedded in domain name.")
                if brand_in_title:
                    indicators.append(f"Webpage title impersonates '{info['name']}'.")
                if not brand_in_domain and brand_in_url:
                    indicators.append(f"URL path mimics '{info['name']}' login or verification endpoint.")

                indicators.append(f"Domain '{domain}' is NOT part of {info['name']}'s official domain registry.")
            break

    return {
        "isBrandImpersonationDetected": is_impersonating,
        "targetedBrand": target_brand_info["name"] if target_brand_info else None,
        "brandKey": detected_brand_key,
        "officialDomains": target_brand_info["officialDomains"] if target_brand_info else [],
        "impersonationIndicators": indicators
    }
