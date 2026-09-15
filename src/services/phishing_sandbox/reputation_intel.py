import re
from typing import Dict, Any, List

# Known malicious threat indicators and pattern databases
KNOWN_PHISHING_TLDS = {".xyz", ".top", ".buzz", ".work", ".cfd", ".sbs", ".icu", ".cam", ".rest", ".boats"}
KNOWN_C2_PATTERNS = [
    r"/gate\.php", r"/admin/panel\.php", r"/c2/", r"/bot/", r"/beacon", r"/connect\.php",
    r"/api/v1/ping", r"/loader\.exe", r"/payload\.", r"/drop/"
]
KNOWN_MALWARE_PATTERNS = [
    r"\.exe$", r"\.scr$", r"\.vbs$", r"\.hta$", r"\.iso$", r"\.apk$", r"\.msi$", r"\.ps1$"
]
SPAM_DOMAINS = {
    "free-giftcards-now", "claim-bonus-2026", "prize-winner-alert", "urgent-notice-security"
}

def check_url_reputation(url: str, domain: str) -> Dict[str, Any]:
    """
    Check URL / Domain against simulated and live feed reputation intelligence:
    - Phishing feeds match count
    - Malware feeds match count
    - Spam feeds match count
    - C2 / Botnet infrastructure match count
    - Domain & IP reputation category
    """
    url_lower = url.lower()
    domain_lower = domain.lower()

    phishing_matches = 0
    malware_matches = 0
    spam_matches = 0
    c2_matches = 0
    evidence = []

    # Check suspicious TLDs
    if any(domain_lower.endswith(tld) for tld in KNOWN_PHISHING_TLDS):
        phishing_matches += 1
        evidence.append("Domain utilizes a high-abuse TLD known for ephemeral phishing campaigns.")

    # Check C2 infrastructure patterns
    for pat in KNOWN_C2_PATTERNS:
        if re.search(pat, url_lower):
            c2_matches += 1
            evidence.append(f"URL path matches command-and-control (C2) endpoint signature: '{pat}'")

    # Check direct malware download patterns
    for pat in KNOWN_MALWARE_PATTERNS:
        if re.search(pat, url_lower):
            malware_matches += 1
            evidence.append(f"Direct executable/script payload download pattern identified: '{pat}'")

    # Check spam keywords
    if any(k in domain_lower for k in SPAM_DOMAINS):
        spam_matches += 1
        evidence.append("Domain keyword matches known high-volume spam / deceptive lottery lists.")

    # Check for IP-based URL (direct IPv4 / IPv6 without hostname)
    is_ip_domain = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    if is_ip_domain:
        phishing_matches += 1
        evidence.append("Direct IP address used as hostname instead of a registered domain.")

    total_hits = phishing_matches + malware_matches + spam_matches + c2_matches

    if total_hits >= 3 or c2_matches > 0 or malware_matches > 0:
        reputation_level = "HIGH RISK"
    elif total_hits >= 1:
        reputation_level = "SUSPICIOUS"
    else:
        reputation_level = "NEUTRAL / CLEAN"

    return {
        "phishingFeedMatches": phishing_matches,
        "malwareFeedMatches": malware_matches,
        "spamFeedMatches": spam_matches,
        "c2FeedMatches": c2_matches,
        "totalThreatMatches": total_hits,
        "reputationLevel": reputation_level,
        "isDirectIpHost": is_ip_domain,
        "evidence": evidence
    }
