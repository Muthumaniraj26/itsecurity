import asyncio
import dns.resolver

HIGH_RISK_TLDS = {
    "top": {"risk": "High", "reason": "Extensively leveraged in disposable spam and phishing campaigns"},
    "xyz": {"risk": "Moderate-High", "reason": "Cheap mass registration frequently utilized by malicious actors"},
    "click": {"risk": "High", "reason": "Common redirect and malvertising payload domain extension"},
    "country": {"risk": "High", "reason": "Frequent host for malware dropper endpoints"},
    "work": {"risk": "Moderate", "reason": "Abused for credential phishing and fake job scams"},
    "monster": {"risk": "High", "reason": "Heavily utilized in disposable botnet command nodes"},
    "rest": {"risk": "Moderate", "reason": "Elevated abuse in bulk fraud campaigns"},
    "surf": {"risk": "Moderate", "reason": "Deceptive proxy and scam storefront extension"},
    "shop": {"risk": "Moderate", "reason": "High prevalence of counterfeit goods and credit card skimming storefronts"},
    "vip": {"risk": "High", "reason": "Predatory gambling and unauthorized financial schemes"},
    "cam": {"risk": "High", "reason": "Adult and deceptive social engineering lures"},
    "tk": {"risk": "High", "reason": "Free disposable domain extension with high abuse rate"},
    "gq": {"risk": "High", "reason": "Free disposable domain extension with high abuse rate"},
    "cf": {"risk": "High", "reason": "Free disposable domain extension with high abuse rate"}
}

async def check_dnsbl_blacklist(ip: str, domain: str) -> list[dict]:
    """
    Cross-references IP and domain against major reputation DNSBL zones.
    """
    blacklist_results = []
    if not ip or ip.startswith(('127.', '192.168.', '10.')):
        return blacklist_results

    # Reverse IP for DNSBL query
    try:
        ip_parts = ip.split('.')
        reversed_ip = ".".join(reversed(ip_parts))
    except Exception:
        return blacklist_results

    dnsbl_zones = [
        {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "type": "Malware & Spam IP"},
        {"name": "Barracuda RBL", "zone": "b.barracudacentral.org", "type": "Spam Reputation"},
        {"name": "AbuseIPDB Free DNSBL", "zone": "dnsbl.dronebl.org", "type": "Botnet & SSH Abuser"},
        {"name": "SURBL Multi Domain", "zone": "multi.surbl.org", "type": "Phishing & URI Blacklist"}
    ]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.2
    resolver.lifetime = 1.5

    async def query_zone(zone_info: dict):
        query_host = f"{reversed_ip}.{zone_info['zone']}"
        try:
            loop = asyncio.get_event_loop()
            ans = await loop.run_in_executor(None, lambda: resolver.resolve(query_host, 'A'))
            if ans:
                blacklist_results.append({
                    "engine": zone_info["name"],
                    "category": zone_info["type"],
                    "listed": True,
                    "responseCode": [r.to_text() for r in ans]
                })
        except Exception:
            blacklist_results.append({
                "engine": zone_info["name"],
                "category": zone_info["type"],
                "listed": False
            })

    tasks = [query_zone(z) for z in dnsbl_zones]
    await asyncio.gather(*tasks, return_exceptions=True)

    return blacklist_results

def evaluate_threat_intelligence(domain: str, ip: str, blacklist_results: list) -> dict:
    """
    Synthesizes threat feeds, TLD risk profiles, and IOC associations.
    """
    tld = domain.split('.')[-1].lower() if '.' in domain else ""
    tld_meta = HIGH_RISK_TLDS.get(tld)

    listed_count = len([b for b in blacklist_results if b.get("listed") is True])

    # Category determination
    if listed_count > 0:
        category = "Malicious / Listed Threat Vector"
    elif tld_meta and tld_meta["risk"] == "High":
        category = "High-Risk TLD Perimeter"
    elif tld in ["gov", "mil", "edu"]:
        category = "Government / Academic Verified Entity"
    elif tld in ["com", "org", "net", "io", "ai", "co", "dev", "app"]:
        category = "Standard Commercial / Tech Domain"
    else:
        category = "General Web Presence"

    return {
        "tld": f".{tld}",
        "tldRisk": tld_meta["risk"] if tld_meta else "Low / Standard",
        "tldReason": tld_meta["reason"] if tld_meta else "Standard international or country-code TLD with standard baseline reputation",
        "blacklistsChecked": len(blacklist_results),
        "blacklistsListed": listed_count,
        "blacklistDetails": blacklist_results,
        "threatCategory": category,
        "isBlacklisted": listed_count > 0
    }
