import re
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse
import httpx
import dns.resolver

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "admin", "app", "vpn", "dev", 
    "portal", "auth", "login", "cpanel", "secure", "gateway", "shop", "blog"
]

def normalize_domain_and_url(target: str) -> tuple[str, str]:
    """
    Normalizes input into (clean_domain, valid_url).
    Strips protocol, paths, ports, and trailing slashes for domain extraction.
    """
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        url = 'https://' + target
    else:
        url = target

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname, url
    except Exception:
        clean = re.sub(r'^https?://', '', target, flags=re.I).split('/')[0].split(':')[0].lower()
        if clean.startswith("www."):
            clean = clean[4:]
        return clean, f"https://{clean}"

async def fetch_rdap_whois(domain: str) -> dict:
    """
    Queries official ICANN RDAP registry for domain creation, expiry, registrar, and status codes.
    """
    result = {
        "createdDate": None,
        "expiresDate": None,
        "updatedDate": None,
        "registrar": "Unknown",
        "registrarIanaId": None,
        "ageDays": None,
        "daysUntilExpiry": None,
        "status": [],
        "privacyProtected": False,
        "source": "RDAP ICANN"
    }

    if not domain or '.' not in domain:
        return result

    try:
        async with httpx.AsyncClient(timeout=4.5) as client:
            response = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/json"},
                follow_redirects=True
            )

            if response.status_code != 200:
                return result

            rdap = response.json()

            # 1. Parse Status Codes
            if "status" in rdap and isinstance(rdap["status"], list):
                result["status"] = rdap["status"]

            # 2. Parse Events (Creation, Expiration, Last Changed)
            events = rdap.get("events", [])
            if isinstance(events, list):
                for ev in events:
                    act = ev.get("eventAction", "").lower()
                    date_val = ev.get("eventDate")
                    if not date_val:
                        continue
                    try:
                        clean_date = date_val.replace('Z', '+00:00')
                        if '.' in clean_date:
                            b, t = clean_date.split('+')
                            clean_date = f"{b.split('.')[0]}+{t}"
                        dt = datetime.fromisoformat(clean_date)
                        
                        if act in ["registration", "created"]:
                            result["createdDate"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            diff = datetime.utcnow() - dt.replace(tzinfo=None)
                            result["ageDays"] = max(0, diff.days)
                        elif act in ["expiration", "expires"]:
                            result["expiresDate"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            diff = dt.replace(tzinfo=None) - datetime.utcnow()
                            result["daysUntilExpiry"] = diff.days
                        elif act in ["last changed", "last update"]:
                            result["updatedDate"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        pass

            # 3. Parse Entities / Registrar / Privacy
            entities = rdap.get("entities", [])
            privacy_keywords = ["privacy", "whoisguard", "proxy", "redacted", "withheld", "cloudfare", "masked"]
            for ent in entities:
                roles = ent.get("roles", [])
                vcard = ent.get("vcardArray", [])
                name = ""
                if isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn" and len(item) > 3:
                            name = item[3]

                if any(k in name.lower() for k in privacy_keywords):
                    result["privacyProtected"] = True

                if "registrar" in roles and name:
                    result["registrar"] = name
                    pub_ids = ent.get("publicIds", [])
                    if pub_ids and isinstance(pub_ids, list):
                        result["registrarIanaId"] = pub_ids[0].get("identifier")

    except Exception:
        pass

    return result

def query_dns_records(domain: str) -> dict:
    """
    Performs comprehensive DNS record extraction (A, AAAA, MX, NS, TXT, CNAME, SOA, DNSSEC).
    """
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": None,
        "hasDnssec": False,
        "nameservers": []
    }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 0.8
    resolver.lifetime = 1.0

    # 1. A Records
    try:
        ans = resolver.resolve(domain, 'A')
        records["A"] = [r.to_text() for r in ans]
    except Exception:
        pass

    # 2. AAAA Records
    try:
        ans = resolver.resolve(domain, 'AAAA')
        records["AAAA"] = [r.to_text() for r in ans]
    except Exception:
        pass

    # 3. MX Records
    try:
        ans = resolver.resolve(domain, 'MX')
        records["MX"] = sorted([{"priority": r.preference, "host": r.exchange.to_text().rstrip('.')} for r in ans], key=lambda x: x["priority"])
    except Exception:
        pass

    # 4. NS Records
    try:
        ans = resolver.resolve(domain, 'NS')
        ns_list = [r.to_text().rstrip('.') for r in ans]
        records["NS"] = ns_list
        records["nameservers"] = ns_list
    except Exception:
        pass

    # 5. TXT Records
    try:
        ans = resolver.resolve(domain, 'TXT')
        records["TXT"] = [r.to_text().strip('"') for r in ans]
    except Exception:
        pass

    # 6. CNAME Records
    try:
        ans = resolver.resolve(domain, 'CNAME')
        records["CNAME"] = [r.to_text().rstrip('.') for r in ans]
    except Exception:
        pass

    # 7. SOA Record
    try:
        ans = resolver.resolve(domain, 'SOA')
        if ans:
            r = ans[0]
            records["SOA"] = {
                "mname": r.mname.to_text().rstrip('.'),
                "rname": r.rname.to_text().rstrip('.'),
                "serial": r.serial,
                "refresh": r.refresh,
                "retry": r.retry,
                "expire": r.expire,
                "minimum": r.minimum
            }
    except Exception:
        pass

    # 8. DNSSEC Verification
    try:
        ans = resolver.resolve(domain, 'DNSKEY')
        if ans:
            records["hasDnssec"] = True
    except Exception:
        records["hasDnssec"] = False

    return records

def check_email_security_protections(domain: str, txt_records: list, mx_records: list) -> dict:
    """
    Audits SPF, DMARC, DKIM, and MX email authentication posture.
    """
    email_sec = {
        "spf": {"deployed": False, "raw": None, "policy": "Missing", "status": "Vulnerable to Email Spoofing"},
        "dmarc": {"deployed": False, "raw": None, "policy": "Missing", "status": "No DMARC Enforcement"},
        "dkim": {"deployed": False, "selectorsTested": [], "status": "Selector Lookup Pending"},
        "mxVerification": {"hasMx": len(mx_records) > 0, "mxCount": len(mx_records), "servers": [m["host"] for m in mx_records]}
    }

    # 1. SPF Check
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            email_sec["spf"]["deployed"] = True
            email_sec["spf"]["raw"] = txt
            if "-all" in txt:
                email_sec["spf"]["policy"] = "HardFail (-all)"
                email_sec["spf"]["status"] = "Strict Protection"
            elif "~all" in txt:
                email_sec["spf"]["policy"] = "SoftFail (~all)"
                email_sec["spf"]["status"] = "Moderate Protection"
            elif "?all" in txt or "+all" in txt:
                email_sec["spf"]["policy"] = "Neutral / Permissive"
                email_sec["spf"]["status"] = "Insecure SPF Policy"
            else:
                email_sec["spf"]["policy"] = "Custom Rules"
                email_sec["spf"]["status"] = "SPF Configured"
            break

    # 2. DMARC Check (_dmarc.<domain>)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 0.8
    resolver.lifetime = 1.0
    try:
        ans = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in ans:
            txt = r.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                email_sec["dmarc"]["deployed"] = True
                email_sec["dmarc"]["raw"] = txt
                # Extract p= policy
                p_match = re.search(r'p\s*=\s*(reject|quarantine|none)', txt, re.I)
                if p_match:
                    pol = p_match.group(1).lower()
                    email_sec["dmarc"]["policy"] = pol
                    if pol == "reject":
                        email_sec["dmarc"]["status"] = "Optimal (Reject unauthorized mail)"
                    elif pol == "quarantine":
                        email_sec["dmarc"]["status"] = "Good (Quarantine suspicious mail)"
                    else:
                        email_sec["dmarc"]["status"] = "Monitoring Only (p=none, No enforcement)"
                break
    except Exception:
        pass

    # 3. DKIM Common Selectors Check
    common_selectors = ["default", "google", "k1", "mail", "s1", "smtp", "selector1"]
    discovered_dkim = []
    for sel in common_selectors:
        try:
            d_ans = resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT')
            for r in d_ans:
                txt = r.to_text().strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    discovered_dkim.append(sel)
                    break
        except Exception:
            pass

    email_sec["dkim"]["selectorsTested"] = common_selectors
    if discovered_dkim:
        email_sec["dkim"]["deployed"] = True
        email_sec["dkim"]["discoveredSelectors"] = discovered_dkim
        email_sec["dkim"]["status"] = f"Valid DKIM keys found ({', '.join(discovered_dkim)})"
    else:
        email_sec["dkim"]["deployed"] = False
        email_sec["dkim"]["status"] = "No standard public DKIM keys detected in common selectors"

    return email_sec

async def fetch_ip_geolocation(ip: str) -> dict:
    """
    Fetches real-time Geolocation, ASN, and Organization for an IP address.
    """
    geo_data = {
        "ip": ip,
        "country": "Unknown",
        "countryCode": "",
        "city": "Unknown",
        "region": "",
        "asn": "Unknown",
        "org": "Unknown",
        "isp": "Unknown",
        "latitude": None,
        "longitude": None,
        "isHosting": False
    }

    if not ip or ip.startswith(('127.', '192.168.', '10.')):
        return geo_data

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,hosting")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    geo_data["country"] = data.get("country", "Unknown")
                    geo_data["countryCode"] = data.get("countryCode", "")
                    geo_data["city"] = data.get("city", "Unknown")
                    geo_data["region"] = data.get("regionName", "")
                    geo_data["asn"] = data.get("as", "Unknown")
                    geo_data["org"] = data.get("org", data.get("isp", "Unknown"))
                    geo_data["isp"] = data.get("isp", "Unknown")
                    geo_data["latitude"] = data.get("lat")
                    geo_data["longitude"] = data.get("lon")
                    geo_data["isHosting"] = data.get("hosting", False)
    except Exception:
        pass

    return geo_data

async def enumerate_subdomains(domain: str) -> list[dict]:
    """
    Asynchronously checks for active public subdomains.
    """
    discovered = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 0.6
    resolver.lifetime = 0.8

    async def check_sub(sub: str):
        full = f"{sub}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            ans = await loop.run_in_executor(None, lambda: resolver.resolve(full, 'A'))
            ips = [r.to_text() for r in ans]
            if ips:
                discovered.append({
                    "subdomain": full,
                    "prefix": sub,
                    "ip": ips[0],
                    "status": "Active"
                })
        except Exception:
            pass

    tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks, return_exceptions=True)

    return sorted(discovered, key=lambda x: x["subdomain"])
