import socket
import httpx
from datetime import datetime
from typing import Dict, Any, List

async def analyze_domain_infrastructure(domain: str) -> Dict[str, Any]:
    """
    Perform deep domain and DNS infrastructure analysis:
    - Domain age & creation date via RDAP
    - Registrar & Nameservers
    - DNS resolution (IP, A, MX, NS records)
    - IP Geolocation & ASN
    - Newly Registered Domain (NRD) check
    """
    result = {
        "domain": domain,
        "ageDays": None,
        "createdDate": None,
        "registrar": "Unknown",
        "nameservers": [],
        "ipAddress": None,
        "ipList": [],
        "mxRecords": [],
        "asn": "Unknown",
        "hostingProvider": "Unknown",
        "country": "Unknown",
        "isNewlyRegistered": False,
        "rawRdap": {}
    }

    # 1. DNS Resolution
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ips = list({item[4][0] for item in addr_info if item[4]})
        result["ipList"] = ips
        if ips:
            result["ipAddress"] = ips[0]
    except Exception:
        pass

    # 2. RDAP Query for Domain Age and Registrar
    parts = domain.split(".")
    if len(parts) >= 2:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(
                    f"https://rdap.org/domain/{domain}",
                    headers={"Accept": "application/json"},
                    follow_redirects=True
                )
                if res.status_code == 200:
                    data = res.json()
                    result["rawRdap"] = data

                    # Parse events
                    events = data.get("events", [])
                    created_date_obj = None
                    for ev in events:
                        action = ev.get("eventAction", "").lower()
                        if action in ("registration", "creation"):
                            d_str = ev.get("eventDate", "")
                            if d_str:
                                try:
                                    clean_d = d_str.replace("Z", "+00:00").split(".")[0]
                                    created_date_obj = datetime.fromisoformat(clean_d)
                                    result["createdDate"] = created_date_obj.strftime("%Y-%m-%d")
                                except Exception:
                                    result["createdDate"] = d_str
                            break

                    if created_date_obj:
                        now = datetime.now(created_date_obj.tzinfo) if created_date_obj.tzinfo else datetime.now()
                        diff_days = (now - created_date_obj).days
                        result["ageDays"] = max(0, diff_days)
                        if result["ageDays"] <= 30:
                            result["isNewlyRegistered"] = True

                    # Parse registrar
                    entities = data.get("entities", [])
                    for ent in entities:
                        roles = ent.get("roles", [])
                        if "registrar" in roles:
                            vcard = ent.get("vcardArray", [])
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                for item in vcard[1]:
                                    if item[0] == "fn" and len(item) > 3:
                                        result["registrar"] = str(item[3])
                                        break
                            if result["registrar"] == "Unknown":
                                result["registrar"] = ent.get("handle", "Unknown")

                    # Parse nameservers
                    ns_list = data.get("nameservers", [])
                    result["nameservers"] = [ns.get("ldhName", "") for ns in ns_list if ns.get("ldhName")]
        except Exception:
            pass

    # 3. IP Geolocation & ASN Lookup
    if result["ipAddress"]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                geo_res = await client.get(f"https://ipapi.co/{result['ipAddress']}/json/")
                if geo_res.status_code == 200:
                    geo = geo_res.json()
                    result["asn"] = geo.get("asn", "Unknown")
                    result["hostingProvider"] = geo.get("org", geo.get("asn_org", "Unknown"))
                    result["country"] = geo.get("country_name", geo.get("country", "Unknown"))
        except Exception:
            pass

    return result
