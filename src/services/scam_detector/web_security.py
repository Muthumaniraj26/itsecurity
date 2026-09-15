import re
import socket
import asyncio
from urllib.parse import urlparse
import httpx

COMMON_PORTS = [
    {"port": 80, "service": "HTTP Web", "risk": "Low"},
    {"port": 443, "service": "HTTPS Secure Web", "risk": "Clean"},
    {"port": 21, "service": "FTP File Transfer", "risk": "Medium"},
    {"port": 22, "service": "SSH Remote Admin", "risk": "Medium"},
    {"port": 25, "service": "SMTP Mail Server", "risk": "Medium"},
    {"port": 53, "service": "DNS Nameserver", "risk": "Low"},
    {"port": 8080, "service": "Alternate HTTP / Proxy", "risk": "Medium"},
    {"port": 8443, "service": "Alternate HTTPS / Admin", "risk": "Medium"},
    {"port": 3306, "service": "MySQL Database Port", "risk": "High"},
    {"port": 5432, "service": "PostgreSQL Database Port", "risk": "High"},
    {"port": 3389, "service": "RDP Windows Remote Desktop", "risk": "Critical"}
]

async def check_port_open(host: str, port: int) -> bool:
    """Fast non-blocking socket port probe."""
    try:
        loop = asyncio.get_event_loop()
        def _probe():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                return s.connect_ex((host, port)) == 0
        return await loop.run_in_executor(None, _probe)
    except Exception:
        return False

async def scan_common_ports(host: str) -> list[dict]:
    """Scans standard perimeter ports."""
    results = []
    tasks = [check_port_open(host, p["port"]) for p in COMMON_PORTS]
    statuses = await asyncio.gather(*tasks, return_exceptions=True)

    for p, is_open in zip(COMMON_PORTS, statuses):
        if is_open is True:
            results.append({
                "port": p["port"],
                "service": p["service"],
                "status": "OPEN",
                "risk": p["risk"]
            })
    return results

async def inspect_web_security_and_headers(domain: str, url: str) -> dict:
    """
    Analyzes HTTP/HTTPS availability, Redirect Chains, Security Headers,
    CMS & Server fingerprinting, and Robots.txt.
    """
    web_data = {
        "httpAvailable": False,
        "httpsAvailable": False,
        "enforcesHttps": False,
        "redirectChain": [],
        "finalUrl": url,
        "statusCode": None,
        "serverHeader": "Unknown",
        "techStack": [],
        "securityHeaders": {
            "grade": "F",
            "score": 0,
            "hsts": {"present": False, "value": None, "preload": False},
            "csp": {"present": False, "value": None},
            "xFrameOptions": {"present": False, "value": None},
            "xContentTypeOptions": {"present": False, "value": None},
            "referrerPolicy": {"present": False, "value": None},
            "permissionsPolicy": {"present": False, "value": None},
            "missingHeaders": []
        },
        "robotsTxt": {"available": False, "disallowedPaths": []},
        "sitemapXml": {"available": False}
    }

    client_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    }

    # 1. Trace HTTP -> HTTPS Redirect Chain
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, max_redirects=5) as client:
            resp = await client.get(f"http://{domain}", headers=client_headers)
            web_data["httpAvailable"] = True
            web_data["statusCode"] = resp.status_code
            web_data["finalUrl"] = str(resp.url)

            # Record history
            chain = []
            for h in resp.history:
                chain.append({
                    "url": str(h.url),
                    "statusCode": h.status_code,
                    "reason": h.reason_phrase
                })
            chain.append({
                "url": str(resp.url),
                "statusCode": resp.status_code,
                "reason": resp.reason_phrase
            })
            web_data["redirectChain"] = chain

            if str(resp.url).startswith("https://"):
                web_data["httpsAvailable"] = True
                web_data["enforcesHttps"] = True

            # Server and Cookies
            web_data["serverHeader"] = resp.headers.get("server", "Unknown")
            raw_headers = resp.headers

            # 2. Audit Security Headers
            score = 0
            missing = []

            # HSTS
            hsts_val = raw_headers.get("strict-transport-security")
            if hsts_val:
                web_data["securityHeaders"]["hsts"] = {
                    "present": True,
                    "value": hsts_val,
                    "preload": "preload" in hsts_val.lower()
                }
                score += 25
            else:
                missing.append("Strict-Transport-Security (HSTS)")

            # CSP
            csp_val = raw_headers.get("content-security-policy")
            if csp_val:
                web_data["securityHeaders"]["csp"] = {"present": True, "value": csp_val[:120] + "..." if len(csp_val) > 120 else csp_val}
                score += 30
            else:
                missing.append("Content-Security-Policy (CSP)")

            # X-Frame-Options
            xfo_val = raw_headers.get("x-frame-options")
            if xfo_val:
                web_data["securityHeaders"]["xFrameOptions"] = {"present": True, "value": xfo_val}
                score += 15
            else:
                missing.append("X-Frame-Options (Clickjacking Protection)")

            # X-Content-Type-Options
            xcto_val = raw_headers.get("x-content-type-options")
            if xcto_val:
                web_data["securityHeaders"]["xContentTypeOptions"] = {"present": True, "value": xcto_val}
                score += 10
            else:
                missing.append("X-Content-Type-Options (MIME Sniffing)")

            # Referrer-Policy
            rp_val = raw_headers.get("referrer-policy")
            if rp_val:
                web_data["securityHeaders"]["referrerPolicy"] = {"present": True, "value": rp_val}
                score += 10
            else:
                missing.append("Referrer-Policy")

            # Permissions-Policy
            pp_val = raw_headers.get("permissions-policy")
            if pp_val:
                web_data["securityHeaders"]["permissionsPolicy"] = {"present": True, "value": pp_val}
                score += 10
            else:
                missing.append("Permissions-Policy")

            web_data["securityHeaders"]["score"] = score
            web_data["securityHeaders"]["missingHeaders"] = missing

            if score >= 90: grade = "A+"
            elif score >= 75: grade = "A"
            elif score >= 60: grade = "B"
            elif score >= 40: grade = "C"
            elif score >= 20: grade = "D"
            else: grade = "F"
            web_data["securityHeaders"]["grade"] = grade

            # 3. Technology Fingerprinting (HTML + Headers)
            html_sample = resp.text[:40000].lower()
            tech = []
            
            # Server header matching
            srv = web_data["serverHeader"].lower()
            if "cloudflare" in srv: tech.append("Cloudflare CDN / WAF")
            if "nginx" in srv: tech.append("Nginx Web Server")
            if "apache" in srv: tech.append("Apache HTTP Server")
            if "litespeed" in srv: tech.append("LiteSpeed Web Server")
            if "caddy" in srv: tech.append("Caddy Server")
            if "microsoft-iis" in srv: tech.append("Microsoft IIS")

            # CMS / Framework signatures
            if "wp-content" in html_sample or "wp-includes" in html_sample: tech.append("WordPress CMS")
            if "cdn.shopify.com" in html_sample: tech.append("Shopify E-Commerce")
            if "woocommerce" in html_sample: tech.append("WooCommerce")
            if "__next" in html_sample or "_next/static" in html_sample: tech.append("Next.js React Framework")
            if "react" in html_sample or "data-reactroot" in html_sample: tech.append("React Frontend")
            if "vue" in html_sample or "data-v-" in html_sample: tech.append("Vue.js")
            if "elementor" in html_sample: tech.append("Elementor Page Builder")
            if "squarespace" in html_sample: tech.append("Squarespace")
            if "wix.com" in html_sample: tech.append("Wix Website Builder")
            if "magento" in html_sample: tech.append("Magento")
            if "drupal" in html_sample: tech.append("Drupal CMS")

            web_data["techStack"] = list(set(tech))

    except Exception:
        pass

    # 4. Fetch Robots.txt
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            r_robots = await client.get(f"https://{domain}/robots.txt", headers=client_headers, follow_redirects=True)
            if r_robots.status_code == 200 and "user-agent" in r_robots.text.lower():
                web_data["robotsTxt"]["available"] = True
                disallows = []
                for line in r_robots.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p: disallows.append(p)
                web_data["robotsTxt"]["disallowedPaths"] = disallows[:10]
    except Exception:
        pass

    # 5. Check Sitemap.xml
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r_sitemap = await client.get(f"https://{domain}/sitemap.xml", headers=client_headers, follow_redirects=True)
            if r_sitemap.status_code == 200 and ("<urlset" in r_sitemap.text.lower() or "<sitemapindex" in r_sitemap.text.lower()):
                web_data["sitemapXml"]["available"] = True
    except Exception:
        pass

    return web_data
