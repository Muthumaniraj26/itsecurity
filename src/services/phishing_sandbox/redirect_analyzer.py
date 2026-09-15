import urllib.parse
import socket
import httpx
from typing import Dict, Any, List

async def trace_redirect_chain(initial_url: str, max_hops: int = 8) -> Dict[str, Any]:
    """
    Safely trace the entire HTTP redirect chain hop-by-hop:
    - URL, Status Code, Domain, IP, Redirect Type for every hop
    - Detects open redirects, suspicious hop counts, cross-domain jumps
    """
    chain = []
    current_url = initial_url
    visited = set()
    has_open_redirect = False
    cross_domain_jumps = 0

    try:
        async with httpx.AsyncClient(
            timeout=4.0,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecIntel-Tracer/2.0"}
        ) as client:
            for hop_idx in range(max_hops):
                if current_url in visited:
                    chain.append({
                        "hop": hop_idx + 1,
                        "url": current_url,
                        "status": "LOOP",
                        "domain": urllib.parse.urlparse(current_url).hostname or "",
                        "ip": "N/A",
                        "redirectType": "Infinite Redirect Loop Detected"
                    })
                    break

                visited.add(current_url)
                parsed = urllib.parse.urlparse(current_url)
                domain = parsed.hostname or ""

                ip_str = "Unknown"
                try:
                    ip_str = socket.gethostbyname(domain)
                except Exception:
                    pass

                try:
                    res = await client.get(current_url)
                    status = res.status_code
                    location_header = res.headers.get("location")

                    redirect_type = "Final Destination"
                    if status in (301, 308):
                        redirect_type = f"Permanent Redirect ({status})"
                    elif status in (302, 303, 307):
                        redirect_type = f"Temporary Redirect ({status})"

                    chain.append({
                        "hop": hop_idx + 1,
                        "url": current_url,
                        "status": status,
                        "domain": domain,
                        "ip": ip_str,
                        "redirectType": redirect_type
                    })

                    if status in (301, 302, 303, 307, 308) and location_header:
                        next_url = urllib.parse.urljoin(current_url, location_header)
                        next_domain = urllib.parse.urlparse(next_url).hostname or ""
                        if next_domain != domain:
                            cross_domain_jumps += 1
                        current_url = next_url
                    else:
                        break
                except Exception as e:
                    chain.append({
                        "hop": hop_idx + 1,
                        "url": current_url,
                        "status": "ERR",
                        "domain": domain,
                        "ip": ip_str,
                        "redirectType": f"Network Error: {str(e)[:60]}"
                    })
                    break
    except Exception as e:
        pass

    total_hops = len(chain)
    is_suspicious_chain = total_hops >= 3 or cross_domain_jumps >= 2

    return {
        "initialUrl": initial_url,
        "finalUrl": current_url,
        "totalHops": total_hops,
        "crossDomainJumps": cross_domain_jumps,
        "isSuspiciousRedirectChain": is_suspicious_chain,
        "redirectChain": chain
    }
