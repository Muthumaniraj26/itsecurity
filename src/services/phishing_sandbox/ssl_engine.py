import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List

def analyze_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Direct socket TLS certificate handshake and analysis:
    - Validity, expiration, issuer org, Subject Alternative Names (SANs)
    - Self-signed detection, domain mismatch check, TLS protocol version
    """
    result = {
        "hasSsl": False,
        "isValid": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "validFrom": None,
        "validTo": None,
        "daysUntilExpiry": None,
        "isExpired": False,
        "isSelfSigned": False,
        "isDomainMismatch": False,
        "tlsVersion": "Unknown",
        "cipherSuite": "Unknown",
        "subjectAltNames": []
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                result["hasSsl"] = True
                result["tlsVersion"] = ssock.version() or "TLSv1.2"
                cipher = ssock.cipher()
                if cipher:
                    result["cipherSuite"] = cipher[0]

                # Parse issuer
                issuer_items = cert.get("issuer", ())
                for rdn in issuer_items:
                    for key, val in rdn:
                        if key == "organizationName":
                            result["issuer"] = val

                # Parse subject
                subject_items = cert.get("subject", ())
                for rdn in subject_items:
                    for key, val in rdn:
                        if key == "commonName":
                            result["subject"] = val

                # Self-signed check
                if result["issuer"] == result["subject"] and result["issuer"] != "Unknown":
                    result["isSelfSigned"] = True

                # Expiration parsing
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result["validTo"] = exp_dt.strftime("%Y-%m-%d")
                        days_left = (exp_dt - datetime.utcnow()).days
                        result["daysUntilExpiry"] = days_left
                        result["isExpired"] = days_left < 0
                        result["isValid"] = days_left > 0 and not result["isSelfSigned"]
                    except Exception:
                        result["validTo"] = not_after

                # Subject Alternative Names (SANs)
                sans = [name for typ, name in cert.get("subjectAltName", ()) if typ == "DNS"]
                result["subjectAltNames"] = sans

                # Domain match check
                if sans:
                    matches_san = any(domain == s or (s.startswith("*.") and domain.endswith(s[1:])) for s in sans)
                    if not matches_san and result["subject"] != domain:
                        result["isDomainMismatch"] = True
    except Exception as e:
        result["error"] = str(e)

    return result
