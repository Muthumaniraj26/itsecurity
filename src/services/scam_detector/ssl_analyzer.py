import ssl
import socket
from datetime import datetime
import OpenSSL.crypto as crypto

def inspect_ssl_tls_certificate(hostname: str, port: int = 443) -> dict:
    """
    Performs in-depth cryptographic SSL/TLS inspection:
    - Subject & Issuer Hierarchy
    - Subject Alternative Names (SANs)
    - Validity Window (Days Remaining, Fresh Issuance Check)
    - Self-Signed & Domain Mismatch Detection
    - Cipher Suite & Protocol Version
    """
    cert_data = {
        "hasSsl": False,
        "issuer": {"organization": "Unknown", "commonName": "Unknown", "country": "Unknown"},
        "subject": {"commonName": "Unknown", "organization": "Unknown"},
        "sans": [],
        "validFrom": None,
        "validTo": None,
        "daysRemaining": None,
        "daysActive": None,
        "isExpired": False,
        "isFreshlyIssued": False,  # <14 days old (frequently seen in disposable phishing)
        "isSelfSigned": False,
        "domainMismatch": False,
        "protocol": "TLS",
        "cipher": None,
        "signatureAlgorithm": "Unknown",
        "keyType": "RSA",
        "keySize": 2048,
        "health": "NO_SSL",
        "issues": []
    }

    if not hostname:
        return cert_data

    try:
        ctx = ssl.create_default_context()
        # Allow checking even if unverified to inspect self-signed/expired certs
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_data["hasSsl"] = True
                cert_data["protocol"] = ssock.version() or "TLSv1.3"
                cipher_info = ssock.cipher()
                if cipher_info:
                    cert_data["cipher"] = {
                        "name": cipher_info[0],
                        "version": cipher_info[1],
                        "bits": cipher_info[2]
                    }

                # Retrieve raw DER certificate and parse with PyOpenSSL
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                    
                    # 1. Subject Details
                    subj = x509.get_subject()
                    cert_data["subject"]["commonName"] = subj.CN or "Unknown"
                    cert_data["subject"]["organization"] = subj.O or "Unknown"

                    # 2. Issuer Details
                    issuer = x509.get_issuer()
                    cert_data["issuer"]["commonName"] = issuer.CN or "Unknown"
                    cert_data["issuer"]["organization"] = issuer.O or "Unknown"
                    cert_data["issuer"]["country"] = issuer.C or "Unknown"

                    # 3. Signature Algorithm & Key
                    cert_data["signatureAlgorithm"] = x509.get_signature_algorithm().decode('utf-8', errors='ignore')
                    pub_key = x509.get_pubkey()
                    if pub_key:
                        cert_data["keySize"] = pub_key.bits()
                        if pub_key.type() == crypto.TYPE_RSA:
                            cert_data["keyType"] = "RSA"
                        elif pub_key.type() == crypto.TYPE_DSA:
                            cert_data["keyType"] = "DSA"
                        else:
                            cert_data["keyType"] = "EC/Other"

                    # 4. Dates & Validity
                    not_before_str = x509.get_notBefore().decode('ascii')
                    not_after_str = x509.get_notAfter().decode('ascii')
                    
                    try:
                        dt_from = datetime.strptime(not_before_str, "%Y%m%d%H%M%SZ")
                        dt_to = datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ")
                        cert_data["validFrom"] = dt_from.strftime("%Y-%m-%d %H:%M:%S UTC")
                        cert_data["validTo"] = dt_to.strftime("%Y-%m-%d %H:%M:%S UTC")

                        now = datetime.utcnow()
                        diff_rem = dt_to - now
                        diff_act = now - dt_from
                        cert_data["daysRemaining"] = diff_rem.days
                        cert_data["daysActive"] = max(0, diff_act.days)

                        if diff_rem.days < 0:
                            cert_data["isExpired"] = True
                            cert_data["issues"].append(f"Certificate Expired {abs(diff_rem.days)} days ago.")
                        elif diff_rem.days < 15:
                            cert_data["issues"].append(f"Certificate Expires soon ({diff_rem.days} days remaining).")

                        if cert_data["daysActive"] <= 14:
                            cert_data["isFreshlyIssued"] = True
                            cert_data["issues"].append(f"Freshly Issued Certificate: Created {cert_data['daysActive']} days ago (Common in automated phishing infrastructure).")
                    except Exception:
                        pass

                    # 5. SANs (Subject Alternative Names)
                    sans = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name() == b'subjectAltName':
                            san_str = str(ext)
                            for part in san_str.split(','):
                                part = part.strip()
                                if part.startswith("DNS:"):
                                    sans.append(part[4:])
                    cert_data["sans"] = sans[:20]  # Cap at 20

                    # 6. Self-Signed Check (Subject == Issuer)
                    if subj.CN == issuer.CN and subj.O == issuer.O and issuer.O not in ["Let's Encrypt", "DigiCert", "Google Trust Services"]:
                        cert_data["isSelfSigned"] = True
                        cert_data["issues"].append("Self-Signed Certificate: Not signed by a recognized Certificate Authority (CA).")

                    # 7. Hostname Mismatch Check
                    matched = False
                    host_lower = hostname.lower()
                    if subj.CN and (subj.CN.lower() == host_lower or (subj.CN.startswith('*.') and host_lower.endswith(subj.CN[1:].lower()))):
                        matched = True
                    for san in sans:
                        san_l = san.lower()
                        if san_l == host_lower or (san_l.startswith('*.') and host_lower.endswith(san_l[1:])):
                            matched = True
                            break
                    
                    if not matched and (subj.CN or sans):
                        cert_data["domainMismatch"] = True
                        cert_data["issues"].append(f"Hostname Mismatch: Certificate issued for [{subj.CN or ', '.join(sans[:2])}], does not cover [{hostname}].")

                    # Final Health Assessment
                    if cert_data["isExpired"] or cert_data["domainMismatch"] or cert_data["isSelfSigned"]:
                        cert_data["health"] = "CRITICAL"
                    elif cert_data["isFreshlyIssued"] or len(cert_data["issues"]) > 0:
                        cert_data["health"] = "WARNING"
                    else:
                        cert_data["health"] = "HEALTHY"

    except Exception as e:
        cert_data["hasSsl"] = False
        cert_data["health"] = "FAILED"
        cert_data["issues"].append(f"TLS Connection Error: {str(e)}")

    return cert_data
