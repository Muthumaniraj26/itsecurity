def compute_comprehensive_domain_risk(
    domain: str,
    domain_info: dict,
    phishing_info: dict,
    threat_intel: dict,
    ssl_info: dict,
    web_security: dict,
    email_sec: dict,
    content_info: dict
) -> dict:
    """
    State-of-the-Art 6-Pillar Weighted Domain Risk Scoring Engine.
    Score: 0 (Safe / Clean) -> 100 (Critical Malicious Risk).
    """
    red_flags = []
    trust_signals = []

    # -------------------------------------------------------------
    # PILLAR 1: Domain Longevity & Registration (Max 20 Points)
    # -------------------------------------------------------------
    p1_score = 0
    p1_reasons = []
    age_days = domain_info.get("ageDays")

    if age_days is None:
        p1_score += 12
        p1_reasons.append("Unverifiable domain creation date in RDAP/WHOIS.")
        red_flags.append("Hidden or Unverifiable Registration: Domain age could not be verified.")
    elif age_days < 14:
        p1_score += 20
        p1_reasons.append(f"Brand New Disposable Domain: Registered only {age_days} days ago.")
        red_flags.append(f"Disposable Domain: Registered just {age_days} days ago (Typical of ephemeral phishing/scams).")
    elif age_days < 30:
        p1_score += 15
        p1_reasons.append(f"Very Fresh Domain: Registered {age_days} days ago.")
        red_flags.append(f"Fresh Domain: Under 30 days old ({age_days} days).")
    elif age_days < 90:
        p1_score += 10
        p1_reasons.append(f"Young Domain: Registered {age_days} days ago.")
    elif age_days < 365:
        p1_score += 5
        p1_reasons.append(f"Under 1 year old ({age_days} days).")
    elif age_days > 1095:  # 3+ years established
        trust_signals.append(f"High Longevity: Domain registered over 3 years ago ({age_days} days).")

    # Short Expiry Warning (< 30 days)
    days_to_exp = domain_info.get("daysUntilExpiry")
    if days_to_exp is not None and days_to_exp < 30 and (age_days and age_days < 365):
        p1_score += 4
        p1_reasons.append("Short expiration window remaining.")

    p1_score = min(p1_score, 20)

    # -------------------------------------------------------------
    # PILLAR 2: Phishing & Brand Impersonation (Max 20 Points)
    # -------------------------------------------------------------
    p2_score = 0
    p2_reasons = []

    if phishing_info.get("isBrandImpersonation"):
        p2_score += 20
        brand_name = phishing_info.get("impersonatedBrand") or "Target Brand"
        p2_reasons.append(f"Direct Brand Impersonation of {brand_name}.")
        red_flags.append(f"Brand Impersonation: Domain unauthorizedly contains trademark [{brand_name}].")
    elif len(phishing_info.get("suspiciousTokensFound", [])) >= 2:
        p2_score += 14
        tokens_str = ", ".join(phishing_info.get("suspiciousTokensFound", []))
        p2_reasons.append(f"Phishing token combinations found: {tokens_str}.")
        red_flags.append(f"Phishing Lures: High-risk security keywords in URL [{tokens_str}].")
    elif len(phishing_info.get("suspiciousTokensFound", [])) == 1:
        p2_score += 6
        p2_reasons.append("Single security lure keyword present.")

    if phishing_info.get("hasHomoglyphs"):
        p2_score += 10
        p2_reasons.append("Internationalized Punycode homoglyph detected.")
        red_flags.append("Homoglyph Camouflage: Domain uses Punycode to masquerade as Latin characters.")

    p2_score = min(p2_score, 20)

    # -------------------------------------------------------------
    # PILLAR 3: Threat Feeds & Blacklist Reputation (Max 20 Points)
    # -------------------------------------------------------------
    p3_score = 0
    p3_reasons = []

    if threat_intel.get("isBlacklisted"):
        p3_score += 20
        count = threat_intel.get("blacklistsListed", 1)
        p3_reasons.append(f"Domain/IP actively listed on {count} threat blacklists.")
        red_flags.append(f"Active Threat Listing: Flagged on {count} public security blacklists (Spam/Malware/Botnet).")
    else:
        trust_signals.append("Clean Blacklist Baseline: Zero listings on verified DNSBL zones.")

    # High Risk TLD
    if threat_intel.get("tldRisk") == "High":
        p3_score += 10
        p3_reasons.append(f"High-Risk TLD extension {threat_intel.get('tld')}.")
        red_flags.append(f"Abused TLD: Extension {threat_intel.get('tld')} is heavily associated with mass fraud campaigns.")
    elif threat_intel.get("tldRisk") == "Moderate-High":
        p3_score += 6
        p3_reasons.append(f"Elevated risk TLD extension {threat_intel.get('tld')}.")

    p3_score = min(p3_score, 20)

    # -------------------------------------------------------------
    # PILLAR 4: Website Security & Security Headers (Max 15 Points)
    # -------------------------------------------------------------
    p4_score = 0
    p4_reasons = []

    sec_headers = web_security.get("securityHeaders", {})
    header_grade = sec_headers.get("grade", "F")
    
    if not web_security.get("httpsAvailable") and not web_security.get("enforcesHttps"):
        p4_score += 8
        p4_reasons.append("No HTTPS enforcement / Cleartext HTTP used.")
        red_flags.append("Insecure Transport: Website does not enforce HTTPS encryption.")
    else:
        trust_signals.append("HTTPS Transport Enforced: All traffic encrypted.")

    if header_grade == "F":
        p4_score += 7
        p4_reasons.append("Grade F: Missing critical HTTP security headers (CSP, HSTS, X-Frame-Options).")
    elif header_grade in ["D", "C"]:
        p4_score += 4
        p4_reasons.append(f"Grade {header_grade}: Incomplete security headers.")
    else:
        trust_signals.append(f"Strong Security Headers (Grade {header_grade}).")

    p4_score = min(p4_score, 15)

    # -------------------------------------------------------------
    # PILLAR 5: SSL/TLS Certificate Health (Max 10 Points)
    # -------------------------------------------------------------
    p5_score = 0
    p5_reasons = []

    if not ssl_info.get("hasSsl"):
        p5_score += 10
        p5_reasons.append("No SSL certificate available or handshake failed.")
    elif ssl_info.get("isExpired"):
        p5_score += 10
        p5_reasons.append("SSL Certificate is Expired.")
        red_flags.append("Expired TLS Certificate: Cryptographic validity has lapsed.")
    elif ssl_info.get("domainMismatch"):
        p5_score += 9
        p5_reasons.append("Certificate Domain Mismatch.")
        red_flags.append("TLS Hostname Mismatch: Certificate does not match the target domain.")
    elif ssl_info.get("isSelfSigned"):
        p5_score += 8
        p5_reasons.append("Self-signed untrusted certificate.")
        red_flags.append("Self-Signed Certificate: Not signed by a trusted Public CA.")
    elif ssl_info.get("isFreshlyIssued") and (age_days and age_days < 30):
        p5_score += 6
        p5_reasons.append(f"Certificate issued only {ssl_info.get('daysActive')} days ago on a young domain.")
        red_flags.append(f"Fresh SSL Certificate: Issued {ssl_info.get('daysActive')} days ago on newly created domain.")
    else:
        trust_signals.append("Valid Public CA Certificate: Issued by recognized Authority.")

    p5_score = min(p5_score, 10)

    # -------------------------------------------------------------
    # PILLAR 6: Content, Payment & Deceptive Patterns (Max 15 Points)
    # -------------------------------------------------------------
    p6_score = 0
    p6_reasons = []

    if content_info.get("externalFormAction"):
        p6_score += 10
        p6_reasons.append("Form credentials submitted to third-party host.")
        red_flags.append("Credential Harvest Vector: Web form submits password/data to external third-party domain.")

    if content_info.get("financialFraudKeywords"):
        p6_score += 9
        p6_reasons.append("Unrealistic guaranteed return / financial fraud claims.")
        red_flags.append("Financial Scam Pattern: High-risk guaranteed investment / crypto giveaway promises.")

    if content_info.get("deceptiveDiscountFound"):
        p6_score += 6
        p6_reasons.append("Extreme clearance / 90% discount marketing pressure.")
        red_flags.append("Fake Storefront Discount Pressure: Unrealistic blowout discount claims.")

    if content_info.get("irreversiblePaymentDemands"):
        p6_score += 7
        p6_reasons.append("Irreversible payment methods requested.")
        red_flags.append("Non-Refundable Payments: Site demands irreversible crypto/gift cards.")

    if content_info.get("hasFreeWebmailSupport"):
        p6_score += 5
        p6_reasons.append("Free personal webmail (Gmail/Yahoo) used for business contact.")
        red_flags.append("Accountability Deficit: Uses free Gmail/Yahoo for customer support.")

    if content_info.get("suspiciousJsPatterns"):
        p6_score += 6
        p6_reasons.append(f"Obfuscated JS detected: {', '.join(content_info.get('suspiciousJsPatterns', []))}.")

    p6_score = min(p6_score, 15)

    # -------------------------------------------------------------
    # TOTAL SCORE & CLASSIFICATION
    # -------------------------------------------------------------
    total_risk_score = p1_score + p2_score + p3_score + p4_score + p5_score + p6_score
    total_risk_score = min(max(total_risk_score, 2), 98)
    trust_score = 100 - total_risk_score

    # Classification
    if total_risk_score >= 85:
        risk_level = "CRITICAL"
        if phishing_info.get("isBrandImpersonation") or content_info.get("externalFormAction"):
            threat_class = "Active Credential Phishing & Brand Impersonation"
        elif threat_intel.get("isBlacklisted"):
            threat_class = "Blacklisted Malicious Infrastructure / Botnet"
        else:
            threat_class = "High-Risk Deceptive Commercial Storefront"
    elif total_risk_score >= 70:
        risk_level = "HIGH"
        if content_info.get("financialFraudKeywords"):
            threat_class = "Fraudulent Investment / Financial Scheme"
        elif phishing_info.get("suspiciousTokensFound"):
            threat_class = "Suspicious Phishing Vector"
        else:
            threat_class = "High-Risk Untrusted Domain"
    elif total_risk_score >= 40:
        risk_level = "MEDIUM"
        threat_class = "Moderate Risk / Security Hygiene Deficiencies"
    elif total_risk_score >= 16:
        risk_level = "LOW"
        threat_class = "Standard Domain / Minor Advisory Warnings"
    else:
        risk_level = "CLEAN"
        threat_class = "Verified Authentic Enterprise Domain"

    breakdown = [
        {
            "pillar": "Domain Longevity & Registrar",
            "score": p1_score,
            "maxScore": 20,
            "status": "Critical" if p1_score > 14 else ("Warning" if p1_score > 6 else "Good"),
            "summary": " ".join(p1_reasons) if p1_reasons else f"Established domain ({age_days or '365+'} days old)."
        },
        {
            "pillar": "Phishing & Brand Abuse",
            "score": p2_score,
            "maxScore": 20,
            "status": "Critical" if p2_score > 12 else ("Warning" if p2_score > 5 else "Clean"),
            "summary": " ".join(p2_reasons) if p2_reasons else "No brand impersonation or phishing tokens detected."
        },
        {
            "pillar": "Threat Intel & Blacklists",
            "score": p3_score,
            "maxScore": 20,
            "status": "Critical" if p3_score > 12 else ("Warning" if p3_score > 5 else "Clean"),
            "summary": " ".join(p3_reasons) if p3_reasons else f"Zero blacklist listings; {threat_intel.get('tld')} reputation baseline."
        },
        {
            "pillar": "Website Security & Headers",
            "score": p4_score,
            "maxScore": 15,
            "status": "Critical" if p4_score > 10 else ("Warning" if p4_score > 5 else "Good"),
            "summary": f"Header Grade {header_grade}. " + (" ".join(p4_reasons) if p4_reasons else "Adequate security posture.")
        },
        {
            "pillar": "SSL/TLS Health & Trust",
            "score": p5_score,
            "maxScore": 10,
            "status": "Critical" if p5_score > 7 else ("Warning" if p5_score > 4 else "Healthy"),
            "summary": " ".join(p5_reasons) if p5_reasons else f"Valid certificate from {ssl_info.get('issuer', {}).get('organization', 'Public CA')}."
        },
        {
            "pillar": "Content & Deceptive Signals",
            "score": p6_score,
            "maxScore": 15,
            "status": "Critical" if p6_score > 9 else ("Warning" if p6_score > 4 else "Clean"),
            "summary": " ".join(p6_reasons) if p6_reasons else "No deceptive commercial claims or credential harvester scripts found."
        }
    ]

    return {
        "riskScore": total_risk_score,
        "trustScore": trust_score,
        "riskLevel": risk_level,
        "threatClassification": threat_class,
        "redFlags": red_flags,
        "trustSignals": trust_signals,
        "breakdown": breakdown
    }
