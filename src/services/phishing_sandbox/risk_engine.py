from typing import Dict, Any, List

def compute_url_risk_score(
    normalizer_data: Dict[str, Any],
    reputation_data: Dict[str, Any],
    domain_data: Dict[str, Any],
    phishing_data: Dict[str, Any],
    brand_data: Dict[str, Any],
    content_data: Dict[str, Any],
    redirect_data: Dict[str, Any],
    js_data: Dict[str, Any],
    download_data: Dict[str, Any],
    ssl_data: Dict[str, Any],
    auth_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculates transparent, evidence-backed URL Phishing & Sandbox Risk Score (0 - 100):
    - Domain Reputation (max 20)
    - Phishing Similarity / Brand Impersonation (max 20)
    - Domain Age & Registration (max 15)
    - Redirect Behavior (max 15)
    - Website Content & Forms (max 15)
    - Threat Intelligence Feeds (max 10)
    - SSL/TLS Security (max 5)
    """

    # 1. Domain Reputation (max 20)
    score_domain_rep = 0
    rep_evidence = []
    if reputation_data.get("isDirectIpHost"):
        score_domain_rep += 15
        rep_evidence.append("Direct IP address used as hostname instead of a domain name (+15 pts)")
    if reputation_data.get("reputationLevel") == "HIGH RISK":
        score_domain_rep += 18
        rep_evidence.append("Multiple threat feed indicators flagged domain reputation as High Risk (+18 pts)")
    elif reputation_data.get("reputationLevel") == "SUSPICIOUS":
        score_domain_rep += 10
        rep_evidence.append("Heuristic indicators flagged domain as suspicious (+10 pts)")
    score_domain_rep = min(20, score_domain_rep)

    # 2. Phishing Similarity & Brand Impersonation (max 20)
    score_phishing = 0
    phishing_evidence = []
    if brand_data.get("isBrandImpersonationDetected"):
        score_phishing += 18
        phishing_evidence.append(f"Target brand '{brand_data.get('targetedBrand')}' impersonated on an unofficial domain (+18 pts)")
    elif phishing_data.get("isPhishingSuspect"):
        score_phishing += 14
        phishing_evidence.append("Fuzzy string similarity / Levenshtein distance matches recognized brand keyword (+14 pts)")

    if phishing_data.get("homoglyphs", {}).get("hasHomoglyphs"):
        score_phishing += 15
        phishing_evidence.append("Unicode homoglyph / deceptive Cyrillic lookalike characters detected in domain (+15 pts)")

    if phishing_data.get("subdomainAbuse"):
        score_phishing += 12
        phishing_evidence.append("Brand name prepended in subdomain hierarchy to deceive users (+12 pts)")
    score_phishing = min(20, score_phishing)

    # 3. Domain Age & Registration (max 15)
    score_domain_age = 0
    age_evidence = []
    age_days = domain_data.get("ageDays")
    if age_days is not None:
        if age_days <= 14:
            score_domain_age = 15
            age_evidence.append(f"Extremely newly registered domain ({age_days} days old) (+15 pts)")
        elif age_days <= 30:
            score_domain_age = 12
            age_evidence.append(f"Newly registered domain ({age_days} days old) (+12 pts)")
        elif age_days <= 90:
            score_domain_age = 7
            age_evidence.append(f"Recently created domain ({age_days} days old) (+7 pts)")
    else:
        # Unknown age or private registration
        if domain_data.get("isNewlyRegistered"):
            score_domain_age = 12
            age_evidence.append("Domain creation date matches recent registration telemetry (+12 pts)")
    score_domain_age = min(15, score_domain_age)

    # 4. Redirect Behavior (max 15)
    score_redirect = 0
    redirect_evidence = []
    total_hops = redirect_data.get("totalHops", 1)
    if redirect_data.get("isSuspiciousRedirectChain"):
        score_redirect += 12
        redirect_evidence.append(f"Suspicious multi-hop redirect chain ({total_hops} hops) with cross-domain jumps (+12 pts)")
    elif total_hops > 1:
        score_redirect += 5
        redirect_evidence.append(f"URL executes automated redirection across {total_hops} hops (+5 pts)")
    if normalizer_data.get("isShortUrl"):
        score_redirect += 6
        redirect_evidence.append("URL shortener used to conceal actual landing endpoint (+6 pts)")
    score_redirect = min(15, score_redirect)

    # 5. Website Content & Forms (max 15)
    score_content = 0
    content_evidence = []
    if auth_data.get("hasCredentialHarvesting"):
        score_content += 12
        content_evidence.append(f"Active credential collection forms ({auth_data.get('harvestVectorCount')} vectors) identified (+12 pts)")
    if content_data.get("hasPaymentForm"):
        score_content += 14
        content_evidence.append("Unverified external payment / credit card submission form (+14 pts)")
    if content_data.get("hiddenForms", 0) > 0:
        score_content += 6
        content_evidence.append("Hidden DOM forms detected (+6 pts)")
    if js_data.get("hasObfuscatedCode") or js_data.get("hasKeyloggingHooks"):
        score_content += 10
        content_evidence.append("Obfuscated JavaScript or keylogger listeners detected in page (+10 pts)")
    if download_data.get("isDangerousExtension") or download_data.get("hasDoubleExtensionLure"):
        score_content += 15
        content_evidence.append("Automatic executable payload download triggered (+15 pts)")
    score_content = min(15, score_content)

    # 6. Threat Intelligence Feeds (max 10)
    score_threat_intel = 0
    threat_evidence = []
    total_matches = reputation_data.get("totalThreatMatches", 0)
    if total_matches >= 3:
        score_threat_intel = 10
        threat_evidence.append(f"Multiple threat intelligence feeds match destination URL ({total_matches} hits) (+10 pts)")
    elif total_matches >= 1:
        score_threat_intel = 7
        threat_evidence.append(f"Threat intelligence feed match found ({total_matches} hit) (+7 pts)")
    score_threat_intel = min(10, score_threat_intel)

    # 7. SSL / TLS Security (max 5)
    score_tls = 0
    tls_evidence = []
    if not ssl_data.get("hasSsl"):
        score_tls = 5
        tls_evidence.append("Insecure plain HTTP connection without encryption (+5 pts)")
    elif ssl_data.get("isExpired"):
        score_tls = 4
        tls_evidence.append("Expired TLS certificate (+4 pts)")
    elif ssl_data.get("isSelfSigned"):
        score_tls = 4
        tls_evidence.append("Self-signed untrusted TLS certificate (+4 pts)")
    elif ssl_data.get("isDomainMismatch"):
        score_tls = 3
        tls_evidence.append("TLS certificate Subject Alternative Name mismatch (+3 pts)")
    score_tls = min(5, score_tls)

    total_score = score_domain_rep + score_phishing + score_domain_age + score_redirect + score_content + score_threat_intel + score_tls
    total_score = max(0, min(100, total_score))

    if total_score >= 75:
        classification = "CRITICAL"
        verdict_title = "High-Confidence Phishing & Malicious Website"
        confidence = 96
    elif total_score >= 50:
        classification = "HIGH"
        verdict_title = "Suspicious Phishing / Fraud Risk"
        confidence = 88
    elif total_score >= 25:
        classification = "MEDIUM"
        verdict_title = "Moderate Risk / Potential Deceptive Vectors"
        confidence = 74
    elif total_score >= 10:
        classification = "LOW"
        verdict_title = "Low Risk / Minor Telemetry Anomalies"
        confidence = 80
    else:
        classification = "SAFE"
        verdict_title = "Clean / Legitimate Website"
        confidence = 94

    return {
        "totalScore": total_score,
        "classification": classification,
        "verdictTitle": verdict_title,
        "confidence": confidence,
        "breakdown": {
            "domainReputation": {"score": score_domain_rep, "max": 20, "evidence": rep_evidence},
            "phishingSimilarity": {"score": score_phishing, "max": 20, "evidence": phishing_evidence},
            "domainAge": {"score": score_domain_age, "max": 15, "evidence": age_evidence},
            "redirectBehavior": {"score": score_redirect, "max": 15, "evidence": redirect_evidence},
            "websiteContent": {"score": score_content, "max": 15, "evidence": content_evidence},
            "threatIntelligence": {"score": score_threat_intel, "max": 10, "evidence": threat_evidence},
            "tlsSecurity": {"score": score_tls, "max": 5, "evidence": tls_evidence}
        }
    }
