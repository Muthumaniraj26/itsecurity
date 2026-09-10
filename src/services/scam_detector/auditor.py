import re

def get_simulated_scam_analysis(scraped_data: dict) -> dict:
    """
    State-of-the-Art Commercial Scam & Website Trust Auditor.
    Audits 5 Trust Vectors:
    1. Domain Age & Longevity (RDAP)
    2. TLD & Extension Reputation
    3. Commercial Claims & Unrealistic Discounts
    4. Accountability & Contact Policies
    5. Payment Red Flags & Deceptive Patterns
    """
    domain = scraped_data.get("domain", "").lower()
    domain_age = scraped_data.get("domainInfo", {}).get("ageDays")
    title = scraped_data.get("pageMetadata", {}).get("title", "").lower()
    text = scraped_data.get("pageMetadata", {}).get("bodySnippet", "").lower()

    scam_score = 5
    red_flags = []
    trust_signals = []

    # 1. Domain Registration & Longevity Vector
    if domain_age is None:
        scam_score += 20
        red_flags.append("Unverifiable Registration: Domain WHOIS / RDAP records are completely hidden or unregistered.")
    elif domain_age < 30:
        scam_score += 55
        red_flags.append(f"Brand New Domain: Registered only {domain_age} days ago (Typical of disposable scam storefronts).")
    elif domain_age < 90:
        scam_score += 35
        red_flags.append(f"Very Fresh Domain: Registered {domain_age} days ago.")
    elif domain_age < 365:
        scam_score += 15
        red_flags.append(f"Young Domain: Under 1 year old ({domain_age} days).")
    elif domain_age > 1095:  # 3+ years established
        trust_signals.append(f"Established Domain: Registered over 3 years ago ({domain_age} days).")
        scam_score -= 10

    # 2. TLD Extension Reputation Vector
    scam_tlds = ['.top', '.xyz', '.shop', '.outlet', '.vip', '.store', '.sale', '.discount', '.cheap', '.click', '.monster', '.work']
    if any(domain.endswith(tld) for tld in scam_tlds):
        scam_score += 15
        red_flags.append(f"High-Risk TLD: Extension [{domain.split('.')[-1]}] is heavily favored by discount scam networks.")

    # 3. Commercial Discount & Counterfeit Claims
    discount_keywords = ['80% off', '90% off', '70% off', 'blowout sale', 'replica', 'factory clearance', 'free giveaway']
    found_discount_kw = [k for k in discount_keywords if k in text or k in title]
    if found_discount_kw:
        scam_score += 20
        red_flags.append(f"Unrealistic Discount Claims: Detected marketing pressure phrases [{', '.join(found_discount_kw)}].")

    # 4. Financial / Crypto Investment Scheme Triggers
    crypto_fraud_keywords = ['crypto investment', '100% guarantee', 'double your deposit', 'risk free profit', 'guaranteed returns', 'bitcoin giveaway']
    found_crypto_kw = [k for k in crypto_fraud_keywords if k in text]
    if found_crypto_kw:
        scam_score += 30
        red_flags.append(f"High-Risk Financial Promises: Promotes speculative investment claims [{', '.join(found_crypto_kw)}].")

    # 5. Payment Method Red Flags (Irreversible Payments)
    irreversible_payments = ['western union', 'moneygram', 'send bitcoin', 'usdt payment', 'gift card payment', 'apple gift card']
    found_pay_kw = [k for k in irreversible_payments if k in text]
    if found_pay_kw:
        scam_score += 25
        red_flags.append(f"Irreversible Payment Demands: Site requests non-refundable payment methods [{', '.join(found_pay_kw)}].")

    # 6. Contact Details & Accountability Audit
    has_contact = any(k in text for k in ['contact us', 'support@', 'help@', 'phone:', 'tel:', 'customer service'])
    has_policy = any(k in text for k in ['refund policy', 'terms of service', 'privacy policy', 'return policy'])
    
    if (domain_age is None or domain_age < 365) and not has_contact:
        scam_score += 15
        red_flags.append("Missing Contact Details: No physical office address, telephone number, or support email identified.")

    if (domain_age is None or domain_age < 365) and not has_policy:
        scam_score += 15
        red_flags.append("Missing Legal Safeguards: No formalized Refund Policy or Terms of Service found on page.")

    # Free Webmail Support Email Check
    if any(k in text for k in ['support@gmail.com', 'help@gmail.com', 'support@yahoo.com', 'support@hotmail.com']):
        scam_score += 15
        red_flags.append("Free Webmail for Business: Official merchant uses free Gmail/Yahoo email instead of a branded domain email.")

    # Bounded Scam Score [2, 98]
    scam_score = min(max(scam_score, 2), 98)
    trust_score = 100 - scam_score

    # Trust Rating Classification
    if trust_score >= 70:
        status_text = "Domain demonstrates high corporate longevity, formal legal policies, and low fraud indicators."
    elif trust_score >= 40:
        status_text = "Domain displays moderate commercial warnings. Exercise caution before submitting financial transactions."
    else:
        status_text = "High probability of deceptive commercial intent, fake storefront, or financial fraud."

    return {
        "scamProbability": scam_score,
        "trustScore": trust_score,
        "redFlags": red_flags,
        "trustSignals": trust_signals,
        "riskSignalsText": f"Audited domain registration ({domain_age or 'Unknown'} days), TLD reputation, commercial claims, and contact transparency.",
        "assessmentText": f"Domain {domain} scored a Trust Rating of {trust_score}/100. {status_text}"
    }
