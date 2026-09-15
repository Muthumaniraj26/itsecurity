import re
from typing import Dict, Any, List

def extract_authentication_harvest_vectors(html_content: str, forms_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze whether the inspected webpage attempts to harvest sensitive user credentials or assets:
    - Username / Email credentials
    - Passwords & PINs
    - Multi-Factor OTP / Passcodes
    - Credit Card / CVV / Expiration dates
    - Banking / Wire routing numbers
    - Crypto seed phrases / Private keys
    - API keys & enterprise secrets
    """
    text = (html_content or "").lower()

    harvest_targets = {
        "usernameOrEmail": False,
        "password": False,
        "otpOr2fa": False,
        "creditCardOrCvv": False,
        "bankAccount": False,
        "cryptoSeedPhrase": False,
        "apiKeysOrSecrets": False
    }

    evidence = []

    # Check form inputs from form summary
    for form in forms_summary:
        if form.get("passwordFieldsCount", 0) > 0:
            harvest_targets["password"] = True
            evidence.append("Target page requests password / PIN input in an HTML form.")
        if form.get("textFieldsCount", 0) > 0:
            harvest_targets["usernameOrEmail"] = True
        if form.get("isPaymentForm"):
            harvest_targets["creditCardOrCvv"] = True
            evidence.append("Page contains explicit payment / credit card / CVV data collection inputs.")
        if form.get("isOtpForm"):
            harvest_targets["otpOr2fa"] = True
            evidence.append("Page requests One-Time Passcode (OTP) or Multi-Factor Authentication token.")

    # Regex heuristic search across text
    if re.search(r'\b(seed phrase|secret recovery phrase|12-word|24-word|private key|metamask|keystore)\b', text):
        harvest_targets["cryptoSeedPhrase"] = True
        evidence.append("Deceptive cryptocurrency seed phrase or private key collection prompt detected.")

    if re.search(r'\b(routing number|account number|sort code|iban|swift bic)\b', text):
        harvest_targets["bankAccount"] = True
        evidence.append("Banking routing / account number collection fields present.")

    if re.search(r'\b(api[_-]?key|access[_-]?token|bearer token|client[_-]?secret)\b', text):
        harvest_targets["apiKeysOrSecrets"] = True
        evidence.append("Developer API key or enterprise credential collection vector detected.")

    active_vectors_count = sum(1 for v in harvest_targets.values() if v)

    return {
        "hasCredentialHarvesting": active_vectors_count > 0,
        "harvestVectorCount": active_vectors_count,
        "harvestTargets": harvest_targets,
        "evidence": evidence
    }
