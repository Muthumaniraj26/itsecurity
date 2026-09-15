import re
import unicodedata
from typing import Dict, Any, List, Tuple

# Common Unicode Cyrillic & Greek homoglyphs that visually mimic Latin letters
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0405': 'S',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M',
    '\u041d': 'H', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X', '\u03bf': 'o', '\u03bd': 'v', '\u03c4': 't', '\u03c1': 'p'
}

# Target High-Value Brands for Similarity Comparison
TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "dropbox", "adobe", "dhl", "fedex", "usps",
    "office365", "outlook", "icloud", "steam", "telegram", "whatsapp", "twitter"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the minimum edit operations (insert, delete, substitute) between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Calculate Jaro-Winkler string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_dist = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] == s2[j]:
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    k = 0
    transpositions = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0

    # Winkler prefix bonus
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * 0.1 * (1.0 - jaro)

def detect_homoglyphs(domain: str) -> Dict[str, Any]:
    """Detect Unicode homoglyphs and mixed-script confusables in domain."""
    has_homoglyphs = False
    replaced_chars = []
    normalized_chars = []

    for ch in domain:
        if ch in HOMOGLYPH_MAP:
            has_homoglyphs = True
            replaced_chars.append({"original": ch, "latinSubstitute": HOMOGLYPH_MAP[ch], "unicodeName": unicodedata.name(ch, "UNKNOWN")})
            normalized_chars.append(HOMOGLYPH_MAP[ch])
        else:
            normalized_chars.append(ch)

    de_homoglyphed = "".join(normalized_chars)
    is_idn = domain.startswith("xn--") or has_homoglyphs

    return {
        "hasHomoglyphs": has_homoglyphs,
        "isIdnOrPunycode": is_idn,
        "detectedConfusables": replaced_chars,
        "normalizedLatinDomain": de_homoglyphed
    }

def detect_phishing_domain_similarity(domain: str, subdomains: List[str] = None) -> Dict[str, Any]:
    """
    Perform multi-technique phishing & typosquatting detection:
    - Levenshtein & Jaro-Winkler comparison against high-profile brands
    - Character substitutions (1 -> l, 0 -> o, vv -> w, rn -> m)
    - Subdomain abuse (e.g., paypal.fake-domain.com)
    - Unicode Homographs / Confusables
    """
    domain_clean = domain.lower().split(":")[0]
    parts = domain_clean.split(".")
    base_name = parts[-2] if len(parts) >= 2 else domain_clean

    homoglyph_info = detect_homoglyphs(domain_clean)
    normalized_base = homoglyph_info["normalizedLatinDomain"].split(".")[0]

    detected_targets = []
    subdomain_abuse_found = []

    # Check subdomain brand prepending
    all_subs = [s.lower() for s in (subdomains or [])]
    for brand in TARGET_BRANDS:
        for sub in all_subs:
            if brand in sub:
                subdomain_abuse_found.append({
                    "brand": brand,
                    "subdomain": sub,
                    "type": "Brand in subdomain hierarchy"
                })

    # Character normalization mappings for common leetspeak
    leetspeak_norm = (
        normalized_base
        .replace("0", "o")
        .replace("1", "l")
        .replace("5", "s")
        .replace("3", "e")
        .replace("vv", "w")
        .replace("rn", "m")
        .replace("-", "")
    )

    for brand in TARGET_BRANDS:
        lev = levenshtein_distance(normalized_base, brand)
        jw = jaro_winkler_similarity(normalized_base, brand)
        lev_leet = levenshtein_distance(leetspeak_norm, brand)

        is_match = False
        mutation_type = None

        if normalized_base == brand:
            # Exact base match (may be official or sub-path spoof)
            is_match = True
            mutation_type = "Exact Brand Name"
        elif lev == 1:
            is_match = True
            mutation_type = "Single character typo (Levenshtein = 1)"
        elif lev_leet == 0 or lev_leet == 1:
            is_match = True
            mutation_type = "Leetspeak / Character substitution"
        elif brand in normalized_base and normalized_base != brand:
            is_match = True
            mutation_type = "Brand name combined with deceptive keyword"
        elif jw >= 0.88:
            is_match = True
            mutation_type = f"High Jaro-Winkler similarity ({jw:.2f})"

        if is_match:
            detected_targets.append({
                "brand": brand,
                "levenshteinDistance": lev,
                "jaroWinklerSimilarity": round(jw, 3),
                "mutationType": mutation_type
            })

    is_phishing_suspect = len(detected_targets) > 0 or len(subdomain_abuse_found) > 0 or homoglyph_info["hasHomoglyphs"]

    return {
        "isPhishingSuspect": is_phishing_suspect,
        "matchedBrands": detected_targets,
        "subdomainAbuse": subdomain_abuse_found,
        "homoglyphs": homoglyph_info
    }
