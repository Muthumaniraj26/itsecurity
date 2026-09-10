import json
from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm
from src.services.phishing_sandbox.heuristics import (
    get_simulated_phishing_analysis,
    extract_ml_feature_vector
)

async def analyze_url_phishing(
    scraped_data: dict,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> dict:
    """Analyze URL phishing risk using ML feature extraction and LLM synthesis."""
    meta = scraped_data.get("pageMetadata", {})
    ml_features = extract_ml_feature_vector(scraped_data)

    prompt = f"""
    You are a cyber security AI sandbox agent specializing in URL Phishing & Social Engineering Analysis.
    Analyze the following metadata and ML feature vector (inspired by the UCI Phishing URL Detection benchmark):

    URL: {scraped_data['url']}
    Domain: {scraped_data['domain']}
    Uses HTTPS: {'Yes' if scraped_data['isHttps'] else 'No'}
    Domain Age: {str(scraped_data['domainInfo']['ageDays']) + ' days' if scraped_data['domainInfo']['ageDays'] is not None else 'Unknown'}
    Registrar: {scraped_data['domainInfo']['registrar']}
    Page Title: "{meta.get('title', '')}"
    Has Password Fields: {'Yes' if meta.get('hasPasswordFields') else 'No'}
    Is Shortened URL: {'Yes' if meta.get('isShortUrl') else 'No'}
    Has Suspicious '@' Symbol: {'Yes' if meta.get('hasAtSymbol') else 'No'}
    Abnormal Form Handler: {'Yes' if meta.get('emptyOrExternalForm') else 'No'}
    Hidden Iframe: {'Yes' if meta.get('hasIframe') else 'No'}
    Right-Click Disabled: {'Yes' if meta.get('hasRightClickDisabled') else 'No'}
    Total Links: {meta.get('totalLinks', 0)}
    External Outbound Links: {meta.get('externalLinks', 0)}
    Suspicious Keywords Present in Text: [{', '.join(meta.get('suspiciousKeywordsFound', []))}]
    
    EXTRACTED ML FEATURE VECTOR (1 = Legitimate, 0 = Suspicious, -1 = Phishing):
    {json.dumps(ml_features, indent=2)}

    Body Text Snippet:
    \"\"\"
    {meta.get('bodySnippet', '')}
    \"\"\"

    Generate a structured JSON response evaluating the risk.
    You must reply in raw JSON format (no markdown blocks, just the JSON object itself). The JSON must match the following schema:
    {{
      "phishingProbability": 85,
      "dangerLevel": "One of: Safe, Suspicious, Dangerous",
      "riskFactors": [
        "First risk factor identified",
        "Second risk factor..."
      ],
      "visualLayoutCheck": "Analysis of the brand alignment, title structure, and login forms from the snippet.",
      "verdictReasoning": "Concise justification of the final risk level and phishing probability rating."
    }}
    """
    try:
        response_text = await call_multi_llm(prompt, provider, user_api_key, model_name, base_url)
        parsed = parse_json_response(response_text)
        parsed["mlFeatureVector"] = ml_features
        return parsed
    except Exception as e:
        print(f"Multi-LLM phishing analysis failed ({provider}): {e}")
        return get_simulated_phishing_analysis(scraped_data)
