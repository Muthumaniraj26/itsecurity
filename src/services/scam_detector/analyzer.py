from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm
from src.services.scam_detector.auditor import get_simulated_scam_analysis

async def analyze_website_scam(
    scraped_data: dict,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> dict:
    """Analyze website scam risk using page metadata and LLM synthesis."""
    meta = scraped_data["pageMetadata"]
    prompt = f"""
    You are a scam audit bot and risk compliance assessor.
    Analyze the following metadata gathered from secure page scraping of a target URL and determine if the site is a scam, fake store, fraudulent project, or high-risk portal:

    URL: {scraped_data['url']}
    Domain: {scraped_data['domain']}
    Uses HTTPS: {'Yes' if scraped_data['isHttps'] else 'No'}
    Domain Registration Date: {scraped_data['domainInfo']['createdDate'] or 'Unknown'}
    Domain Age: {str(scraped_data['domainInfo']['ageDays']) + ' days' if scraped_data['domainInfo']['ageDays'] is not None else 'Unknown'}
    Registrar: {scraped_data['domainInfo']['registrar']}
    Page Title: "{meta['title']}"
    Body Text Snippet:
    \"\"\"
    {meta['bodySnippet']}
    \"\"\"

    Generate a structured JSON response evaluating the scam risk.
    You must reply in raw JSON format (no markdown blocks, just the JSON object itself). The JSON must match the following schema:
    {{
      "scamProbability": 70,
      "trustScore": 30,
      "redFlags": [
        "First trust concern",
        "Second concern..."
      ],
      "riskSignalsText": "Analysis of the company's content, claims, and policies present in the snippet.",
      "assessmentText": "A summary rating and conclusion regarding the website's authenticity and trustworthiness."
    }}
    """
    try:
        response_text = await call_multi_llm(prompt, provider, user_api_key, model_name, base_url)
        return parse_json_response(response_text)
    except Exception as e:
        print(f"Multi-LLM scam analysis failed ({provider}): {e}")
        return get_simulated_scam_analysis(scraped_data)
