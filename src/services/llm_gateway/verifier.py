from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm

async def verify_api_key(
    provider: str = "google",
    test_key: str = "",
    model_name: str = "",
    base_url: str = ""
) -> dict:
    """Validate user provided API key against requested provider."""
    prov = (provider or "google").lower().strip()
    if prov != "custom" and not (test_key and test_key.strip()):
        return {"valid": False, "message": f"API Key string for {prov.upper()} is empty."}
    
    test_prompt = "You must reply in raw JSON format: {\"status\": \"ok\", \"connection\": \"active\"}"
    try:
        response_text = await call_multi_llm(
            prompt=test_prompt,
            provider=prov,
            user_api_key=test_key,
            model_name=model_name,
            base_url=base_url
        )
        parsed = parse_json_response(response_text)
        m_name = model_name if (model_name and model_name.strip()) else prov.upper()
        return {"valid": True, "message": f"Connection verified successfully. {prov.upper()} ({m_name}) is active."}
    except Exception as e:
        return {"valid": False, "message": f"{prov.upper()} API validation error: {str(e)}"}
