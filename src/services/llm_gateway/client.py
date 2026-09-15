import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def get_configured_providers() -> list:
    """Detect which LLM providers have active credentials or local endpoints."""
    available = []
    if os.getenv("GEMINI_API_KEY"):
        available.append("google")
    if os.getenv("GROQ_API_KEY"):
        available.append("groq")
    if os.getenv("OPENAI_API_KEY"):
        available.append("openai")
    if os.getenv("ANTHROPIC_API_KEY"):
        available.append("anthropic")
    # Always check custom / local endpoint if specified
    if os.getenv("CUSTOM_LLM_URL"):
        available.append("custom")
    return available

async def _invoke_single_provider(
    provider: str,
    prompt: str,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> str:
    """Direct provider API invocation."""
    effective_provider = provider.lower().strip()
    effective_key = user_api_key.strip() if (user_api_key and user_api_key.strip()) else None

    if not effective_key:
        if effective_provider == "google":
            effective_key = os.getenv("GEMINI_API_KEY")
        elif effective_provider == "openai":
            effective_key = os.getenv("OPENAI_API_KEY")
        elif effective_provider == "anthropic":
            effective_key = os.getenv("ANTHROPIC_API_KEY")
        elif effective_provider == "groq":
            effective_key = os.getenv("GROQ_API_KEY")

    if not effective_key and effective_provider != "custom":
        raise ValueError(f"No API key configured for {effective_provider.upper()}.")

    async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=10.0)) as client:
        if effective_provider == "google":
            models_to_try = []
            if model_name and model_name.strip():
                models_to_try.append(model_name.strip())
            models_to_try.extend(["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"])
            # Deduplicate while preserving order
            models_to_try = list(dict.fromkeys(models_to_try))

            keys_to_try = [effective_key] if effective_key else []
            env_key = os.getenv("GEMINI_API_KEY")
            if env_key and env_key not in keys_to_try:
                keys_to_try.append(env_key)

            if not keys_to_try:
                raise ValueError("No Gemini API key available.")

            last_gemini_err = None
            for try_key in keys_to_try:
                auth_failed = False
                for g_model in models_to_try:
                    # Try 1: Query parameter ?key=
                    try:
                        url = f"https://generativelanguage.googleapis.com/v1beta/models/{g_model}:generateContent?key={try_key}"
                        payload = {"contents": [{"parts": [{"text": prompt}]}]}
                        res = await client.post(url, json=payload)
                        if res.status_code == 200:
                            data = res.json()
                            candidates = data.get("candidates", [])
                            if candidates and "content" in candidates[0] and "parts" in candidates[0]["content"]:
                                return candidates[0]["content"]["parts"][0].get("text", "")
                        last_gemini_err = f"Status {res.status_code}: {res.text}"
                        if res.status_code in [401, 403] or "API_KEY_SERVICE_BLOCKED" in res.text or "API_KEY_INVALID" in res.text:
                            auth_failed = True
                    except Exception as g_err:
                        last_gemini_err = str(g_err)

                    # Try 2: Header Authorization: Bearer (for OAuth / gcloud / session tokens)
                    if not auth_failed:
                        try:
                            url_bearer = f"https://generativelanguage.googleapis.com/v1beta/models/{g_model}:generateContent"
                            headers_bearer = {
                                "Authorization": f"Bearer {try_key}",
                                "Content-Type": "application/json"
                            }
                            payload = {"contents": [{"parts": [{"text": prompt}]}]}
                            res_bearer = await client.post(url_bearer, json=payload, headers=headers_bearer)
                            if res_bearer.status_code == 200:
                                data = res_bearer.json()
                                candidates = data.get("candidates", [])
                                if candidates and "content" in candidates[0] and "parts" in candidates[0]["content"]:
                                    return candidates[0]["content"]["parts"][0].get("text", "")
                            last_gemini_err = f"Status {res_bearer.status_code}: {res_bearer.text}"
                        except Exception as gb_err:
                            last_gemini_err = str(gb_err)
                            continue

                    if auth_failed:
                        break

            raise ValueError(f"Google Gemini API error across models and auth modes: {last_gemini_err}")

        elif effective_provider in ["openai", "groq", "custom"]:
            default_model = "gpt-4o-mini" if effective_provider == "openai" else ("llama-3.3-70b-versatile" if effective_provider == "groq" else "default")
            target_model = model_name.strip() if (model_name and model_name.strip()) else default_model
            
            if effective_provider == "openai":
                endpoint = "https://api.openai.com/v1/chat/completions"
            elif effective_provider == "groq":
                endpoint = "https://api.groq.com/openai/v1/chat/completions"
            else:
                endpoint = (base_url or os.getenv("CUSTOM_LLM_URL", "http://localhost:11434")).strip().rstrip("/") + "/chat/completions"

            headers = {"Content-Type": "application/json"}
            if effective_key:
                headers["Authorization"] = f"Bearer {effective_key}"

            payload = {
                "model": target_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
            res = await client.post(endpoint, json=payload, headers=headers)
            if res.status_code != 200:
                raise ValueError(f"{effective_provider.upper()} API error ({res.status_code}): {res.text}")
            data = res.json()
            return data["choices"][0]["message"]["content"]

        elif effective_provider == "anthropic":
            target_model = model_name.strip() if (model_name and model_name.strip()) else "claude-3-5-sonnet-20241022"
            endpoint = "https://api.anthropic.com/v1/messages"
            headers = {
                "Content-Type": "application/json",
                "x-api-key": effective_key,
                "anthropic-version": "2023-06-01"
            }
            payload = {
                "model": target_model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}]
            }
            res = await client.post(endpoint, json=payload, headers=headers)
            if res.status_code != 200:
                raise ValueError(f"Anthropic Claude API error ({res.status_code}): {res.text}")
            data = res.json()
            return data["content"][0]["text"]

        else:
            raise ValueError(f"Unsupported LLM provider: {effective_provider}")

async def call_multi_llm(
    prompt: str,
    provider: str = None,
    user_api_key: str = None,
    model_name: str = None,
    base_url: str = None
) -> str:
    """
    Resilient Multi-LLM Gateway with Automated Failover Cascade.
    - Zero lock-in: Automatically switches across providers if one is unavailable.
    - Works with: Google Gemini, OpenAI, Anthropic, Groq, or Local Ollama.
    """
    default_env_provider = os.getenv("DEFAULT_LLM_PROVIDER", "auto").lower().strip()
    requested_provider = (provider or default_env_provider).lower().strip()

    # Determine candidate execution list
    candidates = []
    if requested_provider != "auto":
        candidates.append(requested_provider)

    configured = get_configured_providers()
    for prov in ["google", "groq", "openai", "anthropic", "custom"]:
        if prov in configured and prov not in candidates:
            candidates.append(prov)

    # If no keys are configured at all, try local custom endpoint (Ollama)
    if not candidates:
        candidates = ["custom"]

    last_error = None
    for candidate in candidates:
        try:
            return await _invoke_single_provider(
                provider=candidate,
                prompt=prompt,
                user_api_key=user_api_key if candidate == requested_provider else None,
                model_name=model_name if candidate == requested_provider else None,
                base_url=base_url if candidate == requested_provider else None
            )
        except Exception as e:
            print(f"[LLM Gateway Failover] Provider '{candidate}' encountered issue: {e}. Cascading...")
            last_error = e
            continue

    raise ValueError(f"All configured LLM providers failed or none configured. Last error: {last_error}")
