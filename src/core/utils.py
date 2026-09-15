import json
import re
import email.utils
from datetime import datetime

def parse_json_response(text: str) -> dict:
    """Strip markdown wrappers and parse JSON string into dict."""
    try:
        clean_text = re.sub(r'^```json\s*', '', text, flags=re.IGNORECASE)
        clean_text = re.sub(r'\s*```$', '', clean_text)
        clean_text = clean_text.strip()
        return json.loads(clean_text)
    except Exception as e:
        print("Failed to parse LLM JSON response:", text)
        raise ValueError(f"LLM did not return valid JSON: {str(e)}")

def parse_date_to_iso(date_str: str) -> str:
    """Parse RFC 2822 or ISO dates into normalized UTC ISO 8601 string."""
    from datetime import timezone
    if not date_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        parsed_dt = email.utils.parsedate_to_datetime(date_str)
        return parsed_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        try:
            cleaned_date = date_str.replace('Z', '+00:00')
            parsed_dt = datetime.fromisoformat(cleaned_date)
            return parsed_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
