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
    """Parse RFC 2822 or ISO dates into ISO 8601 string."""
    if not date_str:
        return datetime.utcnow().isoformat() + "Z"
    try:
        parsed_dt = email.utils.parsedate_to_datetime(date_str)
        return parsed_dt.isoformat().replace('+00:00', 'Z')
    except Exception:
        try:
            cleaned_date = date_str.replace('Z', '+00:00')
            parsed_dt = datetime.fromisoformat(cleaned_date)
            return parsed_dt.isoformat().replace('+00:00', 'Z')
        except Exception:
            return datetime.utcnow().isoformat() + "Z"
