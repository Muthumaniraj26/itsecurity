"""
Facade Module for Backward Compatibility.
Re-exports functions from decoupled microservice modules under src/services/
"""

from src.core.utils import parse_json_response
from src.services.llm_gateway.client import call_multi_llm
from src.services.llm_gateway.verifier import verify_api_key

from src.services.threat_digest.tools import run_security_investigation_tools
from src.services.threat_digest.analyzer import (
    analyze_threat_feed_item,
    get_simulated_threat_analysis
)

from src.services.phishing_sandbox.heuristics import get_simulated_phishing_analysis
from src.services.phishing_sandbox.analyzer import analyze_url_phishing

from src.services.scam_detector.auditor import get_simulated_scam_analysis
from src.services.scam_detector.analyzer import analyze_website_scam

__all__ = [
    "parse_json_response",
    "call_multi_llm",
    "verify_api_key",
    "run_security_investigation_tools",
    "analyze_threat_feed_item",
    "get_simulated_threat_analysis",
    "get_simulated_phishing_analysis",
    "analyze_url_phishing",
    "get_simulated_scam_analysis",
    "analyze_website_scam"
]
