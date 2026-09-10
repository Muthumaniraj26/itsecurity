"""
Legacy scraper redirect to cloud-resilient microservice scraper.
"""
from src.services.scraper.url_scraper import (
    normalize_url,
    get_direct_ssl_info,
    get_domain_age_info,
    scrape_url_info
)

__all__ = [
    "normalize_url",
    "get_direct_ssl_info",
    "get_domain_age_info",
    "scrape_url_info"
]
