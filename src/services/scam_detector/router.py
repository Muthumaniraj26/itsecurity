from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from src.services.scraper.url_scraper import scrape_url_info
from src.services.scam_detector.analyzer import analyze_website_scam
from src.services.threat_digest.router import extract_llm_headers

router = APIRouter(prefix="/api", tags=["Scam Detector Service"])

class UrlInputSchema(BaseModel):
    url: str

@router.post("/detect-scam")
async def detect_scam(data: UrlInputSchema, request: Request):
    try:
        opts = extract_llm_headers(request)
        scraped_info = await scrape_url_info(data.url)
        ai_result = await analyze_website_scam(scraped_info, **opts)
        return {
            "scraped": scraped_info,
            "analysis": ai_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scam risk detector failed: {str(e)}")
