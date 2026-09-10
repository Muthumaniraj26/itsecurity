import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Import Microservice Routers
from src.services.llm_gateway.router import router as llm_gateway_router
from src.services.threat_digest.router import router as threat_digest_router
from src.services.phishing_sandbox.router import router as phishing_sandbox_router
from src.services.scam_detector.router import router as scam_detector_router

load_dotenv()

app = FastAPI(
    title="Security Intelligence Microservices Platform",
    description="Decoupled AI Security Analyst Platform with dedicated microservice endpoints."
)

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Microservice Routers
app.include_router(llm_gateway_router)
app.include_router(threat_digest_router)
app.include_router(phishing_sandbox_router)
app.include_router(scam_detector_router)

@app.get("/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "microservices": [
            "llm_gateway",
            "threat_digest",
            "phishing_sandbox",
            "scam_detector",
            "scraper"
        ]
    }

# Serve Static Frontend Files
public_dir = os.path.join(os.path.dirname(__file__), "public")
if os.path.exists(public_dir):
    app.mount("/static", StaticFiles(directory=public_dir), name="static")
    # Mounting at root allows index.html, styles.css, app.js to resolve seamlessly
    app.mount("/", StaticFiles(directory=public_dir, html=True), name="public")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

