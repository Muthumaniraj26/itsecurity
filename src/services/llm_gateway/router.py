from fastapi import APIRouter
from pydantic import BaseModel
from src.services.llm_gateway.verifier import verify_api_key

router = APIRouter(prefix="/api", tags=["LLM Gateway"])

class KeyTestSchema(BaseModel):
    provider: str = "google"
    apiKey: str = ""
    modelName: str = ""
    baseUrl: str = ""

@router.post("/test-key")
async def test_key(data: KeyTestSchema):
    res = await verify_api_key(
        provider=data.provider,
        test_key=data.apiKey,
        model_name=data.modelName,
        base_url=data.baseUrl
    )
    return res
