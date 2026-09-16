"""
SwitchGate - AI Sentinel & Gemini Brain API Router
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.core.gemini_sentinel import gemini_sentinel

router = APIRouter(prefix="/api/gemini-sentinel", tags=["AI Sentinel"])

class ApiKeyUpdate(BaseModel):
    api_key: str

class ModelUpdate(BaseModel):
    model: str

class RemediationRequest(BaseModel):
    id: Optional[str] = None
    type: str
    payload: Dict[str, Any]

class ChatRequest(BaseModel):
    message: str

@router.get("/status")
async def get_sentinel_status():
    return gemini_sentinel.get_status()

@router.post("/api-key")
async def update_api_key(req: ApiKeyUpdate):
    gemini_sentinel.set_api_key(req.api_key)
    return {"status": "SUCCESS", "message": "Gemini API Key updated successfully."}

@router.post("/model")
async def update_model(req: ModelUpdate):
    gemini_sentinel.set_model(req.model)
    return {"status": "SUCCESS", "model": gemini_sentinel.get_model()}

@router.post("/analyze")
async def run_ai_analysis(force_heuristic: bool = False):
    try:
        result = await gemini_sentinel.analyze_network(force_heuristic=force_heuristic)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/remediate")
async def execute_remediation(req: RemediationRequest):
    try:
        res = gemini_sentinel.execute_remediation(req.type, req.payload)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/chat")
async def chat_with_sentinel(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    return await gemini_sentinel.chat(req.message)
