from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Optional

# Import the core engine logic
from engine import validate_and_normalize_ioc, calculate_confidence_score

app = FastAPI(
    title="ThreatMapper v2 API",
    description="Multi-tiered OSINT aggregation and monitoring engine",
    version="2.0.0"
)

# --- Pydantic Data Models ---

class LookupRequest(BaseModel):
    ioc_value: str
    ioc_type: str  # e.g., 'ip', 'domain', 'hash'

class SiemConfig(BaseModel):
    siem_type: str  # 'splunk' or 'wazuh'
    endpoint_url: Optional[HttpUrl] = None
    auth_token: str
    sync_mode: str  # 'push' or 'pull'

# --- Core Endpoints ---

@app.post("/api/lookup")
async def lookup_ioc(request: LookupRequest):
    try:
        # 1. Pre-flight Validation & Normalization
        clean_ioc = validate_and_normalize_ioc(request.ioc_value, request.ioc_type)
    except ValueError as e:
        # Reject malformed inputs immediately with a 400 status code
        raise HTTPException(status_code=400, detail=str(e))
    
    # 2. Mock external API results (to be replaced by Async OSINT Connector Layer)
    mock_source_results = {
        "virustotal": {"is_flagged": True},
        "abuseipdb": {"is_flagged": False},
        "urlhaus": {"is_flagged": True}
    }
    
    # 3. Apply Canonical Confidence Scoring
    score, verdict = calculate_confidence_score(mock_source_results)
    
    return {
        "ioc": clean_ioc,
        "type": request.ioc_type,
        "verdict": verdict, 
        "confidence_score": score,
        "sources_queried": list(mock_source_results.keys())
    }
@app.get("/api/watchlist")
async def get_watchlist():
    return {"status": "success", "data": []}

@app.post("/api/watchlist")
async def add_watchlist(request: LookupRequest):
    return {"status": "success", "message": f"{request.ioc_value} added to watchlist"}

# --- NEW v2 SIEM Endpoints ---

@app.get("/api/feed")
async def get_siem_feed():
    return {"status": "success", "feed": [{"ioc": "10.0.0.5", "verdict": "malicious"}]}

@app.get("/api/siem/config")
async def get_siem_config():
    return {"status": "success", "config": {}}

@app.post("/api/siem/config")
async def update_siem_config(config: SiemConfig):
    # Validates that Denzel sends the exact fields required for Splunk/Wazuh setup
    return {"status": "success", "message": f"{config.siem_type} configuration updated"}