from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Optional

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
    # Denzel will send {"ioc_value": "192.168.1.1", "ioc_type": "ip"}
    return {
        "ioc": request.ioc_value,
        "verdict": "suspicious", 
        "confidence_score": 45
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