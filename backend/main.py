from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Optional
import asyncio
from contextlib import asynccontextmanager

from jobs import start_scheduler

# Import the core engine logic
from engine import validate_and_normalize_ioc, calculate_confidence_score

# Import the new async connector
from connectors import fetch_virustotal, fetch_abuseipdb

# 1. Define the lifespan function FIRST
@asynccontextmanager
async def lifespan(app: FastAPI):
    # This runs when the server starts
    start_scheduler()
    yield
    # This runs when the server shuts down
    print("Shutting down background jobs...")

# 2. Pass it directly into the FastAPI initialization
app = FastAPI(title="ThreatMapper v2 API", lifespan=lifespan)

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
        clean_ioc = validate_and_normalize_ioc(request.ioc_value, request.ioc_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Fire both API requests concurrently in the background
    vt_task = fetch_virustotal(clean_ioc, request.ioc_type)
    abuseipdb_task = fetch_abuseipdb(clean_ioc, request.ioc_type)
    
    # Wait for both tasks to finish simultaneously
    vt_result, abuse_result = await asyncio.gather(vt_task, abuseipdb_task)
    
    live_source_results = {
        "virustotal": vt_result,
        "abuseipdb": abuse_result
    }
    
    score, verdict = calculate_confidence_score(live_source_results)
    
    return {
        "ioc": clean_ioc,
        "type": request.ioc_type,
        "verdict": verdict, 
        "confidence_score": score,
        "sources_queried": list(live_source_results.keys())
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