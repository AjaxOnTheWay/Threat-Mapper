from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from typing import Optional
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

from database import engine, get_db
import models
from jobs import start_scheduler
from engine import validate_and_normalize_ioc, calculate_confidence_score
from connectors import fetch_virustotal, fetch_abuseipdb

# Tell SQLAlchemy to build all the tables in the database
models.Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    print("Shutting down background jobs...")

app = FastAPI(title="ThreatMapper v2 API", lifespan=lifespan)

# --- Pydantic Data Models ---
class WatchlistCreate(BaseModel):
    org_id: int
    ioc_value: str
    ioc_type: str

class IOCRequest(BaseModel):
    ioc_value: str
    ioc_type: str

class OrganizationCreate(BaseModel):
    name: str

class SiemConfigCreate(BaseModel):
    siem_type: str
    endpoint_url: Optional[HttpUrl] = None
    auth_token: str
    sync_mode: str = "push"

# --- Core Endpoints ---
@app.post("/api/lookup")
async def lookup_ioc(request: IOCRequest, db: Session = Depends(get_db)):
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
    
    # Calculate the score and verdict FIRST
    score, verdict = calculate_confidence_score(live_source_results)
    
    # --- DATABASE PERSISTENCE ---
    existing_record = db.query(models.IOCRecord).filter(models.IOCRecord.ioc_value == clean_ioc).first()
    
    if existing_record:
        existing_record.confidence_score = score
        existing_record.verdict = verdict
        existing_record.last_seen = datetime.utcnow()
    else:
        new_record = models.IOCRecord(
            ioc_value=clean_ioc,
            ioc_type=request.ioc_type,
            verdict=verdict,
            confidence_score=score
        )
        db.add(new_record)
        
    db.commit()
    # ----------------------------

    return {
        "ioc": clean_ioc,
        "type": request.ioc_type,
        "verdict": verdict, 
        "confidence_score": score,
        "sources_queried": list(live_source_results.keys())
    }

# --- REAL Watchlist Endpoints ---
@app.post("/api/watchlist")
async def add_to_watchlist(request: WatchlistCreate, db: Session = Depends(get_db)):
    """Adds a new IOC to an organization's continuous monitoring watchlist."""
    # Verify the organization exists
    org = db.query(models.Organization).filter(models.Organization.id == request.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if already watching this IOC for this org
    existing = db.query(models.WatchlistRecord).filter(
        models.WatchlistRecord.org_id == request.org_id,
        models.WatchlistRecord.ioc_value == request.ioc_value
    ).first()
    
    if existing:
        return {"status": "info", "message": "IOC is already on the watchlist"}

    new_watch = models.WatchlistRecord(
        org_id=request.org_id,
        ioc_value=request.ioc_value,
        ioc_type=request.ioc_type
    )
    db.add(new_watch)
    db.commit()
    
    return {"status": "success", "message": f"{request.ioc_value} added to watchlist for org {request.org_id}"}

@app.get("/api/organizations/{org_id}/watchlist")
async def get_watchlist(org_id: int, db: Session = Depends(get_db)):
    """Retrieves all actively watched IOCs for a specific organization."""
    watchlist = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.org_id == org_id).all()
    
    return {
        "org_id": org_id,
        "watchlist": [
            {
                "ioc_value": w.ioc_value,
                "ioc_type": w.ioc_type,
                "added_at": w.added_at,
                "last_checked": w.last_checked
            } for w in watchlist
        ]
    }

# --- Multi-Tenant SIEM Endpoints ---
@app.post("/api/organizations")
async def create_organization(org: OrganizationCreate, db: Session = Depends(get_db)):
    """Creates a new tenant organization."""
    new_org = models.Organization(name=org.name)
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    return {"message": "Organization created", "org_id": new_org.id, "name": new_org.name}

@app.post("/api/organizations/{org_id}/siem/config")
async def update_siem_config(org_id: int, config: SiemConfigCreate, db: Session = Depends(get_db)):
    """Creates or updates a SIEM configuration exclusively for the specified org_id."""
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    existing_config = db.query(models.SiemConfigRecord).filter(
        models.SiemConfigRecord.org_id == org_id,
        models.SiemConfigRecord.siem_type == config.siem_type
    ).first()

    if existing_config:
        existing_config.endpoint_url = str(config.endpoint_url) if config.endpoint_url else None
        existing_config.auth_token = config.auth_token
        existing_config.sync_mode = config.sync_mode
        existing_config.updated_at = datetime.utcnow()
        message = "Configuration updated"
    else:
        new_config = models.SiemConfigRecord(
            org_id=org_id,
            siem_type=config.siem_type,
            endpoint_url=str(config.endpoint_url) if config.endpoint_url else None,
            auth_token=config.auth_token,
            sync_mode=config.sync_mode
        )
        db.add(new_config)
        message = "Configuration created"

    db.commit()
    return {"status": "success", "message": f"{config.siem_type} {message} for org {org_id}"}

@app.get("/api/organizations/{org_id}/siem/config")
async def get_siem_configs(org_id: int, db: Session = Depends(get_db)):
    """Retrieves all SIEM configurations securely scoped to the requested org_id."""
    configs = db.query(models.SiemConfigRecord).filter(models.SiemConfigRecord.org_id == org_id).all()
    if not configs:
        return {"org_id": org_id, "configs": []}
    
    return {
        "org_id": org_id,
        "configs": [
            {   
                "siem_type": c.siem_type,
                "endpoint_url": c.endpoint_url,
                "sync_mode": c.sync_mode,
                "updated_at": c.updated_at
            } for c in configs
        ]
    }