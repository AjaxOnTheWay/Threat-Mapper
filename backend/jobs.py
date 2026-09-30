from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime
import asyncio
from database import SessionLocal
import models
from connectors import fetch_virustotal, fetch_abuseipdb
from engine import calculate_confidence_score

scheduler = AsyncIOScheduler()

async def scan_watchlist():
    print(f"[{datetime.utcnow()}] 🔍 INTERVAL JOB: Scanning database watchlist...", flush=True)
    
    # 1. Fetch data synchronously but quickly
    try:
        db = SessionLocal()
        watchlist = db.query(models.WatchlistRecord).all()
        
        # Detach the records from the session into a safe dictionary 
        # so we can close the DB before doing the slow network calls
        records_to_scan = [
            {
                "id": r.id, 
                "ioc_value": r.ioc_value, 
                "ioc_type": r.ioc_type, 
                "org_id": r.org_id
            } for r in watchlist
        ]
    except Exception as e:
        print(f" -> ❌ DB ERROR: {e}", flush=True)
        return
    finally:
        db.close()

    if not records_to_scan:
        print(" -> Watchlist is currently empty.", flush=True)
        return

    print(f" -> Found {len(records_to_scan)} IOC(s). Commencing re-scan...", flush=True)
    
    # 2. Asynchronously scan each record
    for record in records_to_scan:
        print(f"    [*] Checking {record['ioc_type']}: {record['ioc_value']} (Org: {record['org_id']})", flush=True)
        
        # Fire both connectors concurrently just like in main.py
        vt_task = fetch_virustotal(record['ioc_value'], record['ioc_type'])
        abuse_task = fetch_abuseipdb(record['ioc_value'], record['ioc_type'])
        
        vt_result, abuse_result = await asyncio.gather(vt_task, abuse_task)
        
        live_source_results = {
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        }
        
        # Calculate the new verdict
        score, verdict = calculate_confidence_score(live_source_results)
        print(f"        -> Result: {verdict.upper()} (Score: {score})", flush=True)
        
        # (Next step: Save this new score to the database and alert the SIEM)

def run_retention_cleanup():
    print(f"[{datetime.now()}] 🧹 CRON JOB: Sweeping database for records older than 90 days...", flush=True)

def start_scheduler():
    scheduler.add_job(scan_watchlist, 'interval', minutes=1)
    scheduler.add_job(run_retention_cleanup, 'cron', hour=0, minute=0)
    scheduler.start()
    print("⏳ Background scheduler initialized and running.", flush=True)