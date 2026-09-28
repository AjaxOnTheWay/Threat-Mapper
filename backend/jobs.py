from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime

def run_retention_cleanup():
    """
    Simulates the 90-day data retention policy cleanup.
    Eventually, this will execute a SQLAlchemy DELETE query.
    """
    print(f"[{datetime.now()}] CRON JOB: Sweeping database for records older than 90 days...")

def run_watchlist_monitor():
    """
    Simulates checking highly critical IPs against OSINT sources periodically.
    """
    print(f"[{datetime.now()}] INTERVAL JOB: Re-evaluating watchlisted IOCs...")

def start_scheduler():
    scheduler = AsyncIOScheduler()
    
    # Schedule the retention job to run once a day at midnight (Cron format)
    scheduler.add_job(run_retention_cleanup, 'cron', hour=0, minute=0)
    
    # Schedule the watchlist monitor to run every 60 seconds for testing purposes
    scheduler.add_job(run_watchlist_monitor, 'interval', seconds=60)
    
    scheduler.start()
    print("Background scheduler initialized and running.")