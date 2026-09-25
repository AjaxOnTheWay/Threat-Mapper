from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum, Float, JSON
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
import enum

Base = declarative_base()

class SiemType(enum.Enum):
    splunk = "splunk"
    wazuh = "wazuh"

class SyncMode(enum.Enum):
    push = "push"
    pull = "pull"

# 1. Primary Authentication & Organizational Tables
class Organization(Base):
    __tablename__ = "organizations"
    org_id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False) # Enforces org_id isolation
    username = Column(String, unique=True, nullable=False)

# 2. Local Cache & Raw Data
class Ioc(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    ioc_value = Column(String, index=True, nullable=False)
    ioc_type = Column(String, nullable=False) # e.g., IP, domain, hash
    verdict = Column(String, nullable=False)
    confidence_score = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class SourceResult(Base):
    __tablename__ = "source_results"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    raw_payload = Column(JSON, nullable=False) # Stores raw JSON from external APIs

# 3. Continuous Monitoring
class Watchlist(Base):
    __tablename__ = "watchlist"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    asset_value = Column(String, nullable=False)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    message_body = Column(String, nullable=False)
    acknowledged = Column(Boolean, default=False) # Tracks user acknowledgment state

# 4. v2 Architecture Addition
class SiemConfig(Base):
    __tablename__ = "siem_config"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.org_id"), nullable=False)
    siem_type = Column(Enum(SiemType), nullable=False)
    endpoint_url = Column(String, nullable=True)
    auth_token = Column(String, nullable=False) # Must be encrypted at rest in production
    sync_mode = Column(Enum(SyncMode), nullable=False)
    last_synced_at = Column(DateTime, nullable=True)