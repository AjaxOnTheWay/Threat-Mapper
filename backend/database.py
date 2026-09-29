import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Fetches the connection string from your .env file
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# The engine handles the actual connection to PostgreSQL
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# SessionLocal is the factory that generates new database sessions for each request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the parent class all our database models will inherit from
Base = declarative_base()

def get_db():
    """Dependency to generate a database session and close it after the request finishes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()