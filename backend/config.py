"""
Configuration settings for JobShield backend.
Loads environment variables from .env or uses beginner-friendly defaults.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Base directories
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Load .env file if it exists
load_dotenv(BACKEND_DIR / ".env")

# Server settings
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))

# Database settings
MONGODB_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI", "")
DATABASE_NAME = os.getenv("DATABASE_NAME") or os.getenv("DB_NAME", "jobshield_db")
LOCAL_DB_FILE = DATA_DIR / "local_db.json"
SQLITE_DB_FILE = DATA_DIR / "jobshield.db"
