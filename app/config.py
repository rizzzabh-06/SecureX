"""
Configuration module — loads environment variables with type safety.
Uses pydantic-settings for validation and python-dotenv for .env loading.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env from project root
project_root = Path(__file__).resolve().parent.parent
load_dotenv(project_root / ".env")

# Force HuggingFace to download models inside the project directory
os.environ["HF_HOME"] = str(project_root / ".hf_cache")


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # === LLM API Keys ===
    GROQ_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # === Threat Intelligence ===
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # === Supabase ===
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    SUPABASE_SERVICE_KEY: str = ""

    # === MobSF ===
    MOBSF_URL: str = "http://localhost:8008"
    MOBSF_API_KEY: str = ""

    # === App Settings ===
    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"
    CHROMADB_DIR: str = "./chromadb_data"

    # === Server ===
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def ensure_dirs(self):
        """Create required directories if they don't exist."""
        for d in [self.UPLOAD_DIR, self.REPORTS_DIR, self.CHROMADB_DIR]:
            Path(d).mkdir(parents=True, exist_ok=True)


# Singleton instance
settings = Settings()
settings.ensure_dirs()
