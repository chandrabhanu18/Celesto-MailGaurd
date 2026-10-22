import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    BACKEND_DIR: Path = Path(__file__).resolve().parent.parent
    SANDBOX_AGENT_DIR: Path = Path(__file__).resolve().parent / "sandbox_agent"

    # Celesto Credentials & Settings
    CELESTO_API_KEY: str = os.getenv("CELESTO_API_KEY", "")
    SANDBOX_PROVIDER_MODE: str = os.getenv("SANDBOX_PROVIDER_MODE", "auto").lower()
    CELESTO_PROVIDER: str = os.getenv("CELESTO_PROVIDER", "cloud")
    CELESTO_TEMPLATE_ID: str = os.getenv("CELESTO_TEMPLATE_ID", "coding-agent")

    # Security Invariant Constraints
    MAX_SANDBOX_OUTPUT_BYTES: int = 512 * 1024  # 512 KB maximum stdout size limit
    EXECUTION_TIMEOUT_SECONDS: int = 45

    # LLM Settings & Invariants
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "mock").lower()
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
    LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
    MAX_LLM_OUTPUT_BYTES: int = int(os.getenv("MAX_LLM_OUTPUT_BYTES", str(256 * 1024)))  # 256 KB max output

    # Server Settings
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./mailguard.db")

settings = Settings()
