"""
AEGIX Configuration — Pydantic Settings
Single source of truth for all system configuration.
Loads from .env file in project root.
"""
import os
from pydantic_settings import BaseSettings
from pathlib import Path


class AEGIXSettings(BaseSettings):
    """Central configuration for the AEGIX Agentic Brain."""

    # ── Ollama (Offline LLM) ──
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3:8b"
    OLLAMA_TIMEOUT: int = 30

    # ── Online LLM (Mistral AI) ──
    ONLINE_LLM_PROVIDER: str = "mistral"
    ONLINE_LLM_API_KEY: str = ""
    ONLINE_LLM_MODEL: str = "mistral-small-latest"
    ONLINE_LLM_BASE_URL: str = "https://api.mistral.ai/v1"

    # ── Vector Memory (ChromaDB) ──
    CHROMA_PERSIST_DIR: str = "./data/memory"

    # ── Audit ──
    AUDIT_LOG_DIR: str = "./data/audit"

    # ── Reports ──
    REPORTS_DIR: str = "./data/reports"

    # ── Security ──
    AGENT_SECRET_KEY: str = "aegix_default_secret_override_in_production"
    DEMO_MODE: bool = True

    # ── Network Monitor ──
    HEARTBEAT_INTERVAL: int = 30
    HEARTBEAT_TIMEOUT: int = 5

    @property
    def project_root(self) -> Path:
        """Return the project root directory."""
        return Path(__file__).parent

    @property
    def data_dir(self) -> Path:
        """Return the data directory."""
        return self.project_root / "data"

    @property
    def prompts_dir(self) -> Path:
        """Return the prompts directory."""
        return self.project_root / "prompts"

    model_config = {
        "env_file": os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }



settings = AEGIXSettings()
