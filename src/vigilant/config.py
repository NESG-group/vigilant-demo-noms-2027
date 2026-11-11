from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings managed via environment variables."""

    project_name: str = "VIGILANT"
    api_v1_prefix: str = "/v1"

    # Database (PostgreSQL + pgvector)
    database_url: str = "postgresql+asyncpg://vigilant:vigilant_pass@localhost:5432/vigilant_db"
    db_echo: bool = False

    hermes_base_url: str = "http://localhost:8642/v1"
    hermes_api_key: str = "change-me"
    default_llm_model: str = "qwen2.5:72b"

    # Datalake pcap staging
    pcap_staging_root: Path = Path("/var/lib/vigilant/pcap_staging")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
