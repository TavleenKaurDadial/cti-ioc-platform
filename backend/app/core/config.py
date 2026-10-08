from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Supply DATABASE_URL through the process environment or backend/.env.
    database_url: str
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.8-flash"
    frontend_origin: str | None = None

    @field_validator("gemini_model", mode="before")
    @classmethod
    def default_model_when_blank(cls, value: str | None) -> str:
        if not isinstance(value, str) or not value.strip():
            return "gemini-3.8-flash"
        return value.strip()

    @field_validator("frontend_origin", mode="before")
    @classmethod
    def normalize_frontend_origin(cls, value: str | None) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        return value.strip().rstrip("/")

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()
