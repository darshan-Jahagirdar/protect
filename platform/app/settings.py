"""Platform settings, read from environment variables (prefix PROTECT_) or platform/.env."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLATFORM_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PLATFORM_DIR / "data" / "protect.sqlite"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROTECT_",
        env_file=PLATFORM_DIR / ".env",
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = f"sqlite:///{DEFAULT_DB_PATH}"
    base_url: str = "http://127.0.0.1:8000"
    secret_key: SecretStr | None = None

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @model_validator(mode="after")
    def _check_prod(self) -> "Settings":
        if self.is_prod:
            if self.secret_key is None or len(self.secret_key.get_secret_value()) < 32:
                raise ValueError("PROTECT_SECRET_KEY must be set (32+ chars) in prod")
            if not self.base_url.startswith("https://"):
                raise ValueError("PROTECT_BASE_URL must use https:// in prod")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
