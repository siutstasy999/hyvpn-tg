from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cert_service import DEFAULT_ACME_DIR, DEFAULT_STATUS_PATH


class CoreSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="/etc/hyvpn/.env.core",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_path: str = Field(default="/var/lib/hyvpn/hyvpn.sqlite3", alias="DATABASE_PATH")
    core_host: str = Field(default="127.0.0.1", alias="CORE_HOST")
    core_port: int = Field(default=8080, alias="CORE_PORT")

    hysteria_stats_url: str = Field(default="http://127.0.0.1:9999", alias="HYSTERIA_STATS_URL")
    hysteria_stats_secret: str = Field(alias="HYSTERIA_STATS_SECRET")

    poll_interval_seconds: int = Field(default=60, alias="POLL_INTERVAL_SECONDS")
    flush_interval_seconds: int = Field(default=600, alias="FLUSH_INTERVAL_SECONDS")

    server_domain: str = Field(alias="SERVER_DOMAIN")
    server_port: int = Field(default=443, alias="SERVER_PORT")

    # Profile name shown by VPN clients; defaults to the domain.
    location_name: str = Field(default="", alias="LOCATION_NAME")

    acme_dir: str = Field(default=DEFAULT_ACME_DIR, alias="ACME_DIR")
    cert_status_path: str = Field(default=DEFAULT_STATUS_PATH, alias="CERT_STATUS_PATH")

    @field_validator("poll_interval_seconds", "flush_interval_seconds")
    @classmethod
    def positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("interval must be positive")
        return value

    @property
    def stats_url(self) -> str:
        return self.hysteria_stats_url.rstrip("/")

    @property
    def profile_name(self) -> str:
        return self.location_name or self.server_domain


@lru_cache
def get_settings() -> CoreSettings:
    return CoreSettings()


class BotSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="/etc/hyvpn/.env.bot",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str = Field(alias="BOT_TOKEN")
    allowed_tg_ids: str = Field(default="", alias="ALLOWED_TG_IDS")
    database_path: str = Field(default="/var/lib/hyvpn/hyvpn.sqlite3", alias="DATABASE_PATH")
    server_domain: str = Field(alias="SERVER_DOMAIN")
    server_port: int = Field(default=443, alias="SERVER_PORT")

    # Profile name shown by VPN clients; defaults to the domain.
    location_name: str = Field(default="", alias="LOCATION_NAME")

    # Interface language used until the operator picks one: "ru" or "en".
    default_lang: str = Field(default="ru", alias="DEFAULT_LANG")

    # Optional: lets the bot show "online now" and unflushed traffic.
    # The bot only reads (never clears) the counters, so it cannot steal
    # deltas from hy-core.
    hysteria_stats_url: str = Field(default="http://127.0.0.1:9999", alias="HYSTERIA_STATS_URL")
    hysteria_stats_secret: str = Field(default="", alias="HYSTERIA_STATS_SECRET")

    acme_dir: str = Field(default=DEFAULT_ACME_DIR, alias="ACME_DIR")
    cert_status_path: str = Field(default=DEFAULT_STATUS_PATH, alias="CERT_STATUS_PATH")

    @property
    def allowed_ids(self) -> set[int]:
        result: set[int] = set()
        for raw in self.allowed_tg_ids.replace(";", ",").split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                result.add(int(raw))
            except ValueError:
                raise ValueError(
                    f"ALLOWED_TG_IDS contains a non-numeric value: {raw!r}"
                ) from None
        return result

    @property
    def stats_url(self) -> str:
        return self.hysteria_stats_url.rstrip("/")

    @property
    def profile_name(self) -> str:
        return self.location_name or self.server_domain


@lru_cache
def get_bot_settings() -> BotSettings:
    return BotSettings()
