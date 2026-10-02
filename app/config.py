from decimal import Decimal
from functools import lru_cache
from typing import Any

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(..., alias="DATABASE_URL")
    redis_url: str = Field(..., alias="REDIS_URL")
    jwt_secret: str = Field(..., alias="JWT_SECRET")
    jwt_issuer: str = "clerkai-auth"
    service_token: str = Field(..., alias="SERVICE_TOKEN")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

    access_token_ttl_min: int = Field(30, alias="ACCESS_TOKEN_TTL_MIN", ge=1)
    refresh_token_ttl_days: int = Field(30, alias="REFRESH_TOKEN_TTL_DAYS", ge=1)
    cookie_secure: bool = Field(False, alias="COOKIE_SECURE")
    app_url: str = Field("http://localhost", alias="APP_URL")

    trial_days: int = Field(14, alias="TRIAL_DAYS", ge=0)
    subscription_price: Decimal = Field(Decimal("159"), alias="SUBSCRIPTION_PRICE", gt=0)

    smtp_host: str | None = Field(None, alias="SMTP_HOST")
    smtp_port: int = Field(587, alias="SMTP_PORT")
    smtp_user: str | None = Field(None, alias="SMTP_USER")
    smtp_password: str | None = Field(None, alias="SMTP_PASSWORD")
    smtp_from: str | None = Field(None, alias="SMTP_FROM")
    smtp_tls: bool = Field(True, alias="SMTP_TLS")

    telegram_bot_username: str | None = Field(None, alias="TELEGRAM_BOT_USERNAME")

    tbank_terminal_key: str | None = Field(None, alias="TBANK_TERMINAL_KEY")
    tbank_password: str | None = Field(None, alias="TBANK_PASSWORD")
    tbank_api_url: str = Field("https://securepay.tinkoff.ru/v2", alias="TBANK_API_URL")
    tbank_auto_renew: bool = Field(False, alias="TBANK_AUTO_RENEW")

    # Версия текста согласия на обработку ПДн, фиксируется при регистрации (152-ФЗ).
    pd_consent_version: str = Field("2026-10", alias="PD_CONSENT_VERSION", min_length=1, max_length=32)

    # Сервисы, в которых при удалении компании вызывается очистка данных (раздел 12.5).
    task_service_url: str = Field("http://task-service:8009", alias="TASK_SERVICE_URL")
    documents_service_url: str = Field("http://documents-service:8003", alias="DOCUMENTS_SERVICE_URL")
    financial_service_url: str = Field("http://financial-service:8005", alias="FINANCIAL_SERVICE_URL")
    notification_service_url: str = Field("http://notification-service:8004", alias="NOTIFICATION_SERVICE_URL")

    @field_validator("*", mode="before")
    @classmethod
    def _empty_to_default(cls, v: Any, info: ValidationInfo) -> Any:
        # Пустая переменная окружения (FOO=) трактуется как «не задано».
        if isinstance(v, str) and v.strip() == "" and info.field_name:
            field = cls.model_fields[info.field_name]
            if not field.is_required():
                return field.get_default(call_default_factory=True)
        return v

    @field_validator("jwt_secret")
    @classmethod
    def _secret_len(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET должен быть не короче 32 символов")
        return v

    @field_validator(
        "app_url",
        "tbank_api_url",
        "task_service_url",
        "documents_service_url",
        "financial_service_url",
        "notification_service_url",
    )
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def payments_enabled(self) -> bool:
        return bool(self.tbank_terminal_key and self.tbank_password)

    @property
    def access_ttl_seconds(self) -> int:
        return self.access_token_ttl_min * 60

    @property
    def refresh_ttl_seconds(self) -> int:
        return self.refresh_token_ttl_days * 86400


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
