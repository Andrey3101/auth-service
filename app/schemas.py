import uuid
from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, EmailStr, Field, field_validator

T = TypeVar("T")

CompanyType = Literal["self_employed", "ip", "ooo"]
Role = Literal["owner", "admin", "user"]
AssignableRole = Literal["admin", "user"]

INN_PATTERN = r"^(\d{10}|\d{12})$"


def _blank_to_none(v: object) -> object:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    limit: int


# ---------- Выходные типы ----------


class CompanyOut(BaseModel):
    id: uuid.UUID
    name: str
    type: CompanyType
    inn: str | None
    created_at: datetime


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    phone: str | None
    position: str | None
    role: Role
    is_active: bool
    company: CompanyOut
    telegram_linked: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int
    user: UserOut


class SubscriptionOut(BaseModel):
    status: Literal["trial", "active", "expired"]
    plan: Literal["standard"] = "standard"
    price: float
    trial_ends_at: datetime | None
    paid_until: datetime | None
    days_left: int
    auto_renew: bool
    payments_enabled: bool


class DetailOut(BaseModel):
    detail: str


class LinkCodeOut(BaseModel):
    code: str
    expires_in: int
    bot_username: str | None


class PaymentUrlOut(BaseModel):
    payment_url: str


# ---------- Входные типы: auth ----------


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)
    phone: str | None = Field(None, max_length=32)
    company_name: str = Field(min_length=1, max_length=255)
    company_type: CompanyType
    inn: str | None = Field(None, pattern=INN_PATTERN)

    @field_validator("phone", "inn", mode="before")
    @classmethod
    def _blank(cls, v: object) -> object:
        return _blank_to_none(v)

    @field_validator("full_name", "company_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Поле не может быть пустым")
        return v


class LoginIn(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class RefreshIn(BaseModel):
    refresh_token: str | None = None


class MeUpdateIn(BaseModel):
    full_name: str | None = Field(None, min_length=1, max_length=255)
    phone: str | None = Field(None, max_length=32)
    position: str | None = Field(None, max_length=255)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetIn(BaseModel):
    email: str = Field(min_length=1, max_length=255)


class PasswordResetConfirmIn(BaseModel):
    token: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)


# ---------- Компания и пользователи ----------


class CompanyUpdateIn(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    inn: str | None = Field(None, pattern=INN_PATTERN)
    type: CompanyType | None = None

    @field_validator("inn", mode="before")
    @classmethod
    def _blank(cls, v: object) -> object:
        return _blank_to_none(v)


class UserCreateIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: AssignableRole = "user"
    phone: str | None = Field(None, max_length=32)
    position: str | None = Field(None, max_length=255)

    @field_validator("phone", "position", mode="before")
    @classmethod
    def _blank(cls, v: object) -> object:
        return _blank_to_none(v)


class UserUpdateIn(BaseModel):
    full_name: str | None = Field(None, min_length=1, max_length=255)
    phone: str | None = Field(None, max_length=32)
    position: str | None = Field(None, max_length=255)
    role: AssignableRole | None = None
    is_active: bool | None = None


# ---------- Внутренние ----------


class InternalUserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    company_id: uuid.UUID
    telegram_chat_id: int | None
    is_active: bool


class TelegramLinkIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")
    chat_id: int


class TelegramLinkOut(BaseModel):
    user_id: uuid.UUID
    full_name: str


class TelegramTokenIn(BaseModel):
    chat_id: int


class TelegramTokenOut(BaseModel):
    access_token: str
    expires_in: int
