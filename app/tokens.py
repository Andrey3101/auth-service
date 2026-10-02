"""Выпуск и проверка JWT (контракт docs/API.md, раздел 3)."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.config import get_settings

ALGORITHM = "HS256"


class InvalidTokenError(Exception):
    """Токен недействителен (подпись, срок, тип, формат)."""


@dataclass(frozen=True)
class TokenSubject:
    user_id: uuid.UUID
    company_id: uuid.UUID
    company_type: str
    role: str
    email: str
    name: str


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_in: int  # секунды


@dataclass(frozen=True)
class RefreshClaims:
    user_id: uuid.UUID
    jti: str


def _encode(subject: TokenSubject, typ: str, ttl_seconds: int) -> IssuedToken:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": str(subject.user_id),
        "company_id": str(subject.company_id),
        "company_type": subject.company_type,
        "role": subject.role,
        "email": subject.email,
        "name": subject.name,
        "typ": typ,
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": jti,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)
    return IssuedToken(token=token, jti=jti, expires_in=ttl_seconds)


def create_access_token(subject: TokenSubject) -> IssuedToken:
    return _encode(subject, "access", get_settings().access_ttl_seconds)


def create_refresh_token(subject: TokenSubject) -> IssuedToken:
    return _encode(subject, "refresh", get_settings().refresh_ttl_seconds)


def decode_refresh_token(token: str) -> RefreshClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError("invalid refresh token") from exc
    if payload.get("typ") != "refresh":
        raise InvalidTokenError("wrong token type")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidTokenError("missing jti")
    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except ValueError as exc:
        raise InvalidTokenError("bad sub") from exc
    return RefreshClaims(user_id=user_id, jti=jti)
