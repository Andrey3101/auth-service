import hmac
import uuid
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    company_id: uuid.UUID
    company_type: str
    role: str
    email: str
    name: str
    token: str  # исходный access-токен (для проброса в другие сервисы)

    @property
    def is_admin(self) -> bool:
        return self.role in ("owner", "admin")


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не авторизован",
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_access_token(token: str) -> CurrentUser:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise _unauthorized() from exc
    if payload.get("typ") != "access" or not payload.get("company_id"):
        raise _unauthorized()
    try:
        return CurrentUser(
            id=uuid.UUID(payload["sub"]),
            company_id=uuid.UUID(payload["company_id"]),
            company_type=payload.get("company_type", "self_employed"),
            role=payload.get("role", "user"),
            email=payload.get("email", ""),
            name=payload.get("name", ""),
            token=token,
        )
    except (ValueError, TypeError) as exc:
        raise _unauthorized() from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> CurrentUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    return decode_access_token(credentials.credentials)


async def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    return user


async def require_service(x_service_token: str | None = Header(default=None)) -> None:
    expected = get_settings().service_token
    # Сравниваем байты: compare_digest(str, str) бросает TypeError на не-ASCII символах (→ 500)
    if not x_service_token or not hmac.compare_digest(x_service_token.encode(), expected.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный сервисный токен")
