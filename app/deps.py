"""Общие зависимости и преобразования для роутеров auth-service."""

import uuid

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import Company, User
from app.schemas import CompanyOut, UserOut
from app.security import CurrentUser, get_current_user
from app.tokens import TokenSubject


async def get_db_user(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Пользователь из БД по access-токену. Удалён/отключён/сменил компанию → 401."""
    user = await db.get(User, current.id)
    if user is None or not user.is_active or user.company_id != current.company_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не авторизован",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin_user(user: User = Depends(get_db_user)) -> User:
    # Роль проверяется по БД, а не по (возможно устаревшему) claim токена
    if user.role not in ("owner", "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    return user


async def require_owner_user(user: User = Depends(get_db_user)) -> User:
    if user.role != "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    return user


async def get_company(db: AsyncSession, company_id: uuid.UUID) -> Company:
    company = await db.get(Company, company_id)
    if company is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Компания не найдена")
    return company


def company_out(company: Company) -> CompanyOut:
    return CompanyOut(
        id=company.id,
        name=company.name,
        type=company.type,  # type: ignore[arg-type]
        inn=company.inn,
        created_at=company.created_at,
    )


def user_out(user: User, company: Company) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        phone=user.phone,
        position=user.position,
        role=user.role,  # type: ignore[arg-type]
        is_active=user.is_active,
        company=company_out(company),
        telegram_linked=user.telegram_chat_id is not None,
        pd_consent_at=user.pd_consent_at,
        created_at=user.created_at,
    )


def token_subject(user: User, company: Company) -> TokenSubject:
    return TokenSubject(
        user_id=user.id,
        company_id=company.id,
        company_type=company.type,
        role=user.role,
        email=user.email,
        name=user.full_name,
    )
