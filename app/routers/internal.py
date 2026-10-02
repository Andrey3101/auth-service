import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import redis_store
from app.db import get_db
from app.deps import get_company, token_subject
from app.models import User
from app.redis_store import get_redis
from app.schemas import (
    InternalUserOut,
    TelegramLinkIn,
    TelegramLinkOut,
    TelegramTokenIn,
    TelegramTokenOut,
)
from app.security import require_service
from app.tokens import create_access_token

router = APIRouter(prefix="/api/internal/auth", tags=["internal"], dependencies=[Depends(require_service)])


@router.get("/users/{user_id}", response_model=InternalUserOut)
async def internal_get_user(user_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> InternalUserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")
    return InternalUserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        company_id=user.company_id,
        telegram_chat_id=user.telegram_chat_id,
        is_active=user.is_active,
    )


@router.post("/telegram/link", response_model=TelegramLinkOut)
async def internal_telegram_link(
    data: TelegramLinkIn,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> TelegramLinkOut:
    user_id = await redis_store.consume_tg_code(redis, data.code)
    user = await db.get(User, user_id) if user_id is not None else None
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный или просроченный код привязки"
        )
    # chat_id уникален: если он был привязан к другому пользователю — перепривязываем
    await db.execute(
        update(User)
        .where(User.telegram_chat_id == data.chat_id, User.id != user.id)
        .values(telegram_chat_id=None)
        .execution_options(synchronize_session=False)
    )
    user.telegram_chat_id = data.chat_id
    await db.commit()
    return TelegramLinkOut(user_id=user.id, full_name=user.full_name)


@router.post("/telegram/token", response_model=TelegramTokenOut)
async def internal_telegram_token(
    data: TelegramTokenIn, db: AsyncSession = Depends(get_db)
) -> TelegramTokenOut:
    user = (await db.execute(select(User).where(User.telegram_chat_id == data.chat_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Telegram не привязан")
    company = await get_company(db, user.company_id)
    access = create_access_token(token_subject(user, company))
    return TelegramTokenOut(access_token=access.token, expires_in=access.expires_in)
