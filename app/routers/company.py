import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response, status
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import purge, redis_store
from app.config import get_settings
from app.db import get_db
from app.deps import (
    company_out,
    get_company,
    get_db_user,
    require_admin_user,
    require_owner_user,
)
from app.models import Company, Payment, Subscription, User
from app.redis_store import get_redis
from app.schemas import CompanyOut, CompanyUpdateIn

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/company", tags=["company"])


@router.get("", response_model=CompanyOut)
async def get_my_company(user: User = Depends(get_db_user), db: AsyncSession = Depends(get_db)) -> CompanyOut:
    return company_out(await get_company(db, user.company_id))


@router.put("", response_model=CompanyOut)
async def update_company(
    data: CompanyUpdateIn,
    user: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> CompanyOut:
    company = await get_company(db, user.company_id)
    fields = data.model_dump(exclude_unset=True)
    if fields.get("name") is not None:
        company.name = fields["name"].strip() or company.name
    if "inn" in fields:
        company.inn = fields["inn"]
    if fields.get("type") is not None:
        company.type = fields["type"]
    await db.commit()
    return company_out(company)


PURGE_FAILED = "Не удалось удалить данные во всех сервисах, повторите попытку"


@router.delete("", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_company(
    user: User = Depends(require_owner_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> Response:
    settings = get_settings()
    company_id = user.company_id
    user_ids = list((await db.scalars(select(User.id).where(User.company_id == company_id))).all())
    # Закрываем транзакцию чтения: не держим соединение «idle in transaction» во время HTTP-вызовов.
    await db.commit()

    # 1. Очистка во всех сервисах (152-ФЗ). Любая неудача → 502, в auth ничего не удаляется.
    try:
        async with httpx.AsyncClient(timeout=purge.PURGE_TIMEOUT_SEC) as client:
            await purge.purge_company_data(
                client, purge.purge_targets(settings), settings.service_token, company_id, user_ids
            )
    except purge.PurgeError as exc:
        logger.error("Компания %s не удалена: очистка в %s не удалась", company_id, exc.service)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=PURGE_FAILED) from exc

    # 2. Удаление в auth.
    await db.execute(delete(Payment).where(Payment.company_id == company_id))
    await db.execute(delete(Subscription).where(Subscription.company_id == company_id))
    await db.execute(delete(User).where(User.company_id == company_id))
    await db.execute(delete(Company).where(Company.id == company_id))
    await db.commit()
    logger.info("Компания %s удалена владельцем %s (пользователей: %d)", company_id, user.id, len(user_ids))

    # 3. Отзыв refresh-сессий. Ошибка Redis не отменяет удаление: refresh удалённого
    # пользователя всё равно отклоняется (пользователь не найден в БД).
    for uid in user_ids:
        try:
            await redis_store.revoke_all_refresh(redis, uid)
        except RedisError as exc:
            logger.warning("Не удалось отозвать сессии пользователя %s: %s", uid, type(exc).__name__)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
