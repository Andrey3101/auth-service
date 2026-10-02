import logging

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.deps import (
    company_out,
    get_company,
    get_db_user,
    require_admin_user,
    require_owner_user,
)
from app.models import Company, Payment, Subscription, User
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


@router.delete("", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_company(
    user: User = Depends(require_owner_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    company_id = user.company_id
    await db.execute(delete(Payment).where(Payment.company_id == company_id))
    await db.execute(delete(Subscription).where(Subscription.company_id == company_id))
    await db.execute(delete(User).where(User.company_id == company_id))
    await db.execute(delete(Company).where(Company.id == company_id))
    await db.commit()
    logger.info("Компания %s удалена владельцем %s", company_id, user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
