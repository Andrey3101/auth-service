import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import billing, tbank
from app.config import get_settings
from app.db import get_db
from app.deps import get_db_user, require_admin_user
from app.models import Payment, User
from app.schemas import PaymentUrlOut, SubscriptionOut

logger = logging.getLogger(__name__)

router = APIRouter(tags=["subscription"])


@router.get("/api/subscription", response_model=SubscriptionOut)
async def get_subscription(
    user: User = Depends(get_db_user), db: AsyncSession = Depends(get_db)
) -> SubscriptionOut:
    sub = await billing.get_subscription(db, user.company_id)
    await db.commit()
    return billing.subscription_out(sub, get_settings())


@router.post("/api/subscription/pay", response_model=PaymentUrlOut)
async def pay_subscription(
    user: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> PaymentUrlOut:
    if not get_settings().payments_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Онлайн-оплата не настроена"
        )
    try:
        url = await billing.create_payment_url(db, user.company_id)
    except tbank.TBankError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Ошибка платёжной системы: {exc.message}"
        ) from exc
    return PaymentUrlOut(payment_url=url)


@router.post("/api/subscription/cancel-auto-renew", response_model=SubscriptionOut)
async def cancel_auto_renew(
    user: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> SubscriptionOut:
    sub = await billing.get_subscription(db, user.company_id)
    sub.auto_renew = False
    await db.commit()
    return billing.subscription_out(sub, get_settings())


def _opt_str(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


@router.post("/api/auth/payments/tbank/notify", response_class=PlainTextResponse)
async def tbank_notify(request: Request, db: AsyncSession = Depends(get_db)) -> PlainTextResponse:
    settings = get_settings()
    if not settings.payments_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Онлайн-оплата не настроена"
        )
    try:
        payload = json.loads(await request.body())
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Некорректное уведомление"
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Некорректное уведомление")
    if not tbank.verify_token(payload, settings.tbank_password or ""):
        logger.warning("T-Bank notify: неверная подпись")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверная подпись")
    if str(payload.get("TerminalKey")) != settings.tbank_terminal_key:
        logger.warning("T-Bank notify: чужой TerminalKey")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный терминал")

    order_id = _opt_str(payload.get("OrderId"))
    new_status = _opt_str(payload.get("Status"))
    if order_id is None or new_status is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Некорректное уведомление")

    payment = (
        await db.execute(
            select(Payment)
            .where(Payment.order_id == order_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if payment is None:
        logger.warning("T-Bank notify: платёж с OrderId %s не найден", order_id)
        return PlainTextResponse("OK")

    amount_raw = payload.get("Amount")
    amount = int(amount_raw) if isinstance(amount_raw, (int, str)) and str(amount_raw).isdigit() else None
    success = payload.get("Success")
    if success is False and new_status == "CONFIRMED":
        new_status = "REJECTED"
    await billing.apply_payment_status(
        db,
        payment,
        new_status,
        tbank_payment_id=_opt_str(payload.get("PaymentId")),
        rebill_id=_opt_str(payload.get("RebillId")),
        amount=amount,
    )
    await db.commit()
    return PlainTextResponse("OK")
