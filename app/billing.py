"""Подписка: вычисление статуса, оплата через T-Bank, автопродление."""

import asyncio
import logging
import math
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal

from redis.asyncio import Redis
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import tbank
from app.config import Settings, get_settings
from app.db import SessionLocal
from app.models import Payment, Subscription
from app.schemas import SubscriptionOut

logger = logging.getLogger(__name__)

PERIOD = timedelta(days=30)
AUTORENEW_INTERVAL_SEC = 6 * 60 * 60
AUTORENEW_LOCK_KEY = "lock:subscription-autorenew"
AUTORENEW_LOCK_TTL_SEC = 60 * 60
PAYMENT_DESCRIPTION = "Подписка ClerkAI «Стандарт», 30 дней"

# Статусы, после которых CONFIRMED-платёж больше не меняется (кроме возвратов)
REFUND_STATUSES = {"REFUNDED", "PARTIAL_REFUNDED", "REVERSED"}

_RELEASE_LOCK_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _days_left(until: datetime, now: datetime) -> int:
    return max(0, math.ceil((until - now).total_seconds() / 86400))


def effective_status(sub: Subscription, now: datetime) -> tuple[str, int]:
    paid_until = _aware(sub.paid_until)
    trial_ends_at = _aware(sub.trial_ends_at)
    if paid_until is not None and paid_until > now:
        return "active", _days_left(paid_until, now)
    if trial_ends_at is not None and trial_ends_at > now:
        return "trial", _days_left(trial_ends_at, now)
    return "expired", 0


def amount_kopecks(settings: Settings) -> int:
    kop = (settings.subscription_price * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(kop)


def subscription_out(sub: Subscription, settings: Settings) -> SubscriptionOut:
    now = datetime.now(timezone.utc)
    status, days_left = effective_status(sub, now)
    return SubscriptionOut(
        status=status,  # type: ignore[arg-type]
        plan="standard",
        price=float(settings.subscription_price.quantize(Decimal("0.01"))),
        trial_ends_at=_aware(sub.trial_ends_at),
        paid_until=_aware(sub.paid_until),
        days_left=days_left,
        auto_renew=sub.auto_renew,
        payments_enabled=settings.payments_enabled,
    )


def new_trial_subscription(company_id: uuid.UUID, settings: Settings) -> Subscription:
    now = datetime.now(timezone.utc)
    return Subscription(
        company_id=company_id,
        status="trial",
        trial_ends_at=now + timedelta(days=settings.trial_days),
        paid_until=None,
        auto_renew=False,
        rebill_id=None,
        customer_key=str(company_id),
    )


async def get_subscription(
    db: AsyncSession, company_id: uuid.UUID, *, for_update: bool = False
) -> Subscription:
    """Подписка компании; если записи нет (старые данные) — создаётся истёкшая."""
    stmt = select(Subscription).where(Subscription.company_id == company_id)
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    sub = (await db.execute(stmt)).scalar_one_or_none()
    if sub is None:
        sub = Subscription(
            company_id=company_id,
            status="expired",
            trial_ends_at=None,
            paid_until=None,
            auto_renew=False,
            rebill_id=None,
            customer_key=str(company_id),
        )
        db.add(sub)
        await db.flush()
    return sub


def _notification_url(settings: Settings) -> str:
    return f"{settings.app_url}/api/auth/payments/tbank/notify"


async def create_payment_url(db: AsyncSession, company_id: uuid.UUID) -> str:
    """Создаёт платёж и вызывает T-Bank Init. Ошибки T-Bank — tbank.TBankError."""
    settings = get_settings()
    sub = await get_subscription(db, company_id)
    payment = Payment(
        company_id=company_id,
        order_id=str(uuid.uuid4()),
        amount=amount_kopecks(settings),
        status="NEW",
    )
    db.add(payment)
    await db.commit()

    try:
        data = await tbank.init_payment(
            api_url=settings.tbank_api_url,
            terminal_key=settings.tbank_terminal_key or "",
            password=settings.tbank_password or "",
            amount_kop=payment.amount,
            order_id=payment.order_id,
            description=PAYMENT_DESCRIPTION,
            customer_key=sub.customer_key,
            notification_url=_notification_url(settings),
            success_url=f"{settings.app_url}/subscription?status=success",
            fail_url=f"{settings.app_url}/subscription?status=fail",
            recurrent=True,
        )
    except tbank.TBankError:
        payment.status = "ERROR"
        await db.commit()
        raise

    payment_url = data.get("PaymentURL")
    # Статус не перезаписываем: его меняет только webhook/apply_payment_status (под FOR UPDATE)
    payment.tbank_payment_id = str(data["PaymentId"]) if data.get("PaymentId") is not None else None
    await db.commit()
    if not isinstance(payment_url, str) or not payment_url:
        raise tbank.TBankError("Платёжная система не вернула ссылку на оплату")
    return payment_url


async def apply_payment_status(
    db: AsyncSession,
    payment: Payment,
    status: str,
    *,
    tbank_payment_id: str | None,
    rebill_id: str | None,
    amount: int | None,
) -> None:
    """Применяет статус платежа (идемпотентно). Платёж должен быть заблокирован (FOR UPDATE).

    Подписка продлевается ровно один раз — при первом переходе платежа в CONFIRMED.
    Вызывающий делает commit.
    """
    settings = get_settings()
    if payment.status == "CONFIRMED" and status not in REFUND_STATUSES:
        return  # повтор или уведомление, пришедшее не по порядку
    if tbank_payment_id:
        payment.tbank_payment_id = tbank_payment_id

    if status != "CONFIRMED":
        payment.status = status
        return

    if amount is not None and amount != payment.amount:
        logger.error("T-Bank: сумма CONFIRMED не совпадает с платежом %s", payment.order_id)
        payment.status = "AMOUNT_MISMATCH"
        return

    payment.status = "CONFIRMED"
    sub = await get_subscription(db, payment.company_id, for_update=True)
    now = datetime.now(timezone.utc)
    current = _aware(sub.paid_until)
    base = current if current is not None and current > now else now
    sub.paid_until = base + PERIOD
    sub.status = "active"
    if rebill_id:
        sub.rebill_id = rebill_id
        sub.auto_renew = settings.tbank_auto_renew
    logger.info("Подписка компании %s продлена до %s", sub.company_id, sub.paid_until.isoformat())


# ---------- Автопродление ----------


async def _charge_company(sub: Subscription) -> None:
    settings = get_settings()
    terminal_key = settings.tbank_terminal_key or ""
    password = settings.tbank_password or ""
    rebill_id = sub.rebill_id or ""

    async with SessionLocal() as db:
        payment = Payment(
            company_id=sub.company_id,
            order_id=str(uuid.uuid4()),
            amount=amount_kopecks(settings),
            status="NEW",
        )
        db.add(payment)
        await db.commit()

        try:
            init = await tbank.init_payment(
                api_url=settings.tbank_api_url,
                terminal_key=terminal_key,
                password=password,
                amount_kop=payment.amount,
                order_id=payment.order_id,
                description=PAYMENT_DESCRIPTION + " (автопродление)",
                customer_key=sub.customer_key,
                notification_url=_notification_url(settings),
                success_url=f"{settings.app_url}/subscription?status=success",
                fail_url=f"{settings.app_url}/subscription?status=fail",
                recurrent=False,
            )
            payment_id = str(init["PaymentId"])
            payment.tbank_payment_id = payment_id
            await db.commit()

            result = await tbank.charge(
                api_url=settings.tbank_api_url,
                terminal_key=terminal_key,
                password=password,
                payment_id=payment_id,
                rebill_id=rebill_id,
            )
        except (tbank.TBankError, KeyError) as exc:
            logger.warning("Автопродление компании %s не удалось: %s", sub.company_id, exc)
            # Условное обновление: не затираем CONFIRMED, если webhook успел прийти (например, при таймауте Charge)
            await db.execute(
                update(Payment)
                .where(Payment.id == payment.id, Payment.status != "CONFIRMED")
                .values(status="ERROR")
                .execution_options(synchronize_session=False)
            )
            await db.commit()
            return

        # populate_existing: перечитать строку, т.к. её мог уже обработать webhook notify
        locked = (
            await db.execute(
                select(Payment)
                .where(Payment.id == payment.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
        await apply_payment_status(
            db,
            locked,
            str(result.get("Status") or "NEW"),
            tbank_payment_id=payment_id,
            rebill_id=None,
            amount=None,
        )
        await db.commit()


async def run_autorenew_once(redis: Redis) -> None:
    lock_value = secrets.token_hex(16)
    if not await redis.set(AUTORENEW_LOCK_KEY, lock_value, nx=True, ex=AUTORENEW_LOCK_TTL_SEC):
        logger.info("Автопродление уже выполняется другим процессом")
        return
    try:
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)
        async with SessionLocal() as db:
            recent_payment = (
                select(func.count())
                .select_from(Payment)
                .where(Payment.company_id == Subscription.company_id, Payment.created_at > day_ago)
                .scalar_subquery()
            )
            subs = (
                (
                    await db.execute(
                        select(Subscription).where(
                            Subscription.auto_renew.is_(True),
                            Subscription.rebill_id.is_not(None),
                            Subscription.paid_until.is_not(None),
                            Subscription.paid_until < now + timedelta(days=1),
                            recent_payment == 0,  # не более одного платежа на компанию в сутки
                        )
                    )
                )
                .scalars()
                .all()
            )
        for sub in subs:
            await _charge_company(sub)
    finally:
        await redis.eval(_RELEASE_LOCK_LUA, 1, AUTORENEW_LOCK_KEY, lock_value)


async def autorenew_loop(redis: Redis) -> None:
    logger.info("Фоновое автопродление подписок запущено")
    while True:
        try:
            await run_autorenew_once(redis)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Ошибка автопродления подписок")
        await asyncio.sleep(AUTORENEW_INTERVAL_SEC)
