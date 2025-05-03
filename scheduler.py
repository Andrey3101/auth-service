import logging
from datetime import datetime
from sqlalchemy.orm import Session
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from config import Config
from models import Subscription, SubscriptionStatus
from services.auth_service import AuthService

logger = logging.getLogger("scheduler")
logging.basicConfig(level=logging.INFO)

class PaymentScheduler:
    RECURRENT_PAYMENT_INTERVAL = 30  # Интервал рекуррентного платежа в днях

    def __init__(self, db: Session):
        self.db = db
        self.auth_service = AuthService(db)
        self.scheduler = AsyncIOScheduler()
        self.scheduler.start()
        self._schedule_recurrent_payments()

    def _schedule_recurrent_payments(self):
        async def check_recurrent_payments():
            logger.info("Начало проверки рекуррентных платежей")
            subscriptions = self.db.query(Subscription).filter(
                Subscription.status == SubscriptionStatus.ACTIVE,
                Subscription.recurrent_payment_id.isnot(None)
            ).all()
            for subscription in subscriptions:
                if subscription.last_payment_date and (datetime.utcnow() - subscription.last_payment_date).days >= self.RECURRENT_PAYMENT_INTERVAL:
                    logger.info(f"Обработка рекуррентного платежа для подписки {subscription.subscription_id}")
                    await self.auth_service.process_recurrent_payment(subscription)

        self.scheduler.add_job(
            check_recurrent_payments,
            trigger=IntervalTrigger(days=1),
            id="recurrent_payments",
            replace_existing=True
        )
        logger.info("Шедулер рекуррентных платежей запущен")

    def shutdown(self):
        self.scheduler.shutdown()
        logger.info("Шедулер рекуррентных платежей остановлен")

if __name__ == "__main__":
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(Config.DB_URL)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    scheduler = PaymentScheduler(db)
    import asyncio
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        scheduler.shutdown()
        db.close()