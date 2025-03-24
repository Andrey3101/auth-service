import json
import logging
import aio_pika
import asyncio
from config import Config

logger = logging.getLogger("auth-service")

class QueueService:
    def __init__(self):
        self.rabbitmq_url = Config.RABBITMQ_URL

    async def send_notification(self, user_id: str, message: str) -> None:
        for attempt in range(3):
            try:
                async with aio_pika.connect_robust(self.rabbitmq_url) as connection:
                    channel = await connection.channel()
                    await channel.default_exchange.publish(
                        aio_pika.Message(
                            body=json.dumps({
                                "type": "notify",
                                "data": {"user_id": user_id, "channel": "email", "message": message}
                            }).encode(),
                            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                        ),
                        routing_key="notifications_queue"
                    )
                logger.info(f"Уведомление отправлено для {user_id}: {message}")
                break
            except Exception as e:
                logger.error(f"Ошибка при отправке уведомления, попытка {attempt + 1}: {str(e)}")
                if attempt == 2:
                    raise
                await asyncio.sleep(2 ** attempt)

    async def close(self) -> None:
        """Закрытие соединения (в данном случае не требуется, так как используется контекстный менеджер)."""
        logger.info("Соединение с RabbitMQ закрыто (контекстный менеджер)")