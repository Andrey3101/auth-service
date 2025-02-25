import json
import pika
from config import Config
import logging

logger = logging.getLogger("auth-service")

class QueueService:
    def __init__(self):
        self.connection = pika.BlockingConnection(pika.URLParameters(Config.RABBITMQ_URL))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue="notifications_queue", durable=True)

    def send_notification(self, user_id: str, message: str) -> None:
        """Отправка уведомления в очередь."""
        payload = {
            "type": "notify",
            "data": {"user_id": user_id, "channel": "email", "message": message}
        }
        self.channel.basic_publish(
            exchange="",
            routing_key="notifications_queue",
            body=json.dumps(payload).encode(),
            properties=pika.BasicProperties(delivery_mode=2)  # Делаем сообщение persistent
        )
        logger.info(f"Уведомление отправлено для {user_id}: {message}")

    def close(self) -> None:
        """Закрытие соединения с RabbitMQ."""
        self.connection.close()
        logger.info("Соединение с RabbitMQ закрыто")
