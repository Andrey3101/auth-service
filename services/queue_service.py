import json
import logging
import aio_pika
import asyncio
from typing import Optional
from config import Config

logger = logging.getLogger("auth-service")

class QueueService:
    def __init__(self):
        """Инициализация сервиса очередей с проверкой конфигурации."""
        if not hasattr(Config, 'RABBITMQ_URL') or not Config.RABBITMQ_URL:
            raise ValueError("RABBITMQ_URL не задан в конфигурации")
        self.rabbitmq_url = Config.RABBITMQ_URL
        self.connection: Optional[aio_pika.Connection] = None
        self.channel: Optional[aio_pika.Channel] = None
        logger.info("QueueService инициализирован")

    async def connect(self) -> None:
        """Установка соединения с RabbitMQ."""
        try:
            self.connection = await aio_pika.connect_robust(
                self.rabbitmq_url,
                timeout=10,
                reconnect_interval=5
            )
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=1)
            logger.info("Установлено соединение с RabbitMQ")
        except Exception as e:
            logger.error(f"Ошибка при установке соединения с RabbitMQ: {str(e)}")
            raise

    async def send_notification(self, user_id: str, message: str) -> None:
        """
        Асинхронная отправка уведомления с механизмом повторных попыток.
        
        Args:
            user_id (str): ID пользователя
            message (str): Сообщение для отправки
        """
        if not user_id or not message:
            raise ValueError("user_id и message не могут быть пустыми")

        # Устанавливаем соединение, если оно еще не установлено
        if not self.channel or self.channel.is_closed:
            await self.connect()

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if not self.channel:
                    raise ConnectionError("Канал не инициализирован")

                message_body = json.dumps({
                    "type": "notify",
                    "data": {
                        "user_id": user_id,
                        "channel": "email",
                        "message": message
                    }
                }).encode()

                await self.channel.default_exchange.publish(
                    aio_pika.Message(
                        body=message_body,
                        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                        expiration=3600  # TTL сообщения - 1 час
                    ),
                    routing_key="notifications_queue"
                )
                logger.info(f"Уведомление отправлено для {user_id}: {message}")
                return  # Успешная отправка - выходим из цикла

            except (aio_pika.exceptions.AMQPError, ConnectionError) as e:
                logger.error(f"Ошибка при отправке уведомления, попытка {attempt + 1}/{max_attempts}: {str(e)}")
                if attempt == max_attempts - 1:
                    raise Exception(f"Не удалось отправить уведомление после {max_attempts} попыток: {str(e)}")
                await asyncio.sleep(2 ** attempt)  # Экспоненциальная задержка
                # Переподключаемся перед следующей попыткой
                await self.connect()
            except Exception as e:
                logger.error(f"Неожиданная ошибка при отправке уведомления: {str(e)}")
                raise

    async def close(self) -> None:
        """Корректное закрытие соединения с RabbitMQ."""
        try:
            if self.channel and not self.channel.is_closed:
                await self.channel.close()
            if self.connection and not self.connection.is_closed:
                await self.connection.close()
            logger.info("Соединение с RabbitMQ корректно закрыто")
        except Exception as e:
            logger.error(f"Ошибка при закрытии соединения: {str(e)}")
        finally:
            self.channel = None
            self.connection = None

    async def __aenter__(self):
        """Поддержка асинхронного контекстного менеджера."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Выход из асинхронного контекстного менеджера."""
        await self.close()