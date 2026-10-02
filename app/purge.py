"""Очистка данных компании во всех сервисах перед её удалением (docs/API.md, 12.5).

Сервисы вызываются по очереди: `POST {URL}/api/internal/<svc>/purge` с X-Service-Token
и телом `{company_id, user_ids}`. Первая же неуспешная очистка (не 2xx или ошибка сети)
прерывает процесс исключением PurgeError — тогда данные в auth удалять нельзя.
Повтор безопасен: purge-эндпоинты идемпотентны.
"""

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

PURGE_TIMEOUT_SEC = 30.0


@dataclass(frozen=True)
class PurgeTarget:
    service: str  # имя сервиса для логов
    url: str  # полный URL purge-эндпоинта


class PurgeError(Exception):
    """Очистка в одном из сервисов не удалась; удалять данные в auth нельзя."""

    def __init__(self, service: str, reason: str) -> None:
        super().__init__(f"{service}: {reason}")
        self.service = service
        self.reason = reason


def purge_targets(settings: Settings) -> list[PurgeTarget]:
    """Порядок вызова: задачи, документы, финансы, уведомления."""
    return [
        PurgeTarget("task-service", f"{settings.task_service_url}/api/internal/tasks/purge"),
        PurgeTarget("documents-service", f"{settings.documents_service_url}/api/internal/documents/purge"),
        PurgeTarget("financial-service", f"{settings.financial_service_url}/api/internal/finance/purge"),
        PurgeTarget(
            "notification-service", f"{settings.notification_service_url}/api/internal/notifications/purge"
        ),
    ]


def _deleted_count(resp: httpx.Response) -> int:
    try:
        data = resp.json()
    except ValueError:
        return 0
    value = data.get("deleted") if isinstance(data, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


async def purge_company_data(
    client: httpx.AsyncClient,
    targets: Sequence[PurgeTarget],
    service_token: str,
    company_id: uuid.UUID,
    user_ids: Sequence[uuid.UUID],
) -> dict[str, int]:
    """Вызывает purge во всех сервисах по очереди.

    Возвращает {сервис: deleted}. При первой неудаче бросает PurgeError
    (остальные сервисы не вызываются).
    """
    payload = {"company_id": str(company_id), "user_ids": [str(u) for u in user_ids]}
    headers = {"X-Service-Token": service_token}
    result: dict[str, int] = {}
    for target in targets:
        try:
            resp = await client.post(target.url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            # Только тип исключения: текст может содержать детали запроса.
            logger.error(
                "Удаление компании %s: %s недоступен (%s)", company_id, target.service, type(exc).__name__
            )
            raise PurgeError(target.service, type(exc).__name__) from exc
        if not resp.is_success:
            logger.error(
                "Удаление компании %s: %s ответил HTTP %s", company_id, target.service, resp.status_code
            )
            raise PurgeError(target.service, f"HTTP {resp.status_code}")
        result[target.service] = _deleted_count(resp)
        logger.info(
            "Удаление компании %s: %s очищен (удалено %d)", company_id, target.service, result[target.service]
        )
    return result
