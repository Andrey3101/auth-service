"""v2.1: согласие на обработку ПДн (12.6) и оркестрация очистки при удалении компании (12.5).

Без БД и Redis: схемы Pydantic и app.purge с httpx.MockTransport.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.purge import PURGE_TIMEOUT_SEC, PurgeError, PurgeTarget, purge_company_data, purge_targets
from app.schemas import PD_CONSENT_REQUIRED, CompanyOut, RegisterIn, UserOut

# ---------- 12.6: pd_consent ----------

_REGISTER = {
    "email": "owner@example.com",
    "password": "password123",
    "full_name": "Иван Петров",
    "company_name": "ИП Петров",
    "company_type": "ip",
}


def test_register_accepts_consent_true() -> None:
    data = RegisterIn.model_validate({**_REGISTER, "pd_consent": True})
    assert data.pd_consent is True
    data = RegisterIn.model_validate_json(json.dumps({**_REGISTER, "pd_consent": True}))
    assert data.pd_consent is True


@pytest.mark.parametrize("value", [False, "__missing__"])
def test_register_rejects_missing_or_false_consent(value: object) -> None:
    body: dict[str, object] = dict(_REGISTER)
    if value != "__missing__":
        body["pd_consent"] = value
    with pytest.raises(ValidationError) as exc:
        RegisterIn.model_validate(body)
    errors = exc.value.errors()
    assert len(errors) == 1
    assert errors[0]["loc"] == ("pd_consent",)
    assert errors[0]["msg"] == PD_CONSENT_REQUIRED


@pytest.mark.parametrize("value", ["true", 1, "yes", None])
def test_register_rejects_non_boolean_consent(value: object) -> None:
    with pytest.raises(ValidationError) as exc:
        RegisterIn.model_validate({**_REGISTER, "pd_consent": value})
    assert exc.value.errors()[0]["loc"] == ("pd_consent",)


def test_user_out_has_pd_consent_at() -> None:
    company = CompanyOut(
        id=uuid.uuid4(), name="К", type="ip", inn=None, created_at=datetime.now(timezone.utc)
    )
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    common = {
        "id": uuid.uuid4(),
        "email": "a@example.com",
        "full_name": "А",
        "phone": None,
        "position": None,
        "role": "owner",
        "is_active": True,
        "company": company,
        "telegram_linked": False,
        "created_at": now,
    }
    dumped = json.loads(UserOut(**common, pd_consent_at=now).model_dump_json())
    assert dumped["pd_consent_at"] == "2026-10-03T12:00:00Z"
    dumped = json.loads(UserOut(**common, pd_consent_at=None).model_dump_json())
    assert "pd_consent_at" in dumped and dumped["pd_consent_at"] is None


def test_settings_defaults() -> None:
    settings = get_settings()
    assert settings.pd_consent_version == "2026-10"
    assert settings.task_service_url == "http://task-service:8009"
    assert settings.documents_service_url == "http://documents-service:8003"
    assert settings.financial_service_url == "http://financial-service:8005"
    assert settings.notification_service_url == "http://notification-service:8004"


# ---------- 12.5: оркестрация purge ----------

_TOKEN = "svc-token-for-tests"  # noqa: S105


def _targets() -> list[PurgeTarget]:
    return purge_targets(get_settings())


def test_purge_targets_order_and_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TASK_SERVICE_URL", "http://tasks.local:1/")
    settings = Settings()  # type: ignore[call-arg]
    targets = purge_targets(settings)
    assert [t.service for t in targets] == [
        "task-service",
        "documents-service",
        "financial-service",
        "notification-service",
    ]
    assert [t.url for t in targets] == [
        "http://tasks.local:1/api/internal/tasks/purge",
        "http://documents-service:8003/api/internal/documents/purge",
        "http://financial-service:8005/api/internal/finance/purge",
        "http://notification-service:8004/api/internal/notifications/purge",
    ]
    assert PURGE_TIMEOUT_SEC == 30.0


def _run(handler, user_ids: list[uuid.UUID], company_id: uuid.UUID) -> dict[str, int]:
    async def go() -> dict[str, int]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await purge_company_data(client, _targets(), _TOKEN, company_id, user_ids)

    return asyncio.run(go())


def test_purge_all_services_succeed() -> None:
    company_id = uuid.uuid4()
    user_ids = [uuid.uuid4(), uuid.uuid4()]
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"deleted": len(calls)})

    result = _run(handler, user_ids, company_id)

    assert [c.url.path for c in calls] == [
        "/api/internal/tasks/purge",
        "/api/internal/documents/purge",
        "/api/internal/finance/purge",
        "/api/internal/notifications/purge",
    ]
    for call in calls:
        assert call.method == "POST"
        assert call.headers["X-Service-Token"] == _TOKEN
        assert json.loads(call.content) == {
            "company_id": str(company_id),
            "user_ids": [str(u) for u in user_ids],
        }
    assert result == {
        "task-service": 1,
        "documents-service": 2,
        "financial-service": 3,
        "notification-service": 4,
    }


def test_purge_accepts_any_2xx_and_odd_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "tasks" in request.url.path:
            return httpx.Response(204)
        return httpx.Response(200, json={"deleted": "много"})

    result = _run(handler, [], uuid.uuid4())
    assert result == dict.fromkeys(result, 0) and len(result) == 4


@pytest.mark.parametrize("status_code", [500, 404, 401, 503])
def test_purge_stops_on_failed_service(status_code: int) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if "documents" in request.url.path:
            return httpx.Response(status_code, json={"detail": "ошибка"})
        return httpx.Response(200, json={"deleted": 0})

    with pytest.raises(PurgeError) as exc:
        _run(handler, [uuid.uuid4()], uuid.uuid4())
    assert exc.value.service == "documents-service"
    assert exc.value.reason == f"HTTP {status_code}"
    # Последующие сервисы не вызываются; удаление в auth не выполняется (исключение).
    assert calls == ["/api/internal/tasks/purge", "/api/internal/documents/purge"]


def test_purge_network_error() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if "notifications" in request.url.path:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, json={"deleted": 1})

    with pytest.raises(PurgeError) as exc:
        _run(handler, [uuid.uuid4()], uuid.uuid4())
    assert exc.value.service == "notification-service"
    assert exc.value.reason == "ConnectError"
    assert len(calls) == 4


def test_purge_timeout_is_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    with pytest.raises(PurgeError) as exc:
        _run(handler, [], uuid.uuid4())
    assert exc.value.service == "task-service"


def test_purge_error_does_not_leak_token(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    with caplog.at_level("INFO"), pytest.raises(PurgeError):
        _run(handler, [], uuid.uuid4())
    assert "task-service" in caplog.text
    assert _TOKEN not in caplog.text
