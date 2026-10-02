"""Клиент T-Bank Acquiring API v2 (Init, Charge) и подпись Token."""

import hashlib
import hmac
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

HTTP_TIMEOUT_SEC = 20.0


class TBankError(Exception):
    """Ошибка платёжной системы (сеть, неуспешный ответ)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _token_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def make_token(params: dict[str, Any], password: str) -> str:
    """Token по алгоритму T-Bank.

    Берутся только корневые скалярные параметры (вложенные объекты/массивы, например
    Receipt и DATA, а также сам Token и null-значения пропускаются), добавляется пара
    Password, пары сортируются по ключу, значения конкатенируются, от строки берётся SHA-256.
    """
    pairs: dict[str, str] = {}
    for key, value in params.items():
        if key == "Token" or value is None or isinstance(value, (dict, list, tuple)):
            continue
        pairs[key] = _token_value(value)
    pairs["Password"] = password
    concatenated = "".join(pairs[key] for key in sorted(pairs))
    return hashlib.sha256(concatenated.encode("utf-8")).hexdigest()


def verify_token(params: dict[str, Any], password: str) -> bool:
    received = params.get("Token")
    if not isinstance(received, str) or not received:
        return False
    expected = make_token(params, password)
    # Байты: compare_digest(str, str) бросает TypeError на не-ASCII символах (→ 500)
    return hmac.compare_digest(expected.lower().encode(), received.lower().encode())


async def _post(api_url: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{api_url}/{method}"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.error("T-Bank %s: сетевая ошибка %s", method, exc.__class__.__name__)
        raise TBankError("Платёжная система недоступна") from exc
    try:
        data = resp.json()
    except ValueError as exc:
        logger.error("T-Bank %s: некорректный ответ, HTTP %s", method, resp.status_code)
        raise TBankError("Некорректный ответ платёжной системы") from exc
    if not isinstance(data, dict):
        raise TBankError("Некорректный ответ платёжной системы")
    if not data.get("Success"):
        message = str(data.get("Message") or data.get("Details") or "Платёж отклонён")
        logger.warning("T-Bank %s: ErrorCode=%s Message=%s", method, data.get("ErrorCode"), message)
        raise TBankError(message)
    return data


async def init_payment(
    *,
    api_url: str,
    terminal_key: str,
    password: str,
    amount_kop: int,
    order_id: str,
    description: str,
    customer_key: str,
    notification_url: str,
    success_url: str,
    fail_url: str,
    recurrent: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "TerminalKey": terminal_key,
        "Amount": amount_kop,
        "OrderId": order_id,
        "Description": description,
        "CustomerKey": customer_key,
        "NotificationURL": notification_url,
        "SuccessURL": success_url,
        "FailURL": fail_url,
    }
    if recurrent:
        payload["Recurrent"] = "Y"
    payload["Token"] = make_token(payload, password)
    return await _post(api_url, "Init", payload)


async def charge(
    *, api_url: str, terminal_key: str, password: str, payment_id: str, rebill_id: str
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "TerminalKey": terminal_key,
        "PaymentId": payment_id,
        "RebillId": rebill_id,
    }
    payload["Token"] = make_token(payload, password)
    return await _post(api_url, "Charge", payload)
