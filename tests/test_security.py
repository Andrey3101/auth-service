"""Юнит-тесты выпуска/проверки JWT и подписи T-Bank (без БД и Redis)."""

import hashlib
import time
import uuid

import jwt
import pytest
from fastapi import HTTPException

from app.config import get_settings
from app.security import decode_access_token
from app.tbank import make_token, verify_token
from app.tokens import (
    InvalidTokenError,
    TokenSubject,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
)


def _subject() -> TokenSubject:
    return TokenSubject(
        user_id=uuid.uuid4(),
        company_id=uuid.uuid4(),
        company_type="ip",
        role="admin",
        email="user@example.com",
        name="Иван Петров",
    )


def _raw_claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


# ---------- JWT ----------


def test_access_token_claims_match_contract() -> None:
    subject = _subject()
    issued = create_access_token(subject)
    claims = _raw_claims(issued.token)

    assert jwt.get_unverified_header(issued.token)["alg"] == "HS256"
    assert claims["sub"] == str(subject.user_id)
    assert claims["company_id"] == str(subject.company_id)
    assert claims["company_type"] == "ip"
    assert claims["role"] == "admin"
    assert claims["email"] == "user@example.com"
    assert claims["name"] == "Иван Петров"
    assert claims["typ"] == "access"
    assert claims["iss"] == "clerkai-auth"
    assert uuid.UUID(claims["jti"]) and claims["jti"] == issued.jti
    settings = get_settings()
    assert claims["exp"] - claims["iat"] == settings.access_token_ttl_min * 60
    assert issued.expires_in == settings.access_token_ttl_min * 60


def test_access_token_accepted_by_shared_verifier() -> None:
    subject = _subject()
    issued = create_access_token(subject)
    user = decode_access_token(issued.token)
    assert user.id == subject.user_id
    assert user.company_id == subject.company_id
    assert user.role == "admin"
    assert user.is_admin
    assert user.token == issued.token


def test_refresh_token_roundtrip() -> None:
    subject = _subject()
    issued = create_refresh_token(subject)
    claims = _raw_claims(issued.token)
    assert claims["typ"] == "refresh"
    assert claims["iss"] == "clerkai-auth"
    assert claims["exp"] - claims["iat"] == get_settings().refresh_token_ttl_days * 86400

    decoded = decode_refresh_token(issued.token)
    assert decoded.user_id == subject.user_id
    assert decoded.jti == issued.jti


def test_each_token_has_unique_jti() -> None:
    subject = _subject()
    assert create_refresh_token(subject).jti != create_refresh_token(subject).jti


def test_refresh_token_rejected_as_access() -> None:
    issued = create_refresh_token(_subject())
    with pytest.raises(HTTPException) as exc:
        decode_access_token(issued.token)
    assert exc.value.status_code == 401


def test_access_token_rejected_as_refresh() -> None:
    issued = create_access_token(_subject())
    with pytest.raises(InvalidTokenError):
        decode_refresh_token(issued.token)


def test_tampered_token_rejected() -> None:
    issued = create_access_token(_subject())
    header, payload, signature = issued.token.split(".")
    bad_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(HTTPException):
        decode_access_token(f"{header}.{payload}.{bad_signature}")


def test_foreign_secret_and_issuer_rejected() -> None:
    now = int(time.time())
    base = {
        "sub": str(uuid.uuid4()),
        "company_id": str(uuid.uuid4()),
        "typ": "access",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    wrong_secret = jwt.encode({**base, "iss": "clerkai-auth"}, "x" * 40, algorithm="HS256")
    with pytest.raises(HTTPException):
        decode_access_token(wrong_secret)

    wrong_issuer = jwt.encode({**base, "iss": "evil"}, get_settings().jwt_secret, algorithm="HS256")
    with pytest.raises(HTTPException):
        decode_access_token(wrong_issuer)


def test_expired_token_rejected() -> None:
    now = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()),
        "company_id": str(uuid.uuid4()),
        "typ": "refresh",
        "iss": "clerkai-auth",
        "iat": now - 120,
        "exp": now - 60,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, get_settings().jwt_secret, algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_refresh_token(token)


def test_unsigned_token_rejected() -> None:
    now = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()),
        "company_id": str(uuid.uuid4()),
        "typ": "access",
        "iss": "clerkai-auth",
        "iat": now,
        "exp": now + 60,
    }
    token = jwt.encode(payload, None, algorithm="none")
    with pytest.raises(HTTPException):
        decode_access_token(token)


# ---------- T-Bank Token ----------


def test_tbank_token_doc_example() -> None:
    # Пример из документации T-Bank: значения сортируются по ключам
    # (Amount, Description, OrderId, Password, TerminalKey) и конкатенируются.
    params = {
        "TerminalKey": "MerchantTerminalKey",
        "Amount": 19200,
        "OrderId": "21090",
        "Description": "Подарочная карта на 1000 рублей",
        "Receipt": {"Email": "a@test.ru", "Items": [{"Name": "x"}]},
        "DATA": {"Phone": "+71234567890"},
    }
    expected_concat = "19200Подарочная карта на 1000 рублей21090usaf8fw8fsw21gMerchantTerminalKey"
    expected = hashlib.sha256(expected_concat.encode("utf-8")).hexdigest()
    assert make_token(params, "usaf8fw8fsw21g") == expected


def test_tbank_token_ignores_existing_token_and_formats_bool() -> None:
    params = {
        "TerminalKey": "TK",
        "OrderId": "o-1",
        "Success": True,
        "Status": "CONFIRMED",
        "PaymentId": 13660,
        "ErrorCode": "0",
        "Amount": 15900,
        "Token": "ignored",
    }
    expected_concat = "15900" + "0" + "o-1" + "pwd" + "13660" + "CONFIRMED" + "true" + "TK"
    expected = hashlib.sha256(expected_concat.encode("utf-8")).hexdigest()
    assert make_token(params, "pwd") == expected
    assert make_token({**params, "Success": False}, "pwd") != expected


def test_tbank_verify_token() -> None:
    notification = {
        "TerminalKey": "TK",
        "OrderId": "o-1",
        "Success": True,
        "Status": "CONFIRMED",
        "PaymentId": 13660,
        "Amount": 15900,
        "RebillId": 145919,
    }
    notification["Token"] = make_token(notification, "pwd")
    assert verify_token(notification, "pwd")
    assert not verify_token(notification, "other-password")
    assert not verify_token({**notification, "Amount": 100}, "pwd")
    assert not verify_token({k: v for k, v in notification.items() if k != "Token"}, "pwd")
