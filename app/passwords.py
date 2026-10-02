"""Хеширование паролей bcrypt (блокирующие вызовы — в отдельном потоке)."""

import asyncio

import bcrypt

_dummy_hash: bytes | None = None


def _prepare(password: str) -> bytes:
    # bcrypt учитывает только первые 72 байта
    return password.encode("utf-8")[:72]


def _hash_sync(password: str) -> str:
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt()).decode("ascii")


def _check_sync(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("ascii"))
    except ValueError:
        return False


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_hash_sync, password)


async def verify_password(password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(_check_sync, password, password_hash)


async def burn_password_check(password: str) -> None:
    """Проверка против фиктивного хеша, чтобы время ответа не выдавало отсутствие пользователя."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = await asyncio.to_thread(bcrypt.hashpw, b"dummy-password", bcrypt.gensalt())
    await asyncio.to_thread(bcrypt.checkpw, _prepare(password), _dummy_hash)
