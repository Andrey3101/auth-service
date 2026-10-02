"""Работа с Redis: refresh-allowlist, rate limit, коды сброса пароля и привязки Telegram."""

import hashlib
import secrets
import uuid

from fastapi import Request
from redis.asyncio import Redis

LOGIN_LIMIT = 10
LOGIN_WINDOW_SEC = 15 * 60
RESET_LIMIT = 5
RESET_WINDOW_SEC = 60 * 60
RESET_TTL_SEC = 60 * 60
TG_CODE_TTL_SEC = 600


async def get_redis(request: Request) -> Redis:
    return request.app.state.redis


# ---------- Refresh-токены (allowlist jti) ----------


def _refresh_key(jti: str) -> str:
    return f"refresh:{jti}"


def _user_refresh_key(user_id: uuid.UUID) -> str:
    return f"user_refresh:{user_id}"


async def store_refresh(r: Redis, jti: str, user_id: uuid.UUID, ttl: int) -> None:
    await r.set(_refresh_key(jti), str(user_id), ex=ttl)
    await r.sadd(_user_refresh_key(user_id), jti)
    await r.expire(_user_refresh_key(user_id), ttl)


async def consume_refresh(r: Redis, jti: str, user_id: uuid.UUID) -> bool:
    """Атомарно забирает jti из allowlist. True — токен был действителен."""
    stored = await r.getdel(_refresh_key(jti))
    await r.srem(_user_refresh_key(user_id), jti)
    return stored == str(user_id)


async def revoke_all_refresh(r: Redis, user_id: uuid.UUID, keep_jti: str | None = None) -> None:
    key = _user_refresh_key(user_id)
    jtis = await r.smembers(key)
    to_delete = [j for j in jtis if j != keep_jti]
    if to_delete:
        await r.delete(*[_refresh_key(j) for j in to_delete])
        await r.srem(key, *to_delete)


# ---------- Rate limit ----------


async def rate_limit_exceeded(r: Redis, key: str, limit: int, window_sec: int) -> bool:
    count = int(await r.incr(key))
    # TTL ставится при первом обращении в окне и восстанавливается, если потерян (-1 = ключ без TTL).
    # Без EXPIRE NX, чтобы работать и на Redis 6.2.
    if count == 1 or await r.ttl(key) == -1:
        await r.expire(key, window_sec)
    return count > limit


async def reset_rate_limit(r: Redis, key: str) -> None:
    await r.delete(key)


def login_rl_key(email: str) -> str:
    return f"login_attempts:{email}"


def reset_rl_key(email: str) -> str:
    return f"pwreset_attempts:{email}"


# ---------- Сброс пароля ----------


def _reset_key(token: str) -> str:
    return "pwreset:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_reset_token(r: Redis, user_id: uuid.UUID) -> str:
    token = secrets.token_urlsafe(32)
    await r.set(_reset_key(token), str(user_id), ex=RESET_TTL_SEC)
    return token


async def consume_reset_token(r: Redis, token: str) -> uuid.UUID | None:
    stored = await r.getdel(_reset_key(token))
    if not stored:
        return None
    try:
        return uuid.UUID(stored)
    except ValueError:
        return None


# ---------- Привязка Telegram ----------


def _tg_key(code: str) -> str:
    return f"tglink:{code}"


async def create_tg_code(r: Redis, user_id: uuid.UUID) -> str:
    for _ in range(10):
        code = f"{secrets.randbelow(1_000_000):06d}"
        if await r.set(_tg_key(code), str(user_id), ex=TG_CODE_TTL_SEC, nx=True):
            return code
    raise RuntimeError("Не удалось сгенерировать код привязки")


async def consume_tg_code(r: Redis, code: str) -> uuid.UUID | None:
    stored = await r.getdel(_tg_key(code))
    if not stored:
        return None
    try:
        return uuid.UUID(stored)
    except ValueError:
        return None
