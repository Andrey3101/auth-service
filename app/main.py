import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import text

from app.billing import autorenew_loop
from app.config import get_settings
from app.db import engine
from app.routers import auth, company, internal, subscription, users

settings = get_settings()
logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("auth-service")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Схема БД управляется Alembic (python -m app.migrate перед запуском uvicorn).
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = redis

    renew_task: asyncio.Task[None] | None = None
    if settings.tbank_auto_renew:
        if settings.payments_enabled:
            renew_task = asyncio.create_task(autorenew_loop(redis))
        else:
            logger.warning("TBANK_AUTO_RENEW=true, но T-Bank не настроен — автопродление не запущено")

    logger.info(
        "auth-service запущен (SMTP: %s, T-Bank: %s)",
        "да" if settings.smtp_enabled else "нет",
        "да" if settings.payments_enabled else "нет",
    )
    try:
        yield
    finally:
        if renew_task is not None:
            renew_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renew_task
        await redis.aclose()
        await engine.dispose()


app = FastAPI(title="ClerkAI auth-service", version="2.0.0", lifespan=lifespan)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(company.router)
app.include_router(subscription.router)
app.include_router(internal.router)


@app.exception_handler(RedisError)
async def redis_error_handler(request: Request, exc: RedisError) -> JSONResponse:
    logger.error("Redis недоступен: %s %s (%s)", request.method, request.url.path, exc.__class__.__name__)
    return JSONResponse(status_code=503, content={"detail": "Сервис временно недоступен, повторите позже"})


@app.get("/health")
async def health(request: Request) -> JSONResponse:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Health: БД недоступна (%s)", exc.__class__.__name__)
        return JSONResponse(status_code=503, content={"status": "error", "detail": "База данных недоступна"})
    try:
        await request.app.state.redis.ping()
    except Exception as exc:
        logger.error("Health: Redis недоступен (%s)", exc.__class__.__name__)
        return JSONResponse(status_code=503, content={"status": "error", "detail": "Redis недоступен"})
    return JSONResponse(content={"status": "ok"})
