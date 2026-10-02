"""Применение миграций Alembic при старте контейнера: `python -m app.migrate`.

Если схема создана прежним `Base.metadata.create_all` (таблицы сервиса есть, а
`alembic_version` нет), базовая ревизия помечается применённой (stamp), затем
выполняется `upgrade head`. Alembic API синхронный, а env.py сам запускает
asyncio.run(...), поэтому команды вызываются вне работающего event loop.
"""

import asyncio
import logging
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings

ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"
BASE_REVISION = "0001_initial"
SERVICE_TABLES = frozenset({"companies", "users", "subscriptions", "payments"})
CONNECT_ATTEMPTS = 15
CONNECT_DELAY_SEC = 2.0

logger = logging.getLogger("migrate")


def _table_names(conn: Connection) -> list[str]:
    return inspect(conn).get_table_names()


async def _existing_tables() -> set[str]:
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(await conn.run_sync(_table_names))
    finally:
        await engine.dispose()


def _wait_for_tables() -> set[str]:
    for attempt in range(1, CONNECT_ATTEMPTS + 1):
        try:
            return asyncio.run(_existing_tables())
        except (OSError, DBAPIError) as exc:
            if attempt == CONNECT_ATTEMPTS:
                raise
            logger.warning("БД недоступна (%s), попытка %d/%d", type(exc).__name__, attempt, CONNECT_ATTEMPTS)
            time.sleep(CONNECT_DELAY_SEC)
    raise RuntimeError("unreachable")


def main() -> None:
    logging.basicConfig(
        level=get_settings().log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    tables = _wait_for_tables()
    cfg = Config(str(ALEMBIC_INI))
    if "alembic_version" not in tables and tables & SERVICE_TABLES:
        logger.info("Схема создана без Alembic — помечаю ревизию %s как применённую", BASE_REVISION)
        command.stamp(cfg, BASE_REVISION)
    command.upgrade(cfg, "head")
    logger.info("Миграции применены")


if __name__ == "__main__":
    main()
