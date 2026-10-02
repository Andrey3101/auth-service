import os

# Минимальное окружение для импорта app.config (без БД/Redis — они в юнит-тестах не используются)
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/auth_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET", "test-secret-test-secret-test-secret-0123456789")
os.environ.setdefault("SERVICE_TOKEN", "test-service-token")
