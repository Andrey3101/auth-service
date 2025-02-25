import os

class Config:
    DB_URL = os.getenv("DB_URL", "postgresql://user:password@localhost:5432/auth")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
    JWT_EXPIRY = int(os.getenv("JWT_EXPIRY", "3600"))  # 1 час
    REFRESH_TOKEN_EXPIRY = int(os.getenv("REFRESH_TOKEN_EXPIRY", "604800"))  # 7 дней
    JWT_SECRET = "your_initial_secret_key"
    JWT_EXPIRY = 3600
    REFRESH_TOKEN_EXPIRY = 604800
    JWT_ROTATION_INTERVAL = 86400
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900