import hashlib
import jwt
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from config import Config
from models import User, Company, AuditLog
from passlib.context import CryptContext
import redis.asyncio as redis
import asyncio
import secrets

logger = logging.getLogger("auth-service")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthError(Exception):
    pass

class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.redis = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)
        self.current_secret = Config.JWT_SECRET
        self.old_secret = None
        self.rotation_interval = Config.JWT_ROTATION_INTERVAL
        self.max_login_attempts = Config.MAX_LOGIN_ATTEMPTS
        self.lockout_duration = Config.LOCKOUT_DURATION
        asyncio.create_task(self.rotate_keys_periodically())

    async def rotate_keys_periodically(self):
        """Периодическая смена JWT_SECRET."""
        while True:
            await asyncio.sleep(self.rotation_interval)
            self.old_secret = self.current_secret
            self.current_secret = hashlib.sha256(f"{datetime.utcnow()}{Config.JWT_SECRET}".encode()).hexdigest()
            logger.info("JWT_SECRET rotated")
            await self.redis.set("jwt_old_secret", self.old_secret, ex=self.rotation_interval * 2)

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def _generate_token(self, user_id: str, role: str, expires_delta: int) -> str:
        payload = {
            "sub": user_id,
            "role": role,
            "exp": datetime.utcnow() + timedelta(seconds=expires_delta),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.current_secret, algorithm="HS256")

    def _verify_token(self, token: str) -> dict:
        """Проверка токена с учетом текущего и старого ключа."""
        try:
            return jwt.decode(token, self.current_secret, algorithms=["HS256"])
        except jwt.JWTError:
            if self.old_secret:
                try:
                    return jwt.decode(token, self.old_secret, algorithms=["HS256"])
                except jwt.JWTError as e:
                    logger.error(f"Token verification failed: {str(e)}")
                    raise AuthError("Неверный или просроченный токен")
            raise AuthError("Неверный или просроченный токен")

    async def _log_audit(self, user_id: str, action: str):
        """Логирование действий пользователя."""
        audit_log = AuditLog(user_id=user_id, action=action, timestamp=datetime.utcnow())
        self.db.add(audit_log)
        self.db.commit()

    async def _check_login_attempts(self, email: str) -> bool:
        """Проверка количества попыток входа."""
        key = f"login_attempts:{email}"
        attempts = await self.redis.get(key)
        if attempts and int(attempts) >= self.max_login_attempts:
            logger.warning(f"Login locked for {email}")
            return False
        return True

    async def _increment_login_attempts(self, email: str):
        """Увеличение счетчика попыток входа."""
        key = f"login_attempts:{email}"
        attempts = await self.redis.get(key)
        if attempts:
            await self.redis.incr(key)
        else:
            await self.redis.set(key, 1, ex=self.lockout_duration)

    async def _reset_login_attempts(self, email: str):
        """Сброс счетчика попыток входа."""
        key = f"login_attempts:{email}"
        await self.redis.delete(key)

    async def register(self, email: str, password: str, company_name: str, inn: str, role: str = "user") -> Tuple[str, str, str]:
        """Регистрация нового пользователя и компании."""
        if self.db.query(User).filter(User.email == email).first():
            raise AuthError("Email уже зарегистрирован")
        if self.db.query(Company).filter(Company.inn == inn).first():
            raise AuthError("ИНН уже используется")

        hashed_password = self._hash_password(password)
        company = Company(name=company_name, inn=inn)
        self.db.add(company)
        self.db.flush()
        user = User(email=email, password_hash=hashed_password, company_id=company.company_id, role=role)
        self.db.add(user)
        self.db.commit()

        user_id = str(user.user_id)
        token = self._generate_token(user_id, user.role, Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, user.role, Config.REFRESH_TOKEN_EXPIRY)
        profile = {"user_id": user_id, "email": email, "company_name": company_name, "inn": inn, "role": role}
        await self._cache_profile(user_id, profile)
        await self._log_audit(user_id, f"User registered with role {role}")
        logger.info(f"Пользователь зарегистрирован: {email}, роль: {role}")
        return user_id, token, refresh_token

    async def login(self, email: str, password: str) -> Tuple[str, str, str, str]:
        """Аутентификация с учетом ограничения попыток, аудита и CSRF."""
        if not await self._check_login_attempts(email):
            raise AuthError("Слишком много неудачных попыток входа. Попробуйте позже.")

        user = self.db.query(User).filter(User.email == email).first()
        if not user or not self._verify_password(password, user.password_hash):
            await self._increment_login_attempts(email)
            await self._log_audit(user.user_id if user else "unknown", f"Failed login attempt for {email}")
            raise AuthError("Неверный email или пароль")

        await self._reset_login_attempts(email)
        user_id = str(user.user_id)
        token = self._generate_token(user_id, user.role, Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, user.role, Config.REFRESH_TOKEN_EXPIRY)
        csrf_token = await self.generate_csrf_token(user_id)
        await self._log_audit(user_id, "Successful login")
        logger.info(f"Пользователь вошел: {email}")
        return user_id, token, refresh_token, csrf_token

    async def logout(self, token: str) -> None:
        """Выход пользователя с добавлением токена в черный список."""
        user_id, _ = self._verify_token(token)
        await self.redis.set(f"blacklist:{token}", "1", ex=Config.JWT_EXPIRY)
        await self._log_audit(user_id, "Logout")
        logger.info("Пользователь вышел")

    async def refresh_token(self, refresh_token: str) -> Tuple[str, str]:
        """Обновление токена доступа."""
        try:
            payload = self._verify_token(refresh_token)
            user_id = payload["sub"]
            role = payload["role"]
            user = self.db.query(User).filter(User.user_id == user_id).first()
            if not user:
                raise AuthError("Пользователь не найден")
            new_token = self._generate_token(user_id, role, Config.JWT_EXPIRY)
            new_refresh_token = self._generate_token(user_id, role, Config.REFRESH_TOKEN_EXPIRY)
            await self._log_audit(user_id, "Token refreshed")
            logger.info(f"Токен обновлен для пользователя: {user_id}")
            return new_token, new_refresh_token
        except jwt.JWTError as e:
            logger.error(f"Неверный refresh token: {str(e)}")
            raise AuthError("Неверный refresh token")

    async def get_profile(self, user_id: str) -> Dict:
        """Получение профиля пользователя."""
        cached_profile = await self.redis.get(f"profile:{user_id}")
        if cached_profile:
            logger.info(f"Профиль получен из кэша для {user_id}")
            return json.loads(cached_profile)

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            logger.error(f"Профиль не найден для {user_id}")
            raise AuthError("Пользователь не найден")
        company = self.db.query(Company).filter(Company.company_id == user.company_id).first()
        profile = {
            "user_id": str(user.user_id),
            "email": user.email,
            "company_name": company.name,
            "inn": company.inn,
            "role": user.role,
            "editable": user.role == "admin"
        }
        if user.role == "user":
            profile.pop("company_name")
            profile.pop("inn")
            profile["tasks_endpoint"] = "/tasks/my"
        await self._cache_profile(user_id, profile)
        return profile

    async def update_profile(self, user_id: str, email: Optional[str] = None, company_name: Optional[str] = None, inn: Optional[str] = None) -> Dict:
        """Обновление профиля пользователя."""
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            logger.error(f"Не удалось обновить профиль: пользователь {user_id} не найден")
            raise AuthError("Пользователь не найден")
        company = self.db.query(Company).filter(Company.company_id == user.company_id).first()

        if email and email != user.email and self.db.query(User).filter(User.email == email).first():
            raise AuthError("Email уже используется")
        if inn and inn != company.inn and self.db.query(Company).filter(Company.inn == inn).first():
            raise AuthError("ИНН уже используется")

        if email:
            user.email = email
        if company_name:
            company.name = company_name
        if inn:
            company.inn = inn
        self.db.commit()
        await self.redis.delete(f"profile:{user_id}")
        await self._log_audit(user_id, "Profile updated")
        logger.info(f"Профиль обновлен для пользователя {user_id}")
        return await self.get_profile(user_id)

    async def delete_user(self, user_id: str, requester_id: str) -> None:
        """Удаление пользователя."""
        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        target = self.db.query(User).filter(User.user_id == user_id).first()
        if not target:
            logger.error(f"Не удалось удалить: пользователь {user_id} не найден")
            raise AuthError("Пользователь не найден")
        if requester.role not in ["super_admin", "admin"] or (requester.role == "admin" and target.role in ["admin", "super_admin"]):
            logger.error(f"Нет прав для {requester_id} на удаление {user_id}")
            raise AuthError("Нет прав")
        self.db.delete(target)
        self.db.commit()
        await self.redis.delete(f"profile:{user_id}")
        await self._log_audit(requester_id, f"User {user_id} deleted")
        logger.info(f"Пользователь {user_id} удален пользователем {requester_id}")

    async def superadmin_report(self, requester_id: str, period: str) -> Dict:
        """Генерация отчета для SuperAdmin."""
        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        if not requester or requester.role != "super_admin":
            raise AuthError("Требуется роль SuperAdmin")

        time_filter = {
            "day": func.date_trunc("day", User.created_at) == func.current_date(),
            "month": func.date_trunc("month", User.created_at) == func.date_trunc("month", func.current_date()),
            "year": func.date_trunc("year", User.created_at) == func.date_trunc("year", func.current_date())
        }[period]

        stats = {
            "users": self.db.query(User).filter(time_filter).count(),
            "companies": self.db.query(Company).filter(time_filter).count(),
            "transactions": self.db.query(User).filter(User.role != "super_admin", time_filter).count() * 1000
        }
        await self._log_audit(requester_id, f"SuperAdmin report generated for {period}")
        return stats

    def generate_report(self, requester_id: str, period: str) -> Dict:
        """Генерация отчета для SuperAdmin (устаревший метод)."""
        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        if not requester or requester.role != "super_admin":
            logger.error(f"Нет прав для {requester_id} на генерацию отчета")
            raise AuthError("Нет прав")

        if period not in ["day", "month", "year"]:
            raise ValueError("Неверный период")
        time_filter = {
            "day": func.date_trunc("day", User.created_at) == func.current_date(),
            "month": func.date_trunc("month", User.created_at) == func.date_trunc("month", func.current_date()),
            "year": func.date_trunc("year", User.created_at) == func.date_trunc("year", func.current_date())
        }[period]

        companies_count = self.db.query(Company).filter(time_filter).count()
        users_count = self.db.query(User).filter(time_filter).count()
        admins_count = self.db.query(User).filter(User.role == "admin", time_filter).count()
        report = {
            "period": period,
            "companies_registered": companies_count,
            "users_registered": users_count,
            "admins_registered": admins_count
        }
        logger.info(f"Отчет сгенерирован для {requester_id}: {report}")
        return report

    async def generate_csrf_token(self, user_id: str) -> str:
        """Генерация CSRF-токена."""
        csrf_token = secrets.token_hex(16)
        await self.redis.set(f"csrf:{user_id}", csrf_token, ex=3600)
        return csrf_token

    async def verify_csrf_token(self, user_id: str, csrf_token: str) -> bool:
        """Проверка CSRF-токена."""
        stored_token = await self.redis.get(f"csrf:{user_id}")
        return stored_token == csrf_token

    async def _cache_profile(self, user_id: str, profile: Dict, ttl: int = 600) -> None:
        await self.redis.set(f"profile:{user_id}", json.dumps(profile), ex=ttl)

    async def get_current_user(self, token: str) -> Tuple[str, str]:
        """Получение текущего пользователя из токена с проверкой черного списка."""
        if await self.redis.get(f"blacklist:{token}"):
            raise AuthError("Токен в черном списке")
        payload = self._verify_token(token)
        return payload["sub"], payload["role"]

    async def close(self) -> None:
        """Закрытие соединения с Redis."""
        await self.redis.close()