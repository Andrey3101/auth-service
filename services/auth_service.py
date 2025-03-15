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
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

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
        self.queue = QueueService()
        asyncio.create_task(self.rotate_keys_periodically())

    async def rotate_keys_periodically(self):
        """Периодическая смена JWT_SECRET."""
        while True:
            await asyncio.sleep(self.rotation_interval)
            self.old_secret = self.current_secret
            self.current_secret = hashlib.sha256(f"{datetime.utcnow()}{Config.JWT_SECRET}".encode()).hexdigest()
            await self.notify_user("all", "email", "JWT secret rotated, please re-login within 1 hour", priority=5)

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

    async def _log_audit(self, user_id: str, action: str, ip: str = None, user_agent: str = None):
        """Логирование действий пользователя."""
        audit_log = AuditLog(
            user_id=user_id, 
            action=action, 
            timestamp=datetime.utcnow(), 
            ip=ip, 
            user_agent=user_agent
        )
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

    async def notify_user(self, user_id: str, channel: str, message: str, priority: int = 1):
        async with self.session.post(
            f"{Config.NOTIFICATION_SERVICE_URL}/notifications/send",
            json={"user_id": user_id, "channel": channel, "message": message, "priority": priority},
            headers={"Authorization": f"Bearer {self._generate_service_token()}"}
        ) as resp:
            if resp.status != 200:
                logger.error(f"Failed to send notification: {await resp.text()}")

    async def register(self, email: str, password: str, company_name: str, inn: Optional[str] = None, role: str = "user"):
        user_id, token, refresh_token = await super().register(email, password, company_name, inn, role)
        await notifications_service.send_verification_code(user_id, email)
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
        ttl = 3600 if user.role == "user" else 300
        await self._cache_profile(user_id, profile, ttl)
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

    async def google_login_url(self) -> str:
        """Генерирует URL для авторизации через Google."""
        state = secrets.token_urlsafe(16)
        await self.redis.set(f"oauth_state:{state}", "1", ex=600)
        google_auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={Config.GOOGLE_CLIENT_ID}&"
            f"redirect_uri={Config.GOOGLE_REDIRECT_URI}&"
            "response_type=code&"
            "scope=openid%20email%20profile"
            f"state={state}"
        )
        return google_auth_url

    async def google_callback(self, code: str, state: str) -> Tuple[str, str, str]:
        """Обрабатывает callback от Google и возвращает токены."""
        if not await self.redis.get(f"oauth_state:{state}"):
            raise AuthError("Неверный или просроченный state")
        token_url = "https://oauth2.googleapis.com/token"
        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url,
                data={
                    "code": code,
                    "client_id": Config.GOOGLE_CLIENT_ID,
                    "client_secret": Config.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": Config.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                }
            ) as response:
                token_data = await response.json()
                if "id_token" not in token_data:
                    raise AuthError("Ошибка получения токена от Google")

        # Проверяем id_token и получаем email
        id_info = id_token.verify_oauth2_token(
            token_data["id_token"], google_requests.Request(), Config.GOOGLE_CLIENT_ID
        )
        email = id_info["email"]

        # Проверяем, существует ли пользователь с этой почтой
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            # Создаём нового пользователя с email из Google
            company = Company(name=f"Google User {email.split('@')[0]}")
            self.db.add(company)
            self.db.flush()
            user = User(
                email=email,  # Сохраняем почту из Google
                password_hash="",  # Пустой хэш для Google-пользователей
                company_id=company.company_id,
                role="user"
            )
            self.db.add(user)
            self.db.commit()
            logger.info(f"Создан новый пользователь через Google: {email}")
        else:
            logger.info(f"Существующий пользователь вошел через Google: {email}")

        user_id = str(user.user_id)
        token = self._generate_token(user_id, user.role, Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, user.role, Config.REFRESH_TOKEN_EXPIRY)
        await self._log_audit(user_id, "Google login")
        return user_id, token, refresh_token

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

    async def delete_company(self, user_id: str, company_id: str):
        """Удаление компании по company_id."""
        # Получаем пользователя и проверяем его роль
        user = self.db.query(User).filter_by(user_id=user_id).first()
        if not user or user.role not in ["admin", "super_admin"]:
            raise AuthError("Недостаточно прав для удаления компании")

        # Находим компанию по company_id
        company = self.db.query(Company).filter_by(company_id=company_id).first()
        if not company:
            raise AuthError("Компания не найдена")

        # Удаляем компанию
        self.db.delete(company)
        self.db.commit()

        logger.info(f"Компания {company_id} успешно удалена пользователем {user_id}")

    async def get_current_user(self, token: str) -> Tuple[str, str]:
        """Получение текущего пользователя из токена с проверкой черного списка."""
        if await self.redis.get(f"blacklist:{token}"):
            raise AuthError("Токен в черном списке")
        payload = self._verify_token(token)
        return payload["sub"], payload["role"]
    
    async def request_password_reset(self, email: str):
        """Запрос на сброс пароля с генерацией токена и отправкой ссылки на email."""
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"Попытка сброса пароля для несуществующего email: {email}")
            raise AuthError("Пользователь с таким email не найден")
        
        reset_token = secrets.token_urlsafe(32)
        await self.redis.set(f"reset:{reset_token}", user.user_id, ex=3600)  # Токен действителен 1 час
        reset_link = f"{Config.APP_URL}/reset-password/confirm?token={reset_token}"
        
        # Отправка уведомления через QueueService
        await self.queue.send_notification(
            user.user_id,
            f"Для сброса пароля перейдите по ссылке: {reset_link}"
        )
        
        await self._log_audit(user.user_id, f"Password reset requested for {email}")
        logger.info(f"Запрос на сброс пароля отправлен для {email}")
        return {"message": "Ссылка для сброса пароля отправлена на ваш email"}

    async def confirm_password_reset(self, reset_token: str, new_password: str) -> Dict:
        """Подтверждение сброса пароля с использованием токена."""
        user_id = await self.redis.get(f"reset:{reset_token}")
        if not user_id:
            logger.warning(f"Попытка сброса пароля с неверным или просроченным токеном: {reset_token}")
            raise AuthError("Неверный или просроченный токен сброса пароля")

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            logger.error(f"Пользователь с ID {user_id} не найден при сбросе пароля")
            raise AuthError("Пользователь не найден")

        # Обновляем пароль
        user.password_hash = self._hash_password(new_password)
        self.db.commit()

        # Удаляем токен из Redis после использования
        await self.redis.delete(f"reset:{reset_token}")
        
        await self._log_audit(user_id, "Password reset completed")
        logger.info(f"Пароль успешно сброшен для пользователя {user.email}")
        return {"message": "Пароль успешно изменен"}
    
    async def request_password_reset(self, email: str):
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            raise AuthError("User not found")
        reset_token = secrets.token_urlsafe(32)
        await self.redis.set(f"reset:{reset_token}", user.user_id, ex=3600)
        await self.queue.send_notification(user.user_id, f"Reset link: {Config.APP_URL}/reset-password/confirm?token={reset_token}")
        return {"message": "Reset link sent"}

    async def close(self) -> None:
        """Закрытие соединения с Redis."""
        await self.redis.close()