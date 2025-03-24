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
from services.queue_service import QueueService
import aiohttp
import aio_pika
import re 
import uuid

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
        self.secret_rotation_window = 3600

    def _generate_service_token(self) -> str:
        return self._generate_token("service", "service", Config.JWT_EXPIRY)
    
    async def rotate_keys_periodically(self):
        while True:
            try:
                await asyncio.sleep(self.rotation_interval - self.secret_rotation_window)
                await self.notify_user("all", "email", "JWT secret will rotate in 1 hour, please prepare to re-login", priority=5)
                await asyncio.sleep(self.secret_rotation_window)
                self.old_secret = self.current_secret
                self.current_secret = hashlib.sha256(f"{datetime.utcnow()}{Config.JWT_SECRET}".encode()).hexdigest()
                await self.notify_user("all", "email", "JWT secret rotated, please re-login now", priority=10)
            except Exception as e:
                logger.error(f"Ошибка при ротации ключей: {str(e)}")
                await asyncio.sleep(60)
                

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def _generate_token(self, user_id: str, role: str, expiry: int) -> str:
        payload = {
            "sub": user_id,
            "role": role,
            "exp": datetime.utcnow() + timedelta(seconds=expiry),
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

    async def _log_audit(self, user_id: str, action: str) -> None:
        logger.info(f"Аудит: пользователь {user_id} выполнил действие '{action}'")

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

    async def notify_user(self, user_id: str, method: str, message: str, priority: int = 1) -> None:
        """Уведомление пользователя через RabbitMQ."""
        async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
            channel = await connection.channel()
            await channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps({
                        "type": "notify_user",
                        "data": {"user_id": user_id, "method": method, "message": message, "priority": priority}
                    }).encode()
                ),
                routing_key="notifications_queue"
            )
        logger.info(f"Уведомление отправлено пользователю {user_id}: {message}")

    async def register(self, email: str, password: str, phone: str, company_type: str, company_data: Dict) -> Tuple[str, str, str]:
        """Регистрация пользователя с учетом типа компании и дополнительных проверок."""
        if self.db.query(User).filter(User.email == email).first():
            raise AuthError("Пользователь с таким email уже существует")

        # Валидация телефона
        if not re.match(r"^\+7\(\d{3}\)\s\d{3}-\d{2}-\d{2}$", phone):
            raise AuthError("Неверный формат телефона. Используйте +7(XXX) XXX-XX-XX")

        # Маппинг типов компаний
        company_type_map = {
            "Самозанятый": "self_employed",
            "ИП": "ip",
            "ООО": "ooo"
        }
        company_type = company_type_map.get(company_type, company_type)

        # Валидация и создание компании
        if company_type == "self_employed":
            inn = company_data.get("inn")
            if inn and (len(inn) != 12 or not inn.isdigit()):
                raise AuthError("ИНН должен содержать 12 цифр")
            company = Company(
                name=f"Самозанятый {email.split('@')[0]}",
                company_type="self_employed",
                inn=inn if inn else None
            )
        elif company_type == "ip":
            inn = company_data.get("inn")
            ogrnip = company_data.get("ogrnip")
            if not (inn and len(inn) == 12 and inn.isdigit() and ogrnip and len(ogrnip) == 15 and ogrnip.isdigit()):
                raise AuthError("ИНН (12 цифр) и ОГРНИП (15 цифр) обязательны и должны быть числовыми")
            if self.db.query(Company).filter(Company.ogrnip == ogrnip, Company.company_type == "ip").first():
                raise AuthError("ОГРНИП уже зарегистрирован для ИП")
            company = Company(
                name=f"ИП {email.split('@')[0]}",
                company_type="ip",
                inn=inn,
                ogrnip=ogrnip
            )
        elif company_type == "ooo":
            company_name = company_data.get("company_name")
            inn = company_data.get("inn")
            ogrn = company_data.get("ogrn")
            if not (company_name and len(company_name) <= 100 and inn and len(inn) == 10 and inn.isdigit() and ogrn and len(ogrn) == 13 and ogrn.isdigit()):
                raise AuthError("Название компании (макс. 100 символов), ИНН (10 цифр) и ОГРН (13 цифр) обязательны")
            if self.db.query(Company).filter(Company.ogrn == ogrn, Company.company_type == "ooo").first():
                raise AuthError("ОГРН уже зарегистрирован для ООО")
            company = Company(
                name=company_name,
                company_type="ooo",
                inn=inn,
                ogrn=ogrn
            )
        else:
            raise AuthError("Неверный тип компании")

        # Проверка уникальности INN
        if company.inn and self.db.query(Company).filter(Company.inn == company.inn).first():
            raise AuthError("ИНН уже зарегистрирован")

        self.db.add(company)
        self.db.flush()

        # Создание пользователя
        user = User(
            email=email,
            password_hash=self._hash_password(password),
            company_id=company.company_id,
            role="user"
        )
        self.db.add(user)
        self.db.commit()

        user_id = str(user.user_id)
        token = self._generate_token(user_id, "user", Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, "user", Config.REFRESH_TOKEN_EXPIRY)

        # Отправка уведомления
        await self.queue.send_notification(user_id, f"Ваш код верификации: {secrets.token_hex(3)}")
    
        async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
            channel = await connection.channel()
            await channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps({
                        "type": "create_onboarding_tasks",
                        "data": {
                            "user_id": user_id,
                            "company_type": company_type
                        }
                    }).encode()
                ),
                routing_key="task_queue"
            )
        logger.info(f"Запрос на создание онбординг-задач отправлен для {user_id}")

        await self._log_audit(user_id, f"Registered as {company_type}")
        return user_id, token, refresh_token

    async def login(self, email: str, password: str) -> Tuple[str, str, str, str]:
        if not await self._check_login_attempts(email):
            raise AuthError("Слишком много неудачных попыток входа. Попробуйте позже.")

        user = self.db.query(User).filter(User.email == email).first()
        if not user or not self._verify_password(password, user.password_hash):
            await self._increment_login_attempts(email)
            user_id = str(user.user_id) if user else "unknown"
            await self._log_audit(user_id, f"Failed login attempt for {email}")
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

    # Обновление get_profile для возврата новых полей
    async def get_profile(self, user_id: str, csrf_token: Optional[str] = None) -> Dict:
        if csrf_token:
            if not await self.verify_csrf_token(user_id, csrf_token):
                raise AuthError("Неверный CSRF-токен")
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
            "company_type": company.company_type,
            "ogrnip": company.ogrnip,
            "ogrn": company.ogrn,
            "role": user.role,
            "editable": user.role == "admin",
            "company_id": str(company.company_id)
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
        """Обрабатывает callback от Google с проверкой уникальности компании."""
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

        id_info = id_token.verify_oauth2_token(
            token_data["id_token"], google_requests.Request(), Config.GOOGLE_CLIENT_ID
        )
        email = id_info["email"]

        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            company_name = f"Google User {email.split('@')[0]}"
            existing_company = self.db.query(Company).filter(Company.name == company_name).first()
            if existing_company:
                company = existing_company
            else:
                company = Company(name=company_name)
                self.db.add(company)
                self.db.flush()
            
            user = User(
                email=email,
                password_hash="",
                company_id=company.company_id,
                role="user"
            )
            self.db.add(user)
            self.db.commit()
            logger.info(f"Создан новый пользователь через Google: {email}")
            
            # Создание онбординг чек-листа через RabbitMQ
            await self._create_onboarding(user.user_id)
        else:
            logger.info(f"Существующий пользователь вошел через Google: {email}")

        user_id = str(user.user_id)
        token = self._generate_token(user_id, user.role, Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, user.role, Config.REFRESH_TOKEN_EXPIRY)
        await self._log_audit(user_id, "Google login")
        return user_id, token, refresh_token
    
    async def _create_onboarding(self, user_id: uuid.UUID):
        """Отправка запроса на создание онбординг чек-листа."""
        async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
            channel = await connection.channel()
            await channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps({"type": "create_onboarding", "data": {"user_id": str(user_id)}}).encode()
                ),
                routing_key="task_queue"
            )
        logger.info(f"Запрос на создание онбординга отправлен для {user_id}")


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
        """Подтверждение сброса пароля с одноразовым токеном."""
        user_id = await self.redis.get(f"reset:{reset_token}")
        if not user_id:
            logger.warning(f"Попытка сброса пароля с неверным или просроченным токеном: {reset_token}")
            raise AuthError("Неверный или просроченный токен сброса пароля")

        used = await self.redis.get(f"reset_used:{reset_token}")
        if used:
            raise AuthError("Токен сброса пароля уже использован")

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            logger.error(f"Пользователь с ID {user_id} не найден при сбросе пароля")
            raise AuthError("Пользователь не найден")

        user.password_hash = self._hash_password(new_password)
        self.db.commit()

        await self.redis.set(f"reset_used:{reset_token}", "1", ex=3600)
        await self.redis.delete(f"reset:{reset_token}")
        
        await self._log_audit(user_id, "Password reset completed")
        logger.info(f"Пароль успешно сброшен для пользователя {user.email}")
        return {"message": "Пароль успешно изменен"}


    async def close(self) -> None:
        await self.redis.close()
        self.queue.close()