import hashlib
import jwt
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from config import Config
from models import User, Company, AuditLog, Client, Subscription, SubscriptionStatus, Card
from passlib.context import CryptContext
import redis.asyncio as redis
import asyncio
import secrets
import uuid
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger("auth-service")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthError(Exception):
    pass

class AuthService:
    MAX_USERS_PER_COMPANY = 8
    SUBSCRIPTION_AMOUNT = 159  # Стоимость подписки в рублях
    TRIAL_DAYS = 5  # Длительность пробного периода
    RECURRENT_PAYMENT_INTERVAL = 30  # Интервал рекуррентного платежа в днях

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
        self.tbank_api_key = Config.TBANK_API_KEY
        self.tbank_terminal_key = Config.TBANK_TERMINAL_KEY
        self.scheduler = AsyncIOScheduler()
        self.scheduler.start()
        self._schedule_recurrent_payments()

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
        try:
            if asyncio.run(self.redis.get(f"blacklist:{token}")):
                raise AuthError("Токен в черном списке")
            payload = jwt.decode(token, self.current_secret, algorithms=["HS256"])
            return payload
        except jwt.JWTError as e:
            if self.old_secret:
                try:
                    payload = jwt.decode(token, self.old_secret, algorithms=["HS256"])
                    if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]) + timedelta(seconds=self.secret_rotation_window):
                        raise AuthError("Токен слишком старый")
                    return payload
                except jwt.JWTError:
                    logger.error(f"Ошибка проверки токена с обоими ключами: {str(e)}")
                    raise AuthError("Неверный или просроченный токен")
            logger.error(f"Ошибка проверки токена: {str(e)}")
            raise AuthError("Неверный или просроченный токен")

    async def _log_audit(self, user_id: str, action: str, details: Optional[Dict] = None):
        """Логирование действий пользователя."""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                details=details or {},
                timestamp=datetime.utcnow()
            )
            self.db.add(audit_log)
            self.db.commit()
        except Exception as e:
            logger.error(f"Ошибка логирования аудита: {str(e)}")
            self.db.rollback()

    # НОВЫЕ МЕТОДЫ ДЛЯ УПРАВЛЕНИЯ БАНКОВСКИМИ СЧЕТАМИ
    
    async def connect_bank_account(self, user_id: str, bank_name: str, account_number: str, account_type: str) -> str:
        """Подключение банковского счета пользователя."""
        try:
            # Проверяем, не подключен ли уже этот счет
            existing_connection = self.db.query(Card).filter(
                Card.user_id == user_id,
                Card.bank_name == bank_name,
                Card.account_number == account_number
            ).first()
            
            if existing_connection:
                raise AuthError("Этот банковский счет уже подключен")
            
            # Создаем новое подключение
            connection = Card(
                user_id=user_id,
                bank_name=bank_name,
                account_number=account_number,
                account_type=account_type,
                status="active",
                connected_at=datetime.utcnow()
            )
            
            self.db.add(connection)
            self.db.commit()
            self.db.refresh(connection)
            
            await self._log_audit(user_id, f"Connected bank account {bank_name}:{account_number}")
            logger.info(f"User {user_id} connected bank account {bank_name}:{account_number}")
            
            return str(connection.id)
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Ошибка подключения банковского счета: {str(e)}")
            raise AuthError(f"Не удалось подключить банковский счет: {str(e)}")
    
    async def get_bank_accounts(self, user_id: str) -> List[Dict]:
        """Получение списка подключенных банковских счетов."""
        try:
            accounts = self.db.query(Card).filter(
                Card.user_id == user_id,
                Card.status == "active"
            ).all()
            
            return [
                {
                    "connection_id": str(account.id),
                    "bank_name": account.bank_name,
                    "account_number": account.account_number,
                    "account_type": account.account_type,
                    "status": account.status,
                    "connected_at": account.connected_at.isoformat() if account.connected_at else None
                }
                for account in accounts
            ]
            
        except Exception as e:
            logger.error(f"Ошибка получения банковских счетов: {str(e)}")
            raise AuthError(f"Не удалось получить банковские счета: {str(e)}")
    
    async def disconnect_bank_account(self, user_id: str, connection_id: str) -> None:
        """Отключение банковского счета."""
        try:
            connection = self.db.query(Card).filter(
                Card.id == connection_id,
                Card.user_id == user_id
            ).first()
            
            if not connection:
                raise AuthError("Банковский счет не найден")
            
            connection.status = "disconnected"
            connection.disconnected_at = datetime.utcnow()
            
            self.db.commit()
            
            await self._log_audit(user_id, f"Disconnected bank account {connection.bank_name}:{connection.account_number}")
            logger.info(f"User {user_id} disconnected bank account {connection.bank_name}:{connection.account_number}")
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Ошибка отключения банковского счета: {str(e)}")
            raise AuthError(f"Не удалось отключить банковский счет: {str(e)}")
    
    async def request_bank_connection(self, user_id: str, bank_name: str, account_number: str, account_type: str) -> str:
        """Отправка запроса в банк для подключения счета."""
        try:
            # Создаем запрос на подключение
            connection_request = Card(
                user_id=user_id,
                bank_name=bank_name,
                account_number=account_number,
                account_type=account_type,
                status="pending",
                connection_requested_at=datetime.utcnow()
            )
            
            self.db.add(connection_request)
            self.db.commit()
            self.db.refresh(connection_request)
            
            # Отправляем запрос в банк через очередь
            await self.queue.send_message("bank_queue", {
                "type": "connection_request",
                "data": {
                    "request_id": str(connection_request.id),
                    "user_id": user_id,
                    "bank_name": bank_name,
                    "account_number": account_number,
                    "account_type": account_type
                }
            })
            
            await self._log_audit(user_id, f"Requested bank connection {bank_name}:{account_number}")
            logger.info(f"User {user_id} requested bank connection {bank_name}:{account_number}")
            
            return str(connection_request.id)
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Ошибка отправки запроса в банк: {str(e)}")
            raise AuthError(f"Не удалось отправить запрос в банк: {str(e)}")
    
    async def get_bank_connection_status(self, user_id: str, request_id: str) -> Dict:
        """Получение статуса запроса на подключение банковского счета."""
        try:
            connection_request = self.db.query(Card).filter(
                Card.id == request_id,
                Card.user_id == user_id
            ).first()
            
            if not connection_request:
                raise AuthError("Запрос на подключение не найден")
            
            return {
                "request_id": str(connection_request.id),
                "status": connection_request.status,
                "bank_name": connection_request.bank_name,
                "account_number": connection_request.account_number,
                "created_at": connection_request.connection_requested_at.isoformat() if connection_request.connection_requested_at else None,
                "updated_at": connection_request.updated_at.isoformat() if connection_request.updated_at else None
            }
            
        except Exception as e:
            logger.error(f"Ошибка получения статуса подключения: {str(e)}")
            raise AuthError(f"Не удалось получить статус подключения: {str(e)}")

    async def _check_login_attempts(self, email: str) -> bool:
        key = f"login_attempts:{email}"
        attempts = await self.redis.get(key)
        if attempts and int(attempts) >= self.max_login_attempts:
            logger.warning(f"Login locked for {email}")
            return False
        return True

    async def _increment_login_attempts(self, email: str):
        key = f"login_attempts:{email}"
        attempts = await self.redis.get(key)
        if attempts:
            await self.redis.incr(key)
        else:
            await self.redis.set(key, 1, ex=self.lockout_duration)

    async def _reset_login_attempts(self, email: str):
        key = f"login_attempts:{email}"
        await self.redis.delete(key)

    async def notify_user(self, user_id: str, method: str, message: str, priority: int = 1) -> None:
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
        if self.db.query(User).filter(User.email == email).first():
            raise AuthError("Пользователь с таким email уже существует")

        if not re.match(r"^\+7\(\d{3}\)\s\d{3}-\d{2}-\d{2}$", phone):
            raise AuthError("Неверный формат телефона. Используйте +7(XXX) XXX-XX-XX")

        company_type_map = {
            "Самозанятый": "self_employed",
            "ИП": "ip",
            "ООО": "ooo"
        }
        company_type = company_type_map.get(company_type, company_type)

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

        if company.inn and self.db.query(Company).filter(Company.inn == company.inn).first():
            raise AuthError("ИНН уже зарегистрирован")

        self.db.add(company)
        self.db.flush()

        user_count = self.db.query(User).filter(User.company_id == company.company_id).count()
        if user_count >= self.MAX_USERS_PER_COMPANY:
            self.db.rollback()
            raise AuthError(f"Достигнут лимит пользователей ({self.MAX_USERS_PER_COMPANY}) для этой компании")

        user = User(
            email=email,
            password_hash=self._hash_password(password),
            company_id=company.company_id,
            role="user"
        )
        self.db.add(user)

        subscription = Subscription(
            company_id=company.company_id,
            status=SubscriptionStatus.TRIAL,
            trial_start=func.now(),
            trial_end=func.now() + timedelta(days=self.TRIAL_DAYS)
        )
        self.db.add(subscription)
        self.db.commit()

        user_id = str(user.user_id)
        token = self._generate_token(user_id, "user", Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, "user", Config.REFRESH_TOKEN_EXPIRY)

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

    async def create_user_in_company(self, requester_id: str, company_id: str, email: str, password: str, role: str) -> Tuple[str, str, str]:
        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        if not requester:
            raise AuthError("Запросивший пользователь не найден")
        if requester.role != "admin" or requester.company_id != company_id:
            raise AuthError("Только администратор компании может создавать пользователей")

        company = self.db.query(Company).filter(Company.company_id == company_id).first()
        if not company:
            raise AuthError("Компания не найдена")

        user_count = self.db.query(User).filter(User.company_id == company_id).count()
        if user_count >= self.MAX_USERS_PER_COMPANY:
            raise AuthError(f"Достигнут лимит пользователей ({self.MAX_USERS_PER_COMPANY}) для этой компании")

        if self.db.query(User).filter(User.email == email).first():
            raise AuthError("Пользователь с таким email уже существует")

        user = User(
            email=email,
            password_hash=self._hash_password(password),
            company_id=company_id,
            role=role if role in ["user", "manager"] else "user"
        )
        self.db.add(user)
        self.db.commit()

        user_id = str(user.user_id)
        token = self._generate_token(user_id, user.role, Config.JWT_EXPIRY)
        refresh_token = self._generate_token(user_id, user.role, Config.REFRESH_TOKEN_EXPIRY)

        await self.queue.send_notification(user_id, f"Вы были добавлены в компанию {company.name}. Ваш email: {email}")

        await self._log_audit(requester_id, f"Created user {user_id} in company {company_id}")
        logger.info(f"Пользователь {user_id} создан в компании {company_id} администратором {requester_id}")
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
        user_id, _ = self._verify_token(token)
        await self.redis.set(f"blacklist:{token}", "1", ex=Config.JWT_EXPIRY)
        await self._log_audit(user_id, "Logout")
        logger.info("Пользователь вышел")

    async def refresh_token(self, refresh_token: str) -> Tuple[str, str]:
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
        subscription = self.db.query(Subscription).filter(Subscription.company_id == user.company_id).first()
        card = self.db.query(Card).filter(Card.company_id == user.company_id).first()

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
            "company_id": str(company.company_id),
            "subscription_status": subscription.status.value if subscription else "none",
            "trial_end": subscription.trial_end.isoformat() if subscription and subscription.trial_end else None,
            "attachedCard": {
                "card_id": str(card.card_id),
                "last4": card.last4,
                "brand": card.brand
            } if card else None
        }
        ttl = 3600 if user.role == "user" else 300
        await self._cache_profile(user_id, profile, ttl)
        return profile

    async def update_profile(self, user_id: str, email: Optional[str] = None, company_name: Optional[str] = None, inn: Optional[str] = None) -> Dict:
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
            "subscriptions_active": self.db.query(Subscription).filter(Subscription.status == SubscriptionStatus.ACTIVE, time_filter).count(),
            "subscriptions_trial": self.db.query(Subscription).filter(Subscription.status == SubscriptionStatus.TRIAL, time_filter).count()
        }
        await self._log_audit(requester_id, f"SuperAdmin report generated for {period}")
        return stats

    def generate_report(self, requester_id: str, period: str) -> Dict:
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
        csrf_token = secrets.token_hex(16)
        await self.redis.set(f"csrf:{user_id}", csrf_token, ex=3600)
        return csrf_token

    async def verify_csrf_token(self, user_id: str, csrf_token: str) -> bool:
        stored_token = await self.redis.get(f"csrf:{user_id}")
        return stored_token == csrf_token

    async def _cache_profile(self, user_id: str, profile: Dict, ttl: int = 600) -> None:
        await self.redis.set(f"profile:{user_id}", json.dumps(profile), ex=ttl)

    async def delete_company(self, requester_id: str, company_id: str):
        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        if not requester:
            raise AuthError("Пользователь не найден")
        if requester.role not in ["admin", "super_admin"]:
            raise AuthError("Требуются права admin или super_admin")
        if requester.role == "admin" and requester.company_id != company_id:
            raise AuthError("Вы можете удалить только свою компанию")

        company = self.db.query(Company).filter(Company.company_id == company_id).first()
        if not company:
            raise AuthError("Компания не найдена")

        users = self.db.query(User).filter(User.company_id == company_id).all()
        if not users:
            raise AuthError("Пользователи компании не найдены")

        for user in users:
            await self.redis.delete(f"csrf:{user.user_id}")
            await self.redis.delete(f"login_attempts:{user.user_id}")
            self.db.delete(user)

        self.db.delete(company)
        self.db.commit()

        await self._log_audit(requester_id, f"Deleted company {company_id} and all its users")
        logger.info(f"Компания {company_id} и все связанные пользователи удалены пользователем {requester_id}")

    async def update_user(self, user_id: str, requester_id: str, email: str, role: str) -> Dict:
        target_user = self.db.query(User).filter(User.user_id == user_id).first()
        if not target_user:
            logger.error(f"Пользователь {user_id} не найден для обновления")
            raise AuthError("Пользователь не найден")

        requester = self.db.query(User).filter(User.user_id == requester_id).first()
        if not requester:
            raise AuthError("Запросивший пользователь не найден")

        if requester.role not in ["admin", "super_admin"]:
            raise AuthError("Требуются права admin или super_admin")

        if requester.role == "admin" and requester.company_id != target_user.company_id:
            raise AuthError("Вы можете обновлять только пользователей своей компании")

        if requester.role == "admin" and role in ["admin", "super_admin"]:
            raise AuthError("Администратор не может назначить роль admin или super_admin")

        if email != target_user.email and self.db.query(User).filter(User.email == email).first():
            raise AuthError("Email уже используется другим пользователем")

        target_user.email = email
        target_user.role = role if role in ["user", "manager", "admin"] else target_user.role
        self.db.commit()

        await self.redis.delete(f"profile:{user_id}")

        await self._log_audit(requester_id, f"Updated user {user_id} (email: {email}, role: {role})")
        logger.info(f"Пользователь {user_id} обновлён пользователем {requester_id}: email={email}, role={role}")

        return {
            "user_id": str(target_user.user_id),
            "email": target_user.email,
            "role": target_user.role
        }

    async def get_current_user(self, token: str) -> Tuple[str, str]:
        if await self.redis.get(f"blacklist:{token}"):
            raise AuthError("Токен в черном списке")
        payload = self._verify_token(token)
        return payload["sub"], payload["role"]

    async def add_client(
        self,
        user_id: str,
        company_id: str,
        name: str,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        amount: Optional[int] = None,
        description: Optional[str] = None
    ) -> Dict:
        await self._check_subscription_status(company_id)

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or user.company_id != company_id:
            raise AuthError("У вас нет прав добавлять клиентов в эту компанию")

        client = Client(
            company_id=company_id,
            user_id=user_id,
            name=name,
            phone=phone,
            email=email,
            amount=amount,
            description=description
        )
        self.db.add(client)
        self.db.commit()

        await self._log_audit(user_id, f"Added client {client.client_id}")
        logger.info(f"Клиент {name} добавлен пользователем {user_id}")

        return {
            "client_id": str(client.client_id),
            "company_id": client.company_id,
            "user_id": client.user_id,
            "name": client.name,
            "phone": client.phone,
            "email": client.email,
            "amount": client.amount,
            "description": client.description,
            "created_at": client.created_at.isoformat(),
            "updated_at": client.updated_at.isoformat()
        }

    async def get_clients(
        self,
        user_id: str,
        name: Optional[str] = None,
        amount_min: Optional[int] = None,
        amount_max: Optional[int] = None
    ) -> list[Dict]:
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise AuthError("Пользователь не найден")

        query = self.db.query(Client).filter(Client.company_id == user.company_id)

        if name:
            query = query.filter(Client.name.ilike(f"%{name}%"))

        if amount_min is not None:
            query = query.filter(Client.amount >= amount_min)
        if amount_max is not None:
            query = query.filter(Client.amount <= amount_max)

        if amount_min is not None or amount_max is not None:
            query = query.filter(Client.amount.isnot(None))

        clients = query.all()
        result = [{
            "client_id": str(c.client_id),
            "company_id": c.company_id,
            "user_id": c.user_id,
            "name": c.name,
            "phone": c.phone,
            "email": c.email,
            "amount": c.amount,
            "description": c.description,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat()
        } for c in clients]

        logger.info(f"Получено {len(result)} клиентов для user_id={user_id} с фильтрами name={name}, amount_min={amount_min}, amount_max={amount_max}")
        return result

    async def update_client(
        self,
        client_id: str,
        user_id: str,
        name: str,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        amount: Optional[int] = None,
        description: Optional[str] = None
    ) -> Dict:
        await self._check_subscription_status((self.db.query(User).filter(User.user_id == user_id).first()).company_id)

        client = self.db.query(Client).filter(Client.client_id == uuid.UUID(client_id)).first()
        if not client:
            raise AuthError("Клиент не найден")

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or client.company_id != user.company_id:
            raise AuthError("У вас нет прав обновлять этого клиента")

        client.name = name
        client.phone = phone
        client.email = email
        client.amount = amount
        client.description = description
        self.db.commit()

        await self._log_audit(user_id, f"Updated client {client_id}")
        logger.info(f"Клиент {client_id} обновлён пользователем {user_id}")

        return {
            "client_id": str(client.client_id),
            "company_id": client.company_id,
            "user_id": client.user_id,
            "name": client.name,
            "phone": client.phone,
            "email": client.email,
            "amount": client.amount,
            "description": client.description,
            "created_at": client.created_at.isoformat(),
            "updated_at": client.updated_at.isoformat()
        }

    async def delete_client(self, client_id: str, user_id: str):
        await self._check_subscription_status((self.db.query(User).filter(User.user_id == user_id).first()).company_id)

        client = self.db.query(Client).filter(Client.client_id == uuid.UUID(client_id)).first()
        if not client:
            raise AuthError("Клиент не найден")

        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or client.company_id != user.company_id:
            raise AuthError("У вас нет прав удалять этого клиента")

        self.db.delete(client)
        self.db.commit()

        await self._log_audit(user_id, f"Deleted client {client_id}")
        logger.info(f"Клиент {client_id} удалён пользователем {user_id}")

    async def request_password_reset(self, email: str):
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"Попытка сброса пароля для несуществующего email: {email}")
            raise AuthError("Пользователь с таким email не найден")

        reset_token = secrets.token_urlsafe(32)
        await self.redis.set(f"reset:{reset_token}", user.user_id, ex=3600)
        reset_link = f"{Config.APP_URL}/reset-password/confirm?token={reset_token}"

        await self.queue.send_notification(
            user.user_id,
            f"Для сброса пароля перейдите по ссылке: {reset_link}"
        )

        await self._log_audit(user.user_id, f"Password reset requested for {email}")
        logger.info(f"Запрос на сброс пароля отправлен для {email}")
        return {"message": "Ссылка для сброса пароля отправлена на ваш email"}

    async def confirm_password_reset(self, reset_token: str, new_password: str) -> Dict:
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

    async def _check_subscription_status(self, company_id: str) -> None:
        subscription = self.db.query(Subscription).filter(Subscription.company_id == company_id).first()
        if not subscription:
            raise AuthError("Подписка не найдена")

        if subscription.status == SubscriptionStatus.TRIAL:
            if datetime.utcnow() > subscription.trial_end:
                subscription.status = SubscriptionStatus.EXPIRED
                self.db.commit()
                raise AuthError("Пробный период истек. Пожалуйста, оформите подписку.")
        elif subscription.status != SubscriptionStatus.ACTIVE:
            raise AuthError("Подписка не активна. Пожалуйста, оформите подписку.")

    async def attach_card(self, user_id: str, company_id: str, card_number: str, expiry: str, cvc: str) -> Dict:
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or user.company_id != company_id:
            raise AuthError("У вас нет прав для прикрепления карты в этой компании")
        if user.role != "admin":
            raise AuthError("Только администратор может прикреплять карту")

        existing_card = self.db.query(Card).filter(Card.company_id == company_id).first()
        if existing_card:
            raise AuthError("Карта уже прикреплена. Сначала открепите существующую карту.")

        async with aiohttp.ClientSession() as session:
            payload = {
                "TerminalKey": self.tbank_terminal_key,
                "CustomerKey": str(user.user_id),
                "CardNumber": card_number,
                "ExpDate": expiry.replace("/", ""),
                "CardHolder": user.email.split("@")[0],
                "CVC": cvc
            }
            headers = {"Authorization": f"Bearer {self.tbank_api_key}"}
            async with session.post("https://securepay.tinkoff.ru/v2/AddCard", json=payload, headers=headers) as response:
                result = await response.json()
                if not result.get("Success"):
                    logger.error(f"Ошибка прикрепления карты: {result.get('Message')}")
                    raise AuthError(f"Ошибка прикрепления карты: {result.get('Message')}")

                last4 = card_number[-4:]
                brand = result.get("Brand", "Unknown")

                card = Card(
                    company_id=company_id,
                    last4=last4,
                    brand=brand,
                    tbank_customer_key=str(user.user_id),
                    tbank_card_id=result.get("CardId")
                )
                self.db.add(card)
                self.db.commit()

                await self._log_audit(user_id, f"Card attached for company {company_id}")
                logger.info(f"Карта прикреплена для компании {company_id} пользователем {user_id}")

                return {
                    "card_id": str(card.card_id),
                    "last4": card.last4,
                    "brand": card.brand
                }

    async def detach_card(self, user_id: str, company_id: str, card_id: str) -> None:
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or user.company_id != company_id:
            raise AuthError("У вас нет прав для открепления карты в этой компании")
        if user.role != "admin":
            raise AuthError("Только администратор может откреплять карту")

        card = self.db.query(Card).filter(Card.card_id == uuid.UUID(card_id), Card.company_id == company_id).first()
        if not card:
            raise AuthError("Карта не найдена")

        async with aiohttp.ClientSession() as session:
            payload = {
                "TerminalKey": self.tbank_terminal_key,
                "CardId": card.tbank_card_id,
                "CustomerKey": card.tbank_customer_key
            }
            headers = {"Authorization": f"Bearer {self.tbank_api_key}"}
            async with session.post("https://securepay.tinkoff.ru/v2/RemoveCard", json=payload, headers=headers) as response:
                result = await response.json()
                if not result.get("Success"):
                    logger.error(f"Ошибка открепления карты: {result.get('Message')}")
                    raise AuthError(f"Ошибка открепления карты: {result.get('Message')}")

        subscription = self.db.query(Subscription).filter(Subscription.company_id == company_id).first()
        if subscription and subscription.recurrent_payment_id:
            subscription.recurrent_payment_id = None
            self.db.commit()

        self.db.delete(card)
        self.db.commit()

        await self._log_audit(user_id, f"Card {card_id} detached for company {company_id}")
        logger.info(f"Карта {card_id} откреплена для компании {company_id} пользователем {user_id}")

    async def initiate_subscription_payment(self, user_id: str, company_id: str, card_id: Optional[str] = None) -> Dict:
        user = self.db.query(User).filter(User.user_id == user_id).first()
        if not user or user.company_id != company_id:
            raise AuthError("У вас нет прав для оформления подписки в этой компании")
        if user.role != "admin":
            raise AuthError("Только администратор может оформлять подписку")

        subscription = self.db.query(Subscription).filter(Subscription.company_id == company_id).first()
        if not subscription:
            raise AuthError("Подписка не найдена")

        if subscription.status == SubscriptionStatus.ACTIVE:
            raise AuthError("Подписка уже активна")

        card = None
        if card_id:
            card = self.db.query(Card).filter(Card.card_id == uuid.UUID(card_id), Card.company_id == company_id).first()
            if not card:
                raise AuthError("Карта не найдена")

        async with aiohttp.ClientSession() as session:
            payload = {
                "TerminalKey": self.tbank_terminal_key,
                "Amount": self.SUBSCRIPTION_AMOUNT * 100,
                "OrderId": str(uuid.uuid4()),
                "Description": "Ежемесячная подписка",
                "Recurrent": "Y",
                "CustomerKey": str(user.user_id),
                "Receipt": {
                    "Email": user.email,
                    "Taxation": "usn_income",
                    "Items": [{
                        "Name": "Подписка на сервис",
                        "Price": self.SUBSCRIPTION_AMOUNT * 100,
                        "Quantity": 1,
                        "Amount": self.SUBSCRIPTION_AMOUNT * 100,
                        "Tax": "none"
                    }]
                }
            }
            if card:
                payload["CardId"] = card.tbank_card_id

            headers = {"Authorization": f"Bearer {self.tbank_api_key}"}
            async with session.post("https://securepay.tinkoff.ru/v2/Init", json=payload, headers=headers) as response:
                result = await response.json()
                if not result.get("Success"):
                    logger.error(f"Ошибка инициализации платежа: {result.get('Message')}")
                    raise AuthError(f"Ошибка инициализации платежа: {result.get('Message')}")

                subscription.payment_id = result.get("PaymentId")
                subscription.recurrent_payment_id = result.get("PaymentId") if card else None
                self.db.commit()

                return {
                    "payment_url": result.get("PaymentURL"),
                    "payment_id": result.get("PaymentId")
                }

    async def confirm_subscription_payment(self, payment_id: str) -> Dict:
        async with aiohttp.ClientSession() as session:
            payload = {
                "TerminalKey": self.tbank_terminal_key,
                "PaymentId": payment_id
            }
            headers = {"Authorization": f"Bearer {self.tbank_api_key}"}
            async with session.post("https://securepay.tinkoff.ru/v2/GetState", json=payload, headers=headers) as response:
                result = await response.json()
                if not result.get("Success") or result.get("Status") != "CONFIRMED":
                    logger.error(f"Ошибка подтверждения платежа: {result.get('Message')}")
                    raise AuthError("Платеж не подтвержден")

        subscription = self.db.query(Subscription).filter(Subscription.payment_id == payment_id).first()
        if not subscription:
            raise AuthError("Подписка не найдена")

        subscription.status = SubscriptionStatus.ACTIVE
        subscription.last_payment_date = datetime.utcnow()
        self.db.commit()

        user = self.db.query(User).filter(User.company_id == subscription.company_id).first()
        await self._log_audit(user.user_id, f"Subscription activated for company {subscription.company_id}")
        logger.info(f"Подписка активирована для компании {subscription.company_id}")
        return {"message": "Подписка успешно активирована"}

    async def process_recurrent_payment(self, subscription: Subscription) -> None:
        if not subscription.recurrent_payment_id:
            logger.warning(f"Рекуррентный платеж не настроен для подписки {subscription.subscription_id}")
            return

        card = self.db.query(Card).filter(Card.company_id == subscription.company_id).first()
        if not card:
            logger.error(f"Карта не найдена для компании {subscription.company_id}")
            subscription.status = SubscriptionStatus.EXPIRED
            self.db.commit()
            return

        async with aiohttp.ClientSession() as session:
            payload = {
                "TerminalKey": self.tbank_terminal_key,
                "PaymentId": subscription.recurrent_payment_id,
                "RebillId": str(uuid.uuid4()),
                "Amount": self.SUBSCRIPTION_AMOUNT * 100,
                "Description": "Рекуррентный платеж за подписку",
                "Receipt": {
                    "Email": (self.db.query(User).filter(User.company_id == subscription.company_id).first()).email,
                    "Taxation": "usn_income",
                    "Items": [{
                        "Name": "Подписка на сервис",
                        "Price": self.SUBSCRIPTION_AMOUNT * 100,
                        "Quantity": 1,
                        "Amount": self.SUBSCRIPTION_AMOUNT * 100,
                        "Tax": "none"
                    }]
                }
            }
            headers = {"Authorization": f"Bearer {self.tbank_api_key}"}
            async with session.post("https://securepay.tinkoff.ru/v2/Charge", json=payload, headers=headers) as response:
                result = await response.json()
                if not result.get("Success") or result.get("Status") != "CONFIRMED":
                    logger.error(f"Ошибка рекуррентного платежа: {result.get('Message')}")
                    subscription.status = SubscriptionStatus.EXPIRED
                    self.db.commit()
                    await self.notify_user(
                        (self.db.query(User).filter(User.company_id == subscription.company_id).first()).user_id,
                        "email",
                        "Ошибка рекуррентного платежа. Пожалуйста, проверьте данные карты или прикрепите новую.",
                        priority=10
                    )
                    return

        subscription.last_payment_date = datetime.utcnow()
        subscription.payment_id = result.get("PaymentId")
        self.db.commit()

        user = self.db.query(User).filter(User.company_id == subscription.company_id).first()
        await self._log_audit(user.user_id, f"Recurrent payment processed for company {subscription.company_id}")
        logger.info(f"Рекуррентный платеж обработан для компании {subscription.company_id}")

    def _schedule_recurrent_payments(self):
        async def check_recurrent_payments():
            subscriptions = self.db.query(Subscription).filter(
                Subscription.status == SubscriptionStatus.ACTIVE,
                Subscription.recurrent_payment_id.isnot(None)
            ).all()
            for subscription in subscriptions:
                if subscription.last_payment_date and (datetime.utcnow() - subscription.last_payment_date).days >= self.RECURRENT_PAYMENT_INTERVAL:
                    await self.process_recurrent_payment(subscription)

        self.scheduler.add_job(
            check_recurrent_payments,
            trigger=IntervalTrigger(days=1),
            id="recurrent_payments",
            replace_existing=True
        )
        logger.info("Шедулер рекуррентных платежей запущен")

    async def close(self) -> None:
        self.scheduler.shutdown()
        await self.redis.close()
        self.queue.close()