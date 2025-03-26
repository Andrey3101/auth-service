from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from config import Config
from services.auth_service import AuthService, AuthError
from services.queue_service import QueueService
from models import Base
import logging
from typing import Optional, Dict
import aio_pika
import asyncio
import json
from models import User


logger = logging.getLogger("auth-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Сервис Аутентификации",
    description="API для управления пользователями, аутентификации, отчетов и уведомлений.",
    version="1.0.0"
)

engine = create_engine(Config.DB_URL)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    phone: str
    company_type: str = Field(..., regex="^(self_employed|ip|ooo)$")
    company_data: Dict

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    user_id: str
    token: str
    refresh_token: str
    csrf_token: str

class ProfileResponse(BaseModel):
    user_id: str
    email: str
    company_name: str | None = None
    inn: str | None = None
    role: str
    editable: bool = False
    tasks_endpoint: str | None = None

class UpdateProfileRequest(BaseModel):
    email: EmailStr
    company_name: str
    inn: Optional[str] = Field(default=None, pattern=r'^\d{10}$|^\d{12}$')

class ReportRequest(BaseModel):
    period: str

class UpdateUserRequest(BaseModel):
    email: EmailStr
    role: str = Field(..., regex="^(user|manager|admin)$")

class DeleteCompanyRequest(BaseModel):
    company_id: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str

class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = Field(..., regex="^(user|manager)$")

class PayrollResponse(BaseModel):
    id: str
    user_id: str
    period: str
    amount: float
    calculated_at: str

class ClientRequest(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    amount: Optional[int] = None
    description: Optional[str] = None

class ClientResponse(BaseModel):
    client_id: str
    company_id: str
    user_id: Optional[str]
    name: str
    phone: Optional[str]
    email: Optional[str]
    amount: Optional[int]
    description: Optional[str]
    created_at: str
    updated_at: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> tuple[str, str]:
    auth_service = AuthService(db)
    try:
        user_id, role = await auth_service.get_current_user(token)
        return user_id, role
    except AuthError as e:
        logger.error(f"Ошибка аутентификации для токена: {str(e)}")
        raise HTTPException(status_code=401, detail=str(e))

# Убрана зависимость verify_csrf как глобальная, используется только там, где нужна
async def verify_csrf(token: str = Depends(oauth2_scheme), csrf_token: str = Header(...), db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    user_id, _ = await auth_service.get_current_user(token)
    if not await auth_service.verify_csrf_token(user_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return user_id

@app.post("/register", response_model=TokenResponse, summary="Регистрация пользователя")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    try:
        user_id, token, refresh_token = await auth_service.register(
            request.email,
            request.password,
            request.phone,
            request.company_type,
            request.company_data
        )
        queue_service = QueueService()
        await queue_service.send_notification(user_id, f"Добро пожаловать, {request.email}!")
        return TokenResponse(user_id=user_id, token=token, refresh_token=refresh_token, csrf_token="")
    except AuthError as e:
        logger.error(f"Ошибка при регистрации: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Ошибка регистрации: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось зарегистрировать пользователя")

@app.post("/login", response_model=TokenResponse, summary="Вход пользователя")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Аутентификация пользователя с выдачей access, refresh и CSRF токенов."""
    auth_service = AuthService(db)
    try:
        user_id, token, refresh_token, csrf_token = await auth_service.login(request.email, request.password)
        return TokenResponse(user_id=user_id, token=token, refresh_token=refresh_token, csrf_token=csrf_token)
    except AuthError as e:
        logger.error(f"Ошибка входа для {request.email}: {str(e)}")
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/logout", summary="Выход пользователя")
async def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Выход пользователя из системы."""
    auth_service = AuthService(db)
    await auth_service.logout(token)
    return {"message": "Успешный выход"}

@app.post("/companies/{company_id}/users", response_model=TokenResponse, summary="Создание пользователя в компании")
async def create_user_in_company(
    company_id: str,
    request: CreateUserRequest,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    """Создание нового пользователя в указанной компании администратором."""
    requester_id, _ = user_id_role
    auth_service = AuthService(db)
    if not await auth_service.verify_csrf_token(requester_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    try:
        user_id, token, refresh_token = await auth_service.create_user_in_company(
            requester_id,
            company_id,
            request.email,
            request.password,
            request.role
        )
        return TokenResponse(user_id=user_id, token=token, refresh_token=refresh_token, csrf_token="")
    except AuthError as e:
        logger.error(f"Ошибка при создании пользователя в компании {company_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при создании пользователя: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось создать пользователя")

@app.post("/refresh", response_model=TokenResponse, summary="Обновление токена")
async def refresh(refresh_token: str, db: Session = Depends(get_db)):
    """Обновление токена доступа и refresh токена."""
    auth_service = AuthService(db)
    try:
        new_token, new_refresh_token = await auth_service.refresh_token(refresh_token)
        payload = auth_service._verify_token(refresh_token)
        return TokenResponse(user_id=payload["sub"], token=new_token, refresh_token=new_refresh_token, csrf_token="")
    except AuthError as e:
        logger.error(f"Ошибка аутентификации для токена: {str(e)}")
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/leave/request", summary="Запрос на отпуск/больничный")
async def request_leave(
    leave_type: str,
    start_date: str,
    end_date: str,
    user_id_role: tuple = Depends(get_current_user),  # Исправлено на get_current_user
    db: Session = Depends(get_db)
):
    user_id, _ = user_id_role
    async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
        channel = await connection.channel()
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps({
                    "type": "create_leave_request",
                    "data": {
                        "user_id": user_id,
                        "leave_type": leave_type,
                        "start_date": start_date,
                        "end_date": end_date
                    }
                }).encode()
            ),
            routing_key="task_queue"
        )
    return {"message": f"Запрос на {leave_type} отправлен"}

@app.post("/competitors/monitor", summary="Мониторинг конкурентов")
async def monitor_competitors(
    urls: list[str],
    user_id_role: tuple = Depends(get_current_user),  # Исправлено на get_current_user
    db: Session = Depends(get_db)
):
    user_id, _ = user_id_role
    async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
        channel = await connection.channel()
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps({
                    "type": "monitor_competitors",
                    "data": {"user_id": user_id, "urls": urls}
                }).encode()
            ),
            routing_key="ai_queue"
        )
    return {"message": "Мониторинг конкурентов запущен"}

@app.post("/promotion/recommendations", summary="Рекомендации по продвижению")
async def get_promotion_recommendations(
    sales_data: dict,
    competitor_data: dict,
    user_id_role: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id, _ = user_id_role
    async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
        channel = await connection.channel()
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps({
                    "type": "promotion_recommendations",
                    "data": {"user_id": user_id, "sales_data": sales_data, "competitor_data": competitor_data}
                }).encode()
            ),
            routing_key="ai_queue"
        )
    return {"message": "Запрос на рекомендации отправлен"}

@app.get("/profile", response_model=ProfileResponse, summary="Получение профиля")
async def get_profile(
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(default=None, alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    user_id, _ = user_id_role
    auth_service = AuthService(db)
    profile = await auth_service.get_profile(user_id, csrf_token)
    return ProfileResponse(**profile)

@app.put("/profile", response_model=ProfileResponse, summary="Обновление профиля")
async def update_profile(
    request: UpdateProfileRequest,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),  # CSRF проверка перенесена сюда
    db: Session = Depends(get_db)
):
    user_id, _ = user_id_role
    auth_service = AuthService(db)
    if not await auth_service.verify_csrf_token(user_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    try:
        profile = await auth_service.update_profile(user_id, request.email, request.company_name, request.inn)
        return ProfileResponse(**profile)
    except AuthError as e:
        logger.error(f"Ошибка обновления профиля {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/users/{user_id}", summary="Удаление пользователя")
async def delete_user(user_id: str, requester_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Удаление пользователя (только для admin или super_admin)."""
    try:
        requester_id, _ = requester_id_role
        auth_service = AuthService(db)
        await auth_service.delete_user(user_id, requester_id)
        return {"message": "Пользователь успешно удален"}
    except AuthError as e:
        logger.error("Ошибка при удалении профиля")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/report", summary="Генерация отчета")
async def generate_report(request: ReportRequest, user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Генерация отчета о регистрации (только super_admin, устаревший метод)."""
    try:
        user_id, _ = user_id_role
        auth_service = AuthService(db)
        report = auth_service.generate_report(user_id, request.period)
        return report
    except AuthError as e:
        logger.error("Ошибка при генерации отчета")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/users", summary="Получение списка пользователей")
async def get_users(db: Session = Depends(get_db), user_id_role: tuple = Depends(get_current_user)):
    user_id, role = user_id_role
    if role not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Требуются права admin или super_admin")
    auth_service = AuthService(db)
    users = db.query(User).all()
    return [{"user_id": str(u.user_id), "email": u.email, "role": u.role} for u in users]

@app.get("/superadmin/stats", summary="Статистика для SuperAdmin")
async def superadmin_stats(period: str, user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получение статистики для SuperAdmin."""
    user_id, role = user_id_role
    if role != "super_admin":
        raise HTTPException(status_code=403, detail="Требуется роль SuperAdmin")
    auth_service = AuthService(db)
    stats = await auth_service.superadmin_report(user_id, period)
    return stats

@app.get("/auth/google/callback", response_model=TokenResponse, summary="Callback для Google OAuth")
async def google_callback(code: str, state: str, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    try:
        user_id, token, refresh_token = await auth_service.google_callback(code, state)
        return TokenResponse(user_id=user_id, token=token, refresh_token=refresh_token, csrf_token="")
    except AuthError as e:
        logger.error(f"Ошибка в Google callback: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/auth/google", summary="Получить URL для Google OAuth")
async def google_login(db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    url = await auth_service.google_login_url()
    return {"url": url}

@app.delete("/companies/{company_id}", summary="Удаление компании")
async def delete_company(
    company_id: str,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    """
    Удаление компании по company_id вместе со всеми связанными пользователями.
    Только для пользователей с ролью admin или super_admin.
    """
    try:
        user_id, role = user_id_role
        auth_service = AuthService(db)
        if not await auth_service.verify_csrf_token(user_id, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        if role not in ["admin", "super_admin"]:
            raise HTTPException(status_code=403, detail="Требуются права admin или super_admin")

        await auth_service.delete_company(user_id, company_id)
        return {"message": "Компания и все связанные пользователи успешно удалены"}
    except AuthError as e:
        logger.error(f"Ошибка при удалении компании {company_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при удалении компании {company_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось удалить компанию")

@app.post("/reset-password", summary="Запрос на сброс пароля")
async def reset_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    """Запрос на сброс пароля с отправкой ссылки на email."""
    auth_service = AuthService(db)
    try:
        result = await auth_service.request_password_reset(request.email)
        return result
    except AuthError as e:
        logger.error(f"Ошибка при запросе сброса пароля для {request.email}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при запросе сброса пароля: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось обработать запрос на сброс пароля")

@app.post("/reset-password/confirm", summary="Подтверждение сброса пароля")
async def confirm_reset_password(request: PasswordResetConfirmRequest, db: Session = Depends(get_db)):
    """Подтверждение сброса пароля с использованием токена и нового пароля."""
    auth_service = AuthService(db)
    try:
        result = await auth_service.confirm_password_reset(request.token, request.new_password)
        return result
    except AuthError as e:
        logger.error(f"Ошибка при подтверждении сброса пароля: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при подтверждении сброса пароля: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось сбросить пароль")
    
@app.put("/users/{user_id}", summary="Обновление пользователя")
async def update_user(
    user_id: str,
    request: UpdateUserRequest,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    """Обновление данных пользователя (email, роль) администратором или super_admin."""
    requester_id, requester_role = user_id_role
    auth_service = AuthService(db)
    
    if not await auth_service.verify_csrf_token(requester_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    
    try:
        updated_user = await auth_service.update_user(
            user_id=user_id,
            requester_id=requester_id,
            email=request.email,
            role=request.role
        )
        return {
            "user_id": updated_user["user_id"],
            "email": updated_user["email"],
            "role": updated_user["role"]
        }
    except AuthError as e:
        logger.error(f"Ошибка при обновлении пользователя {user_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Неизвестная ошибка при обновлении пользователя {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Не удалось обновить пользователя")
    
@app.post("/clients", response_model=ClientResponse, summary="Добавить клиента")
async def add_client(
    request: ClientRequest,
    user_id_role: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id, role = user_id_role
    auth_service = AuthService(db)
    try:
        client = await auth_service.add_client(
            user_id=user_id,
            company_id=(db.query(User).filter(User.user_id == user_id).first()).company_id,
            name=request.name,
            phone=request.phone,
            email=request.email,
            amount=request.amount,
            description=request.description
        )
        # Отправка в ai-service через RabbitMQ
        async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
            channel = await connection.channel()
            await channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps({
                        "type": "add_client",
                        "data": {
                            "user_id": user_id,
                            "client_id": str(client["client_id"]),
                            "name": client["name"],
                            "amount": client["amount"],
                            "description": client["description"]
                        }
                    }).encode()
                ),
                routing_key="ai_queue"
            )
        return ClientResponse(**client)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/clients", response_model=List[ClientResponse], summary="Получить список клиентов")
async def get_clients(
    user_id_role: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id, role = user_id_role
    auth_service = AuthService(db)
    try:
        clients = await auth_service.get_clients(user_id)
        return [ClientResponse(**client) for client in clients]
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/clients/{client_id}", response_model=ClientResponse, summary="Обновить клиента")
async def update_client(
    client_id: str,
    request: ClientRequest,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    user_id, role = user_id_role
    auth_service = AuthService(db)
    if not await auth_service.verify_csrf_token(user_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    try:
        client = await auth_service.update_client(
            client_id=client_id,
            user_id=user_id,
            name=request.name,
            phone=request.phone,
            email=request.email,
            amount=request.amount,
            description=request.description
        )
        return ClientResponse(**client)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/clients/{client_id}", summary="Удалить клиента")
async def delete_client(
    client_id: str,
    user_id_role: tuple = Depends(get_current_user),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
    db: Session = Depends(get_db)
):
    user_id, role = user_id_role
    auth_service = AuthService(db)
    if not await auth_service.verify_csrf_token(user_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    try:
        await auth_service.delete_client(client_id, user_id)
        return {"message": "Клиент удалён"}
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/health", summary="Проверка состояния")
def health_check():
    """Проверка работоспособности сервиса."""
    return {"status": "healthy"}

@app.on_event("shutdown")
async def shutdown_event():
    auth_service = AuthService(SessionLocal())
    await auth_service.close()
    logger.info("Сервис аутентификации завершает работу")

@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    service = AuthService(db)
    asyncio.create_task(service.rotate_keys_periodically())

    # Добавляем слушателя ai_queue
    async def consume_ai_queue():
        async with aio_pika.connect_robust(Config.RABBITMQ_URL) as connection:
            channel = await connection.channel()
            queue = await channel.declare_queue("ai_queue")
            async for message in queue:
                with message.process():
                    data = json.loads(message.body.decode())
                    if data["type"] == "add_client":
                        auth_service = AuthService(SessionLocal())
                        await auth_service.add_client(
                            user_id=data["data"]["user_id"],
                            company_id=data["data"]["company_id"],
                            name=data["data"]["name"],
                            phone=data["data"].get("phone")
                        )
                        logger.info(f"Клиент добавлен через ai_queue: {data['data']['name']}")

    asyncio.create_task(consume_ai_queue())
    logger.info("Потребитель RabbitMQ для ai_queue запущен")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)