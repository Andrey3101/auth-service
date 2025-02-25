from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from config import Config
from services.auth_service import AuthService, AuthError
from services.queue_service import QueueService
from models import Base
import logging

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
    company_name: str
    inn: str

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
    email: EmailStr | None = None
    company_name: str | None = None
    inn: str | None = None

class ReportRequest(BaseModel):
    period: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> tuple[str, str]:
    """Получение текущего пользователя из токена."""
    auth_service = AuthService(db)
    try:
        return await auth_service.get_current_user(token)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

async def verify_csrf(token: str = Depends(oauth2_scheme), csrf_token: str = Header(...), db: Session = Depends(get_db)):
    """Проверка CSRF-токена."""
    auth_service = AuthService(db)
    user_id, _ = await auth_service.get_current_user(token)
    if not await auth_service.verify_csrf_token(user_id, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return user_id

@app.post("/register", response_model=TokenResponse, summary="Регистрация пользователя")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Регистрация нового пользователя и компании."""
    auth_service = AuthService(db)
    try:
        user_id, token, refresh_token = await auth_service.register(request.email, request.password, request.company_name, request.inn)
        QueueService().send_notification(user_id, f"Добро пожаловать, {request.email}!")
        return TokenResponse(user_id=user_id, token=token, refresh_token=refresh_token, csrf_token="")
    except AuthError as e:
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
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/logout", summary="Выход пользователя")
async def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Выход пользователя из системы."""
    auth_service = AuthService(db)
    await auth_service.logout(token)
    return {"message": "Успешный выход"}

@app.post("/refresh", response_model=TokenResponse, summary="Обновление токена")
async def refresh(refresh_token: str, db: Session = Depends(get_db)):
    """Обновление токена доступа и refresh токена."""
    auth_service = AuthService(db)
    try:
        new_token, new_refresh_token = await auth_service.refresh_token(refresh_token)
        payload = auth_service._verify_token(refresh_token)
        return TokenResponse(user_id=payload["sub"], token=new_token, refresh_token=new_refresh_token, csrf_token="")
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/profile", response_model=ProfileResponse, summary="Получение профиля")
async def get_profile(user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получение данных профиля текущего пользователя."""
    user_id, _ = user_id_role
    auth_service = AuthService(db)
    profile = await auth_service.get_profile(user_id)
    return ProfileResponse(**profile)

@app.put("/profile", response_model=ProfileResponse, summary="Обновление профиля", dependencies=[Depends(verify_csrf)])
async def update_profile(request: UpdateProfileRequest, user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Обновление информации профиля пользователя (требуется CSRF-токен)."""
    user_id, _ = user_id_role
    auth_service = AuthService(db)
    profile = await auth_service.update_profile(user_id, request.email, request.company_name, request.inn)
    return ProfileResponse(**profile)

@app.delete("/users/{user_id}", summary="Удаление пользователя")
async def delete_user(user_id: str, requester_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Удаление пользователя (только для admin или super_admin)."""
    requester_id, _ = requester_id_role
    auth_service = AuthService(db)
    await auth_service.delete_user(user_id, requester_id)
    return {"message": "Пользователь успешно удален"}

@app.post("/report", summary="Генерация отчета")
async def generate_report(request: ReportRequest, user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Генерация отчета о регистрации (только super_admin, устаревший метод)."""
    user_id, _ = user_id_role
    auth_service = AuthService(db)
    report = auth_service.generate_report(user_id, request.period)
    return report

@app.get("/superadmin/stats", summary="Статистика для SuperAdmin")
async def superadmin_stats(period: str, user_id_role: tuple = Depends(get_current_user), db: Session = Depends(get_db)):
    """Получение статистики для SuperAdmin."""
    user_id, role = user_id_role
    if role != "super_admin":
        raise HTTPException(status_code=403, detail="Требуется роль SuperAdmin")
    auth_service = AuthService(db)
    stats = await auth_service.superadmin_report(user_id, period)
    return stats

@app.get("/health", summary="Проверка состояния")
def health_check():
    """Проверка работоспособности сервиса."""
    return {"status": "healthy"}