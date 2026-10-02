import logging
from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Cookie,
    Depends,
    HTTPException,
    Response,
    status,
)
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import redis_store
from app.billing import new_trial_subscription
from app.config import get_settings
from app.db import get_db
from app.deps import get_company, get_db_user, token_subject, user_out
from app.mailer import send_password_reset_email
from app.models import Company, User
from app.passwords import burn_password_check, hash_password, verify_password
from app.redis_store import get_redis
from app.schemas import (
    DetailOut,
    LinkCodeOut,
    LoginIn,
    MeUpdateIn,
    PasswordChangeIn,
    PasswordResetConfirmIn,
    PasswordResetIn,
    RefreshIn,
    RegisterIn,
    TokenResponse,
    UserOut,
)
from app.tokens import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_NAME = "refresh_token"
COOKIE_PATH = "/api/auth"


def _invalid_refresh() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный refresh-токен")


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.refresh_ttl_seconds,
        path=COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        path=COOKIE_PATH,
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite="strict",
    )


async def _issue_tokens(response: Response, redis: Redis, user: User, company: Company) -> TokenResponse:
    subject = token_subject(user, company)
    access = create_access_token(subject)
    refresh = create_refresh_token(subject)
    await redis_store.store_refresh(redis, refresh.jti, user.id, refresh.expires_in)
    _set_refresh_cookie(response, refresh.token)
    return TokenResponse(
        access_token=access.token,
        token_type="bearer",  # noqa: S106
        expires_in=access.expires_in,
        user=user_out(user, company),
    )


def _pick_refresh_token(body: RefreshIn | None, cookie_token: str | None) -> str | None:
    if body is not None and body.refresh_token:
        return body.refresh_token
    return cookie_token or None


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    data: RegisterIn,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> TokenResponse:
    settings = get_settings()
    email = data.email.strip().lower()
    exists = await db.scalar(select(User.id).where(User.email == email))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Пользователь с таким email уже существует"
        )

    password_hash = await hash_password(data.password)
    company = Company(name=data.company_name, type=data.company_type, inn=data.inn)
    db.add(company)
    await db.flush()
    user = User(
        company_id=company.id,
        email=email,
        password_hash=password_hash,
        full_name=data.full_name,
        phone=data.phone,
        position=None,
        role="owner",
        is_active=True,
        pd_consent_at=datetime.now(timezone.utc),
        pd_consent_version=settings.pd_consent_version,
    )
    db.add(user)
    db.add(new_trial_subscription(company.id, settings))
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Пользователь с таким email уже существует"
        ) from exc
    logger.info("Зарегистрирована компания %s, владелец %s", company.id, user.id)
    return await _issue_tokens(response, redis, user, company)


@router.post("/login", response_model=TokenResponse)
async def login(
    data: LoginIn,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> TokenResponse:
    email = data.email.strip().lower()
    rl_key = redis_store.login_rl_key(email)
    if await redis_store.rate_limit_exceeded(
        redis, rl_key, redis_store.LOGIN_LIMIT, redis_store.LOGIN_WINDOW_SEC
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Слишком много попыток входа. Повторите через 15 минут",
        )

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        await burn_password_check(data.password)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный email или пароль")
    if not await verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный email или пароль")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Учётная запись отключена")

    await redis_store.reset_rate_limit(redis, rl_key)
    company = await get_company(db, user.company_id)
    return await _issue_tokens(response, redis, user, company)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    response: Response,
    body: RefreshIn | None = None,
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> TokenResponse:
    token = _pick_refresh_token(body, refresh_token)
    if not token:
        raise _invalid_refresh()
    try:
        claims = decode_refresh_token(token)
    except InvalidTokenError as exc:
        raise _invalid_refresh() from exc
    # Ротация: старый jti удаляется атомарно (GETDEL), повторное использование → 401
    if not await redis_store.consume_refresh(redis, claims.jti, claims.user_id):
        raise _invalid_refresh()

    user = await db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise _invalid_refresh()
    company = await db.get(Company, user.company_id)
    if company is None:
        raise _invalid_refresh()
    return await _issue_tokens(response, redis, user, company)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def logout(
    body: RefreshIn | None = None,
    refresh_token: str | None = Cookie(default=None),
    redis: Redis = Depends(get_redis),
) -> Response:
    token = _pick_refresh_token(body, refresh_token)
    if token:
        try:
            claims = decode_refresh_token(token)
        except InvalidTokenError:
            claims = None
        if claims is not None:
            await redis_store.consume_refresh(redis, claims.jti, claims.user_id)
    resp = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(resp)
    return resp


@router.get("/me", response_model=UserOut)
async def get_me(user: User = Depends(get_db_user), db: AsyncSession = Depends(get_db)) -> UserOut:
    company = await get_company(db, user.company_id)
    return user_out(user, company)


@router.put("/me", response_model=UserOut)
async def update_me(
    data: MeUpdateIn,
    user: User = Depends(get_db_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    fields = data.model_dump(exclude_unset=True)
    if "full_name" in fields:
        full_name = (fields["full_name"] or "").strip()
        if not full_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Имя не может быть пустым")
        user.full_name = full_name
    if "phone" in fields:
        user.phone = (fields["phone"] or "").strip() or None
    if "position" in fields:
        user.position = (fields["position"] or "").strip() or None
    await db.commit()
    company = await get_company(db, user.company_id)
    return user_out(user, company)


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def change_password(
    data: PasswordChangeIn,
    refresh_token: str | None = Cookie(default=None),
    user: User = Depends(get_db_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> Response:
    if not await verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный текущий пароль")
    user.password_hash = await hash_password(data.new_password)
    await db.commit()

    # Завершаем остальные сессии, текущую (cookie) оставляем
    keep_jti: str | None = None
    if refresh_token:
        try:
            claims = decode_refresh_token(refresh_token)
            if claims.user_id == user.id:
                keep_jti = claims.jti
        except InvalidTokenError:
            keep_jti = None
    await redis_store.revoke_all_refresh(redis, user.id, keep_jti=keep_jti)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _send_reset_email(email: str, token: str) -> None:
    try:
        await send_password_reset_email(email, token)
    except Exception:
        logger.exception("Не удалось отправить письмо для сброса пароля")


@router.post("/password-reset", response_model=DetailOut, status_code=status.HTTP_202_ACCEPTED)
async def password_reset(
    data: PasswordResetIn,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> DetailOut:
    answer = DetailOut(
        detail="Если такой email зарегистрирован, на него отправлено письмо со ссылкой для сброса пароля"
    )
    email = data.email.strip().lower()
    if not get_settings().smtp_enabled:
        logger.warning("SMTP не настроен — письмо для сброса пароля не будет отправлено")
        return answer
    if await redis_store.rate_limit_exceeded(
        redis, redis_store.reset_rl_key(email), redis_store.RESET_LIMIT, redis_store.RESET_WINDOW_SEC
    ):
        return answer
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or not user.is_active:
        return answer
    token = await redis_store.create_reset_token(redis, user.id)
    background.add_task(_send_reset_email, user.email, token)
    return answer


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def password_reset_confirm(
    data: PasswordResetConfirmIn,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> Response:
    user_id = await redis_store.consume_reset_token(redis, data.token)
    user = await db.get(User, user_id) if user_id is not None else None
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ссылка для сброса пароля недействительна или устарела",
        )
    user.password_hash = await hash_password(data.new_password)
    await db.commit()
    await redis_store.revoke_all_refresh(redis, user.id)
    await redis_store.reset_rate_limit(redis, redis_store.login_rl_key(user.email))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/telegram/link-code", response_model=LinkCodeOut)
async def telegram_link_code(
    user: User = Depends(get_db_user),
    redis: Redis = Depends(get_redis),
) -> LinkCodeOut:
    code = await redis_store.create_tg_code(redis, user.id)
    return LinkCodeOut(
        code=code,
        expires_in=redis_store.TG_CODE_TTL_SEC,
        bot_username=get_settings().telegram_bot_username,
    )


@router.delete("/telegram/link", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def telegram_unlink(
    user: User = Depends(get_db_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user.telegram_chat_id = None
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
