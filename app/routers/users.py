import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.deps import get_company, get_db_user, require_admin_user, user_out
from app.models import User
from app.passwords import hash_password
from app.schemas import Page, Role, UserCreateIn, UserOut, UserUpdateIn

router = APIRouter(prefix="/api/users", tags=["users"])


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")


async def _get_company_user(db: AsyncSession, company_id: uuid.UUID, user_id: uuid.UUID) -> User:
    user = (
        await db.execute(select(User).where(User.id == user_id, User.company_id == company_id))
    ).scalar_one_or_none()
    if user is None:
        raise _not_found()
    return user


@router.get("", response_model=Page[UserOut])
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    role: Role | None = Query(None),
    search: str | None = Query(None, max_length=255),
    me: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> Page[UserOut]:
    conditions = [User.company_id == me.company_id]
    if role is not None:
        conditions.append(User.role == role)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        conditions.append(or_(User.full_name.ilike(pattern), User.email.ilike(pattern)))

    total = await db.scalar(select(func.count()).select_from(User).where(*conditions)) or 0
    rows = (
        (
            await db.execute(
                select(User)
                .where(*conditions)
                .order_by(User.created_at, User.id)
                .offset((page - 1) * limit)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    company = await get_company(db, me.company_id)
    return Page[UserOut](items=[user_out(u, company) for u in rows], total=total, page=page, limit=limit)


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreateIn,
    me: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    email = data.email.strip().lower()
    if await db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Пользователь с таким email уже существует"
        )
    full_name = data.full_name.strip()
    if not full_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Имя не может быть пустым")
    user = User(
        company_id=me.company_id,
        email=email,
        password_hash=await hash_password(data.password),
        full_name=full_name,
        phone=data.phone,
        position=data.position,
        role=data.role,
        is_active=True,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Пользователь с таким email уже существует"
        ) from exc
    company = await get_company(db, me.company_id)
    return user_out(user, company)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    me: User = Depends(get_db_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await _get_company_user(db, me.company_id, user_id)
    company = await get_company(db, me.company_id)
    return user_out(user, company)


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    data: UserUpdateIn,
    me: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    user = await _get_company_user(db, me.company_id, user_id)
    fields = data.model_dump(exclude_unset=True)

    if user.role == "owner":
        if me.role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Нельзя изменять владельца компании"
            )
        if fields.get("role") is not None and fields["role"] != "owner":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя изменить роль владельца"
            )
        if fields.get("is_active") is False:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя отключить владельца")
    if user.id == me.id and fields.get("is_active") is False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя отключить самого себя")

    if "full_name" in fields:
        full_name = (fields["full_name"] or "").strip()
        if not full_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Имя не может быть пустым")
        user.full_name = full_name
    if "phone" in fields:
        user.phone = (fields["phone"] or "").strip() or None
    if "position" in fields:
        user.position = (fields["position"] or "").strip() or None
    if fields.get("role") is not None and user.role != "owner":
        user.role = fields["role"]
    if fields.get("is_active") is not None:
        user.is_active = fields["is_active"]
    await db.commit()
    company = await get_company(db, me.company_id)
    return user_out(user, company)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_user(
    user_id: uuid.UUID,
    me: User = Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_company_user(db, me.company_id, user_id)
    if user.id == me.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя удалить самого себя")
    if user.role == "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нельзя удалить владельца компании")
    await db.delete(user)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
