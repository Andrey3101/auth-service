from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Float, Boolean, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
import uuid
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()

class SubscriptionStatus(enum.Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

class Company(Base):
    __tablename__ = "companies"
    company_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, nullable=False)
    company_type = Column(String, nullable=False)
    inn = Column(String, unique=True)
    ogrn = Column(String, unique=True)
    ogrnip = Column(String, unique=True)
    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
    clients = relationship("Client", back_populates="company", cascade="all, delete-orphan")
    subscriptions = relationship("Subscription", back_populates="company", cascade="all, delete-orphan")
    cards = relationship("Card", back_populates="company", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False, default="user")
    company = relationship("Company", back_populates="users")
    cards = relationship("Card", back_populates="user", cascade="all, delete-orphan")  # НОВОЕ: связь с картами

class Client(Base):
    __tablename__ = "clients"
    client_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True)
    name = Column(String, nullable=False)
    phone = Column(String)
    email = Column(String)
    amount = Column(Integer)
    description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    company = relationship("Company", back_populates="clients")

class AuditLog(Base):
    __tablename__ = "audit_log"
    audit_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String, ForeignKey("users.user_id"), nullable=False)
    action = Column(String, nullable=False)
    details = Column(String, nullable=True)  # НОВОЕ: детали действия в JSON формате
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class Payroll(Base):
    __tablename__ = "payroll"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False)
    period = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    calculated_at = Column(DateTime(timezone=True), server_default=func.now())

class Subscription(Base):
    __tablename__ = "subscriptions"
    subscription_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id", ondelete="CASCADE"), nullable=False)
    status = Column(Enum(SubscriptionStatus), nullable=False, default=SubscriptionStatus.TRIAL)
    trial_start = Column(DateTime(timezone=True), server_default=func.now())
    trial_end = Column(DateTime(timezone=True))
    payment_id = Column(String, nullable=True)  # ID последнего платежа в Т-Банк
    recurrent_payment_id = Column(String, nullable=True)  # ID рекуррентного платежа в Т-Банк
    last_payment_date = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    company = relationship("Company", back_populates="subscriptions")

class Card(Base):
    __tablename__ = "cards"
    card_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True)  # НОВОЕ: связь с пользователем
    bank_name = Column(String, nullable=True)  # НОВОЕ: название банка
    account_number = Column(String, nullable=True)  # НОВОЕ: номер счета
    account_type = Column(String, nullable=True)  # НОВОЕ: тип счета (current, savings, credit)
    status = Column(String, default="active")  # НОВОЕ: статус подключения
    last4 = Column(String(4), nullable=True)  # Последние 4 цифры карты (опционально)
    brand = Column(String, nullable=True)  # Тип карты (Visa, MasterCard и т.д.) (опционально)
    tbank_customer_key = Column(String, nullable=True)  # CustomerKey для рекуррентных платежей
    tbank_card_id = Column(String, nullable=True)  # ID карты в Т-Банк
    connected_at = Column(DateTime(timezone=True), nullable=True)  # НОВОЕ: дата подключения
    disconnected_at = Column(DateTime(timezone=True), nullable=True)  # НОВОЕ: дата отключения
    connection_requested_at = Column(DateTime(timezone=True), nullable=True)  # НОВОЕ: дата запроса на подключение
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    company = relationship("Company", back_populates="cards")
    user = relationship("User", back_populates="cards")  # НОВОЕ: связь с пользователем