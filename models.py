from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, CheckConstraint, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()

class Company(Base):
    __tablename__ = "companies"
    company_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    inn = Column(String(12), unique=True, nullable=True)
    company_type = Column(String, nullable=False)
    ogrnip = Column(String(15), unique=True, nullable=True)
    ogrn = Column(String(13), unique=True, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=True)  # Изменено на nullable для Google OAuth
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id"))
    role = Column(String, default="user")
    rate = Column(Float, default=500.0)
    tax_rate = Column(Float, default=0.13)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_log"
    audit_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class Client(Base):
    __tablename__ = "clients"
    client_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.company_id"))
    name = Column(String, nullable=False)
    phone = Column(String)
    email = Column(String)

class Payroll(Base):
    __tablename__ = "payroll"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False)
    period = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    calculated_at = Column(DateTime(timezone=True), server_default=func.now())