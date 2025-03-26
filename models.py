from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, CheckConstraint, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
import uuid
from sqlalchemy.orm import relationship

Base = declarative_base()

class Company(Base):
    __tablename__ = "companies"
    company_id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    company_type = Column(String, nullable=False)
    inn = Column(String, unique=True)
    ogrn = Column(String, unique=True)
    ogrnip = Column(String, unique=True)
    # Связь с пользователями
    users = relationship("User", back_populates="company", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    company_id = Column(String, ForeignKey("companies.company_id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False, default="user")
    # Связь с компанией
    company = relationship("Company", back_populates="users")

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