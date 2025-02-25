import pytest
from services.auth_service import AuthService
from models import User, Company
from sqlalchemy.orm import Session
from unittest.mock import AsyncMock

@pytest.fixture
def db_session():
    return Session()

@pytest.fixture
def auth_service(db_session):
    return AuthService(db_session)

@pytest.mark.asyncio
async def test_register(auth_service, db_session):
    auth_service._hash_password = lambda x: x
    db_session.query = lambda x: MockQuery()
    auth_service.redis.set = AsyncMock()
    user_id, token, refresh_token = await auth_service.register("test@example.com", "password", "TestCompany", "123456789012")
    assert user_id
    assert token
    assert refresh_token

class MockQuery:
    def filter(self, *args): return self
    def first(self): return None