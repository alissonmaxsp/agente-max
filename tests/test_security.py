import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.main import app
from src.database import Base, get_db
from src.schemas import UserCreate
from src.models import User

# Configuração do Banco de Dados de Testes local baseado em arquivo
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_secure.db"

engine_test = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = async_sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine_test,
    class_=AsyncSession
)

import pytest_asyncio

@pytest_asyncio.fixture(autouse=True)
async def prepare_database():
    # Garante que criamos as tabelas no arquivo sqlite de teste
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Limpa as tabelas
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    # Fecha o pool de conexões
    await engine_test.dispose()
    # Exclui o arquivo do banco de testes
    if os.path.exists("./test_secure.db"):
        try:
            os.remove("./test_secure.db")
        except PermissionError:
            pass

async def override_get_db():
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

def test_password_strength_validation():
    # Senhas fracas devem lançar erro de validação (Pydantic)
    with pytest.raises(ValueError, match="A senha deve ter no mínimo 10 caracteres"):
        UserCreate(email="test@example.com", password="123")
        
    with pytest.raises(ValueError, match="A senha deve conter pelo menos uma letra maiúscula"):
        UserCreate(email="test@example.com", password="weakpassword123!")
        
    with pytest.raises(ValueError, match="A senha deve conter pelo menos uma letra minúscula"):
        UserCreate(email="test@example.com", password="WEAKPASSWORD123!")
        
    with pytest.raises(ValueError, match="A senha deve conter pelo menos um dígito numérico"):
        UserCreate(email="test@example.com", password="WeakPassword!")
        
    with pytest.raises(ValueError, match="A senha deve conter pelo menos um caractere especial"):
        UserCreate(email="test@example.com", password="WeakPassword123")

    # Senha forte deve passar
    valid_user = UserCreate(email="test@example.com", password="StrongPassword123!")
    assert valid_user.password == "StrongPassword123!"

def test_xss_sanitization():
    # O email contendo tags html vazias ou tags que viram email válido após sanitização deve ser limpo e aceito
    user_with_html = UserCreate(email="<script></script>test@example.com", password="StrongPassword123!")
    assert user_with_html.email == "test@example.com"

def test_security_headers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")

@pytest.mark.asyncio
async def test_auth_flow_and_rbac():
    # 1. Cadastra usuário comum
    reg_response = client.post(
        "/api/auth/register",
        json={"email": "user@example.com", "password": "UserPassword123!"}
    )
    assert reg_response.status_code == 201
    
    # 2. Login com sucesso
    login_response = client.post(
        "/api/auth/login",
        data={"username": "user@example.com", "password": "UserPassword123!"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # 3. Acessa rota /me
    me_response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_response.status_code == 200
    assert me_response.json()["email"] == "user@example.com"
    assert me_response.json()["role"] == "user"
    
    # 4. Tenta acessar rota de admin (deve dar 403)
    admin_response = client.get(
        "/api/users/admin-only",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert admin_response.status_code == 403

