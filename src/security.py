from datetime import datetime, timedelta, timezone
from typing import Any
from jose import jwt
import bcrypt
from src.config import settings

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha fornecida bate com o hash armazenado no banco."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    """Gera um hash Bcrypt seguro a partir da senha em texto plano."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Cria um token de acesso JWT assinado com expiração definida."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # O claim 'exp' no JWT deve ser um timestamp numérico UTC
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt
