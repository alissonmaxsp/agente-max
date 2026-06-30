import re
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr

    @field_validator("*", mode="before")
    @classmethod
    def sanitize_strings(cls, v):
        """Sanitiza strings de entrada para evitar XSS removendo tags HTML básicas."""
        if isinstance(v, str):
            # Remove tags HTML simples <...>
            cleaned = re.sub(r"<[^>]*>", "", v)
            return cleaned
        return v

class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Aplica regras estritas para a complexidade da senha (mínimo de 10 caracteres, maiúsculas, minúsculas, números e caracteres especiais)."""
        if len(v) < 10:
            raise ValueError("A senha deve ter no mínimo 10 caracteres para dificultar ataques de força bruta.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r"[a-z]", v):
            raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
        if not re.search(r"[0-9]", v):
            raise ValueError("A senha deve conter pelo menos um dígito numérico.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("A senha deve conter pelo menos um caractere especial (ex: !@#$%).")
        return v

class UserResponse(UserBase):
    id: int
    is_active: bool
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None
    role: str | None = None
