import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

class Settings(BaseSettings):
    APP_NAME: str = "Secure FastAPI"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    DATABASE_URL: str
    
    ALLOWED_ORIGINS: str = ""

    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "qwen/qwen3-coder:free"

    # Multi-provedor de LLM (todos com tier/uso gratuito)
    LLM_PROVIDER: str = "openrouter"   # openrouter, gemini, groq, mistral, ollama
    LLM_MODEL: str = ""                 # alias/slug que sobrescreve o padrão, se definido
    GEMINI_API_KEY: str = ""
    MISTRAL_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    OLLAMA_HOST: str = "http://localhost:11434"   # Ollama LOCAL (sem chave)
    OLLAMA_API_KEY: str = ""                       # Ollama CLOUD (https://ollama.com)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        # Impede chaves fracas ou inseguras
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY deve ter pelo menos 32 caracteres para garantir a segurança contra força bruta.")
        
        insecure_keys = {
            "SUA_CHAVE_SUPER_SECRETA_E_LONGA_DEVE_SER_MUDADA_EM_PRODUCAO",
            "supersecretkey",
            "secret",
            "12345678901234567890123456789012"
        }
        if v in insecure_keys:
            raise ValueError("JWT_SECRET_KEY não pode utilizar uma chave padrão insegura de exemplo.")
        
        return v

settings = Settings()


def parse_keys(raw: str) -> list[str]:
    """
    Converte uma string de chaves separadas por vírgula em uma lista.
    Ex.: "key1, key2 ,key3" -> ["key1", "key2", "key3"].
    Ignora espaços e entradas vazias.
    """
    return [k.strip() for k in (raw or "").split(",") if k.strip()]
