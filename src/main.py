from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from src.config import settings
from src.database import Base, engine
from src.limiter import limiter
from src.routes import auth, users

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Criação automática de tabelas se não existirem (apenas desenvolvimento)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description="API demonstrando práticas robustas de segurança defensiva.",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,  # Oculta documentação de rotas em produção
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

# Configuração do Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS estrito baseado nas configurações do .env
origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Middleware para Headers de Segurança e Tratamento de Erros de Produção
@app.middleware("http")
async def security_and_error_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if settings.DEBUG:
            raise exc
        # Em produção, nunca vaze mensagens de erro detalhadas ou stack traces para o usuário
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Erro interno do servidor."}
        )
    
    # Headers de Segurança (Proteção defensiva no navegador)
    response.headers["X-Frame-Options"] = "DENY"  # Previne Clickjacking
    response.headers["X-Content-Type-Options"] = "nosniff"  # Previne MIME sniffing
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Ativa bloqueio de XSS no navegador
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    
    return response

# Registro das rotas
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/health", tags=["Monitoramento"])
async def health():
    return {"status": "healthy"}
