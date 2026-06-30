from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from src.database import get_db
from src.models import User
from src.schemas import UserCreate, UserResponse, Token
from src.security import get_password_hash, verify_password, create_access_token
from src.limiter import limiter

router = APIRouter(prefix="/api/auth", tags=["Autenticação"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(request: Request, user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Registra um novo usuário.
    
    Possui limite de requisição de 5 cadastros por minuto por IP para evitar spam/DDoS.
    """
    result = await db.execute(select(User).filter(User.email == user_in.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O e-mail informado já está cadastrado no sistema."
        )
    
    hashed_password = get_password_hash(user_in.password)
    
    new_user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        role="user"  # Padrão seguro: novos cadastros ganham privilégios básicos
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Autentica o usuário e gera um token JWT de curta duração.
    
    Possui limite de 5 tentativas por minuto para mitigar ataques de força bruta.
    Prevenção de Timing Attack: tempos de processamento similares para e-mails válidos e inválidos.
    """
    result = await db.execute(select(User).filter(User.email == form_data.username))
    user = result.scalars().first()
    
    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="E-mail ou senha incorretos.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not user:
        # Prevenção de timing attack: mesmo tempo de processamento simulando o hash
        get_password_hash("dummy_password")
        raise invalid_credentials_exception
        
    if not verify_password(form_data.password, user.hashed_password):
        raise invalid_credentials_exception
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta conta está suspensa ou desativada."
        )
        
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}
    )
    return {"access_token": access_token, "token_type": "bearer"}
