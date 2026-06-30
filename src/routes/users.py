from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from src.database import get_db
from src.dependencies import get_current_user, RoleChecker
from src.models import User
from src.schemas import UserResponse

router = APIRouter(prefix="/api/users", tags=["Usuários"])

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Retorna as informações da conta do usuário atualmente autenticado.
    
    Exige autenticação JWT válida (Bearer Token).
    """
    return current_user

@router.get("/admin-only", response_model=list[UserResponse])
async def read_users_admin(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(RoleChecker(allowed_roles=["admin"]))
):
    """
    Lista todos os usuários do sistema.
    
    Exige perfil de 'admin' (RBAC - Controle de Acesso Baseado em Perfil).
    """
    result = await db.execute(select(User))
    users = result.scalars().all()
    return users
