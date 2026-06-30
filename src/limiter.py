from slowapi import Limiter
from slowapi.util import get_remote_address

# Inicializa o limitador global por IP da requisição
limiter = Limiter(key_func=get_remote_address)
