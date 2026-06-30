"""
Sessão autenticada — faz login no SEU app e extrai o token/cookies para usar
nos testes dos endpoints que só existem depois de logar.

⚠️  USO AUTORIZADO: apenas no seu próprio sistema.
"""

import json as _json
import httpx

# Chaves comuns onde o token costuma vir na resposta de login
TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "id_token", "idToken",
              "authToken", "auth_token", "sessionToken", "session_token", "bearer")


def _find_token(obj, prefer_key: str | None = None) -> str | None:
    """Procura recursivamente um token na resposta JSON do login."""
    if isinstance(obj, dict):
        # Chave preferida explícita
        if prefer_key and prefer_key in obj and isinstance(obj[prefer_key], str):
            return obj[prefer_key]
        for k, v in obj.items():
            if k in TOKEN_KEYS and isinstance(v, str) and len(v) > 10:
                return v
        for v in obj.values():
            t = _find_token(v, prefer_key)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj:
            t = _find_token(v, prefer_key)
            if t:
                return t
    return None


async def login(
    login_url: str,
    body: dict,
    method: str = "POST",
    token_key: str | None = None,
    timeout: float = 25.0,
) -> dict:
    """
    Faz login e devolve {ok, token, cookies, status, detail}.
    O token é buscado no JSON da resposta (e cookies são capturados se houver).
    """
    out = {"ok": False, "token": None, "cookies": {}, "status": None, "detail": ""}
    headers = {"Content-Type": "application/json",
               "User-Agent": "AgenteMAX-Auth/1.0 (authorized testing)"}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.request(method, login_url, content=_json.dumps(body), headers=headers)
            out["status"] = r.status_code
            out["cookies"] = {c.name: c.value for c in client.cookies.jar}
            if r.status_code >= 400:
                out["detail"] = f"login falhou (HTTP {r.status_code}): {r.text[:160]}"
                return out
            try:
                data = r.json()
                out["token"] = _find_token(data, token_key)
            except Exception:
                pass
            # Sucesso se achou token OU recebeu cookie de sessão
            if out["token"] or out["cookies"]:
                out["ok"] = True
            else:
                out["detail"] = "login respondeu 2xx, mas não achei token nem cookie de sessão."
    except Exception as e:
        out["detail"] = f"erro ao conectar: {e}"
    return out
