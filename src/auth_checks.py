"""
Testes de Autenticação & JWT (modo detecção, NÃO destrutivo p/ os dados).

⚠️  USO AUTORIZADO: apenas em alvos seus ou com permissão.

- analyze_jwts(url): captura tokens JWT (tráfego de rede + localStorage) e analisa
  fraquezas: alg:none, segredo HMAC fraco, sem expiração, expiração muito longa.
- test_login_protection(endpoint, body): tenta vários logins inválidos e vê se há
  rate-limit / bloqueio (proteção contra brute force).
- test_idor(endpoint, token): tenta acessar IDs vizinhos para detectar IDOR.
"""

import json
import time
import hmac
import base64
import hashlib

import httpx
from playwright.async_api import async_playwright


# Segredos comuns para detectar JWT HS256 assinado com chave fraca
WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "password", "123456", "changeme",
    "jwt_secret", "jwtsecret", "supersecret", "your-256-bit-secret", "key",
    "admin", "test", "qwerty", "default", "mysecret", "token", "s3cr3t",
]


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _decode_jwt(token: str) -> tuple[dict, dict] | None:
    try:
        h, p, _ = token.split(".")
        return json.loads(_b64url_decode(h)), json.loads(_b64url_decode(p))
    except Exception:
        return None


def _hs256_weak_secret(token: str) -> str | None:
    """Tenta validar a assinatura HS256 com segredos comuns. Retorna o que casar."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = _b64url_decode(sig_b64)
        for secret in WEAK_SECRETS:
            expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig):
                return secret
    except Exception:
        return None
    return None


def analyze_token(token: str) -> list[dict]:
    """Analisa um único JWT e devolve a lista de achados."""
    findings = []
    decoded = _decode_jwt(token)
    if not decoded:
        return findings
    header, payload = decoded
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append({"point": "JWT", "type": "algoritmo 'none'", "severity": "CRÍTICA",
                         "evidence": "token aceita alg:none — assinatura pode ser forjada"})
    if alg.startswith("hs"):
        weak = _hs256_weak_secret(token)
        if weak:
            findings.append({"point": "JWT", "type": "segredo HMAC fraco", "severity": "CRÍTICA",
                             "evidence": f"assinado com segredo trivial: '{weak}' — tokens podem ser forjados"})
    if "exp" not in payload:
        findings.append({"point": "JWT", "type": "sem expiração (exp)", "severity": "MÉDIA",
                         "evidence": "token sem 'exp' — válido para sempre se vazar"})
    else:
        dur = payload["exp"] - payload.get("iat", time.time())
        if dur > 30 * 86400:
            findings.append({"point": "JWT", "type": "expiração muito longa", "severity": "BAIXA",
                             "evidence": f"token válido por ~{int(dur/86400)} dias"})
    # Claims sensíveis no payload (informativo)
    sens = [k for k in payload if k.lower() in ("password", "senha", "secret", "saldo", "balance")]
    if sens:
        findings.append({"point": "JWT", "type": "claim sensível no payload", "severity": "MÉDIA",
                         "evidence": f"campos no token (são legíveis por qualquer um): {', '.join(sens)}"})
    return findings


async def _collect_tokens(url: str, timeout_ms: int) -> list[str]:
    """Captura JWTs do tráfego de rede (header Authorization) e do localStorage."""
    tokens = set()
    jwt_like = lambda s: s.count(".") == 2 and s.startswith("eyJ")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await (await browser.new_context()).new_page()

        def _on_req(req):
            auth = req.headers.get("authorization", "")
            if "bearer " in auth.lower():
                t = auth.split(" ", 1)[1].strip()
                if jwt_like(t):
                    tokens.add(t)
        page.on("request", _on_req)

        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            store = await page.evaluate(
                "() => JSON.stringify({...localStorage, ...sessionStorage})"
            )
            for val in json.loads(store or "{}").values():
                if isinstance(val, str):
                    for piece in val.replace('"', " ").split():
                        if jwt_like(piece):
                            tokens.add(piece)
        except Exception:
            pass
        finally:
            await browser.close()
    return list(tokens)


async def analyze_jwts(url: str, timeout_ms: int = 15000) -> dict:
    """Captura e analisa os JWTs usados pelo site."""
    result = {"url": url, "findings": [], "tokens_found": 0}
    tokens = await _collect_tokens(url, timeout_ms)
    result["tokens_found"] = len(tokens)
    for t in tokens:
        result["findings"].extend(analyze_token(t))
    return result


async def test_login_protection(
    endpoint: str, body: dict, attempts: int = 8, method: str = "POST", timeout: float = 20.0
) -> dict:
    """Envia vários logins inválidos e verifica se há rate-limit / bloqueio."""
    result = {"endpoint": endpoint, "method": method.upper(), "findings": [], "attempts": attempts}
    headers = {"Content-Type": "application/json",
               "User-Agent": "AgenteMAX-Auth/1.0 (authorized testing)"}
    statuses = []
    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for _ in range(attempts):
            try:
                r = await client.request(method, endpoint, content=json.dumps(body))
                statuses.append(r.status_code)
            except Exception:
                statuses.append(0)
    blocked = any(s == 429 for s in statuses)
    if blocked:
        result["findings"].append({"point": "login", "type": "rate-limit presente", "severity": "OK",
                                    "evidence": f"recebeu HTTP 429 após várias tentativas (bom)"})
    else:
        result["findings"].append({"point": "login", "type": "sem rate-limit / brute-force possível",
                                    "severity": "ALTA",
                                    "evidence": f"{attempts} tentativas sem bloqueio (status: {set(statuses)})"})
    return result


async def test_idor(
    endpoint_with_id: str, the_id: str, auth_header: str | None = None,
    method: str = "GET", timeout: float = 20.0, cookie: str | None = None
) -> dict:
    """
    Testa IDOR: troca o ID atual por IDs vizinhos e vê se devolve dados (200) de outros.
    `endpoint_with_id` deve conter o id (ex.: https://api.site/users/100); `the_id`=100.
    Autenticação: `auth_header` (Bearer) ou `cookie` (sessão).
    """
    result = {"endpoint": endpoint_with_id, "findings": [], "tested": 0}
    headers = {"User-Agent": "AgenteMAX-IDOR/1.0 (authorized testing)"}
    if auth_header:
        headers["Authorization"] = auth_header
    if cookie:
        headers["Cookie"] = cookie

    candidates = []
    if the_id.isdigit():
        n = int(the_id)
        candidates = [str(n - 1), str(n + 1), str(max(1, n // 2))]
    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for cid in candidates:
            if cid == the_id:
                continue
            # troca o id em TODAS as posições (path E query string)
            target = endpoint_with_id.replace(the_id, cid)
            result["tested"] += 1
            try:
                r = await client.request(method, target)
            except Exception:
                continue
            if r.status_code == 200 and len(r.text) > 20:
                result["findings"].append({
                    "point": target, "type": "possível IDOR", "severity": "ALTA",
                    "evidence": f"acesso a recurso de outro id (HTTP 200) — confirme se são dados de terceiros",
                })
    if not candidates:
        result["error"] = "O id informado não é numérico — IDOR automático suporta ids numéricos."
    return result
