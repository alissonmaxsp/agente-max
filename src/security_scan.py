"""
Scanner de SQL Injection (modo detecção, NÃO destrutivo) — focado em
aplicações com backend Postgres/Supabase.

⚠️  USO AUTORIZADO: rode apenas em sites/APIs que você é dono ou tem permissão
explícita para testar. Testar alvos de terceiros sem autorização é ilegal.

Como funciona (sem causar dano):
- Descobre pontos de entrada: parâmetros da query string e campos de formulários.
- Envia apenas payloads de DETECÇÃO (aspas e lógica booleana). Nunca DROP/DELETE/UPDATE.
- Detecta vulnerabilidade por:
    1. Erros de SQL/Postgres vazados na resposta (error-based).
    2. Diferença de comportamento entre uma condição verdadeira e uma falsa
       (boolean-based): mesmo tamanho/status para 1=1 e diferente para 1=2.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from playwright.async_api import async_playwright


# Payloads NÃO destrutivos (apenas detecção)
ERROR_PROBE = "'"
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"

# Assinaturas de erro SQL. Foco em Postgres/Supabase, mas inclui outros bancos
# para que o scanner também detecte vazamentos genéricos de erro de SQL.
SQL_ERROR_SIGNATURES = [
    # Postgres / Supabase (PostgREST)
    r"syntax error at or near",
    r"unterminated quoted string",
    r"invalid input syntax for",
    r"operator does not exist",
    r"column .{1,40} does not exist",
    r"relation .{1,40} does not exist",
    r"PostgreSQL",
    r"PostgrestException",
    r"PGRST\d{3}",          # códigos de erro do PostgREST (Supabase)
    r"pg_query",
    r"SQLSTATE",
    # MySQL / MariaDB
    r"You have an error in your SQL syntax",
    r"warning: mysql",
    r"MySqlException",
    r"valid MySQL result",
    r"mysql_fetch",
    # MS SQL Server
    r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SqlException",
    # Oracle
    r"ORA-\d{5}",
    r"Oracle error",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLiteException",
    r"sqlite3.OperationalError",
    # Genéricos
    r"SQL syntax.*?error",
    r"quoted string not properly terminated",
]

_SQL_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)


def _detect_sql_error(text: str) -> str | None:
    """Retorna a assinatura de erro SQL encontrada na resposta, se houver."""
    m = _SQL_RE.search(text or "")
    return m.group(0) if m else None


async def _discover_entry_points(url: str, timeout_ms: int) -> dict:
    """
    Descobre pontos de injeção:
    - query params da própria URL
    - formulários (action, method, nomes dos inputs) renderizados na página
    """
    points = {"query_params": [], "forms": []}

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    points["query_params"] = list(qs.keys())

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await (await browser.new_context()).new_page()
            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                forms = await page.evaluate(
                    """() => Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'get').toLowerCase(),
                        inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                            .map(i => i.name).filter(Boolean)
                    }))"""
                )
                points["forms"] = forms or []
            finally:
                await browser.close()
    except Exception as e:
        points["discovery_error"] = str(e)

    return points


def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


async def _probe_get_param(client: httpx.AsyncClient, url: str, param: str) -> dict | None:
    """Testa um parâmetro de query string. Retorna um finding ou None."""
    # Preserva o valor original do parâmetro para tornar a injeção mais realista.
    orig = (parse_qs(urlparse(url).query).get(param) or ["1"])[0]
    try:
        # condição verdadeira + condição falsa + sonda de erro (valor original + aspa)
        r_true = await client.get(_build_url_with_param(url, param, orig + TRUE_PAYLOAD))
        r_false = await client.get(_build_url_with_param(url, param, orig + FALSE_PAYLOAD))
        r_err = await client.get(_build_url_with_param(url, param, orig + ERROR_PROBE))
    except Exception:
        return None

    sig = _detect_sql_error(r_err.text)
    if sig:
        return {
            "point": f"query param '{param}'",
            "method": "GET",
            "type": "error-based",
            "evidence": f"Erro SQL vazado: '{sig}'",
            "severity": "ALTA",
        }

    # boolean-based: exige sinal FORTE pra evitar falso-positivo de conteúdo dinâmico.
    # Critério: TRUE responde 200 e (status difere de FALSE) OU diferença grande
    # de tamanho (> 30% do baseline e > 400 bytes).
    delta = abs(len(r_true.text) - len(r_false.text))
    big = delta > 400 and delta > 0.30 * max(1, len(r_true.text))
    status_diff = r_true.status_code != r_false.status_code
    if r_true.status_code == 200 and (status_diff or big):
        return {
            "point": f"query param '{param}'",
            "method": "GET",
            "type": "boolean-based (suspeita)",
            "evidence": f"TRUE/FALSE diferem (status {r_true.status_code}/{r_false.status_code}, Δ {delta} bytes) — confirme manualmente",
            "severity": "MÉDIA",
        }
    return None


async def _probe_form(client: httpx.AsyncClient, form: dict) -> list[dict]:
    """Testa os campos de um formulário (GET ou POST)."""
    findings = []
    action = form.get("action")
    method = form.get("method", "get")
    inputs = form.get("inputs", [])
    if not action or not inputs:
        return findings

    for field in inputs:
        base = {f: "test" for f in inputs}
        err_data = {**base, field: "test" + ERROR_PROBE}
        try:
            if method == "post":
                r_err = await client.post(action, data=err_data)
            else:
                r_err = await client.get(action, params=err_data)
        except Exception:
            continue

        sig = _detect_sql_error(r_err.text)
        if sig:
            findings.append({
                "point": f"campo '{field}' (form {action})",
                "method": method.upper(),
                "type": "error-based",
                "evidence": f"Erro SQL vazado: '{sig}'",
                "severity": "ALTA",
            })
    return findings


async def scan_sqli(url: str, timeout_ms: int = 15000) -> dict:
    """
    Executa o scan de SQL Injection (detecção) no alvo informado.
    Retorna {url, entry_points, findings, tested}.
    """
    result = {"url": url, "entry_points": {}, "findings": [], "tested": 0}

    points = await _discover_entry_points(url, timeout_ms)
    result["entry_points"] = points

    headers = {"User-Agent": "AgenteMAX-SecurityScanner/1.0 (authorized testing)"}
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0, headers=headers) as client:
        # 1. Query params
        for param in points.get("query_params", []):
            result["tested"] += 1
            f = await _probe_get_param(client, url, param)
            if f:
                result["findings"].append(f)

        # 2. Formulários
        for form in points.get("forms", []):
            result["tested"] += len(form.get("inputs", []))
            result["findings"].extend(await _probe_form(client, form))

    return result
