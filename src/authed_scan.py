"""
Scanner AUTENTICADO (modo detecção, NÃO destrutivo).

⚠️  USO AUTORIZADO: apenas no seu próprio sistema.

Fluxo:
1. Faz login no app (src.auth_session.login) e obtém token/cookies.
2. Abre o navegador com o token injetado (header Authorization + localStorage)
   e/ou cookies, navega o site e CAPTURA os endpoints de API reais (com corpo).
3. Para cada endpoint JSON capturado, executa testes seguros:
   - NoSQL Injection (operadores $ne/$gt/$regex) — bypass/erro.
   - Mass Assignment (campo canário inofensivo) — aceita campo extra?
4. Devolve achados para o relatório.
"""

import json as _json
from urllib.parse import urlparse

import httpx
from playwright.async_api import async_playwright

from src.auth_session import login
from src.nosql_scan import _detect_mongo_error, _JSON_OPERATORS
from src.api_checks import CANARY_FIELD


async def discover_authed_endpoints(site_url: str, token: str | None, cookies: dict, timeout_ms: int,
                                    extra_routes: list[str] | None = None) -> list[dict]:
    """
    Navega o site autenticado e captura chamadas de API (mesma origem).

    `extra_routes`: caminhos internos informados pelo usuário (ex.: /checkout,
    /recarga) que são visitados ALÉM da lista padrão — é o que mais aumenta a
    cobertura, pois leva o scanner exatamente às telas onde estão os endpoints
    sensíveis (pagamento, saldo, etc.).
    """
    origin = urlparse(site_url).netloc
    calls = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        # Cookies de sessão (se o login usa cookie)
        if cookies:
            try:
                await context.add_cookies([
                    {"name": k, "value": v, "domain": origin, "path": "/"} for k, v in cookies.items()
                ])
            except Exception:
                pass

        # Injeta o token (Authorization em toda requisição same-origin + localStorage)
        if token:
            await context.set_extra_http_headers({"Authorization": f"Bearer {token}"})
            await context.add_init_script(
                f"""() => {{
                    try {{
                        const t = {_json.dumps(token)};
                        for (const k of ['token','access_token','accessToken','jwt','authToken'])
                            localStorage.setItem(k, t);
                    }} catch (e) {{}}
                }}"""
            )

        page = await context.new_page()

        def _on_req(req):
            if req.resource_type in ("xhr", "fetch") and origin in req.url:
                key = (req.method, req.url.split("?")[0])
                if key not in calls:
                    body = None
                    try:
                        pd = req.post_data
                        if pd:
                            body = _json.loads(pd)
                    except Exception:
                        body = None
                    calls[key] = {"method": req.method, "url": req.url, "body": body}
        page.on("request", _on_req)

        # Rotas autenticadas comuns (SPA) — só navegação GET, sem clicar em botões
        # (evita disparar ações como enviar SMS). Captura as chamadas de API que
        # cada tela faz ao carregar.
        base = f"{urlparse(site_url).scheme}://{origin}"
        rotas = ["", "/dashboard", "/painel", "/profile", "/perfil", "/account", "/conta",
                 "/settings", "/configuracoes", "/wallet", "/carteira", "/saldo", "/billing",
                 "/user", "/usuario", "/home", "/app"]
        # Rotas informadas pelo usuário entram primeiro (prioridade) e sem duplicar.
        for r in reversed(extra_routes or []):
            rota = r if r.startswith("/") else "/" + r
            if rota not in rotas:
                rotas.insert(0, rota)
        for rota in rotas:
            try:
                await page.goto(base + rota, wait_until="networkidle", timeout=min(timeout_ms, 12000))
                await page.wait_for_timeout(800)
            except Exception:
                continue
        try:
            await browser.close()
        except Exception:
            pass

    return list(calls.values())


async def _test_endpoint_authed(client: httpx.AsyncClient, call: dict, auth_headers: dict) -> list[dict]:
    """Testa um endpoint capturado: NoSQL injection (se tem body JSON) + mass assignment."""
    findings = []
    url, method = call["url"], call["method"]
    body = call.get("body")
    if not isinstance(body, dict) or not body:
        return findings  # só testamos endpoints com corpo JSON

    # baseline
    try:
        baseline = await client.request(method, url, content=_json.dumps(body), headers=auth_headers)
    except Exception:
        return findings

    # 1) NoSQL injection por campo
    for field in list(body.keys()):
        for op in _JSON_OPERATORS:
            try:
                r = await client.request(method, url, content=_json.dumps({**body, field: op}), headers=auth_headers)
            except Exception:
                continue
            sig = _detect_mongo_error(r.text)
            if sig:
                findings.append({"point": f"{method} {urlparse(url).path} campo '{field}'",
                                 "type": "NoSQL Injection", "severity": "ALTA",
                                 "evidence": f"operador {op} causou erro Mongo: '{sig}'"})
                break
            if baseline.status_code >= 400 and r.status_code < 300:
                findings.append({"point": f"{method} {urlparse(url).path} campo '{field}'",
                                 "type": "NoSQL auth/filter bypass", "severity": "CRÍTICA",
                                 "evidence": f"operador {op} retornou {r.status_code} (baseline {baseline.status_code})"})
                break

    # 2) Mass assignment (campo canário)
    try:
        r = await client.request(method, url, content=_json.dumps({**body, CANARY_FIELD: "x"}), headers=auth_headers)
        if r.status_code < 300 and method in ("POST", "PUT", "PATCH"):
            findings.append({"point": f"{method} {urlparse(url).path}",
                             "type": "possível mass assignment", "severity": "ALTA",
                             "evidence": "API aceitou campo extra desconhecido — teste 'saldo'/'role' manualmente"})
        elif r.status_code in (400, 422):
            findings.append({"point": f"{method} {urlparse(url).path}",
                             "type": "schema estrito", "severity": "OK",
                             "evidence": "campo extra rejeitado (bom)"})
    except Exception:
        pass
    return findings


async def scan_authenticated(
    site_url: str,
    login_url: str | None = None,
    login_body: dict | None = None,
    token_key: str | None = None,
    login_method: str = "POST",
    timeout_ms: int = 20000,
    token: str | None = None,
    cookie: str | None = None,
    manual_endpoints: list[dict] | None = None,
    extra_routes: list[str] | None = None,
) -> dict:
    """
    Orquestra o scan autenticado. Três modos de auth:
    - login automático: informe login_url + login_body.
    - token direto: informe `token` (apps com captcha que guardam token em JS).
    - cookie direto: informe `cookie` (apps com sessão via cookie HttpOnly).

    `manual_endpoints`: lista de {method, url, body} para testar diretamente
    (além/no lugar da descoberta automática). Útil quando você já sabe o endpoint.
    """
    result = {"url": site_url, "login": {}, "endpoints": [], "findings": [], "tested": 0}

    if cookie:
        cookies = {}
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()
        result["login"] = {"ok": True, "token_found": False,
                           "cookies": list(cookies.keys()), "detail": "cookie de sessão fornecido"}
    elif token:
        cookies = {}
        result["login"] = {"ok": True, "token_found": True, "cookies": [], "detail": "token fornecido diretamente"}
    else:
        sess = await login(login_url, login_body, method=login_method, token_key=token_key)
        result["login"] = {"ok": sess["ok"], "token_found": bool(sess["token"]),
                           "cookies": list(sess["cookies"].keys()), "detail": sess["detail"]}
        if not sess["ok"]:
            result["error"] = sess["detail"] or "login falhou"
            return result
        token, cookies = sess["token"], sess["cookies"]
    endpoints = await discover_authed_endpoints(site_url, token, cookies, timeout_ms, extra_routes=extra_routes)
    if manual_endpoints:
        endpoints = list(manual_endpoints) + endpoints
    result["endpoints"] = [{"method": e["method"], "url": e["url"], "has_body": isinstance(e.get("body"), dict)}
                           for e in endpoints]

    auth_headers = {"Content-Type": "application/json",
                    "User-Agent": "AgenteMAX-AuthScan/1.0 (authorized testing)"}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if cookie_str:
        auth_headers["Cookie"] = cookie_str

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for call in endpoints:
            if isinstance(call.get("body"), dict) and call["body"]:
                result["tested"] += 1
                result["findings"].extend(await _test_endpoint_authed(client, call, auth_headers))
    return result
