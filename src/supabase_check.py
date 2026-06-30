"""
Checagem de segurança de Supabase (NÃO destrutivo) — focado em impedir que
alguém escreva no seu banco sem autorização (ex.: adicionar saldo/licença oculto).

⚠️  USO AUTORIZADO: rode apenas no SEU projeto Supabase / seu site.

O que ele verifica:
1. Chaves vazadas no front-end:
   - anon key (esperada no front, mas verificamos)
   - service_role key  -> CRÍTICO: ignora o RLS, permite escrever qualquer coisa.
2. RLS de LEITURA: a API REST devolve linhas de tabelas sensíveis sem login?
3. RLS de ESCRITA: a API REST aceita UPDATE sem autorização?
   - Testado de forma SEGURA: PATCH com filtro que NÃO casa com nenhuma linha
     (impossible id). Nada é alterado; só observamos se o RLS bloqueia (401/403)
     ou se a escrita é permitida (200/204) = risco real.
"""

import re
import json
import base64

import httpx
from playwright.async_api import async_playwright


SUPABASE_URL_RE = re.compile(r"https://([a-z0-9]{16,40})\.supabase\.co")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
IMPOSSIBLE_ID = "00000000-0000-0000-0000-000000000000"


def _decode_jwt_role(token: str) -> str | None:
    """Decodifica o payload do JWT e retorna o claim 'role' (anon / service_role)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # corrige padding base64
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        return data.get("role")
    except Exception:
        return None


def extract_credentials(text: str) -> dict:
    """Extrai URL do Supabase e chaves (com seus papéis) de um texto/JS."""
    creds = {"url": None, "anon_key": None, "service_role_key": None, "other_keys": []}

    m = SUPABASE_URL_RE.search(text or "")
    if m:
        creds["url"] = m.group(0)

    for token in set(JWT_RE.findall(text or "")):
        role = _decode_jwt_role(token)
        if role == "anon":
            creds["anon_key"] = token
        elif role == "service_role":
            creds["service_role_key"] = token
        elif role:
            creds["other_keys"].append((role, token))
    return creds


async def _collect_site_source(url: str, timeout_ms: int) -> tuple[str, list]:
    """
    Carrega a página e retorna (blob, network_hits).
    - blob: HTML + conteúdo dos scripts JS (para regex de URL/chaves).
    - network_hits: requisições observadas para *.supabase.co, com headers
      (pega a URL real e a chave 'apikey' que o site de fato envia).
    """
    blob = ""
    net_hits = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        # Monitora requisições para o Supabase (detecção via tráfego real)
        def _on_request(req):
            if ".supabase.co" in req.url:
                net_hits.append({"url": req.url, "headers": dict(req.headers)})
        page.on("request", _on_request)

        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            blob += await page.content()
            srcs = await page.evaluate(
                "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
            )
            async with httpx.AsyncClient(timeout=20.0) as client:
                for src in (srcs or [])[:25]:
                    try:
                        r = await client.get(src)
                        if r.status_code == 200:
                            blob += "\n" + r.text
                    except Exception:
                        continue
        finally:
            await browser.close()
    return blob, net_hits


async def _list_tables(client: httpx.AsyncClient, base: str, key: str) -> list[str]:
    """Lista as tabelas expostas via OpenAPI do PostgREST (/rest/v1/)."""
    try:
        r = await client.get(f"{base}/rest/v1/", headers={"apikey": key, "Authorization": f"Bearer {key}"})
        if r.status_code != 200:
            return []
        spec = r.json()
        defs = spec.get("definitions") or spec.get("components", {}).get("schemas", {})
        return list(defs.keys())
    except Exception:
        return []


async def _test_table(client: httpx.AsyncClient, base: str, key: str, table: str) -> dict:
    """Testa leitura e escrita (segura) de uma tabela. Retorna o status de RLS."""
    h = {"apikey": key, "Authorization": f"Bearer {key}"}
    result = {"table": table, "read": "?", "write": "?"}

    # LEITURA (GET) — apenas lê 1 linha
    try:
        r = await client.get(f"{base}/rest/v1/{table}?select=*&limit=1", headers=h)
        if r.status_code == 200:
            rows = r.json()
            result["read"] = "ABERTO" if isinstance(rows, list) and len(rows) > 0 else "vazio/ok"
        elif r.status_code in (401, 403):
            result["read"] = "protegido"
        else:
            result["read"] = f"http {r.status_code}"
    except Exception:
        result["read"] = "erro"

    # ESCRITA (PATCH) — filtro impossível: NÃO altera nenhuma linha
    try:
        wh = {**h, "Content-Type": "application/json", "Prefer": "return=minimal"}
        r = await client.patch(
            f"{base}/rest/v1/{table}?id=eq.{IMPOSSIBLE_ID}",
            headers=wh, content="{}",
        )
        if r.status_code in (200, 204):
            result["write"] = "ABERTO"          # RLS permitiu o UPDATE (risco!)
        elif r.status_code in (401, 403):
            result["write"] = "protegido"
        else:
            result["write"] = f"http {r.status_code}"  # 400/404 = inconclusivo (ex.: sem coluna id)
    except Exception:
        result["write"] = "erro"

    return result


async def check_supabase(
    url: str,
    timeout_ms: int = 15000,
    max_tables: int = 20,
    supabase_url: str | None = None,
    anon_key: str | None = None,
) -> dict:
    """
    Executa a checagem de Supabase.

    Modo 1 (auto): a partir do SEU site, detecta URL/chave no JS e no tráfego de rede.
    Modo 2 (direto): se `supabase_url` e `anon_key` forem informados, testa direto
    (ideal quando o Supabase só é chamado após login).

    Retorna {site, creds, tables, summary}.
    """
    out = {"site": url, "creds": {}, "tables": [], "summary": {}}
    creds = {"url": None, "anon_key": None, "service_role_key": None, "other_keys": []}

    if supabase_url and anon_key:
        # Modo direto: usa as credenciais informadas pelo dono.
        creds["url"] = SUPABASE_URL_RE.search(supabase_url).group(0) if SUPABASE_URL_RE.search(supabase_url) else supabase_url.rstrip("/")
        role = _decode_jwt_role(anon_key)
        if role == "service_role":
            creds["service_role_key"] = anon_key
        creds["anon_key"] = anon_key
        out["creds"] = {
            "url": creds["url"],
            "anon_key_found": True,
            "service_role_exposed": False,  # informada pelo dono, não vazada
            "other_roles": [],
            "detected_via_network": False,
        }
    else:
        source, net_hits = await _collect_site_source(url, timeout_ms)
        creds = extract_credentials(source)

        # Reforça a detecção com o tráfego real para *.supabase.co
        for hit in net_hits:
            m = SUPABASE_URL_RE.search(hit["url"])
            if m and not creds["url"]:
                creds["url"] = m.group(0)
            apikey = hit["headers"].get("apikey") or ""
            if apikey:
                role = _decode_jwt_role(apikey)
                if role == "service_role":
                    creds["service_role_key"] = apikey
                elif role == "anon" and not creds["anon_key"]:
                    creds["anon_key"] = apikey
                elif not creds["anon_key"]:
                    creds["anon_key"] = apikey

        out["creds"] = {
            "url": creds["url"],
            "anon_key_found": bool(creds["anon_key"]),
            "service_role_exposed": bool(creds["service_role_key"]),
            "other_roles": [r for r, _ in creds["other_keys"]],
            "detected_via_network": bool(net_hits),
        }

    base = creds["url"]
    key = creds["anon_key"] or creds["service_role_key"]
    if base and key:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            tables = await _list_tables(client, base, key)
            for t in tables[:max_tables]:
                out["tables"].append(await _test_table(client, base, key, t))

    # Resumo de risco
    read_open = [t["table"] for t in out["tables"] if t["read"] == "ABERTO"]
    write_open = [t["table"] for t in out["tables"] if t["write"] == "ABERTO"]
    out["summary"] = {
        "service_role_exposed": out["creds"]["service_role_exposed"],
        "tables_read_open": read_open,
        "tables_write_open": write_open,
        "tables_tested": len(out["tables"]),
    }
    return out
