"""
Orquestrador dos módulos de teste do Agente MAX.

Define as categorias (front-end / back-end / banco / completo), executa os
módulos selecionados e normaliza tudo numa lista única de achados para o
relatório consolidado.
"""

import asyncio

from src.browser import analyze_website
from src.security_scan import scan_sqli
from src.nosql_scan import scan_nosql
from src.supabase_check import check_supabase
from src.web_checks import (scan_secrets, check_headers_cookies_cors, scan_exposed_paths,
                            scan_xss, scan_open_redirect)
from src.recon_checks import scan_infra
from src.auth_checks import analyze_jwts


# Registro de módulos: key -> {name, category, run(url, timeout)}
MODULES = {
    "errors":   {"name": "Erros de front-end (JS/console/rede)", "cat": "frontend"},
    "secrets":  {"name": "Segredos expostos no JS",              "cat": "frontend"},
    "headers":  {"name": "Headers / Cookies / CORS",             "cat": "frontend"},
    "sqli":     {"name": "SQL Injection",                        "cat": "backend"},
    "nosql":    {"name": "NoSQL Injection (MongoDB)",            "cat": "backend"},
    "paths":    {"name": "Arquivos / rotas expostos",            "cat": "backend"},
    "supabase": {"name": "Supabase (RLS + chaves)",             "cat": "database"},
    # Avançados (URL-only)
    "jwt":      {"name": "Autenticação & JWT (tokens)",          "cat": "avancado"},
    "xss":      {"name": "XSS refletido",                        "cat": "avancado"},
    "redirect": {"name": "Open Redirect",                        "cat": "avancado"},
    "infra":    {"name": "Infra / Recon (TLS, métodos, GraphQL)", "cat": "avancado"},
}

CATEGORIES = {
    "frontend": ["errors", "secrets", "headers"],
    "backend":  ["sqli", "nosql", "paths"],
    "database": ["supabase", "sqli", "nosql"],
    "avancado": ["jwt", "xss", "redirect", "infra"],
}


def category_modules(category: str) -> list[str]:
    if category == "completo":
        # Ordem agradável, sem duplicar
        seen, out = set(), []
        for cat in ("frontend", "backend", "database", "avancado"):
            for k in CATEGORIES[cat]:
                if k not in seen:
                    seen.add(k); out.append(k)
        return out
    return CATEGORIES.get(category, [])


def _normalize(key: str, raw: dict) -> list[dict]:
    """Converte o resultado de cada módulo numa lista padronizada de achados."""
    findings = []

    if key == "errors":
        pe = len(raw.get("page_errors", []))
        ce = len(raw.get("console_errors", []))
        nf = len(raw.get("network_failures", []))
        if pe or ce or nf:
            findings.append({
                "severity": "INFO", "point": "front-end",
                "type": "erros detectados",
                "evidence": f"{pe} erros JS, {ce} console.error, {nf} falhas de rede",
            })
        return findings

    if key == "supabase":
        s = raw.get("summary", {})
        if s.get("service_role_exposed"):
            findings.append({"severity": "CRÍTICA", "point": "Supabase",
                             "type": "service_role exposta no front-end",
                             "evidence": "Chave que ignora o RLS está acessível no cliente!"})
        for t in s.get("tables_read_open", []):
            findings.append({"severity": "ALTA", "point": f"tabela {t}",
                             "type": "RLS de leitura aberto", "evidence": "leitura sem autenticação"})
        for t in s.get("tables_write_open", []):
            findings.append({"severity": "CRÍTICA", "point": f"tabela {t}",
                             "type": "RLS de escrita aberto",
                             "evidence": "UPDATE aceito sem autenticação — risco de alterar saldo/licença!"})
        return findings

    # Módulos que já retornam 'findings' no formato padrão
    return raw.get("findings", [])


def _dedupe(findings: list[dict]) -> list[dict]:
    """Remove achados duplicados pela combinação (severidade, ponto, tipo, evidência)."""
    seen, out = set(), []
    for f in findings:
        key = (f.get("severity"), f.get("point"), f.get("type"), f.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


async def run_module(key: str, url: str, timeout_ms: int = 15000) -> dict:
    """Executa um módulo e devolve {key, name, findings, raw}."""
    info = MODULES[key]
    try:
        if key == "errors":
            raw = await analyze_website(url, timeout_ms=timeout_ms)
        elif key == "secrets":
            raw = await scan_secrets(url, timeout_ms=timeout_ms)
        elif key == "headers":
            raw = await check_headers_cookies_cors(url)
        elif key == "sqli":
            raw = await scan_sqli(url, timeout_ms=timeout_ms)
        elif key == "nosql":
            raw = await scan_nosql(url, timeout_ms=timeout_ms)
        elif key == "paths":
            raw = await scan_exposed_paths(url)
        elif key == "supabase":
            raw = await check_supabase(url, timeout_ms=timeout_ms)
        elif key == "jwt":
            raw = await analyze_jwts(url, timeout_ms=timeout_ms)
        elif key == "xss":
            raw = await scan_xss(url, timeout_ms=timeout_ms)
        elif key == "redirect":
            raw = await scan_open_redirect(url, timeout_ms=timeout_ms)
        elif key == "infra":
            raw = await scan_infra(url, timeout_ms=timeout_ms)
        else:
            raw = {}
    except Exception as e:
        return {"key": key, "name": info["name"], "findings": [], "error": str(e)}

    return {"key": key, "name": info["name"], "findings": _dedupe(_normalize(key, raw)), "raw": raw}


async def run_modules(keys: list[str], url: str, timeout_ms: int = 15000, on_progress=None) -> dict:
    """
    Executa vários módulos EM PARALELO e consolida os achados (sem duplicatas).

    Os módulos rodam concorrentemente (asyncio); `on_progress` é chamado conforme
    cada um termina. A ordem dos resultados em `modules` segue a ordem de `keys`,
    deixando o relatório consolidado estável e determinístico.
    """
    out = {"url": url, "modules": [], "all_findings": []}

    async def _run(key: str) -> dict:
        mod = await run_module(key, url, timeout_ms=timeout_ms)
        if on_progress:
            on_progress(MODULES[key]["name"])
        return mod

    mods = await asyncio.gather(*(_run(key) for key in keys))

    global_seen = set()
    for mod in mods:  # ordem de `keys` preservada pelo gather
        out["modules"].append(mod)
        for f in mod["findings"]:
            # Dedupe global: mesma evidência+ponto não repete entre módulos diferentes.
            gkey = (f.get("point"), f.get("type"), f.get("evidence"))
            if gkey in global_seen:
                continue
            global_seen.add(gkey)
            out["all_findings"].append({**f, "module": mod["name"]})
    return out
