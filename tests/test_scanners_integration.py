"""
Testes de INTEGRAÇÃO dos scanners — exercitam o fluxo real (descoberta →
injeção → detecção) com HTTP simulado via `respx`, sem rede nem alvo externo.

É isto que valida que os scanners REALMENTE acham (e não acham) vulnerabilidades,
em vez de só testar os regexes de detecção isoladamente.
"""

import httpx
import pytest
import respx

from src import security_scan
from src.security_scan import scan_sqli, _probe_form
# Alias para não colidir com a coleta do pytest (funções `test_*` do código-fonte
# seriam recolhidas como casos de teste).
from src.api_checks import test_mass_assignment as run_mass_assignment
from src.auth_checks import test_login_protection as run_login_protection, test_idor as run_idor
from src.nosql_scan import test_json_endpoint as run_json_endpoint

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- #
# SQL Injection (error-based) — fluxo completo de scan_sqli
# --------------------------------------------------------------------------- #
@respx.mock
async def test_scan_sqli_detects_error_based(monkeypatch):
    # Evita o Playwright: simula a descoberta retornando um query param.
    async def fake_discover(url, timeout_ms):
        return {"query_params": ["id"], "forms": []}
    monkeypatch.setattr(security_scan, "_discover_entry_points", fake_discover)

    # Qualquer GET no alvo devolve um erro de Postgres -> deve detectar.
    respx.get("https://vuln.test/produto").mock(
        return_value=httpx.Response(500, text='ERROR: syntax error at or near "OR"')
    )

    result = await scan_sqli("https://vuln.test/produto?id=1")

    assert result["tested"] == 1
    assert any(f["type"] == "error-based" and f["severity"] == "ALTA"
               for f in result["findings"])


@respx.mock
async def test_scan_sqli_clean_site_has_no_findings(monkeypatch):
    async def fake_discover(url, timeout_ms):
        return {"query_params": ["id"], "forms": []}
    monkeypatch.setattr(security_scan, "_discover_entry_points", fake_discover)

    # Resposta normal, mesmo tamanho/status para TRUE/FALSE/ERR -> sem achado.
    respx.get("https://safe.test/p").mock(
        return_value=httpx.Response(200, text="<html>conteúdo normal estável</html>")
    )
    result = await scan_sqli("https://safe.test/p?id=1")
    assert result["findings"] == []


@respx.mock
async def test_probe_form_post_detects_sql_error():
    respx.post("https://vuln.test/login").mock(
        return_value=httpx.Response(200, text="You have an error in your SQL syntax")
    )
    async with httpx.AsyncClient() as client:
        findings = await _probe_form(
            client, {"action": "https://vuln.test/login", "method": "post", "inputs": ["user"]}
        )
    assert findings and findings[0]["method"] == "POST"


# --------------------------------------------------------------------------- #
# Mass Assignment
# --------------------------------------------------------------------------- #
@respx.mock
async def test_mass_assignment_flags_risk_when_extra_field_accepted():
    respx.patch("https://api.test/user").mock(return_value=httpx.Response(200, json={"ok": True}))
    result = await run_mass_assignment("https://api.test/user", {"name": "X"})
    assert result["verdict"] == "RISCO"
    assert result["findings"][0]["severity"] == "ALTA"


@respx.mock
async def test_mass_assignment_protected_when_extra_field_rejected():
    respx.patch("https://api.test/user").mock(return_value=httpx.Response(422, json={"err": "x"}))
    result = await run_mass_assignment("https://api.test/user", {"name": "X"})
    assert result["verdict"] == "PROTEGIDO"
    assert result["findings"][0]["severity"] == "OK"


# --------------------------------------------------------------------------- #
# Brute force / rate-limit
# --------------------------------------------------------------------------- #
@respx.mock
async def test_login_protection_detects_rate_limit():
    route = respx.post("https://api.test/login")
    # Primeiras tentativas 401, depois 429 (rate-limit ativado).
    route.side_effect = [httpx.Response(401)] * 3 + [httpx.Response(429)] * 5
    result = await run_login_protection("https://api.test/login", {"email": "a@a.com", "password": "x"}, attempts=8)
    assert any(f["severity"] == "OK" for f in result["findings"])


@respx.mock
async def test_login_protection_flags_missing_rate_limit():
    respx.post("https://api.test/login").mock(return_value=httpx.Response(401))
    result = await run_login_protection("https://api.test/login", {"email": "a@a.com", "password": "x"}, attempts=5)
    assert any(f["severity"] == "ALTA" for f in result["findings"])


# --------------------------------------------------------------------------- #
# IDOR
# --------------------------------------------------------------------------- #
@respx.mock
async def test_idor_detects_neighbor_access():
    # Qualquer /users/<n> devolve 200 com corpo -> IDOR.
    respx.get(url__regex=r"https://api\.test/users/\d+").mock(
        return_value=httpx.Response(200, text="dados confidenciais de outro usuário aqui")
    )
    result = await run_idor("https://api.test/users/100", "100")
    assert result["tested"] > 0
    assert any(f["type"] == "possível IDOR" for f in result["findings"])


async def test_idor_rejects_non_numeric_id():
    result = await run_idor("https://api.test/users/abc", "abc")
    assert "error" in result


# --------------------------------------------------------------------------- #
# NoSQL Injection — auth bypass
# --------------------------------------------------------------------------- #
@respx.mock
async def test_nosql_endpoint_detects_auth_bypass():
    route = respx.post("https://api.test/login")
    # Baseline (login válido falha) = 401; injeção de operador retorna 200 -> bypass.
    route.side_effect = [httpx.Response(401)] + [httpx.Response(200, json={"token": "x"})] * 10
    result = await run_json_endpoint(
        "https://api.test/login", {"email": "a@a.com", "password": "x"}
    )
    assert any(f["type"] == "auth-bypass" and f["severity"] == "CRÍTICA"
               for f in result["findings"])
