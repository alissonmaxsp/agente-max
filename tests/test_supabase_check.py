"""Testes de supabase_check: extração de credenciais e checagem de RLS (modo direto)."""

import base64
import json

import httpx
import pytest
import respx

from src.supabase_check import (
    extract_credentials, _decode_jwt_role, check_supabase,
)

pytestmark = pytest.mark.integration

SUPA_URL = "https://abcdefghijklmnop.supabase.co"


def _mk_jwt(role: str) -> str:
    """Cria um JWT (não assinado) com o claim role — suficiente p/ ler o payload."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    # Assinatura com >=10 chars para casar com JWT_RE (\.[A-Za-z0-9_-]{10,}$).
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'role': role})}.fakesignature123456"


def test_decode_jwt_role():
    assert _decode_jwt_role(_mk_jwt("anon")) == "anon"
    assert _decode_jwt_role(_mk_jwt("service_role")) == "service_role"
    assert _decode_jwt_role("não-é-jwt") is None


def test_extract_credentials_finds_url_and_roles():
    anon = _mk_jwt("anon")
    service = _mk_jwt("service_role")
    blob = f"const url='{SUPA_URL}'; const k='{anon}'; const admin='{service}';"
    creds = extract_credentials(blob)
    assert creds["url"] == SUPA_URL
    assert creds["anon_key"] == anon
    assert creds["service_role_key"] == service


@respx.mock
async def test_check_supabase_direct_detects_open_rls():
    anon = _mk_jwt("anon")
    # OpenAPI do PostgREST lista a tabela 'contas'.
    respx.get(f"{SUPA_URL}/rest/v1/").mock(return_value=httpx.Response(
        200, json={"definitions": {"contas": {}}}))
    # Leitura aberta: devolve uma linha.
    respx.get(url__regex=rf"{SUPA_URL}/rest/v1/contas.*").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "saldo": 10}]))
    # Escrita aberta: PATCH aceito (204).
    respx.patch(url__regex=rf"{SUPA_URL}/rest/v1/contas.*").mock(
        return_value=httpx.Response(204))

    result = await check_supabase("https://meusite.com", supabase_url=SUPA_URL, anon_key=anon)

    assert result["creds"]["url"] == SUPA_URL
    assert "contas" in result["summary"]["tables_read_open"]
    assert "contas" in result["summary"]["tables_write_open"]


@respx.mock
async def test_check_supabase_direct_protected_tables():
    anon = _mk_jwt("anon")
    respx.get(f"{SUPA_URL}/rest/v1/").mock(return_value=httpx.Response(
        200, json={"definitions": {"contas": {}}}))
    respx.get(url__regex=rf"{SUPA_URL}/rest/v1/contas.*").mock(
        return_value=httpx.Response(401))
    respx.patch(url__regex=rf"{SUPA_URL}/rest/v1/contas.*").mock(
        return_value=httpx.Response(403))

    result = await check_supabase("https://meusite.com", supabase_url=SUPA_URL, anon_key=anon)
    assert result["summary"]["tables_read_open"] == []
    assert result["summary"]["tables_write_open"] == []
