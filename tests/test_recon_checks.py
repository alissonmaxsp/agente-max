"""Testes de recon_checks: métodos HTTP, GraphQL introspection, recon files, fingerprint."""

import httpx
import pytest
import respx

from src.recon_checks import (
    _fingerprint, _check_methods, _check_graphql, _check_recon_files, scan_infra,
)

pytestmark = pytest.mark.integration


def test_fingerprint_detects_revealing_headers():
    findings = _fingerprint({"X-AspNet-Version": "4.0.30319", "X-Runtime": "0.5"})
    assert findings and "tecnologias reveladas" in findings[0]["type"]


def test_fingerprint_clean_headers_no_findings():
    assert _fingerprint({"Content-Type": "text/html"}) == []


@respx.mock
async def test_check_methods_flags_dangerous_allow():
    respx.route(method="OPTIONS").mock(return_value=httpx.Response(
        200, headers={"allow": "GET, POST, PUT, DELETE"}))
    respx.route(method="TRACE").mock(return_value=httpx.Response(405))
    async with httpx.AsyncClient() as client:
        findings = await _check_methods(client, "https://site.test/")
    assert any("métodos perigosos" in f["type"] for f in findings)


@respx.mock
async def test_check_graphql_introspection_open():
    respx.post("https://site.test/graphql").mock(return_value=httpx.Response(
        200, json={"data": {"__schema": {"types": [{"name": "User"}]}}}))
    respx.route(method="POST").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        findings = await _check_graphql(client, "https://site.test")
    assert any("introspection aberta" in f["type"] for f in findings)


@respx.mock
async def test_recon_files_security_txt_missing_and_robots_sensitive():
    respx.get("https://site.test/.well-known/security.txt").mock(
        return_value=httpx.Response(404))
    respx.get("https://site.test/robots.txt").mock(return_value=httpx.Response(
        200, text="User-agent: *\nDisallow: /admin\nDisallow: /backup"))
    async with httpx.AsyncClient() as client:
        findings = await _check_recon_files(client, "https://site.test")
    types = [f["type"] for f in findings]
    assert "security.txt ausente" in types
    assert any("robots.txt revela" in t for t in types)


@respx.mock
async def test_scan_infra_http_skips_tls():
    # Alvo http:// não deve disparar checagem TLS (sem socket real).
    respx.route().mock(return_value=httpx.Response(404))
    result = await scan_infra("http://site.test/")
    assert "findings" in result
    assert not any(f["point"] == "TLS" for f in result["findings"])
