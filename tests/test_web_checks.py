"""Testes de web_checks: headers/cookies/CORS, paths expostos, XSS e open redirect."""

import httpx
import pytest
import respx

from src.web_checks import (
    _set_param, _SECRET_RES,
    check_headers_cookies_cors, scan_exposed_paths, scan_xss, scan_open_redirect,
)

pytestmark = pytest.mark.integration


def test_set_param_preserves_others():
    out = _set_param("https://x.com/p?a=1&b=2", "a", "INJ")
    assert "a=INJ" in out and "b=2" in out


def test_secret_patterns_match_known_keys():
    assert _SECRET_RES["AWS Access Key"].search("AKIAIOSFODNN7EXAMPLE")
    assert _SECRET_RES["Stripe Secret (live)"].search("sk_live_abc123def456ghi789")
    assert _SECRET_RES["Private Key Block"].search("-----BEGIN RSA PRIVATE KEY-----")
    assert not _SECRET_RES["AWS Access Key"].search("texto comum sem chave")


@respx.mock
async def test_headers_flags_missing_security_headers_and_open_cors():
    respx.get("https://site.test").mock(return_value=httpx.Response(
        200,
        headers=[("access-control-allow-origin", "*"),
                 ("set-cookie", "session=abc123"),
                 ("server", "nginx/1.0")],
        text="ok",
    ))
    result = await check_headers_cookies_cors("https://site.test")
    types = [f["type"] for f in result["findings"]]
    assert any("header ausente: content-security-policy" in t for t in types)
    assert any("CORS liberado (*)" == t for t in types)
    assert any("cookie inseguro" == t for t in types)
    assert any("info exposta (server)" == t for t in types)


@respx.mock
async def test_exposed_paths_detects_env_file():
    respx.get("https://site.test/.env").mock(return_value=httpx.Response(
        200, text="DB_PASSWORD=segredo\nSECRET=x\nAPI_KEY=y"))
    # Demais caminhos: 404.
    respx.route(method="GET").mock(return_value=httpx.Response(404, text="not found"))

    result = await scan_exposed_paths("https://site.test/")
    assert result["tested"] > 0
    assert any(".env" in f["point"] and f["severity"] == "ALTA" for f in result["findings"])


@respx.mock
async def test_xss_reflected_detected():
    respx.get("https://site.test/busca").mock(return_value=httpx.Response(
        200, text="resultados para agtmax9z<svg/onload=1> aqui"))
    result = await scan_xss("https://site.test/busca?q=1")
    assert any(f["type"] == "XSS refletido" for f in result["findings"])


@respx.mock
async def test_xss_escaped_is_not_flagged():
    respx.get("https://site.test/busca").mock(return_value=httpx.Response(
        200, text="resultados para agtmax9z&lt;svg/onload=1&gt; (escapado)"))
    result = await scan_xss("https://site.test/busca?q=1")
    assert result["findings"] == []


@respx.mock
async def test_open_redirect_detected():
    respx.get("https://site.test/go").mock(return_value=httpx.Response(
        302, headers={"location": "https://evil-agentemax.example/x"}))
    result = await scan_open_redirect("https://site.test/go?next=/home")
    assert any(f["type"] == "open redirect" for f in result["findings"])
