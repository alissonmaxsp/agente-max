"""
Testes ponta-a-ponta de browser (Playwright real) contra um app vulnerável local.

Exercitam o caminho que os mocks não cobrem: lançar o Chromium, navegar de
verdade e capturar erros/descobrir formulários. Pulam automaticamente se o
navegador do Playwright não estiver instalado.
"""

import pytest

from src.browser import analyze_website
from src.security_scan import _discover_entry_points

pytestmark = [pytest.mark.browser, pytest.mark.integration]


async def test_analyze_website_captures_real_errors(vuln_server, chromium_ready):
    results = await analyze_website(vuln_server, timeout_ms=15000)

    # Exceção JS não tratada capturada via 'pageerror'.
    assert any("nao tratada" in e["message"] for e in results["page_errors"])
    # console.error capturado.
    assert any("console" in e["text"] for e in results["console_errors"])
    # Recurso 404 (/missing-bundle.js) registrado como falha de rede.
    assert any(f.get("status") == 404 or "missing-bundle" in f.get("url", "")
               for f in results["network_failures"])


async def test_analyze_website_handles_unreachable_target(chromium_ready):
    # Porta provavelmente fechada -> deve registrar falha de navegação, sem crashar.
    results = await analyze_website("http://127.0.0.1:1", timeout_ms=4000)
    assert results["page_errors"]
    assert any("navegação" in e["message"].lower() or "navega" in e["message"].lower()
               for e in results["page_errors"])


async def test_discover_entry_points_finds_form(vuln_server, chromium_ready):
    points = await _discover_entry_points(vuln_server, timeout_ms=15000)
    forms = points["forms"]
    assert forms, "deveria descobrir o formulário da página"
    assert any("q" in f.get("inputs", []) for f in forms)
