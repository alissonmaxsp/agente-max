"""
Testes da lógica de rotação de chaves e fallback do motor de LLM (run_prompt).

Esta é a parte mais delicada do produto: ao bater limite/erro de chave (429/401/403)
ele deve trocar de chave; um erro não-rotacionável (ex.: 400) deve parar na hora.
Tudo aqui é mockado — não há rede nem chave real.
"""

import httpx
import pytest
import respx

from src import llm

URL = "https://fake-llm.test/v1/chat/completions"


@pytest.fixture
def fake_provider(monkeypatch):
    """Força um provedor estilo OpenAI com 2 chaves e sem fallback de modelo."""
    monkeypatch.setattr(llm, "get_model", lambda *a, **k: ("modelo-x", "openrouter"))

    def _cfg(provider):
        return {"style": "openai", "url": URL, "keys": ["chave-1", "chave-2"], "signup": ""}
    monkeypatch.setattr(llm, "_provider_config", _cfg)


def _ok(text="resposta da IA"):
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


@respx.mock
async def test_rotates_to_next_key_on_429(fake_provider):
    route = respx.post(URL)
    route.side_effect = [httpx.Response(429, text="rate limited"), _ok("ok depois da troca")]

    out = await llm.run_prompt("oi", provider="openrouter", fallback=False)

    assert out == "ok depois da troca"
    assert route.call_count == 2  # tentou a 1ª chave (429) e rotacionou para a 2ª


@respx.mock
async def test_stops_on_non_rotatable_status(fake_provider):
    route = respx.post(URL)
    route.side_effect = [httpx.Response(400, text="bad request")]

    out = await llm.run_prompt("oi", provider="openrouter", fallback=False)

    assert "400" in out
    assert route.call_count == 1  # 400 não rotaciona — para imediatamente


@respx.mock
async def test_returns_last_message_when_all_keys_exhausted(fake_provider):
    route = respx.post(URL)
    route.side_effect = [httpx.Response(429), httpx.Response(429)]

    out = await llm.run_prompt("oi", provider="openrouter", fallback=False)

    assert route.call_count == 2  # esgotou as 2 chaves
    assert "429" in out or "limite" in out.lower()


@respx.mock
async def test_success_on_first_try_calls_once(fake_provider):
    route = respx.post(URL).mock(return_value=_ok("primeira"))
    out = await llm.run_prompt("oi", provider="openrouter", fallback=False)
    assert out == "primeira"
    assert route.call_count == 1


async def test_missing_key_returns_helpful_message(monkeypatch):
    """Sem chave configurada para um provedor que exige, deve orientar o usuário."""
    monkeypatch.setattr(llm, "get_model", lambda *a, **k: ("modelo-x", "groq"))
    monkeypatch.setattr(llm, "_provider_config",
                        lambda p: {"style": "openai", "url": URL, "keys": [], "signup": "https://x"})
    out = await llm.run_prompt("oi", provider="groq", fallback=False)
    assert "não configurada" in out.lower()
