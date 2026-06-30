import asyncio
import time

import pytest

from src import runner


@pytest.mark.asyncio
async def test_run_modules_preserves_order_and_runs_concurrently(monkeypatch):
    """
    Os módulos rodam EM PARALELO (asyncio.gather), mas a ordem do resultado
    deve seguir a ordem de `keys`. Validamos as duas coisas de uma vez.
    """
    keys = ["errors", "secrets", "headers", "sqli"]

    async def fake_run_module(key, url, timeout_ms=15000):
        # O primeiro da lista demora MAIS; se fosse sequencial a ordem viria
        # naturalmente, então o atraso invertido só importa para o tempo total.
        await asyncio.sleep(0.15 if key == "errors" else 0.05)
        return {"key": key, "name": runner.MODULES[key]["name"],
                "findings": [{"severity": "INFO", "point": key, "type": "t", "evidence": "e"}]}

    monkeypatch.setattr(runner, "run_module", fake_run_module)

    start = time.perf_counter()
    out = await runner.run_modules(keys, "https://x.com")
    elapsed = time.perf_counter() - start

    # Ordem preservada
    assert [m["key"] for m in out["modules"]] == keys
    # Concorrente: bem abaixo da soma sequencial (0.15+0.05*3 = 0.30s)
    assert elapsed < 0.28
    assert len(out["all_findings"]) == 4


@pytest.mark.asyncio
async def test_run_modules_dedupes_findings_across_modules(monkeypatch):
    async def fake_run_module(key, url, timeout_ms=15000):
        # Dois módulos retornam o MESMO achado -> deve aparecer só uma vez.
        return {"key": key, "name": runner.MODULES[key]["name"],
                "findings": [{"severity": "ALTA", "point": "p", "type": "t", "evidence": "mesma"}]}

    monkeypatch.setattr(runner, "run_module", fake_run_module)
    out = await runner.run_modules(["sqli", "nosql"], "https://x.com")
    assert len(out["all_findings"]) == 1
