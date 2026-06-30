"""
Teste de Mass Assignment (atribuição em massa) — modo detecção, SEGURO.

⚠️  USO AUTORIZADO: apenas no SEU endpoint de API.

O medo do dono: alguém mandar campos como `saldo`, `licenca`, `role`, `isAdmin`
no JSON de um update e o servidor aceitar, alterando o banco sem permissão.

Como é testado de forma SEGURA (sem mexer em dados reais):
- Enviamos o corpo normal + um campo "canário" inofensivo e inexistente
  (ex.: "__agentemax_canary"). Se a API:
    * REJEITA campos desconhecidos (400/422)  -> schema estrito (BOM).
    * ACEITA calado (2xx)                      -> sem validação estrita = risco
      de mass assignment (alguém poderia tentar 'saldo'/'role').
- NÃO enviamos valores como saldo=999999 (isso seria destrutivo).
"""

import json as _json
import httpx

CANARY_FIELD = "__agentemax_canary"
# Campos sensíveis típicos que NÃO deveriam ser aceitos do cliente (só reportamos o risco)
SENSITIVE_FIELDS = ["saldo", "balance", "credits", "licenca", "license", "role", "is_admin", "isAdmin"]


async def test_mass_assignment(
    endpoint: str,
    body: dict,
    method: str = "PATCH",
    auth_header: str | None = None,
    timeout: float = 20.0,
) -> dict:
    """
    Testa mass assignment no endpoint informado.
    `body`: corpo válido de update (ex.: {"name":"Fulano"}).
    `auth_header`: valor do header Authorization (ex.: "Bearer <token>") se necessário.
    """
    result = {"endpoint": endpoint, "method": method.upper(), "findings": [], "tested": 0}
    headers = {"Content-Type": "application/json",
               "User-Agent": "AgenteMAX-APIScanner/1.0 (authorized testing)"}
    if auth_header:
        headers["Authorization"] = auth_header

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        # Baseline com o corpo normal
        try:
            baseline = await client.request(method, endpoint, content=_json.dumps(body))
        except Exception as e:
            result["error"] = f"Falha ao chamar o endpoint: {e}"
            return result

        result["baseline_status"] = baseline.status_code

        # Envia o corpo + campo canário inofensivo
        result["tested"] = 1
        probe = {**body, CANARY_FIELD: "agentemax_probe_value"}
        try:
            r = await client.request(method, endpoint, content=_json.dumps(probe))
        except Exception as e:
            result["error"] = f"Falha no probe: {e}"
            return result

        if r.status_code in (400, 422):
            result["verdict"] = "PROTEGIDO"
            result["findings"].append({
                "point": "validação de schema", "type": "campos desconhecidos rejeitados",
                "severity": "OK",
                "evidence": f"API rejeitou campo extra (HTTP {r.status_code}) — schema estrito.",
            })
        elif r.status_code < 300:
            result["verdict"] = "RISCO"
            result["findings"].append({
                "point": "endpoint de update", "type": "possível mass assignment",
                "severity": "ALTA",
                "evidence": (f"API aceitou campo extra desconhecido (HTTP {r.status_code}). "
                             f"Pode aceitar campos como {', '.join(SENSITIVE_FIELDS[:4])}... "
                             f"Teste manual recomendado (com cuidado) nesses campos."),
            })
        else:
            result["verdict"] = "INCONCLUSIVO"
            result["findings"].append({
                "point": "endpoint de update", "type": "resposta inesperada",
                "severity": "BAIXA",
                "evidence": f"HTTP {r.status_code} (baseline {baseline.status_code}) — verifique manualmente.",
            })
    return result
