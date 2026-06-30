import json
from typing import Callable, Optional

import httpx
from src.config import settings, parse_keys
from src.model_catalog import get_model, AVAILABLE_MODELS, PROVIDERS_THAT_NEED_KEY

# Status que disparam rotação para a próxima chave/modelo:
# 429 = rate-limit, 401/403 = chave inválida ou sem permissão.
ROTATE_STATUSES = {401, 403, 429}


# ---------------------------------------------------------------------------
# Configuração dos provedores (todos com uso gratuito)
# Cada provedor pode ter VÁRIAS chaves (separadas por vírgula no .env),
# rotacionadas automaticamente quando uma bate no limite.
# ---------------------------------------------------------------------------
def _provider_config(provider: str) -> dict:
    """Retorna URL/chaves/estilo de cada provedor a partir das settings."""
    return {
        "openrouter": {
            "style": "openai",
            "url": "https://openrouter.ai/api/v1/chat/completions",
            "keys": parse_keys(settings.OPENROUTER_API_KEY),
            "signup": "https://openrouter.ai/keys",
        },
        "groq": {
            "style": "openai",
            "url": "https://api.groq.com/openai/v1/chat/completions",
            "keys": parse_keys(settings.GROQ_API_KEY),
            "signup": "https://console.groq.com",
        },
        "mistral": {
            "style": "openai",
            "url": "https://api.mistral.ai/v1/chat/completions",
            "keys": parse_keys(settings.MISTRAL_API_KEY),
            "signup": "https://console.mistral.ai",
        },
        "gemini": {
            "style": "gemini",
            "keys": parse_keys(settings.GEMINI_API_KEY),
            "signup": "https://aistudio.google.com/apikey",
        },
        "ollama": {
            "style": "ollama",
            "url": f"{settings.OLLAMA_HOST}/api/chat",
            "keys": [],  # local não usa chave
            "signup": "https://ollama.com",
        },
        "ollama-cloud": {
            "style": "ollama",
            "url": "https://ollama.com/api/chat",
            "keys": parse_keys(settings.OLLAMA_API_KEY),
            "signup": "https://ollama.com/settings/keys",
        },
    }.get(provider, {})


def _build_prompt(analysis_results: dict) -> str:
    """Monta o prompt estruturado a partir dos logs coletados no site."""
    url = analysis_results["url"]
    page_errors_str = "\n".join([f"- {err['message']}" for err in analysis_results["page_errors"]]) or "Nenhum erro de runtime JS."
    console_errors_str = "\n".join([f"- {err['text']} (Local: {err.get('location', 'Desconhecido')})" for err in analysis_results["console_errors"]]) or "Nenhum console.error."

    network_failures_list = []
    for fail in analysis_results["network_failures"]:
        if "status" in fail:
            network_failures_list.append(f"- HTTP {fail['status']} ({fail['status_text']}) para {fail['url']}")
        else:
            network_failures_list.append(f"- Falha na requisição: {fail['url']} - Erro: {fail['error_text']}")
    network_failures_str = "\n".join(network_failures_list) or "Nenhuma falha de rede detectada."

    return f"""Você é o Agente MAX, um assistente especialista em depuração e garantia de qualidade (QA) de software.
Analise os seguintes logs de erro reais coletados em um site:
URL do site: {url}

[Erros de console (JavaScript não tratado)]:
{page_errors_str}

[Mensagens do Console.error]:
{console_errors_str}

[Falhas de Rede (HTTP 4xx/5xx ou falhas de conexão)]:
{network_failures_str}

Por favor, forneça um relatório em formato Markdown estruturado em:
1. **Resumo Geral dos Problemas:** Um breve sumário dos principais erros encontrados.
2. **Análise de Causa Raiz:** Para cada erro relevante listado, explique o que provavelmente está causando ele (ex: arquivos estáticos ausentes, erros de digitação de código JavaScript, restrições de CORS, etc.).
3. **Sugestões de Correção:** Soluções de código acionáveis ou passos de infraestrutura para corrigir cada problema.

Seja direto, técnico e preciso. Escreva a resposta em português brasileiro (PT-BR)."""


# ---------------------------------------------------------------------------
# Entrada pública
# ---------------------------------------------------------------------------
async def run_prompt(
    prompt: str,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Motor genérico: envia um prompt ao provedor de LLM, com rotação automática
    de chaves (429/401/403) e fallback de modelos free do OpenRouter.

    - `model`: alias do catálogo, 'provider:slug' ou slug cru.
    - `provider`: força o provedor (sobrescreve o do .env quando `model` é slug cru).
    - `on_chunk`: ativa streaming (recebe pedaços de texto em tempo real).
    """
    # Resolve modelo + provedor (prioridade: argumento > .env)
    chosen = model or settings.LLM_MODEL or None
    if chosen:
        slug, prov = get_model(chosen, provider=provider)
    else:
        prov = provider or settings.LLM_PROVIDER
        slug = settings.OPENROUTER_MODEL if prov == "openrouter" else ""
        if slug:
            slug, prov = get_model(slug, provider=prov)

    cfg = _provider_config(prov)
    if not cfg:
        return f"❌ Provedor desconhecido: '{prov}'. Use openrouter, gemini, groq, mistral, ollama-cloud ou ollama."

    keys = cfg.get("keys", [])

    # Checa chave para provedores que exigem
    if prov in PROVIDERS_THAT_NEED_KEY and not keys:
        env_var = {
            "openrouter": "OPENROUTER_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "groq": "GROQ_API_KEY",
            "mistral": "MISTRAL_API_KEY",
            "ollama-cloud": "OLLAMA_API_KEY",
        }[prov]
        return (
            f"⚠️  Chave do provedor '{prov}' não configurada.\n"
            f"   Crie uma chave GRATUITA em: {cfg.get('signup')}\n"
            f"   e adicione no arquivo .env:  {env_var}=\"chave1,chave2,...\""
        )

    # Provedores sem chave (Ollama local) usam uma "chave vazia" como placeholder.
    if not keys:
        keys = [""]

    # Lista de modelos a tentar: o escolhido + fallback de free do OpenRouter.
    candidates = [slug]
    if fallback and prov == "openrouter":
        for info in AVAILABLE_MODELS.values():
            if info["provider"] == "openrouter" and info["slug"] not in candidates:
                candidates.append(info["slug"])

    async def _attempt(model_slug: str, api_key: str) -> tuple[int, str]:
        """Faz uma tentativa para (modelo, chave) e retorna (status, texto)."""
        if cfg["style"] == "gemini":
            return await _gemini_completion(model_slug, api_key, prompt, on_chunk)
        if cfg["style"] == "ollama":
            return await _ollama_completion(cfg["url"], model_slug, prompt, on_chunk, api_key=api_key)
        headers = _openai_headers(api_key)
        payload = {"model": model_slug, "messages": [{"role": "user", "content": prompt}]}
        if on_chunk is not None:
            return await _openai_stream(cfg["url"], payload, headers, on_chunk)
        return await _openai_full(cfg["url"], payload, headers)

    last_message = ""
    first = True
    for cand in candidates:
        for kidx, key in enumerate(keys):
            if not first and on_fallback:
                suffix = f" (chave #{kidx + 1})" if len(keys) > 1 else ""
                on_fallback(f"{cand}{suffix}")
            first = False

            status, text = await _attempt(cand, key)
            if status == 200:
                return text
            last_message = text
            if status not in ROTATE_STATUSES:
                # Erro que não é limite/chave: não adianta rotacionar.
                return text
            # senão: tenta a próxima chave; esgotando as chaves, vai ao próximo modelo.
    return last_message or "❌ Todas as chaves/modelos estão com limite no momento. Tente novamente em instantes."


async def explain_errors(
    analysis_results: dict,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """Gera a análise dos erros (JS/console/rede) coletados de um site."""
    prompt = _build_prompt(analysis_results)
    return await run_prompt(prompt, model=model, provider=provider,
                            on_chunk=on_chunk, fallback=fallback, on_fallback=on_fallback)


async def explain_security(
    scan_result: dict,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """Gera o relatório de segurança a partir dos achados do scanner de SQLi."""
    prompt = _build_security_prompt(scan_result)
    return await run_prompt(prompt, model=model, provider=provider,
                            on_chunk=on_chunk, fallback=fallback, on_fallback=on_fallback)


async def explain_supabase(
    check_result: dict,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """Gera o relatório de segurança do Supabase a partir da checagem de RLS/chaves."""
    prompt = _build_supabase_prompt(check_result)
    return await run_prompt(prompt, model=model, provider=provider,
                            on_chunk=on_chunk, fallback=fallback, on_fallback=on_fallback)


def _build_supabase_prompt(check: dict) -> str:
    """Monta o prompt do relatório de segurança do Supabase."""
    s = check.get("summary", {})
    creds = check.get("creds", {})
    site = check.get("site", "")

    linhas = []
    linhas.append(f"- service_role exposta no front-end: {'SIM (CRÍTICO)' if s.get('service_role_exposed') else 'não'}")
    linhas.append(f"- URL Supabase detectada: {creds.get('url') or 'não encontrada'}")
    linhas.append(f"- Tabelas testadas: {s.get('tables_tested', 0)}")
    linhas.append(f"- Tabelas com LEITURA aberta (sem login): {', '.join(s.get('tables_read_open', [])) or 'nenhuma'}")
    linhas.append(f"- Tabelas com ESCRITA aberta (UPDATE sem login): {', '.join(s.get('tables_write_open', [])) or 'nenhuma'}")
    achados = "\n".join(linhas)

    return f"""Você é o Agente MAX, especialista em segurança de Supabase/Postgres.
Foi feita uma checagem AUTORIZADA e NÃO destrutiva no site: {site}
A preocupação principal do dono é: impedir que alguém escreva no banco sem autorização
(ex.: adicionar saldo ou ativar licença de forma oculta).

[Resultado da checagem]:
{achados}

Escreva um relatório em Markdown (PT-BR) com:
1. **Nível de Risco** (CRÍTICO / ALTO / MÉDIO / BAIXO) e por quê, em uma frase.
2. **O que isso significa** para o risco de alguém adicionar saldo/licença sem permissão.
3. **Correções prioritárias** — passos concretos: nunca expor a service_role no front; ativar RLS
   em TODAS as tabelas; políticas de RLS corretas para SELECT/INSERT/UPDATE; usar colunas como
   `saldo` e `licenca` protegidas (só alteráveis por função no servidor / service_role no backend);
   validação no servidor; e como impedir mass assignment.
4. **Checklist de hardening** do Supabase.
Se nada crítico foi encontrado, confirme mas reforce o checklist. Seja técnico e direto."""


async def explain_nosql(
    scan_result: dict,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """Gera o relatório de NoSQL Injection (MongoDB) a partir dos achados."""
    prompt = _build_nosql_prompt(scan_result)
    return await run_prompt(prompt, model=model, provider=provider,
                            on_chunk=on_chunk, fallback=fallback, on_fallback=on_fallback)


async def explain_report(
    report: dict,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    on_chunk: Optional[Callable[[str], None]] = None,
    fallback: bool = True,
    on_fallback: Optional[Callable[[str], None]] = None,
) -> str:
    """Gera o relatório consolidado de segurança a partir de vários módulos."""
    prompt = _build_report_prompt(report)
    return await run_prompt(prompt, model=model, provider=provider,
                            on_chunk=on_chunk, fallback=fallback, on_fallback=on_fallback)


def _build_report_prompt(report: dict) -> str:
    """Monta o prompt do relatório consolidado (vários módulos)."""
    url = report.get("url", "")
    mods = report.get("modules", [])
    all_f = report.get("all_findings", [])

    linhas = []
    for m in mods:
        if m.get("error"):
            linhas.append(f"### {m['name']}\n- (erro ao executar: {m['error']})")
            continue
        if not m["findings"]:
            linhas.append(f"### {m['name']}\n- Nenhum problema detectado.")
            continue
        itens = "\n".join(
            f"- [{f.get('severity','?')}] {f.get('point','')}: {f.get('type','')} — {f.get('evidence','')}"
            for f in m["findings"]
        )
        linhas.append(f"### {m['name']}\n{itens}")
    corpo = "\n\n".join(linhas) or "Nenhum módulo executado."

    return f"""Você é o Agente MAX, especialista em segurança web.
Auditoria AUTORIZADA e não destrutiva em: {url}. Total de achados: {len(all_f)}.

[Resultados por módulo]:
{corpo}

Escreva um relatório CURTO e DIRETO em Markdown (PT-BR). REGRAS:
- Maximo ~180 palavras. Sem introducao, sem parabens, sem texto de preenchimento.
- NÃO repita informação. Cada achado aparece UMA vez.
- Estrutura exata:

**Risco geral:** <CRÍTICO/ALTO/MÉDIO/BAIXO> — (meia linha de justificativa)

**Achados e correções:**
- **[severidade] problema** → correção em 1 frase
(um item por achado real; se não houver achados, escreva "Nenhum achado relevante.")

**Anti-fraude (saldo/licença):** inclua APENAS se houver risco de escrita/autenticação no banco; senão omita esta seção inteira.

Vá direto ao ponto, tom técnico."""


def _build_nosql_prompt(scan: dict) -> str:
    """Monta o prompt do relatório de NoSQL Injection (MongoDB)."""
    alvo = scan.get("endpoint") or scan.get("url", "")
    findings = scan.get("findings", [])
    tested = scan.get("tested", 0)

    if findings:
        achados = "\n".join(
            f"- [{f['severity']}] {f['point']} ({f['method']}, {f['type']}): {f['evidence']}"
            for f in findings
        )
    else:
        achados = "Nenhuma vulnerabilidade de NoSQL Injection detectada nos pontos testados."

    return f"""Você é o Agente MAX, especialista em segurança de aplicações com MongoDB.
Foi feito um teste AUTORIZADO e NÃO destrutivo de NoSQL Injection.
A preocupação do dono: impedir que alguém burle a autenticação ou manipule queries
para adicionar saldo/licença sem permissão.

Alvo: {alvo}
Pontos/campos testados: {tested}

[Achados]:
{achados}

Escreva um relatório em Markdown (PT-BR) com:
1. **Nível de Risco** (CRÍTICO/ALTO/MÉDIO/BAIXO) em uma frase.
2. **Vulnerabilidades** — para cada achado, explique como um atacante exploraria
   (ex.: login bypass com {{"$ne": null}}, manipular filtros pra ver/alterar dados de outros).
3. **Como Corrigir** — concreto para MongoDB/Node: validar e tipar entradas (nunca passar
   objetos do usuário direto pro find/update), usar `$eq` explícito, sanitizar operadores
   (ex.: express-mongo-sanitize), schemas estritos (Mongoose), e NUNCA confiar em campos
   como `saldo`/`licenca`/`role` vindos do cliente (mass assignment).
4. **Checklist de hardening** para Mongo + API.
Se nada foi encontrado, confirme mas reforce o checklist. Seja técnico e direto."""


def _build_security_prompt(scan_result: dict) -> str:
    """Monta o prompt do relatório de segurança a partir do resultado do scan."""
    url = scan_result.get("url", "")
    findings = scan_result.get("findings", [])
    tested = scan_result.get("tested", 0)

    if findings:
        achados = "\n".join(
            f"- [{f['severity']}] {f['point']} ({f['method']}, {f['type']}): {f['evidence']}"
            for f in findings
        )
    else:
        achados = "Nenhuma vulnerabilidade de SQL Injection detectada nos pontos testados."

    return f"""Você é o Agente MAX, especialista em segurança de aplicações web (foco em SQL Injection e bancos Postgres/Supabase).
Um scan de DETECÇÃO (não destrutivo) foi realizado em um site AUTORIZADO.

URL testada: {url}
Pontos de entrada testados: {tested}

[Achados do scanner]:
{achados}

Escreva um relatório em Markdown (PT-BR) com:
1. **Resumo Executivo:** risco geral em uma frase.
2. **Vulnerabilidades Encontradas:** para cada achado, explique o risco e como um atacante poderia explorá-lo.
3. **Como Corrigir:** correções concretas — uso de consultas parametrizadas, RLS (Row Level Security) no Supabase, validação de entrada, e o que NÃO fazer.
4. **Boas Práticas Extras:** recomendações de hardening para Supabase/Postgres.
Se nenhum achado foi detectado, parabenize mas reforce as boas práticas defensivas. Seja técnico e direto."""


# ---------------------------------------------------------------------------
# OpenAI-compatível (OpenRouter / Groq / Mistral)
# ---------------------------------------------------------------------------
def _openai_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/antigravity/agente-max",
        "X-Title": "Agente MAX CLI",
        "Content-Type": "application/json",
    }


async def _openai_full(url: str, payload: dict, headers: dict) -> tuple[int, str]:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(url, headers=headers, json=payload, timeout=60.0)
            if r.status_code != 200:
                return r.status_code, f"❌ Erro na API (Status {r.status_code}): {r.text}"
            data = r.json()
            return 200, data["choices"][0]["message"]["content"]
    except Exception as e:
        return 0, f"❌ Falha de conexão: {str(e)}"


async def _openai_stream(url: str, payload: dict, headers: dict, on_chunk: Callable[[str], None]) -> tuple[int, str]:
    payload = {**payload, "stream": True}
    full_text = ""
    try:
        async with httpx.AsyncClient() as client:
            async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as r:
                if r.status_code != 200:
                    body = await r.aread()
                    return r.status_code, f"❌ Erro na API (Status {r.status_code}): {body.decode(errors='ignore')}"
                async for line in r.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[len("data:"):].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    piece = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
                    if piece:
                        full_text += piece
                        on_chunk(piece)
        return 200, full_text
    except Exception as e:
        return 0, f"❌ Falha de conexão: {str(e)}"


# ---------------------------------------------------------------------------
# Google Gemini (Google AI Studio)
# ---------------------------------------------------------------------------
async def _gemini_completion(model: str, api_key: str, prompt: str, on_chunk) -> tuple[int, str]:
    base = "https://generativelanguage.googleapis.com/v1beta/models"
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        if on_chunk is not None:
            url = f"{base}/{model}:streamGenerateContent?alt=sse&key={api_key}"
            full_text = ""
            async with httpx.AsyncClient() as client:
                async with client.stream("POST", url, json=body, timeout=120.0) as r:
                    if r.status_code != 200:
                        b = await r.aread()
                        return r.status_code, f"❌ Erro na API Gemini (Status {r.status_code}): {b.decode(errors='ignore')}"
                    async for line in r.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data_str = line[len("data:"):].strip()
                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue
                        for cand in chunk.get("candidates", []):
                            for part in cand.get("content", {}).get("parts", []):
                                piece = part.get("text")
                                if piece:
                                    full_text += piece
                                    on_chunk(piece)
            return 200, full_text
        else:
            url = f"{base}/{model}:generateContent?key={api_key}"
            async with httpx.AsyncClient() as client:
                r = await client.post(url, json=body, timeout=60.0)
                if r.status_code != 200:
                    return r.status_code, f"❌ Erro na API Gemini (Status {r.status_code}): {r.text}"
                data = r.json()
                return 200, data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return 0, f"❌ Falha de conexão com o Gemini: {str(e)}"


# ---------------------------------------------------------------------------
# Ollama (local sem chave, ou cloud com chave Bearer)
# ---------------------------------------------------------------------------
async def _ollama_completion(url: str, model: str, prompt: str, on_chunk, api_key: str = "") -> tuple[int, str]:
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": on_chunk is not None}
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    full_text = ""
    try:
        if on_chunk is not None:
            async with httpx.AsyncClient() as client:
                async with client.stream("POST", url, json=body, headers=headers, timeout=300.0) as r:
                    if r.status_code != 200:
                        b = await r.aread()
                        return r.status_code, f"❌ Erro no Ollama (Status {r.status_code}): {b.decode(errors='ignore')}"
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        piece = chunk.get("message", {}).get("content")
                        if piece:
                            full_text += piece
                            on_chunk(piece)
            return 200, full_text
        else:
            async with httpx.AsyncClient() as client:
                r = await client.post(url, json=body, headers=headers, timeout=300.0)
                if r.status_code != 200:
                    return r.status_code, f"❌ Erro no Ollama (Status {r.status_code}): {r.text}"
                return 200, r.json().get("message", {}).get("content", "")
    except Exception as e:
        if api_key:  # Ollama Cloud
            return 0, (
                f"❌ Não consegui falar com a Ollama Cloud em {url}.\n"
                f"   Verifique sua OLLAMA_API_KEY e se o modelo '{model}' existe em https://ollama.com/search?c=cloud\n"
                f"   Detalhe: {str(e)}"
            )
        return 0, (  # Ollama local
            f"❌ Não consegui falar com o Ollama local em {url}.\n"
            f"   Verifique se ele está rodando (comando: ollama serve) e se o modelo '{model}' está instalado "
            f"(ollama pull {model}).\n   Detalhe: {str(e)}"
        )
