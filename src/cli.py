import sys
import asyncio
import click

# Garante saída UTF-8 mesmo em consoles Windows (cp1252), evitando
# UnicodeEncodeError ao imprimir emojis/acentos.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

import json as _json
from src.browser import analyze_website
from src.llm import explain_errors, explain_security, explain_supabase, explain_nosql, explain_report
from src.security_scan import scan_sqli
from src.supabase_check import check_supabase
from src.nosql_scan import scan_nosql, test_json_endpoint
from src.api_checks import test_mass_assignment
from src.auth_checks import test_login_protection, test_idor
from src.authed_scan import scan_authenticated
from src.runner import run_modules, category_modules, CATEGORIES
from src.report import save_report, SUPPORTED_FORMATS
from src.config import settings, parse_keys
from src.model_catalog import AVAILABLE_MODELS, get_model, models_by_provider

@click.group()
def cli():
    """Agente MAX CLI - Ferramenta Inteligente de Auditoria de Sites (Open Source)."""
    pass

@cli.command()
@click.argument("url")
@click.option("--timeout", default=15000, help="Tempo limite em milissegundos para carregar a página.")
@click.option("--no-ai", is_flag=True, help="Desativa o diagnóstico por IA (OpenRouter), exibindo apenas logs crus.")
@click.option("--model", "-m", default=None, help="Modelo (alias do catálogo, 'provider:slug' ou slug). Veja 'models'.")
@click.option("--provider", "-p", default=None, help="Provedor: openrouter, gemini, groq, mistral ou ollama.")
@click.option("--no-stream", is_flag=True, help="Desativa o streaming: espera a resposta completa antes de exibir.")
def run(url, timeout, no_ai, model, provider, no_stream):
    """
    Varre a URL informada em busca de erros reais (JS, Console, Rede)
    e gera um relatório explicativo com IA.
    """
    click.echo(f"🔍 Acessando: {url} ...")
    
    try:
        # Executa automação de navegador assíncrona
        results = asyncio.run(analyze_website(url, timeout_ms=timeout))
    except Exception as e:
        click.echo(f"❌ Erro crítico ao iniciar navegador: {e}", err=True)
        return

    # Contagem de erros
    page_errors_count = len(results["page_errors"])
    console_errors_count = len(results["console_errors"])
    network_failures_count = len(results["network_failures"])
    total_errors = page_errors_count + console_errors_count + network_failures_count

    click.echo("\n--- [ RESULTADOS DA CAPTURA ] ---")
    click.echo(f"❌ Erros de runtime JS: {page_errors_count}")
    click.echo(f"⚠️  console.error() emitidos: {console_errors_count}")
    click.echo(f"🔌 Falhas de Requisição/Rede: {network_failures_count}")
    click.echo(f"---------------------------------\n")

    if total_errors == 0:
        click.echo("✅ Nenhum erro detectado no site! Excelente.")
        return

    # Exibe logs crus caso solicitado
    if no_ai:
        click.echo("📝 Exibindo logs crus (--no-ai ativo):")
        if page_errors_count:
            click.echo("\n[Erros de runtime JS]")
            for err in results["page_errors"]:
                click.echo(f"- {err['message']}\nStack: {err['stack']}")
        if console_errors_count:
            click.echo("\n[Console.error]")
            for err in results["console_errors"]:
                click.echo(f"- {err['text']}")
        if network_failures_count:
            click.echo("\n[Falhas de Rede/HTTP]")
            for err in results["network_failures"]:
                if "status" in err:
                    click.echo(f"- HTTP {err['status']} ({err['status_text']}) para {err['url']}")
                else:
                    click.echo(f"- Falha: {err['url']} - Erro: {err['error_text']}")
        return

    # Executa o diagnóstico por IA
    ref = model or settings.LLM_MODEL or (settings.OPENROUTER_MODEL if (provider or settings.LLM_PROVIDER) == "openrouter" else "")
    slug, prov = get_model(ref, provider=provider) if ref else ("(padrão do provedor)", provider or settings.LLM_PROVIDER)
    click.echo(f"🧠 Solicitando análise via {prov} (modelo: {slug})...")
    click.echo("\n--- [ ANÁLISE DO AGENTE MAX ] ---\n")

    def _on_fallback(slug):
        click.echo(f"\n⏭️  Rate-limit no modelo anterior. Tentando: {slug} ...\n")

    if no_stream:
        analysis = asyncio.run(explain_errors(results, model=model, provider=provider, on_fallback=_on_fallback))
        click.echo(analysis)
    else:
        # Streaming: imprime a resposta em tempo real conforme ela chega.
        printed = {"any": False}

        def _print_chunk(piece: str):
            printed["any"] = True
            click.echo(piece, nl=False)

        full = asyncio.run(
            explain_errors(results, model=model, provider=provider, on_chunk=_print_chunk, on_fallback=_on_fallback)
        )
        if printed["any"]:
            click.echo()  # quebra de linha final
        else:
            # Nada foi transmitido (ex.: erro 429/4xx) — mostra a mensagem retornada.
            click.echo(full)

    click.echo("\n---------------------------------")


@cli.command()
@click.argument("url")
@click.option("--timeout", default=15000, help="Timeout (ms) para carregar a página na descoberta.")
@click.option("--model", "-m", default=None, help="Modelo para o relatório de remediação por IA.")
@click.option("--provider", "-p", default=None, help="Provedor de LLM para o relatório.")
@click.option("--yes", is_flag=True, help="Confirma que você tem autorização para testar o alvo (pula a pergunta).")
def scan(url, timeout, model, provider, yes):
    """
    Scanner de SQL Injection (detecção, NÃO destrutivo) para alvos AUTORIZADOS.

    Testa parâmetros de query e formulários do site em busca de injeção SQL
    (foco em Postgres/Supabase) e gera um relatório de correção com IA.
    """
    click.echo("🔒 Agente MAX - Scanner de SQL Injection (modo detecção)\n")
    click.echo("⚠️  Use APENAS em sites/APIs que você é dono ou tem autorização explícita.")
    click.echo("    Testar alvos de terceiros sem permissão é ilegal.\n")

    if not yes:
        if not click.confirm(f"Você confirma ter autorização para testar {url}?", default=False):
            click.echo("❌ Scan cancelado. (Use apenas em alvos autorizados.)")
            return

    click.echo(f"\n🔍 Descobrindo pontos de entrada e testando {url} ...")
    try:
        result = asyncio.run(scan_sqli(url, timeout_ms=timeout))
    except Exception as e:
        click.echo(f"❌ Erro durante o scan: {e}", err=True)
        return

    ep = result["entry_points"]
    n_params = len(ep.get("query_params", []))
    n_forms = len(ep.get("forms", []))
    click.echo("\n--- [ PONTOS DE ENTRADA ] ---")
    click.echo(f"🔗 Parâmetros de query: {n_params}")
    click.echo(f"📝 Formulários: {n_forms}")
    click.echo(f"🧪 Campos testados: {result['tested']}")
    if ep.get("discovery_error"):
        click.echo(f"⚠️  Aviso na descoberta: {ep['discovery_error']}")

    findings = result["findings"]
    click.echo("\n--- [ ACHADOS ] ---")
    if findings:
        for f in findings:
            click.echo(f"🚨 [{f['severity']}] {f['point']} ({f['method']}, {f['type']})")
            click.echo(f"     {f['evidence']}")
    else:
        click.echo("✅ Nenhuma vulnerabilidade de SQL Injection detectada nos pontos testados.")

    if result["tested"] == 0:
        click.echo("\nℹ️  Nenhum ponto de entrada testável encontrado (sem query params nem formulários).")
        return

    # Relatório de remediação por IA (streaming)
    click.echo("\n🧠 Gerando relatório de segurança e correções...\n")
    click.echo("--- [ RELATÓRIO DE SEGURANÇA ] ---\n")

    printed = {"any": False}

    def _chunk(piece: str):
        printed["any"] = True
        click.echo(piece, nl=False)

    full = asyncio.run(explain_security(result, model=model, provider=provider, on_chunk=_chunk))
    if printed["any"]:
        click.echo()
    else:
        click.echo(full)
    click.echo("\n----------------------------------")


@cli.command(name="supabase-scan")
@click.argument("url")
@click.option("--timeout", default=15000, help="Timeout (ms) para carregar a página.")
@click.option("--model", "-m", default=None, help="Modelo para o relatório por IA.")
@click.option("--provider", "-p", default=None, help="Provedor de LLM para o relatório.")
@click.option("--yes", is_flag=True, help="Confirma autorização (pula a pergunta).")
@click.option("--supabase-url", default=None, help="URL do seu Supabase (modo direto, sem precisar detectar no site).")
@click.option("--key", "anon_key", default=None, help="Sua anon key do Supabase (modo direto).")
def supabase_scan(url, timeout, model, provider, yes, supabase_url, anon_key):
    """
    Checa a segurança do Supabase do SEU site (NÃO destrutivo): chaves vazadas
    e RLS de leitura/escrita — pra impedir que adicionem saldo/licença sem permissão.

    Modo direto (recomendado p/ apps com login): informe --supabase-url e --key.
    """
    click.echo("🔒 Agente MAX - Checagem de Segurança Supabase (modo detecção)\n")
    click.echo("⚠️  Use APENAS no SEU projeto Supabase / seu site.\n")

    if not yes:
        alvo = supabase_url or url
        if not click.confirm(f"Você confirma ser o dono de {alvo}?", default=False):
            click.echo("❌ Cancelado.")
            return

    if supabase_url and anon_key:
        click.echo(f"\n🔍 Testando direto o Supabase: {supabase_url} ...")
    else:
        click.echo(f"\n🔍 Coletando o site e analisando o Supabase em {url} ...")
    try:
        result = asyncio.run(check_supabase(url, timeout_ms=timeout, supabase_url=supabase_url, anon_key=anon_key))
    except Exception as e:
        click.echo(f"❌ Erro durante a checagem: {e}", err=True)
        return

    creds = result["creds"]
    s = result["summary"]
    click.echo("\n--- [ CREDENCIAIS DETECTADAS ] ---")
    click.echo(f"🔗 URL Supabase: {creds.get('url') or 'não encontrada'}")
    click.echo(f"🔑 anon key no front: {'sim' if creds.get('anon_key_found') else 'não'}")
    if creds.get("service_role_exposed"):
        click.echo("🚨 service_role EXPOSTA no front-end — CRÍTICO! Qualquer um pode escrever no banco.")
    else:
        click.echo("✅ service_role não exposta no front-end.")

    if result["tables"]:
        click.echo("\n--- [ RLS POR TABELA ] ---")
        for t in result["tables"]:
            flag = "🚨" if "ABERTO" in (t["read"], t["write"]) else "  "
            click.echo(f"{flag} {t['table']:<28} leitura={t['read']:<10} escrita={t['write']}")

    click.echo("\n--- [ RESUMO DE RISCO ] ---")
    click.echo(f"Tabelas com LEITURA aberta: {', '.join(s['tables_read_open']) or 'nenhuma'}")
    click.echo(f"Tabelas com ESCRITA aberta: {', '.join(s['tables_write_open']) or 'nenhuma'}")

    if not creds.get("url"):
        click.echo("\nℹ️  Não detectei Supabase no site (pode estar carregado de outra forma). Nada a analisar.")
        return

    click.echo("\n🧠 Gerando relatório e correções...\n")
    click.echo("--- [ RELATÓRIO DE SEGURANÇA SUPABASE ] ---\n")
    printed = {"any": False}

    def _chunk(piece: str):
        printed["any"] = True
        click.echo(piece, nl=False)

    full = asyncio.run(explain_supabase(result, model=model, provider=provider, on_chunk=_chunk))
    if printed["any"]:
        click.echo()
    else:
        click.echo(full)
    click.echo("\n----------------------------------")


@cli.command(name="nosql-scan")
@click.argument("url")
@click.option("--timeout", default=15000, help="Timeout (ms) para carregar a página.")
@click.option("--endpoint", default=None, help="Endpoint de API JSON p/ teste direto (ex.: https://api.site.com/login).")
@click.option("--body", default=None, help='JSON de exemplo p/ o endpoint (ex.: \'{"email":"a@a.com","password":"x"}\').')
@click.option("--method", default="POST", help="Método HTTP do endpoint (POST/GET/PUT...).")
@click.option("--model", "-m", default=None, help="Modelo para o relatório por IA.")
@click.option("--provider", "-p", default=None, help="Provedor de LLM para o relatório.")
@click.option("--yes", is_flag=True, help="Confirma autorização (pula a pergunta).")
def nosql_scan(url, timeout, endpoint, body, method, model, provider, yes):
    """
    Scanner de NoSQL Injection (MongoDB), NÃO destrutivo, para alvos AUTORIZADOS.

    Modo auto: testa query params do site e lista os endpoints de API observados.
    Modo direto: --endpoint + --body testam um endpoint JSON (ex.: login) injetando
    operadores Mongo ($ne, $gt, $regex) em cada campo — detecta bypass de auth.
    """
    click.echo("🔒 Agente MAX - Scanner de NoSQL Injection / MongoDB (modo detecção)\n")
    click.echo("⚠️  Use APENAS em sites/APIs que você é dono ou tem autorização.\n")

    alvo = endpoint or url
    if not yes:
        if not click.confirm(f"Você confirma ter autorização para testar {alvo}?", default=False):
            click.echo("❌ Cancelado.")
            return

    # Modo direto: endpoint + body
    if endpoint and body:
        try:
            body_dict = _json.loads(body)
        except Exception as e:
            click.echo(f"❌ JSON inválido em --body: {e}", err=True)
            return
        click.echo(f"\n🔍 Testando endpoint {method.upper()} {endpoint} ...")
        result = asyncio.run(test_json_endpoint(endpoint, body_dict, method=method))
        result["url"] = endpoint
    else:
        click.echo(f"\n🔍 Descobrindo pontos de entrada em {url} ...")
        result = asyncio.run(scan_nosql(url, timeout_ms=timeout))
        api_calls = result.get("api_calls", [])
        if api_calls:
            click.echo(f"\n--- [ ENDPOINTS DE API OBSERVADOS ({len(api_calls)}) ] ---")
            for c in api_calls[:15]:
                click.echo(f"  {c['method']:5} {c['url']}")
            click.echo("  💡 Para testar um deles, use: nosql-scan <url> --endpoint <api> --body '<json>'")

    click.echo(f"\n--- [ ACHADOS ] (campos testados: {result.get('tested', 0)}) ---")
    findings = result.get("findings", [])
    if findings:
        for f in findings:
            click.echo(f"🚨 [{f['severity']}] {f['point']} ({f['method']}, {f['type']})")
            click.echo(f"     {f['evidence']}")
    else:
        click.echo("✅ Nenhuma vulnerabilidade de NoSQL Injection detectada nos pontos testados.")

    if result.get("error"):
        click.echo(f"⚠️  {result['error']}")

    if result.get("tested", 0) == 0:
        click.echo("\nℹ️  Nada testável aqui. Use o modo direto (--endpoint + --body) no seu login/API.")
        return

    click.echo("\n🧠 Gerando relatório de segurança...\n")
    click.echo("--- [ RELATÓRIO NoSQL/MongoDB ] ---\n")
    printed = {"any": False}

    def _nchunk(piece: str):
        printed["any"] = True
        click.echo(piece, nl=False)

    full = asyncio.run(explain_nosql(result, model=model, provider=provider, on_chunk=_nchunk))
    if printed["any"]:
        click.echo()
    else:
        click.echo(full)
    click.echo("\n----------------------------------")


@cli.command(name="mass-assign")
@click.argument("endpoint")
@click.option("--body", required=True, help='JSON válido de update, ex.: \'{"name":"Fulano"}\'.')
@click.option("--method", default="PATCH", help="Método (PATCH/PUT/POST).")
@click.option("--auth", default=None, help='Header Authorization, ex.: "Bearer <token>".')
@click.option("--model", "-m", default=None, help="Modelo para o relatório.")
@click.option("--provider", "-p", default=None, help="Provedor de LLM.")
@click.option("--yes", is_flag=True, help="Confirma autorização (pula a pergunta).")
def mass_assign(endpoint, body, method, auth, model, provider, yes):
    """
    Teste SEGURO de Mass Assignment no SEU endpoint de update.

    Verifica se a API aceita campos extras desconhecidos (risco de alguém
    enviar 'saldo'/'role'/'licenca'). NÃO envia valores sensíveis reais.
    """
    click.echo("🔒 Agente MAX - Teste de Mass Assignment (modo seguro)\n")
    click.echo("⚠️  Use APENAS no SEU endpoint de API.\n")
    if not yes:
        if not click.confirm(f"Você confirma ter autorização para testar {endpoint}?", default=False):
            click.echo("❌ Cancelado.")
            return
    try:
        body_dict = _json.loads(body)
    except Exception as e:
        click.echo(f"❌ JSON inválido em --body: {e}", err=True)
        return

    click.echo(f"\n🔍 Testando {method.upper()} {endpoint} ...")
    result = asyncio.run(test_mass_assignment(endpoint, body_dict, method=method, auth_header=auth))

    click.echo(f"\n--- [ RESULTADO ] veredito: {result.get('verdict', '?')} ---")
    for f in result.get("findings", []):
        click.echo(f"  [{f['severity']}] {f['point']}: {f['type']} — {f['evidence']}")
    if result.get("error"):
        click.echo(f"⚠️  {result['error']}")
        return

    # Relatório por IA (reusa o relatório consolidado)
    report = {"url": endpoint, "modules": [{"name": "Mass Assignment", "findings": result.get("findings", [])}],
              "all_findings": result.get("findings", [])}
    click.echo("\n🧠 Gerando relatório...\n")
    printed = {"any": False}

    def _chunk(piece: str):
        printed["any"] = True
        click.echo(piece, nl=False)

    full = asyncio.run(explain_report(report, model=model, provider=provider, on_chunk=_chunk))
    if not printed["any"]:
        click.echo(full)
    else:
        click.echo()


@cli.command(name="auth-test")
@click.argument("endpoint")
@click.option("--body", required=True, help='JSON de login inválido, ex.: \'{"email":"x@x.com","password":"errada"}\'.')
@click.option("--attempts", default=8, help="Quantidade de tentativas de login.")
@click.option("--method", default="POST", help="Método HTTP.")
@click.option("--model", "-m", default=None)
@click.option("--provider", "-p", default=None)
@click.option("--yes", is_flag=True, help="Confirma autorização.")
def auth_test(endpoint, body, attempts, method, model, provider, yes):
    """Testa proteção do login contra brute force (rate-limit) no SEU endpoint."""
    click.echo("🔒 Agente MAX - Teste de proteção de login (brute force)\n")
    if not yes and not click.confirm(f"Você confirma ter autorização para testar {endpoint}?", default=False):
        click.echo("❌ Cancelado.")
        return
    try:
        body_dict = _json.loads(body)
    except Exception as e:
        click.echo(f"❌ JSON inválido em --body: {e}", err=True)
        return
    click.echo(f"\n🔍 Enviando {attempts} logins inválidos para {endpoint} ...")
    result = asyncio.run(test_login_protection(endpoint, body_dict, attempts=attempts, method=method))
    for f in result.get("findings", []):
        click.echo(f"  [{f['severity']}] {f['type']} — {f['evidence']}")
    _ai_report({"url": endpoint, "modules": [{"name": "Auth / Login", "findings": result.get("findings", [])}],
                "all_findings": result.get("findings", [])}, model, provider)


@cli.command()
@click.argument("endpoint")
@click.option("--id", "the_id", required=True, help="O ID presente na URL (ex.: 100).")
@click.option("--auth", default=None, help='Header Authorization, ex.: "Bearer <token>".')
@click.option("--cookie", default=None, help='Cookie de sessão, ex.: "evosms_session=...".')
@click.option("--method", default="GET")
@click.option("--model", "-m", default=None)
@click.option("--provider", "-p", default=None)
@click.option("--yes", is_flag=True, help="Confirma autorização.")
def idor(endpoint, the_id, auth, cookie, method, model, provider, yes):
    """Testa IDOR: acessa IDs vizinhos pra ver se vê dados de outros usuários."""
    click.echo("🔒 Agente MAX - Teste de IDOR / Autorização\n")
    if not yes and not click.confirm(f"Você confirma ter autorização para testar {endpoint}?", default=False):
        click.echo("❌ Cancelado.")
        return
    click.echo(f"\n🔍 Testando IDs vizinhos a partir de {endpoint} ...")
    result = asyncio.run(test_idor(endpoint, the_id, auth_header=auth, method=method, cookie=cookie))
    if result.get("error"):
        click.echo(f"⚠️  {result['error']}")
    for f in result.get("findings", []):
        click.echo(f"  🚨 [{f['severity']}] {f['point']}: {f['evidence']}")
    if not result.get("findings"):
        click.echo("✅ Nenhum acesso indevido detectado nos IDs testados.")
    _ai_report({"url": endpoint, "modules": [{"name": "IDOR", "findings": result.get("findings", [])}],
                "all_findings": result.get("findings", [])}, model, provider)


def _ai_report(report: dict, model, provider):
    """Helper: imprime o relatório consolidado por IA (streaming)."""
    click.echo("\n🧠 Gerando relatório...\n")
    printed = {"any": False}

    def _chunk(piece: str):
        printed["any"] = True
        click.echo(piece, nl=False)

    full = asyncio.run(explain_report(report, model=model, provider=provider, on_chunk=_chunk))
    if printed["any"]:
        click.echo()
    else:
        click.echo(full)


@cli.command()
@click.argument("url")
@click.option("--login-url", default=None, help="Endpoint de login, ex.: https://api.site.com/login")
@click.option("--body", default=None, help='Credenciais JSON, ex.: \'{"email":"a@a.com","password":"x"}\'.')
@click.option("--token", default=None, help="Token JWT já obtido (apps com captcha que guardam token em JS).")
@click.option("--cookie", default=None, help='Cookie de sessão, ex.: "session=abc; outro=xyz" (apps com cookie HttpOnly).')
@click.option("--endpoint", default=None, help="Endpoint específico p/ testar direto (ex.: https://site.com/api/user/update).")
@click.option("--body-test", default=None, help='JSON de exemplo do endpoint, ex.: \'{"name":"x"}\'.')
@click.option("--endpoint-method", default="POST", help="Método do endpoint específico.")
@click.option("--token-key", default=None, help="Chave do token na resposta (ex.: access_token).")
@click.option("--login-method", default="POST")
@click.option("--model", "-m", default=None)
@click.option("--provider", "-p", default=None)
@click.option("--yes", is_flag=True, help="Confirma autorização.")
def authscan(url, login_url, body, token, cookie, endpoint, body_test, endpoint_method,
             token_key, login_method, model, provider, yes):
    """
    Scan AUTENTICADO: descobre os endpoints reais (logado) e testa NoSQL injection
    + mass assignment neles. NÃO destrutivo.

    Três modos: login automático (--login-url + --body), token direto (--token),
    ou cookie de sessão (--cookie) para apps com cookie HttpOnly.
    """
    click.echo("🔒 Agente MAX - Scan Autenticado (modo detecção)\n")
    click.echo("⚠️  Use APENAS no SEU sistema.\n")
    if not token and not cookie and not (login_url and body):
        click.echo("❌ Informe --token OU --cookie OU (--login-url e --body).", err=True)
        return
    if not yes and not click.confirm(f"Você confirma ser o dono de {url}?", default=False):
        click.echo("❌ Cancelado.")
        return
    creds = None
    if body:
        try:
            creds = _json.loads(body)
        except Exception as e:
            click.echo(f"❌ JSON inválido em --body: {e}", err=True)
            return

    manual = None
    if endpoint and body_test:
        try:
            manual = [{"method": endpoint_method.upper(), "url": endpoint, "body": _json.loads(body_test)}]
        except Exception as e:
            click.echo(f"❌ JSON inválido em --body-test: {e}", err=True)
            return

    modo_txt = "Usando cookie de sessão" if cookie else ("Usando token fornecido" if token else "Logando em " + login_url)
    click.echo(f"\n🔑 {modo_txt} ...")
    result = asyncio.run(scan_authenticated(url, login_url, creds, token_key=token_key,
                                            login_method=login_method, token=token, cookie=cookie,
                                            manual_endpoints=manual))

    lg = result["login"]
    if not lg.get("ok"):
        click.echo(f"❌ Login falhou: {result.get('error', lg.get('detail',''))}")
        return
    click.echo(f"✅ Login OK (token: {'sim' if lg['token_found'] else 'não'}, cookies: {lg['cookies'] or 'nenhum'})")
    click.echo(f"🔎 Endpoints autenticados descobertos: {len(result['endpoints'])} | testados: {result['tested']}")
    for e in result["endpoints"][:15]:
        click.echo(f"   {e['method']:5} {e['url']}")

    findings = result.get("findings", [])
    click.echo("\n--- [ ACHADOS ] ---")
    if findings:
        for f in findings:
            click.echo(f"🚨 [{f['severity']}] {f['point']}: {f['type']} — {f['evidence']}")
    else:
        click.echo("✅ Nenhuma vulnerabilidade detectada nos endpoints autenticados testados.")

    _ai_report({"url": url, "modules": [{"name": "Scan Autenticado", "findings": findings}],
                "all_findings": findings}, model, provider)


@cli.command()
@click.argument("url")
@click.option("--category", "-c", "category",
              type=click.Choice(list(CATEGORIES.keys()) + ["completo"]), default="completo",
              help="Categoria a auditar (padrão: completo = todos os módulos URL).")
@click.option("--timeout", default=15000, help="Timeout (ms) por módulo.")
@click.option("--model", "-m", default=None, help="Modelo de IA para o relatório consolidado.")
@click.option("--provider", "-p", default=None, help="Provedor de LLM para o relatório.")
@click.option("--output", "-o", default=None,
              help="Arquivo (ou pasta) para salvar o relatório. Ex.: relatorio.md")
@click.option("--format", "fmt", type=click.Choice(SUPPORTED_FORMATS), default="md",
              help="Formato do arquivo salvo com --output (md/json/html). Padrão: md.")
@click.option("--no-ai", is_flag=True, help="Pula a análise por IA (só lista os achados).")
@click.option("--yes", is_flag=True, help="Confirma autorização (pula a pergunta).")
def audit(url, category, timeout, model, provider, output, fmt, no_ai, yes):
    """
    Auditoria COMPLETA (consolidada) de uma URL: roda todos os módulos da
    categoria EM PARALELO, junta os achados e gera um relatório único por IA.

    Ideal para automação/CI. Use --output para salvar (md/json/html).
    """
    click.echo("🔒 Agente MAX - Auditoria consolidada\n")
    click.echo("⚠️  Use APENAS em sites/APIs que você é dono ou tem autorização.\n")
    if not yes and not click.confirm(f"Você confirma ter autorização para testar {url}?", default=False):
        click.echo("❌ Cancelado.")
        return

    keys = category_modules(category)
    if not keys:
        click.echo(f"❌ Categoria sem módulos: {category}", err=True)
        return

    click.echo(f"\n🔍 Rodando {len(keys)} módulos em {url} (categoria: {category}) ...")

    def _on_progress(name):
        click.echo(f"  ✔ {name}")

    try:
        report = asyncio.run(run_modules(keys, url, timeout_ms=timeout, on_progress=_on_progress))
    except Exception as e:
        click.echo(f"❌ Erro durante a auditoria: {e}", err=True)
        return

    findings = report["all_findings"]
    order = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3, "INFO": 4, "OK": 5}
    click.echo(f"\n--- [ ACHADOS ({len(findings)}) ] ---")
    if findings:
        for f in sorted(findings, key=lambda x: order.get(x.get("severity"), 9)):
            click.echo(f"🚨 [{f.get('severity')}] {f.get('module','')} | {f.get('point','')}: "
                       f"{f.get('type','')} — {f.get('evidence','')}")
    else:
        click.echo("✅ Nenhum achado nos módulos executados.")

    # Avisa sobre módulos que falharam ao executar.
    for m in report["modules"]:
        if m.get("error"):
            click.echo(f"⚠️  Módulo '{m['name']}' falhou: {m['error']}")

    ai_text = ""
    if no_ai:
        click.echo("\nℹ️  Análise por IA desativada (--no-ai).")
    else:
        click.echo("\n🧠 Gerando relatório consolidado...\n")
        click.echo("--- [ RELATÓRIO DE SEGURANÇA ] ---\n")
        printed = {"any": False}

        def _chunk(piece: str):
            printed["any"] = True
            click.echo(piece, nl=False)

        ai_text = asyncio.run(explain_report(report, model=model, provider=provider, on_chunk=_chunk))
        click.echo() if printed["any"] else click.echo(ai_text)
        click.echo("\n----------------------------------")

    if output:
        # Extensão do arquivo manda no formato (ex.: relatorio.html -> html).
        ext = output.rsplit(".", 1)[-1].lower() if "." in output else ""
        if ext in SUPPORTED_FORMATS:
            fmt = ext
        try:
            saved = save_report(report, ai_text, fmt=fmt, path=output)
            click.echo(f"\n💾 Relatório salvo em: {saved}")
        except Exception as e:
            click.echo(f"❌ Falha ao salvar relatório: {e}", err=True)


@cli.command()
def models():
    """Lista os modelos GRATUITOS disponíveis, agrupados por provedor."""
    click.echo("🤖 Modelos gratuitos (use com: run <url> --model <alias>)\n")

    labels = {
        "openrouter": "OpenRouter (free)",
        "groq": "Groq (free, rápido)",
        "gemini": "Google Gemini (free)",
        "mistral": "Mistral (free)",
        "ollama-cloud": "Ollama Cloud (online, free)",
        "ollama": "Ollama (local, sem chave)",
    }
    for prov, aliases in models_by_provider().items():
        click.echo(f"── {labels.get(prov, prov)} ──")
        for alias in aliases:
            info = AVAILABLE_MODELS[alias]
            click.echo(f"  • {alias}")
            click.echo(f"      slug: {info['slug']}  |  {info['desc']}")
        click.echo("")

    click.echo("💡 Defina um padrão no .env (LLM_PROVIDER + LLM_MODEL) ou escolha por execução com --provider/--model.")


def _mask(key: str) -> str:
    if not key:
        return ""
    return key[:6] + "..." + key[-4:] if len(key) > 10 else "***"


@cli.command()
def config():
    """Exibe o status de configuração de todos os provedores de LLM."""
    click.echo("⚙️  Configurações Atuais:\n")
    click.echo(f"Provedor padrão (LLM_PROVIDER): {settings.LLM_PROVIDER}")
    click.echo(f"Modelo padrão (LLM_MODEL): {settings.LLM_MODEL or '(usa o padrão do provedor)'}\n")

    keys = {
        "OpenRouter": settings.OPENROUTER_API_KEY,
        "Gemini": settings.GEMINI_API_KEY,
        "Groq": settings.GROQ_API_KEY,
        "Mistral": settings.MISTRAL_API_KEY,
        "Ollama Cloud": settings.OLLAMA_API_KEY,
    }
    click.echo("Chaves de API (free) — pode ter várias separadas por vírgula:")
    for name, raw in keys.items():
        parsed = parse_keys(raw)
        if parsed:
            qtd = f" ({len(parsed)} chaves)" if len(parsed) > 1 else ""
            click.echo(f"  ✅ {name}: {_mask(parsed[0])}{qtd}")
        else:
            click.echo(f"  ⬜ {name}: não configurada")
    click.echo(f"\nOllama (local): host = {settings.OLLAMA_HOST}")

if __name__ == "__main__":
    cli()
