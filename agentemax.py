"""
Agente MAX - Interface interativa no terminal.

Uso:
    python agentemax.py

Abre um menu interativo: você digita a URL, escolhe o modelo por número
e o agente audita o site (erros de JS, console e rede) e gera um relatório
de diagnóstico com IA, exibido em streaming (em tempo real).
"""

import sys
import json
import asyncio

# Garante saída UTF-8 (emojis/acentos) mesmo em consoles Windows (cp1252).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.markdown import Markdown
from rich.panel import Panel

from src.llm import explain_report
from src.runner import MODULES, category_modules, run_modules
from src.report import save_report, SUPPORTED_FORMATS
from src.authed_scan import scan_authenticated
from src.model_catalog import AVAILABLE_MODELS, PROVIDERS_THAT_NEED_KEY
from src.config import settings

console = Console()


def _provider_key(provider: str) -> str:
    """Retorna a chave configurada para o provedor (vazio se não tiver)."""
    return {
        "openrouter": settings.OPENROUTER_API_KEY,
        "gemini": settings.GEMINI_API_KEY,
        "groq": settings.GROQ_API_KEY,
        "mistral": settings.MISTRAL_API_KEY,
        "ollama-cloud": settings.OLLAMA_API_KEY,
        "ollama": "local",  # não precisa de chave
    }.get(provider, "")


def _provider_ready(provider: str) -> bool:
    """True se o provedor está pronto para uso (tem chave ou é local)."""
    if provider not in PROVIDERS_THAT_NEED_KEY:
        return True
    return bool(_provider_key(provider))

BANNER = r"""
 █████   ██████  ███████ ███    ██ ████████ ███████
██   ██ ██       ██      ████   ██    ██    ██
███████ ██   ███ █████   ██ ██  ██    ██    █████
██   ██ ██    ██ ██      ██  ██ ██    ██    ██
██   ██  ██████  ███████ ██   ████    ██    ███████

        ███    ███  █████  ██   ██
        ████  ████ ██   ██  ██ ██
        ██ ████ ██ ███████   ███
        ██  ██  ██ ██   ██  ██ ██
        ██      ██ ██   ██ ██   ██
"""

ROBOT = r"""
  ██        ██
    ██    ██
  ████████████
 ██████████████
████  ████  ████
████████████████
 ██████████████
   ██      ██
  ██        ██
"""


def show_banner():
    # Banner grande + space invader azul lado a lado (estilo Copilot CLI)
    grid = Table.grid(padding=(0, 3))
    grid.add_row(Text(BANNER, style="bold cyan"), Text(ROBOT, style="bold dodger_blue1"))
    console.print(grid)
    subtitle = Text()
    subtitle.append("  Auditor Inteligente de Sites ", style="bold white")
    subtitle.append("· QA & Debugging com IA", style="dim")
    console.print(subtitle)
    console.print("  [magenta]Instagram @alissonmaxsp[/]\n")

    # Status dos provedores (estilo Copilot CLI)
    labels = {"openrouter": "OpenRouter", "groq": "Groq", "gemini": "Gemini", "mistral": "Mistral",
              "ollama-cloud": "Ollama Cloud", "ollama": "Ollama (local)"}
    parts = []
    for prov, name in labels.items():
        ok = _provider_ready(prov)
        color = "green" if ok else "yellow"
        mark = "●" if ok else "○"
        parts.append(f"[{color}]{mark} {name}[/]")
    console.print("  " + "   ".join(parts))
    console.print(f"  [cyan]●[/] {len(AVAILABLE_MODELS)} modelos gratuitos disponíveis")
    console.print("  [dim]○ = sem chave (gere grátis no site do provedor). Digite 'sair' para encerrar.[/]\n")


def choose_model() -> str | None:
    """Mostra o menu numerado de modelos free e retorna o alias escolhido."""
    aliases = list(AVAILABLE_MODELS.keys())

    table = Table(title="🤖 Escolha o modelo (Enter = padrão)", title_style="bold magenta", show_lines=False)
    table.add_column("#", style="bold cyan", justify="right")
    table.add_column("Modelo", style="bold white")
    table.add_column("Provedor", style="white")
    table.add_column("Descrição", style="dim")

    # Padrão: primeiro modelo cujo provedor esteja pronto.
    default_index = next((i for i, a in enumerate(aliases, start=1) if _provider_ready(AVAILABLE_MODELS[a]["provider"])), 1)

    for i, alias in enumerate(aliases, start=1):
        info = AVAILABLE_MODELS[alias]
        prov = info["provider"]
        ready = _provider_ready(prov)
        prov_cell = f"[green]{prov}[/]" if ready else f"[yellow]{prov} 🔒[/]"
        label = alias if ready else f"[dim]{alias}[/]"
        table.add_row(str(i), label, prov_cell, info["desc"])

    console.print(table)
    console.print("  [dim]🔒 = precisa de chave free no .env (veja 'config' / README).[/]")

    choice = Prompt.ask("[bold]Número do modelo[/]", default=str(default_index))
    if choice.strip().lower() in ("sair", "q", "quit", "exit"):
        return None

    chosen_alias = None
    try:
        idx = int(choice)
        if 1 <= idx <= len(aliases):
            chosen_alias = aliases[idx - 1]
    except ValueError:
        pass

    if chosen_alias is None:
        console.print("[yellow]Opção inválida — usando o modelo padrão.[/]")
        chosen_alias = aliases[default_index - 1]

    # Avisa (mas permite) se o provedor não tem chave configurada.
    prov = AVAILABLE_MODELS[chosen_alias]["provider"]
    if not _provider_ready(prov):
        console.print(f"[yellow]⚠️  O provedor '{prov}' está sem chave no .env — a análise vai falhar até você configurá-la.[/]")

    return chosen_alias


_SEV_COLOR = {"CRÍTICA": "bold red", "ALTA": "red", "MÉDIA": "yellow",
              "BAIXA": "cyan", "INFO": "dim", "OK": "green"}

CATEGORY_MENU = [
    ("frontend", "🎨 Front-end", "Erros JS, segredos vazados, headers/cookies/CORS"),
    ("backend", "⚙️  Back-end / API", "SQL Injection, NoSQL Injection, arquivos expostos"),
    ("database", "🗄️  Banco de dados", "Supabase (RLS + chaves), SQLi, NoSQLi"),
    ("avancado", "🔬 Avançado", "JWT/auth, XSS refletido, Open Redirect, TLS/Infra"),
    ("autenticado", "🔐 Autenticado", "Loga no app e testa os endpoints reais (NoSQL/mass-assign)"),
    ("completo", "🚀 COMPLETO", "Roda TODOS os módulos baseados em URL"),
]


def choose_category() -> str | None:
    table = Table(title="🛡️  O que você quer testar?", title_style="bold magenta")
    table.add_column("#", style="bold cyan", justify="right")
    table.add_column("Categoria", style="bold white")
    table.add_column("Inclui", style="dim")
    for i, (_, nome, desc) in enumerate(CATEGORY_MENU, start=1):
        table.add_row(str(i), nome, desc)
    console.print(table)

    choice = Prompt.ask("[bold]Número da categoria[/]", default="6")
    if choice.strip().lower() in ("sair", "q", "quit", "exit"):
        return None
    try:
        idx = int(choice)
        if 1 <= idx <= len(CATEGORY_MENU):
            return CATEGORY_MENU[idx - 1][0]
    except ValueError:
        pass
    console.print("[yellow]Opção inválida — usando COMPLETO.[/]")
    return "completo"


def choose_modules(category: str) -> list[str]:
    keys = category_modules(category)
    table = Table(title="🧩 Módulos (Enter = todos)", title_style="bold magenta")
    table.add_column("#", style="bold cyan", justify="right")
    table.add_column("Módulo", style="white")
    for i, k in enumerate(keys, start=1):
        table.add_row(str(i), MODULES[k]["name"])
    console.print(table)

    raw = Prompt.ask("[bold]Quais rodar?[/] [dim](ex.: 1,3 — Enter = todos)[/]", default="todos")
    if raw.strip().lower() in ("todos", "all", ""):
        return keys
    selected = []
    for part in raw.split(","):
        try:
            idx = int(part.strip())
            if 1 <= idx <= len(keys):
                selected.append(keys[idx - 1])
        except ValueError:
            continue
    return selected or keys


def _offer_save(report: dict, ai_text: str):
    """Pergunta se o usuário quer salvar o relatório e em qual formato."""
    if not Confirm.ask("\n[bold]💾 Salvar relatório em arquivo?[/]", default=False):
        return
    fmt = Prompt.ask("[bold]Formato[/]", choices=list(SUPPORTED_FORMATS), default="md")
    path = Prompt.ask("[bold]Caminho/arquivo[/] [dim](Enter = nome automático)[/]", default="").strip() or None
    try:
        saved = save_report(report, ai_text, fmt=fmt, path=path)
        console.print(f"[green]✅ Relatório salvo em:[/] {saved}")
    except Exception as e:
        console.print(f"[red]❌ Não consegui salvar:[/] {e}")


def run_suite(url: str, keys: list[str], model_alias: str, timeout_ms: int):
    # Executa os módulos com indicação de progresso
    console.print()
    progress = {"done": 0}

    def on_progress(name: str):
        progress["done"] += 1
        console.print(f"  [cyan]▶[/] ({progress['done']}/{len(keys)}) {name} ...")

    with console.status("[bold cyan]Rodando auditoria de segurança...[/]", spinner="dots"):
        report = asyncio.run(run_modules(keys, url, timeout_ms=timeout_ms, on_progress=on_progress))

    # Tabela consolidada de achados
    findings = report["all_findings"]
    table = Table(title=f"🔎 Achados ({len(findings)})", title_style="bold cyan")
    table.add_column("Sev.", style="bold")
    table.add_column("Módulo", style="white")
    table.add_column("Ponto", style="white")
    table.add_column("Detalhe", style="dim")
    if findings:
        order = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3, "INFO": 4, "OK": 5}
        for f in sorted(findings, key=lambda x: order.get(x.get("severity"), 9)):
            sev = f.get("severity", "?")
            color = _SEV_COLOR.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/]", f.get("module", ""), f.get("point", ""),
                          f"{f.get('type','')}: {f.get('evidence','')}")
    else:
        table.add_row("[green]OK[/]", "-", "-", "Nenhum achado nos módulos executados.")
    console.print(table)

    # Relatório consolidado com IA — gera tudo e renderiza UMA vez (sem repetição).
    console.print(f"\n[bold magenta]🧠 Gerando relatório consolidado[/] [dim](modelo: {model_alias})[/]")
    with console.status("[bold cyan]Analisando achados e escrevendo o relatório...[/]", spinner="dots"):
        full = asyncio.run(explain_report(report, model=model_alias))

    console.rule("[bold]Relatório de Segurança - Agente MAX[/]")
    console.print(Markdown(full))
    console.rule()
    _offer_save(report, full)


def run_authed_suite(url: str, model_alias: str, timeout_ms: int):
    """Fluxo autenticado: pede login + credenciais, loga, descobre e testa endpoints."""
    console.print("\n[bold]🔐 Scan Autenticado[/] — testa os endpoints reais (logado).")
    console.print("[dim]Como você quer autenticar?[/]")
    console.print("  [cyan]1[/] Login automático (e-mail/senha) — só funciona se NÃO tiver captcha")
    console.print("  [cyan]2[/] Colar token (apps que guardam token em JS/localStorage)")
    console.print("  [cyan]3[/] Colar cookie de sessão (apps com cookie HttpOnly)")
    modo = Prompt.ask("[bold]Modo[/]", choices=["1", "2", "3"], default="3")

    login_url = creds = token = cookie = token_key = None
    if modo == "1":
        login_url = Prompt.ask("[bold]Endpoint de login[/] [dim](ex.: https://api.site.com/api/auth/login)[/]")
        body = Prompt.ask('[bold]Credenciais JSON[/] [dim]({"email":"a@a.com","password":"x"})[/]')
        token_key = Prompt.ask("[bold]Chave do token na resposta[/] [dim](Enter se não souber)[/]", default="")
        try:
            creds = json.loads(body)
        except Exception as e:
            console.print(f"[red]❌ JSON inválido:[/] {e}")
            return
    elif modo == "2":
        console.print("[dim]Token: F12 → Application → Local Storage, ou Network (header Authorization).[/]")
        token = Prompt.ask("[bold]Cole o token[/]").strip().replace("Bearer ", "")
        if not token:
            console.print("[red]❌ Token vazio.[/]")
            return
    else:
        console.print(Panel(
            "[bold]Como funciona:[/] você cola o cookie da sua sessão já logada. O Agente MAX\n"
            "usa esse cookie pra abrir o site [bold]como você[/] e visitar as telas internas,\n"
            "capturando os endpoints de API que cada uma chama — e então testa esses endpoints.\n\n"
            "[bold]O que VOCÊ deve fazer:[/]\n"
            "1. Faça [bold]login[/] no site no seu navegador.\n"
            "2. Abra o DevTools: [cyan]F12 → Application → Cookies[/] (escolha o domínio do site).\n"
            "3. Copie os cookies no formato: [green]nome=valor; nome2=valor2[/]\n\n"
            "[bold yellow]⚠️  Importante:[/] o cookie é definido [bold]no login[/] — navegar mais NÃO o\n"
            "deixa 'mais completo'. O que amplia a cobertura é informar, no próximo passo,\n"
            "[yellow]as rotas internas/pagamento do seu site[/] (ex.: /checkout, /recarga). Só dá pra\n"
            "testar o que o scanner visita — então aponte as telas onde estão saldo/pagamento.\n"
            "[dim](Exceção: se o app cria cookies extras no checkout — ex.: CSRF/carrinho — visite\n"
            "essas telas antes de copiar pra incluir esses cookies também.)[/]",
            title="🍪 Scan autenticado por Cookie", border_style="cyan", padding=(1, 2)))
        cookie = Prompt.ask("[bold]Cole o cookie de sessão[/]").strip()
        if not cookie:
            console.print("[red]❌ Cookie vazio.[/]")
            return

    # Rotas internas/pagamento informadas pelo usuário — ampliam a descoberta.
    console.print(
        "\n[dim]O scanner já visita rotas comuns (/dashboard, /wallet, /billing...).\n"
        "Informe as ESPECÍFICAS do seu site onde ficam saldo/pagamento p/ cobrir mais.[/]")
    rotas_raw = Prompt.ask(
        "[bold]Rotas internas/pagamento a testar[/] [dim](ex.: /checkout, /recarga — Enter pula)[/]",
        default="")
    extra_routes = [r.strip() for r in rotas_raw.replace(",", " ").split() if r.strip()] or None

    with console.status("[bold cyan]Descobrindo e testando endpoints autenticados...[/]", spinner="dots"):
        report = asyncio.run(scan_authenticated(url, login_url, creds, token=token, cookie=cookie,
                                                token_key=token_key or None, timeout_ms=timeout_ms,
                                                extra_routes=extra_routes))

    lg = report.get("login", {})
    if not lg.get("ok"):
        console.print(f"[red]❌ Login falhou:[/] {report.get('error', lg.get('detail',''))}")
        return
    console.print(f"[green]✅ Login OK[/] (token: {'sim' if lg['token_found'] else 'não'}, "
                  f"cookies: {lg['cookies'] or 'nenhum'})")
    console.print(f"🔎 Endpoints autenticados: {len(report['endpoints'])} | testados: {report['tested']}")

    findings = report.get("findings", [])
    table = Table(title=f"🔎 Achados ({len(findings)})", title_style="bold cyan")
    table.add_column("Sev.", style="bold"); table.add_column("Ponto"); table.add_column("Detalhe", style="dim")
    if findings:
        for f in findings:
            color = _SEV_COLOR.get(f.get("severity"), "white")
            table.add_row(f"[{color}]{f.get('severity')}[/]", f.get("point", ""),
                          f"{f.get('type','')}: {f.get('evidence','')}")
    else:
        table.add_row("[green]OK[/]", "-", "Nenhuma vulnerabilidade nos endpoints testados.")
    console.print(table)

    # Relatório consolidado (render único)
    rep = {"url": url, "modules": [{"name": "Scan Autenticado", "findings": findings}], "all_findings": findings}
    console.print(f"\n[bold magenta]🧠 Gerando relatório[/] [dim](modelo: {model_alias})[/]")
    with console.status("[bold cyan]Escrevendo o relatório...[/]", spinner="dots"):
        full = asyncio.run(explain_report(rep, model=model_alias))
    console.rule("[bold]Relatório de Segurança - Agente MAX[/]")
    console.print(Markdown(full))
    console.rule()
    _offer_save(rep, full)


def main():
    console.clear()
    show_banner()

    while True:
        url = Prompt.ask("\n[bold green]🌐 URL do site[/] [dim](ou 'sair')[/]")
        if not url or url.strip().lower() in ("sair", "q", "quit", "exit"):
            console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
            break
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        console.print("\n[yellow]⚠️  Teste APENAS sites/APIs que você é dono ou tem autorização.[/]")

        category = choose_category()
        if category is None:
            console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
            break

        # Modo autenticado tem fluxo próprio (pede login + credenciais)
        if category == "autenticado":
            model_alias = choose_model()
            if model_alias is None:
                console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
                break
            run_authed_suite(url, model_alias, 20000)
            if not Confirm.ask("\n[bold]Fazer outro teste?[/]", default=True):
                console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
                break
            continue

        keys = choose_modules(category)
        model_alias = choose_model()
        if model_alias is None:
            console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
            break

        timeout_str = Prompt.ask("[bold]⏱️  Timeout em ms[/]", default="15000")
        try:
            timeout_ms = int(timeout_str)
        except ValueError:
            timeout_ms = 15000

        run_suite(url, keys, model_alias, timeout_ms)

        if not Confirm.ask("\n[bold]Fazer outro teste?[/]", default=True):
            console.print("\n[bold cyan]👋 Até mais! Agente MAX encerrado.[/]\n")
            break


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[bold cyan]👋 Encerrado pelo usuário.[/]\n")
