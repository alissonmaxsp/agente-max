# 📘 Tutorial do Agente MAX

Guia prático, do zero ao primeiro relatório. Mostra o **modo interativo**, a
**CLI** (para automação) e, em detalhe, o **scan autenticado por cookie**.

> [!WARNING]
> **Uso autorizado e defensivo.** Rode **apenas** em sites/APIs que são seus ou
> que você tem permissão **por escrito** para testar. Todos os módulos são de
> detecção **não destrutiva** — mas testar terceiros sem autorização é ilegal.

---

## 1. Instalação (uma vez)

```powershell
# 1. Crie e ative o ambiente virtual
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate          # Linux/Mac

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Instale o navegador do Playwright (obrigatório)
python -m playwright install chromium

# 4. Configure suas chaves de IA (grátis)
copy .env.example .env             # depois edite o .env
```

No `.env`, basta **uma** chave de provedor gratuito para começar (ex.: `GROQ_API_KEY`
ou `GEMINI_API_KEY`). Veja a tabela de provedores no [README](README.md).

Confira se está tudo certo:

```powershell
python -m src.cli config           # mostra quais chaves estão ativas
```

---

## 2. Modo interativo (recomendado para começar)

```powershell
python agentemax.py
```

O fluxo é guiado por menus:

1. **🌐 URL do site** — digite o alvo (ex.: `meusite.com`).
2. **🛡️ O que testar?** — escolha a categoria:
   | # | Categoria | Inclui |
   |---|-----------|--------|
   | 1 | 🎨 Front-end | Erros JS, segredos vazados, headers/cookies/CORS |
   | 2 | ⚙️ Back-end / API | SQL Injection, NoSQL Injection, arquivos expostos |
   | 3 | 🗄️ Banco de dados | Supabase (RLS + chaves), SQLi, NoSQLi |
   | 4 | 🔬 Avançado | JWT/auth, XSS refletido, Open Redirect, TLS/Infra |
   | 5 | 🔐 Autenticado | Loga no app e testa os endpoints reais |
   | 6 | 🚀 COMPLETO | Roda todos os módulos baseados em URL |
3. **🧩 Módulos** — Enter para rodar todos, ou escolha (ex.: `1,3`).
4. **🤖 Modelo de IA** — Enter usa o padrão; ou escolha pelo número.
5. **⏱️ Timeout** — Enter para `15000` ms.

No fim aparece a **tabela de achados** + um **relatório por IA**, e o app pergunta
se você quer **salvar o relatório** em arquivo.

---

## 3. 🔐 Scan autenticado por Cookie (passo a passo)

Use quando os endpoints sensíveis (saldo, pagamento, perfil) **só existem depois
do login**. Escolha a categoria **5 (Autenticado)** e depois o **modo 3 (cookie)**.

### Como funciona
Você cola o cookie da sua sessão **já logada**. O Agente MAX usa esse cookie para
abrir o site **como você**, visitar as telas internas e **capturar os endpoints de
API** que cada uma chama — e então testa esses endpoints (NoSQL Injection e Mass
Assignment, de forma segura).

### O que VOCÊ precisa fazer
1. **Faça login** no site, normalmente, no seu navegador.
2. Abra o **DevTools**: `F12 → Application → Cookies` e selecione o domínio do site.
3. **Copie os cookies** no formato:
   ```
   nome=valor; nome2=valor2
   ```
   (junte os cookies relevantes da sessão separados por `; `)
4. Cole quando o app pedir.

### ⚠️ O ponto mais importante
O cookie é definido **no login** — **navegar mais não o deixa "mais completo"**.
O que **realmente** amplia a cobertura é o passo seguinte:

> **Rotas internas/pagamento a testar** *(ex.: `/checkout`, `/recarga`)*

O scanner já visita rotas comuns (`/dashboard`, `/wallet`, `/billing`...), mas
**só testa o que ele visita**. Então informe aqui as **telas específicas do seu
site** onde ficam saldo/pagamento. Pode separar por espaço ou vírgula:

```
/checkout /recarga /minha-conta/saldo
```

> 💡 **Exceção útil:** se o seu app cria **cookies extras** ao entrar no checkout
> (ex.: CSRF, carrinho), visite essas telas **antes** de copiar — assim esses
> cookies entram junto.

### Outros modos de autenticação
- **Modo 1 — Login automático:** informe o endpoint de login + credenciais JSON.
  Só funciona se **não houver captcha**.
- **Modo 2 — Token:** cole um JWT/token (apps que guardam token em `localStorage`).

---

## 4. CLI (para automação / CI)

Todos os módulos também rodam direto pelo terminal.

### Auditoria completa consolidada (paralela) + salvar relatório
```powershell
# Roda TODOS os módulos de URL em paralelo e salva em Markdown
python -m src.cli audit https://meusite.com --output relatorio.md

# Só o back-end, salvando em JSON (ótimo para CI)
python -m src.cli audit https://meusite.com -c backend --format json -o ./relatorios/

# Sem IA (apenas a lista de achados)
python -m src.cli audit https://meusite.com --no-ai --yes
```
O **formato é inferido pela extensão** do arquivo (`.md`, `.json`, `.html`).

### Módulos individuais
```powershell
# Erros de front-end (JS/console/rede)
python -m src.cli run https://meusite.com

# SQL Injection (detecção)
python -m src.cli scan "https://meusite.com/produtos?id=1"

# Supabase (RLS + chaves) — modo direto
python -m src.cli supabase-scan https://meusite.com \
  --supabase-url https://suaref.supabase.co --key ANON_KEY

# NoSQL Injection no login (bypass de auth)
python -m src.cli nosql-scan https://meusite.com \
  --endpoint https://api.meusite.com/login --body '{"email":"a@a.com","password":"x"}'

# Scan AUTENTICADO por cookie
python -m src.cli authscan https://meusite.com --cookie "session=abc; csrf=xyz"
```

### Utilitários
```powershell
python -m src.cli models     # lista os modelos de IA gratuitos
python -m src.cli config     # status das chaves configuradas
```

> Dica: adicione `--yes` para pular a confirmação de autorização em scripts.

---

## 5. Relatórios

Tanto o modo interativo quanto o comando `audit` permitem **exportar** o relatório:

| Formato | Para quê |
|---------|----------|
| `md`    | Ler/compartilhar (Markdown) |
| `json`  | Automação / CI / integração |
| `html`  | Relatório visual autocontido |

No interativo, basta responder **sim** quando perguntar *"💾 Salvar relatório?"*.
Na CLI, use `--output arquivo.ext`.

---

## 6. Como interpretar a severidade

| Severidade | Significado |
|------------|-------------|
| 🔴 **CRÍTICA** | Exploração direta (ex.: bypass de auth, service_role exposta). Corrija já. |
| 🟠 **ALTA** | Risco sério (ex.: SQLi error-based, mass assignment, IDOR). |
| 🟡 **MÉDIA** | Falha de hardening (ex.: header ausente, CORS aberto, XSS). |
| 🔵 **BAIXA** | Informativo / boa prática faltando. |
| ⚪ **INFO / OK** | Sem problema / proteção confirmada. |

---

## 7. Problemas comuns

- **"Chave do provedor não configurada"** → rode `python -m src.cli config` e adicione
  a chave no `.env`. Crie uma grátis no site do provedor (links no README).
- **Erro ao iniciar o navegador** → rode `python -m playwright install chromium`.
- **Scan autenticado não acha endpoints** → informe as **rotas internas/pagamento**
  (passo do item 3); o scanner só testa as telas que visita.
- **Rate-limit (HTTP 429) na IA** → configure **várias chaves** separadas por vírgula
  no `.env`; o sistema rotaciona sozinho.

---

## 8. Rodar os testes (para quem for contribuir)

```powershell
pytest                      # tudo, com cobertura
pytest -m integration       # só testes de integração (HTTP mockado)
pytest -m "not browser"     # pula os que exigem o Chromium do Playwright
```

---

Feito por **Alisson Max** · Instagram [@alissonmaxsp](https://instagram.com/alissonmaxsp)
