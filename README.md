# 🤖 Agente MAX — Auditor Inteligente de Sites & Scanner de Segurança

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-orange.svg)](https://playwright.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

O **Agente MAX** é um auditor inteligente de sites, depurador de front-end e scanner de segurança (QA + Pentest Defensivo) executado diretamente no terminal. Ele analisa a saúde de aplicações web de ponta a ponta e gera relatórios consolidados automáticos usando Inteligência Artificial através de diversos provedores gratuitos.

> [!WARNING]
> **Uso Autorizado & Defensivo:** Os módulos de segurança são projetados exclusivamente para auditoria e detecção **não destrutiva**. Use-os apenas em sistemas próprios ou com autorização explícita e por escrito dos proprietários.

> [!TIP]
> 📘 **Novo por aqui?** Comece pelo **[TUTORIAL.md](TUTORIAL.md)** — guia passo a passo do zero ao primeiro relatório, incluindo o scan autenticado por cookie.

---

## ✨ Funcionalidades Principais

*   **Auditorias Completas de Front-End:** Captura erros de runtime Javascript, falhas de requisição HTTP e `console.error` simulando a navegação do usuário através de um navegador headless.
*   **Detecção de Segredos:** Varre arquivos e códigos JS estáticos buscando chaves de API expostas (AWS, Google, Stripe, Firebase, conexões de DB, JWTs, etc.).
*   **Módulos de Pentest Defensivo:**
    *   **SQL Injection:** Detecção segura (baseada em erros e lógica booleana) em formulários e parâmetros.
    *   **NoSQL Injection:** Testes de bypass de autenticação injetando operadores NoSQL (MongoDB).
    *   **Arquivos Sensíveis:** Varredura automática por rotas administrativas e arquivos expostos (`.env`, `.git`, backups, logs).
    *   **Supabase Audit:** Auditoria automática de configurações abertas de RLS (Row Level Security) e chaves administrativas vazadas.
*   **Relatórios em Tempo Real com IA:** Integração com múltiplos provedores gratuitos de LLM em modo *streaming* direto no console.
*   **Exportação de Relatórios:** Salve a auditoria consolidada em `Markdown`, `JSON` (ideal para CI/automação) ou `HTML` autocontido, via `--output` na CLI ou pelo modo interativo.
*   **Auditoria Paralela:** O comando `audit` roda todos os módulos da categoria simultaneamente (asyncio), reduzindo o tempo total de varredura.
*   **Fallback & Rotação de Chaves:** Permite configurar múltiplas chaves de API (separadas por vírgula) por provedor. O sistema rotaciona as chaves automaticamente caso uma bate no limite de requisições (HTTP 429).

---

## 🏗️ Estrutura do Projeto

```text
├── agentemax.py         # Arquivo principal (Interface CLI interativa)
├── requirements.txt     # Dependências do projeto
├── .env.example         # Template de configuração de ambiente
├── src/
│   ├── main.py          # API FastAPI com boas práticas de segurança aplicada
│   ├── cli.py           # Interface de Linha de Comando (CLI direta)
│   ├── llm.py           # Integração com os provedores de LLM e streaming
│   ├── model_catalog.py # Catálogo de modelos de IA suportados (Gratuitos)
│   ├── runner.py        # Orquestrador de execução dos módulos de varredura
│   └── routes/          # Rotas de exemplo do boilerplate de segurança
└── tests/               # Testes automatizados do sistema
```

---

## 🧠 Provedores de IA Suportados (Gratuitos)

O Agente MAX suporta vários provedores que possuem planos gratuitos generosos. Cadastre suas chaves no arquivo `.env` para habilitá-los:

| Provedor | Apelido no Sistema | Onde Obter a Chave de API |
| :--- | :--- | :--- |
| **Google Gemini** | `gemini` | [Google AI Studio](https://aistudio.google.com/apikey) |
| **OpenRouter** | `openrouter` | [OpenRouter Keys](https://openrouter.ai/keys) |
| **Groq** | `groq` | [Groq Console](https://console.groq.com) |
| **Mistral AI** | `mistral` | [Mistral Console](https://console.mistral.ai) |
| **Ollama Cloud** | `ollama-cloud` | [Ollama Settings](https://ollama.com/settings/keys) |
| **Ollama Local** | `ollama` | Roda 100% offline na sua máquina (Sem chave) |

---

## 🛠️ Instalação e Configuração

### Requisitos
*   Python 3.10 ou superior
*   Pip configurado

### Passo a Passo

1. **Clonar o Repositório e Navegar:**
   ```powershell
   cd "caminho/do/projeto"
   ```

2. **Criar e Ativar o Ambiente Virtual (Venv):**
   ```powershell
   python -m venv venv
   # No Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # No Linux/Mac:
   source venv/bin/activate
   ```

3. **Instalar as Dependências:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Instalar os Navegadores do Playwright:**
   ```powershell
   python -m playwright install chromium
   ```

5. **Configurar as Variáveis de Ambiente:**
   Copie o arquivo de exemplo e insira suas chaves de API:
   ```powershell
   copy .env.example .env
   ```

### 📱 Instalação no Android (Termux)

Como o Agente MAX depende do **Playwright (Chromium Headless)**, a instalação direta no Termux nativo pode falhar devido à falta de bibliotecas de sistema do Linux. A forma recomendada e 100% funcional é utilizando o **PRoot Distro (Ubuntu)**:

1. **Instale o PRoot Distro e o Ubuntu no Termux:**
   ```bash
   pkg update && pkg upgrade -y
   pkg install proot-distro -y
   proot-distro install ubuntu
   proot-distro login ubuntu
   ```

2. **Dentro do Ubuntu, instale as dependências e o Python:**
   ```bash
   apt update && apt upgrade -y
   apt install python3 python3-pip python3-venv git curl libgbm1 libnss3 libatk-bridge2.0-0 libgtk-3-0 -y
   ```

3. **Configure o repositório, dependências e navegadores do Playwright:**
   ```bash
   # Crie e ative a venv
   python3 -m venv venv
   source venv/bin/activate

   # Instale os pacotes python
   pip install -r requirements.txt

   # Instale os navegadores e dependências do Playwright no Linux
   playwright install chromium
   playwright install-deps
   ```

4. **Copie e configure as chaves:**
   ```bash
   cp .env.example .env
   nano .env
   ```

---

## 🚀 Como Executar

### Modo Interativo (Interface no Terminal)
Para executar a interface interativa amigável do Agente MAX, rode:
```powershell
python agentemax.py
```
*Siga as instruções na tela para inserir a URL, selecionar a categoria de varredura, os módulos específicos e o modelo de IA.*

### Modo Direto via CLI (Para Automações)
Você também pode invocar os módulos do scanner diretamente pelo terminal:

```powershell
# 0. Auditoria COMPLETA consolidada (roda todos os módulos EM PARALELO) + salvar relatório
python -m src.cli audit https://meusite.com --output relatorio.md
python -m src.cli audit https://meusite.com -c backend --format json -o ./relatorios/

# 1. Auditoria geral de erros de front-end em um site
python -m src.cli run https://meusite.com

# 2. Testar falha de SQL Injection em um endpoint específico
python -m src.cli scan "https://meusite.com/produtos?id=1"

# 3. Auditoria direta de RLS em projeto Supabase
python -m src.cli supabase-scan https://meusite.com --supabase-url https://suaref.supabase.co --key ANON_KEY

# 4. Auditoria direta de NoSQL Injection em tela de Login
python -m src.cli nosql-scan https://meusite.com --endpoint https://api.meusite.com/login --body '{"email":"admin@site.com","password":"x"}'

# 5. Listar os modelos e testar o status das chaves de API configuradas
python -m src.cli models
python -m src.cli config
```

### Módulos Avançados (CLI)
Testes que exigem credenciais/endpoint do seu próprio sistema:

```powershell
# Mass Assignment (a API aceita campos extras como saldo/role?)
python -m src.cli mass-assign https://api.meusite.com/user/update --body '{"name":"Teste"}' --auth "Bearer TOKEN"

# Proteção do login contra brute force (rate-limit)
python -m src.cli auth-test https://api.meusite.com/login --body '{"email":"x@x.com","password":"errada"}'

# IDOR (acessar dados de outro usuário trocando o ID)
python -m src.cli idor https://api.meusite.com/users/100 --id 100 --auth "Bearer TOKEN"
```

> No **modo interativo**, a categoria **🔬 Avançado** roda automaticamente os testes baseados em URL: análise de **JWT**, **XSS refletido**, **Open Redirect** e **Infra/Recon** (TLS, métodos HTTP, GraphQL introspection, robots/security.txt e fingerprint).

---

## 🧪 Testes Automatizados

A suíte cobre desde funções puras (detecção de erros SQL/Mongo, análise de JWT)
até **testes de integração** dos scanners com HTTP simulado (`respx`) — validando
o fluxo real de descoberta → injeção → detecção sem depender de rede ou de um alvo
externo — além da lógica de rotação de chaves/fallback do motor de IA e dos
comandos da CLI.

```powershell
# Roda tudo, já com relatório de cobertura (configurado no pyproject.toml)
pytest

# Apenas os testes de integração (HTTP mockado)
pytest -m integration

# Pula testes que exigem o navegador do Playwright instalado
pytest -m "not browser"

# Cobertura detalhada em HTML
pytest --cov=src --cov-report=html
```

> Os testes injetam o próprio ambiente (não exigem um `.env` real) e rodam
> automaticamente no **CI** (GitHub Actions) a cada push/PR em Python 3.10–3.12.

---

## 💬 Contato e Comunidade

Desenvolvido por **Alisson Max**
*   **Instagram:** [@alissonmaxsp](https://instagram.com/alissonmaxsp)

---
