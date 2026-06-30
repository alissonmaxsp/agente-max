"""
Catálogo de modelos de LLM recomendados para tarefas de código/depuração.

Cada entrada tem:
- alias  : nome curto para usar no CLI/menu (ex.: 'groq-llama-70b')
- slug   : identificador do modelo no provedor
- provider: openrouter | gemini | groq | mistral | ollama
- desc   : descrição curta

Todos os modelos abaixo têm uso GRATUITO:
- openrouter: modelos com sufixo ':free'. Limite menor; sobe com saldo na conta.
- groq      : tier free generoso e muito rápido. Chave free: https://console.groq.com
- gemini    : tier free do Google AI Studio. Chave free: https://aistudio.google.com/apikey
- mistral   : tier free (plano "Experiment"). Chave free: https://console.mistral.ai
- ollama    : 100% gratuito e LOCAL (roda no seu PC). Instale: https://ollama.com
"""

# Provedores que precisam de chave de API (Ollama LOCAL não precisa)
PROVIDERS_THAT_NEED_KEY = {"openrouter", "gemini", "groq", "mistral", "ollama-cloud"}

# alias -> {slug, provider, desc}
AVAILABLE_MODELS: dict[str, dict] = {
    # ---------------- OpenRouter (free) ----------------
    "qwen-coder-free": {"slug": "qwen/qwen3-coder:free", "provider": "openrouter",
                        "desc": "Qwen3 Coder - especialista em código (OpenRouter, grátis)."},
    "qwen-next-free": {"slug": "qwen/qwen3-next-80b-a3b-instruct:free", "provider": "openrouter",
                       "desc": "Qwen3 Next 80B - forte e versátil (OpenRouter, grátis)."},
    "gpt-oss-free": {"slug": "openai/gpt-oss-120b:free", "provider": "openrouter",
                     "desc": "GPT-OSS 120B - open source da OpenAI (OpenRouter, grátis)."},
    "llama-70b-free": {"slug": "meta-llama/llama-3.3-70b-instruct:free", "provider": "openrouter",
                       "desc": "Llama 3.3 70B - generalista sólido (OpenRouter, grátis)."},
    "north-code-free": {"slug": "cohere/north-mini-code:free", "provider": "openrouter",
                        "desc": "Cohere North Mini Code - focado em código (OpenRouter, grátis)."},
    "nemotron-free": {"slug": "nvidia/nemotron-3-super-120b-a12b:free", "provider": "openrouter",
                      "desc": "NVIDIA Nemotron 3 Super 120B - raciocínio forte (OpenRouter, grátis)."},

    # ---------------- Groq (tier free, super rápido) ----------------
    "groq-llama-70b": {"slug": "llama-3.3-70b-versatile", "provider": "groq",
                       "desc": "Llama 3.3 70B - rápido e forte (Groq, free)."},
    "groq-llama-8b": {"slug": "llama-3.1-8b-instant", "provider": "groq",
                      "desc": "Llama 3.1 8B - instantâneo, ótimo p/ respostas rápidas (Groq, free)."},
    "groq-gemma-9b": {"slug": "gemma2-9b-it", "provider": "groq",
                      "desc": "Gemma 2 9B - leve e capaz (Groq, free)."},

    # ---------------- Google Gemini (tier free) ----------------
    "gemini-flash": {"slug": "gemini-2.5-flash", "provider": "gemini",
                     "desc": "Gemini 2.5 Flash - rápido, contexto grande (Google AI Studio, free)."},
    "gemini-flash-lite": {"slug": "gemini-2.5-flash-lite", "provider": "gemini",
                          "desc": "Gemini 2.5 Flash-Lite - mais econômico em quota (Google, free)."},

    # ---------------- Mistral (tier free) ----------------
    "codestral": {"slug": "codestral-latest", "provider": "mistral",
                  "desc": "Codestral - especialista em código (Mistral, free)."},
    "mistral-small": {"slug": "mistral-small-latest", "provider": "mistral",
                      "desc": "Mistral Small - equilibrado e capaz (Mistral, free)."},

    # ---------------- Ollama Cloud (online, tier free) ----------------
    # Chave free: https://ollama.com/settings/keys  |  Acesso free validado via /api/chat.
    # (DeepSeek V4, GLM-5.x, Kimi e Mistral-Large exigem assinatura paga — fora do free.)
    "cloud-qwen-coder": {"slug": "qwen3-coder:480b", "provider": "ollama-cloud",
                         "desc": "Qwen3 Coder 480B - top em código (Ollama Cloud, free)."},
    "cloud-qwen-coder-next": {"slug": "qwen3-coder-next", "provider": "ollama-cloud",
                              "desc": "Qwen3 Coder Next - versão mais recente p/ código (Ollama Cloud, free)."},
    "cloud-devstral": {"slug": "devstral-2:123b", "provider": "ollama-cloud",
                       "desc": "Devstral 2 123B - especialista em código da Mistral (Ollama Cloud, free)."},
    "cloud-gpt-oss": {"slug": "gpt-oss:120b", "provider": "ollama-cloud",
                      "desc": "GPT-OSS 120B - open source da OpenAI (Ollama Cloud, free)."},
    "cloud-glm-47": {"slug": "glm-4.7", "provider": "ollama-cloud",
                     "desc": "GLM-4.7 - generalista forte (Ollama Cloud, free)."},
    "cloud-minimax": {"slug": "minimax-m2.5", "provider": "ollama-cloud",
                      "desc": "MiniMax M2.5 - capaz e equilibrado (Ollama Cloud, free)."},
    "cloud-nemotron": {"slug": "nemotron-3-ultra", "provider": "ollama-cloud",
                       "desc": "NVIDIA Nemotron 3 Ultra - raciocínio forte (Ollama Cloud, free)."},

    # ---------------- Ollama (local, 100% free, sem chave) ----------------
    "ollama-qwen": {"slug": "qwen2.5-coder", "provider": "ollama",
                    "desc": "Qwen 2.5 Coder - rodando localmente (Ollama, sem chave)."},
    "ollama-llama": {"slug": "llama3.2", "provider": "ollama",
                     "desc": "Llama 3.2 - rodando localmente (Ollama, sem chave)."},
}

_KNOWN_PROVIDERS = {"openrouter", "gemini", "groq", "mistral", "ollama", "ollama-cloud"}


def get_model(value: str, provider: str | None = None) -> tuple[str, str]:
    """
    Resolve um identificador de modelo para (slug, provider).

    Aceita:
    - um alias do catálogo            -> ex.: 'groq-llama-70b'
    - 'provider:slug'                 -> ex.: 'groq:llama-3.3-70b-versatile'
    - um slug cru (assume openrouter, ou o `provider` informado)
    """
    if value in AVAILABLE_MODELS:
        e = AVAILABLE_MODELS[value]
        return e["slug"], e["provider"]

    # formato "provider:slug" (não confundir com slugs do OpenRouter que terminam em ':free')
    if ":" in value:
        prefix = value.split(":", 1)[0]
        if prefix in _KNOWN_PROVIDERS:
            p, s = value.split(":", 1)
            return s, p

    # slug cru: usa o provider informado, ou openrouter por padrão
    return value, (provider or "openrouter")


def resolve_model(value: str) -> str:
    """Compatibilidade: devolve apenas o slug a partir de um alias/slug."""
    if not value:
        return value
    return get_model(value)[0]


def models_by_provider() -> dict[str, list[str]]:
    """Agrupa os aliases por provedor (para exibição em menus)."""
    grouped: dict[str, list[str]] = {}
    for alias, info in AVAILABLE_MODELS.items():
        grouped.setdefault(info["provider"], []).append(alias)
    return grouped
