"""
Checagens web (front-end / recon) — modo detecção, NÃO destrutivo.

⚠️  USO AUTORIZADO: apenas em sites/APIs seus ou com permissão.

Inclui:
- scan_secrets()        : segredos/chaves vazados no HTML/JS (Stripe, AWS, Firebase, JWT...).
- check_headers_cookies_cors(): headers de segurança ausentes, cookies inseguros, CORS aberto.
- scan_exposed_paths()  : arquivos/rotas sensíveis acessíveis (.env, .git, /admin, backups...).
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from playwright.async_api import async_playwright


def _set_param(url: str, param: str, value: str) -> str:
    """Devolve a URL com `param` setado para `value` (preservando os demais)."""
    parsed = urlparse(url)
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


# ---------------------------------------------------------------------------
# 1) Segredos expostos no front-end
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
    "Stripe Secret (live)": r"sk_live_[0-9a-zA-Z]{16,}",
    "Stripe Publishable (live)": r"pk_live_[0-9a-zA-Z]{16,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "GitHub Token": r"gh[pousr]_[0-9A-Za-z]{30,}",
    "Private Key Block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "Mongo Connection String": r"mongodb(?:\+srv)?://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+",
    "Postgres Connection String": r"postgres(?:ql)?://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+",
    "Firebase config": r"(?:firebaseio\.com|firebaseapp\.com|FIREBASE_API_KEY)",
    "Generic Secret Assignment": r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
}
_SECRET_RES = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}


def _mask(s: str) -> str:
    s = s.strip()
    return s[:8] + "..." + s[-4:] if len(s) > 16 else s[:4] + "..."


async def _collect_source(url: str, timeout_ms: int) -> str:
    """HTML + conteúdo dos scripts JS da página."""
    blob = ""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await (await browser.new_context()).new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            blob += await page.content()
            srcs = await page.evaluate(
                "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
            )
            async with httpx.AsyncClient(timeout=20.0) as client:
                for src in (srcs or [])[:30]:
                    try:
                        r = await client.get(src)
                        if r.status_code == 200:
                            blob += "\n" + r.text
                    except Exception:
                        continue
        finally:
            await browser.close()
    return blob


async def scan_secrets(url: str, timeout_ms: int = 15000) -> dict:
    """Procura segredos/chaves vazados no HTML e nos bundles JS."""
    result = {"url": url, "findings": []}
    try:
        source = await _collect_source(url, timeout_ms)
    except Exception as e:
        result["error"] = str(e)
        return result

    seen = set()
    for name, rgx in _SECRET_RES.items():
        for m in rgx.findall(source):
            val = m if isinstance(m, str) else (m[0] if m else "")
            key = (name, val)
            if not val or key in seen:
                continue
            seen.add(key)
            # "Generic" e "Firebase config" são indícios; os demais são chaves reais.
            sev = "MÉDIA" if name in ("Generic Secret Assignment", "Firebase config") else "ALTA"
            result["findings"].append({
                "point": "código front-end (HTML/JS)",
                "type": f"segredo exposto: {name}",
                "severity": sev,
                "evidence": _mask(val),
            })
    return result


# ---------------------------------------------------------------------------
# 2) Headers de segurança + cookies + CORS
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "content-security-policy": "Sem CSP — facilita XSS e injeção de conteúdo.",
    "strict-transport-security": "Sem HSTS — conexões podem cair para HTTP.",
    "x-frame-options": "Sem X-Frame-Options — risco de clickjacking.",
    "x-content-type-options": "Sem X-Content-Type-Options — risco de MIME sniffing.",
    "referrer-policy": "Sem Referrer-Policy — pode vazar URLs em referer.",
    "permissions-policy": "Sem Permissions-Policy — APIs do browser sem restrição.",
}


async def check_headers_cookies_cors(url: str) -> dict:
    """Analisa headers de segurança, flags de cookies e configuração de CORS."""
    result = {"url": url, "findings": []}
    headers_evil = {"Origin": "https://evil-agentemax-test.example"}

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
            r = await client.get(url)
            r_cors = await client.get(url, headers=headers_evil)
    except Exception as e:
        result["error"] = str(e)
        return result

    h = {k.lower(): v for k, v in r.headers.items()}

    # Headers de segurança ausentes
    for header, msg in SECURITY_HEADERS.items():
        if header not in h:
            result["findings"].append({
                "point": "headers HTTP", "type": f"header ausente: {header}",
                "severity": "MÉDIA", "evidence": msg,
            })

    # Vazamento de tecnologia
    for leak in ("server", "x-powered-by"):
        if h.get(leak):
            result["findings"].append({
                "point": "headers HTTP", "type": f"info exposta ({leak})",
                "severity": "BAIXA", "evidence": h[leak],
            })

    # Cookies inseguros
    for cookie in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
        low = cookie.lower()
        nome = cookie.split("=", 1)[0]
        faltando = [f for f in ("httponly", "secure", "samesite") if f not in low]
        if faltando:
            result["findings"].append({
                "point": f"cookie '{nome}'", "type": "cookie inseguro",
                "severity": "MÉDIA", "evidence": f"faltando flags: {', '.join(faltando)}",
            })

    # CORS aberto / refletindo origem maliciosa
    acao = r_cors.headers.get("access-control-allow-origin", "")
    acc = r_cors.headers.get("access-control-allow-credentials", "")
    if acao == "*":
        result["findings"].append({
            "point": "CORS", "type": "CORS liberado (*)",
            "severity": "MÉDIA", "evidence": "Access-Control-Allow-Origin: * (qualquer site lê respostas)",
        })
    elif "evil-agentemax-test.example" in acao:
        sev = "ALTA" if acc.lower() == "true" else "MÉDIA"
        result["findings"].append({
            "point": "CORS", "type": "CORS reflete origem arbitrária",
            "severity": sev,
            "evidence": f"reflete Origin malicioso (credentials={acc or 'false'})",
        })
    return result


# ---------------------------------------------------------------------------
# 3) Arquivos / rotas sensíveis expostos
# ---------------------------------------------------------------------------
SENSITIVE_PATHS = {
    "/.env": ["DB_", "SECRET", "API_KEY", "PASSWORD"],
    "/.env.local": ["DB_", "SECRET", "API_KEY"],
    "/.git/config": ["[core]", "repositoryformatversion"],
    "/.git/HEAD": ["ref:"],
    "/config.json": ["{", "key", "secret"],
    "/backup.zip": ["PK"],
    "/backup.sql": ["INSERT INTO", "CREATE TABLE"],
    "/.DS_Store": ["Bud1"],
    "/wp-config.php": ["DB_PASSWORD", "DB_NAME"],
    "/phpinfo.php": ["PHP Version"],
    "/server-status": ["Apache Server Status"],
    "/.aws/credentials": ["aws_access_key_id"],
    "/docker-compose.yml": ["services:", "image:"],
}


async def scan_exposed_paths(url: str) -> dict:
    """Tenta acessar arquivos/rotas sensíveis e confirma por assinatura de conteúdo."""
    result = {"url": url, "findings": [], "tested": 0}
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    headers = {"User-Agent": "AgenteMAX-Recon/1.0 (authorized testing)"}

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, headers=headers) as client:
        for path, signatures in SENSITIVE_PATHS.items():
            result["tested"] += 1
            try:
                r = await client.get(base + path)
            except Exception:
                continue
            if r.status_code == 200 and any(sig in r.text for sig in signatures):
                result["findings"].append({
                    "point": f"{base}{path}", "type": "arquivo/rota sensível exposto",
                    "severity": "ALTA", "evidence": f"HTTP 200 com conteúdo sensível confirmado",
                })
    return result


# ---------------------------------------------------------------------------
# 4) XSS refletido (canário, detecção)
# ---------------------------------------------------------------------------
_XSS_MARKER = "agtmax9z"
_XSS_PAYLOAD = f"{_XSS_MARKER}<svg/onload=1>"


async def scan_xss(url: str, timeout_ms: int = 15000) -> dict:
    """Injeta um canário em cada query param e vê se volta SEM escape (XSS refletido)."""
    result = {"url": url, "findings": [], "tested": 0}
    params = list(parse_qs(urlparse(url).query).keys())
    headers = {"User-Agent": "AgenteMAX-XSS/1.0 (authorized testing)"}
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, headers=headers) as client:
        for param in params:
            result["tested"] += 1
            try:
                r = await client.get(_set_param(url, param, _XSS_PAYLOAD))
            except Exception:
                continue
            # Vulnerável se o payload volta com os caracteres < > intactos (sem &lt;)
            # Só alta confiança: o payload volta com < > intactos (sem &lt;/&gt;).
            if f"{_XSS_MARKER}<svg/onload=1>" in r.text:
                result["findings"].append({
                    "point": f"query param '{param}'", "type": "XSS refletido",
                    "severity": "ALTA",
                    "evidence": "payload <svg/onload=1> refletido sem escape no HTML",
                })
    return result


# ---------------------------------------------------------------------------
# 5) Open Redirect (detecção)
# ---------------------------------------------------------------------------
_REDIRECT_HINTS = ("next", "url", "redirect", "redirect_uri", "return", "returnurl",
                   "return_to", "dest", "destination", "continue", "goto", "r", "u")
_EVIL = "https://evil-agentemax.example/x"


async def scan_open_redirect(url: str, timeout_ms: int = 15000) -> dict:
    """Testa se algum parâmetro redireciona para um domínio externo arbitrário."""
    result = {"url": url, "findings": [], "tested": 0}
    all_params = list(parse_qs(urlparse(url).query).keys())
    # Prioriza params com cara de redirect; se não houver, testa todos
    params = [p for p in all_params if p.lower() in _REDIRECT_HINTS] or all_params
    headers = {"User-Agent": "AgenteMAX-Redirect/1.0 (authorized testing)"}
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, headers=headers) as client:
        for param in params:
            result["tested"] += 1
            try:
                r = await client.get(_set_param(url, param, _EVIL))
            except Exception:
                continue
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 303, 307, 308) and "evil-agentemax.example" in loc:
                result["findings"].append({
                    "point": f"query param '{param}'", "type": "open redirect",
                    "severity": "MÉDIA",
                    "evidence": f"redireciona (HTTP {r.status_code}) para domínio externo: {loc[:80]}",
                })
    return result
