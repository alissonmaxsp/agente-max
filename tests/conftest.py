import sys
import os

# Adiciona o diretório raiz do projeto ao sys.path para permitir importações absolutas de 'src'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Defaults de ambiente para os testes — garantem que `src.config.Settings`
# carregue mesmo SEM um arquivo .env real (CI, clone limpo). Só define o que
# ainda não estiver no ambiente, para não sobrescrever um .env legítimo.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-com-mais-de-32-caracteres-1234567890")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("LLM_PROVIDER", "openrouter")


# --------------------------------------------------------------------------- #
# Servidor-alvo VULNERÁVEL local (para testes de browser ponta-a-ponta).
# Serve uma página que dispara erro de JS, console.error, um recurso 404 e
# expõe um endpoint com XSS refletido — tudo em localhost, sem internet.
# --------------------------------------------------------------------------- #
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

_VULN_HTML = """<!doctype html><html><head><title>Alvo de Teste</title>
<script src="/missing-bundle.js"></script>
</head><body>
<h1>Aplicação vulnerável de teste</h1>
<form action="/search" method="get">
  <input name="q" placeholder="buscar"><button type="submit">Ir</button>
</form>
<script>
  console.error("erro proposital do agente max no console");
  throw new Error("excecao JS nao tratada do agente max");
</script>
</body></html>"""


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silencia o log do servidor nos testes
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, _VULN_HTML)
        elif parsed.path == "/search":
            # XSS refletido: devolve o parâmetro 'q' SEM escape.
            q = (parse_qs(parsed.query).get("q") or [""])[0]
            self._send(200, f"<html><body>resultados para: {q}</body></html>")
        else:
            self._send(404, "<html><body>not found</body></html>")


@pytest.fixture(scope="session")
def vuln_server():
    """Sobe o app vulnerável numa porta livre e devolve a URL base."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
async def chromium_ready():
    """Pula o teste se o navegador do Playwright não estiver instalado."""
    from playwright.async_api import async_playwright
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            await browser.close()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"Playwright Chromium indisponível: {e}")
