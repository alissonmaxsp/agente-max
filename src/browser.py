import asyncio
from playwright.async_api import async_playwright

async def analyze_website(url: str, timeout_ms: int = 15000) -> dict:
    """
    Inicia um navegador headless usando Playwright, acessa a URL informada
    e captura erros de runtime (JavaScript no console, requisições HTTP falhas).
    """
    results = {
        "url": url,
        "page_errors": [],       # Erros de runtime JS não tratados
        "console_errors": [],    # Chamadas explicitas a console.error
        "network_failures": []   # Status codes >= 400 ou falhas de rede
    }

    async with async_playwright() as p:
        # Inicia Chromium headless
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        # 1. Captura exceções JS não tratadas (ex: uncaught exceptions)
        page.on("pageerror", lambda err: results["page_errors"].append({
            "message": err.message,
            "stack": err.stack
        }))

        # 2. Captura logs do console que sejam do tipo 'error'
        page.on("console", lambda msg: results["console_errors"].append({
            "text": msg.text,
            "location": msg.location
        }) if msg.type == "error" else None)

        # 3. Captura requisições de rede falhas (ex: bloqueadas por adblock, DNS ou CORS)
        page.on("requestfailed", lambda req: results["network_failures"].append({
            "url": req.url,
            "error_text": req.failure.error_text if req.failure else "Desconhecido"
        }))

        # 4. Captura respostas HTTP com erro (status >= 400)
        page.on("response", lambda res: results["network_failures"].append({
            "url": res.url,
            "status": res.status,
            "status_text": res.status_text
        }) if res.status >= 400 else None)

        try:
            # Navega até o site
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            # Aguarda um curto intervalo adicional para scripts dinâmicos rodarem
            await asyncio.sleep(2)
        except Exception as e:
            # Captura a falha ao tentar carregar a página em si (ex: site fora do ar)
            results["page_errors"].append({
                "message": f"Falha de navegação na página principal: {str(e)}",
                "stack": ""
            })
        finally:
            await context.close()
            await browser.close()

    return results
