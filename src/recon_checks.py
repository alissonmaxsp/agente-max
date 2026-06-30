"""
Checagens de Infra / Recon (modo detecção, NÃO destrutivo).

⚠️  USO AUTORIZADO: apenas em alvos seus ou com permissão.

Inclui (consolidado em scan_infra):
- TLS/SSL: validade e expiração do certificado.
- Métodos HTTP perigosos habilitados (PUT/DELETE/TRACE/PATCH via OPTIONS).
- GraphQL introspection aberta.
- Arquivos de recon (robots.txt, security.txt, sitemap.xml).
- Fingerprint de tecnologias (headers reveladores).
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx


def _check_tls(host: str, port: int = 443) -> list[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        # Expiração
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            dias = (exp - datetime.now(timezone.utc)).days
            if dias < 0:
                findings.append({"point": "TLS", "type": "certificado expirado",
                                 "severity": "ALTA", "evidence": f"expirou há {-dias} dias"})
            elif dias < 21:
                findings.append({"point": "TLS", "type": "certificado perto de expirar",
                                 "severity": "MÉDIA", "evidence": f"expira em {dias} dias"})
        # Protocolo antigo
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({"point": "TLS", "type": "protocolo TLS obsoleto",
                             "severity": "ALTA", "evidence": f"negociou {proto}"})
    except ssl.SSLCertVerificationError as e:
        findings.append({"point": "TLS", "type": "certificado inválido",
                         "severity": "ALTA", "evidence": str(e)[:120]})
    except Exception as e:
        findings.append({"point": "TLS", "type": "falha ao checar TLS",
                         "severity": "BAIXA", "evidence": str(e)[:120]})
    return findings


async def _check_methods(client: httpx.AsyncClient, url: str) -> list[dict]:
    findings = []
    try:
        r = await client.request("OPTIONS", url)
        allow = r.headers.get("allow", "") or r.headers.get("access-control-allow-methods", "")
        perigosos = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow.upper()]
        if perigosos:
            findings.append({"point": "métodos HTTP", "type": "métodos perigosos habilitados",
                             "severity": "MÉDIA", "evidence": f"Allow: {', '.join(perigosos)}"})
    except Exception:
        pass
    # TRACE (XST)
    try:
        r = await client.request("TRACE", url)
        if r.status_code == 200 and "TRACE" in r.text.upper():
            findings.append({"point": "métodos HTTP", "type": "TRACE habilitado (XST)",
                             "severity": "MÉDIA", "evidence": "servidor ecoa requisição TRACE"})
    except Exception:
        pass
    return findings


async def _check_graphql(client: httpx.AsyncClient, base: str) -> list[dict]:
    findings = []
    query = {"query": "{__schema{types{name}}}"}
    for path in ("/graphql", "/api/graphql", "/v1/graphql"):
        try:
            r = await client.post(base + path, json=query)
            if r.status_code == 200 and "__schema" in r.text and "types" in r.text:
                findings.append({"point": base + path, "type": "GraphQL introspection aberta",
                                 "severity": "MÉDIA", "evidence": "schema completo exposto via introspection"})
        except Exception:
            continue
    return findings


async def _check_recon_files(client: httpx.AsyncClient, base: str) -> list[dict]:
    findings = []
    # security.txt ausente é boa prática faltando (informativo)
    try:
        r = await client.get(base + "/.well-known/security.txt")
        if r.status_code != 200:
            findings.append({"point": "/.well-known/security.txt", "type": "security.txt ausente",
                             "severity": "BAIXA", "evidence": "sem canal de contato para reporte de vulnerabilidades"})
    except Exception:
        pass
    # robots.txt revelando caminhos sensíveis
    try:
        r = await client.get(base + "/robots.txt")
        if r.status_code == 200:
            sens = [ln for ln in r.text.splitlines()
                    if any(k in ln.lower() for k in ("admin", "backup", "config", "private", "api", "dashboard"))]
            if sens:
                findings.append({"point": "/robots.txt", "type": "robots.txt revela caminhos sensíveis",
                                 "severity": "BAIXA", "evidence": "; ".join(sens[:4])[:160]})
    except Exception:
        pass
    return findings


def _fingerprint(headers: dict) -> list[dict]:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}
    # 'server' e 'x-powered-by' já são reportados pelo módulo Headers — evitamos duplicar.
    techs = []
    for hdr in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime"):
        if h.get(hdr):
            techs.append(f"{hdr}: {h[hdr]}")
    if techs:
        findings.append({"point": "fingerprint", "type": "tecnologias reveladas em headers",
                         "severity": "BAIXA", "evidence": "; ".join(techs)[:200]})
    return findings


async def scan_infra(url: str, timeout_ms: int = 15000) -> dict:
    """Executa todas as checagens de infra/recon e consolida os achados."""
    result = {"url": url, "findings": []}
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname

    if parsed.scheme == "https" and host:
        result["findings"].extend(_check_tls(host))

    headers = {"User-Agent": "AgenteMAX-Recon/1.0 (authorized testing)"}
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
        try:
            r = await client.get(url)
            result["findings"].extend(_fingerprint(dict(r.headers)))
        except Exception:
            pass
        result["findings"].extend(await _check_methods(client, url))
        result["findings"].extend(await _check_graphql(client, base))
        result["findings"].extend(await _check_recon_files(client, base))
    return result
