"""
Exportação de relatórios do Agente MAX.

Pega o relatório consolidado (dict com url/modules/all_findings) + o texto
gerado pela IA e grava em arquivo nos formatos: md, json, html.

Uso típico (CLI):
    from src.report import save_report
    caminho = save_report(report, ai_text, fmt="md")
"""

import json
import html as _html
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

SUPPORTED_FORMATS = ("md", "json", "html")

_SEV_ORDER = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3, "INFO": 4, "OK": 5}


def _slug_host(url: str) -> str:
    """Extrai um host limpo da URL para compor o nome do arquivo."""
    host = urlparse(url).netloc or urlparse("https://" + url).netloc or "alvo"
    return re.sub(r"[^a-zA-Z0-9.-]", "_", host) or "alvo"


def default_filename(url: str, fmt: str) -> str:
    """Gera um nome de arquivo determinístico: agente-max_<host>_<timestamp>.<ext>."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"agente-max_{_slug_host(url)}_{ts}.{fmt}"


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))


def render_markdown(report: dict, ai_text: str) -> str:
    """Monta o relatório completo em Markdown (achados + análise da IA)."""
    url = report.get("url", "")
    findings = _sorted_findings(report.get("all_findings", []))
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    out = [
        "# 🤖 Relatório do Agente MAX",
        "",
        f"- **Alvo:** {url}",
        f"- **Gerado em:** {ts}",
        f"- **Total de achados:** {len(findings)}",
        "",
        "## 🔎 Achados",
        "",
    ]
    if findings:
        out.append("| Severidade | Módulo | Ponto | Detalhe |")
        out.append("| --- | --- | --- | --- |")
        for f in findings:
            detalhe = f"{f.get('type', '')}: {f.get('evidence', '')}".strip(": ")
            out.append(
                f"| {f.get('severity', '?')} | {f.get('module', '')} | "
                f"{f.get('point', '')} | {detalhe} |"
            )
    else:
        out.append("✅ Nenhum achado nos módulos executados.")

    out += ["", "## 🧠 Análise e Correções (IA)", "", (ai_text or "_(sem análise)_"), ""]
    return "\n".join(out)


def render_json(report: dict, ai_text: str) -> str:
    """Serializa o relatório bruto + análise da IA em JSON (para automação/CI)."""
    payload = {
        "tool": "Agente MAX",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "url": report.get("url", ""),
        "findings": _sorted_findings(report.get("all_findings", [])),
        "modules": report.get("modules", []),
        "ai_analysis": ai_text or "",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_html(report: dict, ai_text: str) -> str:
    """Relatório HTML autocontido (sem dependências externas)."""
    url = report.get("url", "")
    findings = _sorted_findings(report.get("all_findings", []))
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    colors = {"CRÍTICA": "#c0392b", "ALTA": "#e74c3c", "MÉDIA": "#f39c12",
              "BAIXA": "#3498db", "INFO": "#7f8c8d", "OK": "#27ae60"}

    rows = ""
    for f in findings:
        sev = f.get("severity", "?")
        c = colors.get(sev, "#555")
        detalhe = _html.escape(f"{f.get('type', '')}: {f.get('evidence', '')}".strip(": "))
        rows += (
            f"<tr><td><b style='color:{c}'>{_html.escape(sev)}</b></td>"
            f"<td>{_html.escape(f.get('module', ''))}</td>"
            f"<td>{_html.escape(f.get('point', ''))}</td>"
            f"<td>{detalhe}</td></tr>"
        )
    if not rows:
        rows = "<tr><td colspan='4'>✅ Nenhum achado nos módulos executados.</td></tr>"

    ai_html = _html.escape(ai_text or "(sem análise)")
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<title>Relatório Agente MAX — {_html.escape(url)}</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}}
 h1{{color:#2c3e50}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem}}
 th{{background:#2c3e50;color:#fff}} pre{{background:#f6f8fa;padding:1rem;border-radius:6px;white-space:pre-wrap}}
 .meta{{color:#666;font-size:.9rem}}
</style></head><body>
<h1>🤖 Relatório do Agente MAX</h1>
<p class="meta"><b>Alvo:</b> {_html.escape(url)}<br><b>Gerado em:</b> {ts}<br>
<b>Total de achados:</b> {len(findings)}</p>
<h2>🔎 Achados</h2>
<table><thead><tr><th>Severidade</th><th>Módulo</th><th>Ponto</th><th>Detalhe</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>🧠 Análise e Correções (IA)</h2>
<pre>{ai_html}</pre>
</body></html>"""


_RENDERERS = {"md": render_markdown, "json": render_json, "html": render_html}


def save_report(report: dict, ai_text: str, fmt: str = "md", path: str | None = None) -> str:
    """
    Grava o relatório em disco e retorna o caminho do arquivo criado.

    - `fmt`: 'md', 'json' ou 'html'.
    - `path`: caminho de saída; se omitido, gera um nome com host + timestamp
      no diretório atual. Se `path` for uma pasta existente, o arquivo é criado
      dentro dela com o nome padrão.
    """
    fmt = (fmt or "md").lower().lstrip(".")
    if fmt not in _RENDERERS:
        raise ValueError(f"Formato não suportado: {fmt!r}. Use: {', '.join(SUPPORTED_FORMATS)}.")

    content = _RENDERERS[fmt](report, ai_text)

    if path:
        dest = Path(path)
        if dest.is_dir():
            dest = dest / default_filename(report.get("url", ""), fmt)
    else:
        dest = Path(default_filename(report.get("url", ""), fmt))

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return str(dest)
