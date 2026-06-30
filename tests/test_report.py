import json

import pytest

from src.report import render_markdown, render_json, render_html, save_report, default_filename


REPORT = {
    "url": "https://exemplo.com",
    "modules": [{"name": "SQL Injection", "findings": [], "error": None}],
    "all_findings": [
        {"severity": "BAIXA", "module": "Headers", "point": "CSP", "type": "ausente", "evidence": "sem header"},
        {"severity": "CRÍTICA", "module": "Supabase", "point": "tabela contas",
         "type": "RLS escrita aberto", "evidence": "update sem login"},
    ],
}


def test_markdown_lists_findings_sorted_by_severity():
    md = render_markdown(REPORT, "análise da IA aqui")
    # CRÍTICA deve aparecer antes de BAIXA (ordenação por severidade).
    assert md.index("CRÍTICA") < md.index("BAIXA")
    assert "análise da IA aqui" in md
    assert "exemplo.com" in md


def test_json_is_valid_and_carries_ai_text():
    data = json.loads(render_json(REPORT, "texto IA"))
    assert data["url"] == "https://exemplo.com"
    assert data["ai_analysis"] == "texto IA"
    assert data["findings"][0]["severity"] == "CRÍTICA"  # ordenado


def test_html_escapes_content():
    rep = {**REPORT, "all_findings": [
        {"severity": "ALTA", "module": "XSS", "point": "<script>", "type": "x", "evidence": "y"}]}
    out = render_html(rep, "<b>oi</b>")
    assert "<script>" not in out          # foi escapado
    assert "&lt;script&gt;" in out
    assert "&lt;b&gt;oi&lt;/b&gt;" in out  # texto da IA também escapado


def test_default_filename_uses_host_and_extension():
    name = default_filename("https://meu.site.com/x?a=1", "html")
    assert name.startswith("agente-max_meu.site.com_")
    assert name.endswith(".html")


def test_save_report_writes_file(tmp_path):
    saved = save_report(REPORT, "ia", fmt="md", path=str(tmp_path))
    assert saved.endswith(".md")
    content = (tmp_path / saved.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]).read_text(encoding="utf-8")
    assert "Relatório do Agente MAX" in content


def test_save_report_rejects_unknown_format():
    with pytest.raises(ValueError):
        save_report(REPORT, "ia", fmt="pdf")
