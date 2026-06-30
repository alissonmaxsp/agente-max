"""Testes do comando `audit` da CLI (suíte consolidada + exportação)."""

import json
import os

from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from src.cli import cli


REPORT = {
    "url": "https://example.com",
    "modules": [{"name": "SQL Injection", "findings": [], "error": None}],
    "all_findings": [
        {"severity": "CRÍTICA", "module": "Supabase", "point": "contas",
         "type": "RLS escrita", "evidence": "update sem login"},
    ],
}


@patch("src.cli.explain_report", new_callable=AsyncMock)
@patch("src.cli.run_modules", new_callable=AsyncMock)
def test_audit_runs_and_prints_findings(mock_run, mock_explain):
    mock_run.return_value = REPORT
    mock_explain.return_value = "**Risco geral:** CRÍTICO"

    result = CliRunner().invoke(cli, ["audit", "https://example.com", "--yes"])

    assert result.exit_code == 0
    assert "CRÍTICA" in result.output
    assert "Supabase" in result.output
    assert "Risco geral" in result.output


@patch("src.cli.run_modules", new_callable=AsyncMock)
def test_audit_no_ai_skips_llm(mock_run):
    mock_run.return_value = REPORT
    result = CliRunner().invoke(cli, ["audit", "https://example.com", "--yes", "--no-ai"])
    assert result.exit_code == 0
    assert "Análise por IA desativada" in result.output


@patch("src.cli.explain_report", new_callable=AsyncMock)
@patch("src.cli.run_modules", new_callable=AsyncMock)
def test_audit_exports_json_by_extension(mock_run, mock_explain):
    mock_run.return_value = REPORT
    mock_explain.return_value = "analise"

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli, ["audit", "https://example.com", "--yes", "-o", "saida.json"]
        )
        assert result.exit_code == 0
        assert os.path.exists("saida.json")
        with open("saida.json", encoding="utf-8") as fh:
            data = json.loads(fh.read())
        assert data["url"] == "https://example.com"
        assert data["ai_analysis"] == "analise"
        assert data["findings"][0]["severity"] == "CRÍTICA"


def test_audit_aborts_without_confirmation():
    # Sem --yes e respondendo "n" à confirmação, deve cancelar sem rodar nada.
    result = CliRunner().invoke(cli, ["audit", "https://example.com"], input="n\n")
    assert "Cancelado" in result.output


@patch("src.cli.scan_sqli", new_callable=AsyncMock)
@patch("src.cli.explain_security", new_callable=AsyncMock)
def test_scan_command_reports_findings(mock_explain, mock_scan):
    mock_scan.return_value = {
        "url": "https://example.com",
        "entry_points": {"query_params": ["id"], "forms": []},
        "tested": 1,
        "findings": [{"severity": "ALTA", "point": "query param 'id'", "method": "GET",
                      "type": "error-based", "evidence": "Erro SQL vazado"}],
    }
    mock_explain.return_value = "relatorio"
    result = CliRunner().invoke(cli, ["scan", "https://example.com", "--yes"])
    assert result.exit_code == 0
    assert "error-based" in result.output
