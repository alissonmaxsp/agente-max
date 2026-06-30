import pytest
from click.testing import CliRunner
from unittest.mock import AsyncMock, patch
from src.cli import cli

def test_cli_config_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["config"])
    assert result.exit_code == 0
    assert "Configurações Atuais" in result.output
    assert "Provedor padrão" in result.output

@patch("src.cli.analyze_website", new_callable=AsyncMock)
def test_cli_run_no_errors(mock_analyze):
    mock_analyze.return_value = {
        "url": "https://example.com",
        "page_errors": [],
        "console_errors": [],
        "network_failures": []
    }
    
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "https://example.com"])
    assert result.exit_code == 0
    assert "Nenhum erro detectado no site" in result.output

@patch("src.cli.explain_errors", new_callable=AsyncMock)
@patch("src.cli.analyze_website", new_callable=AsyncMock)
def test_cli_run_with_errors_and_ai(mock_analyze, mock_explain):
    mock_analyze.return_value = {
        "url": "https://example.com",
        "page_errors": [{"message": "Uncaught ReferenceError: x is not defined", "stack": ""}],
        "console_errors": [],
        "network_failures": []
    }
    mock_explain.return_value = "O erro indica que a variável 'x' não foi declarada."

    runner = CliRunner()
    # --no-stream usa o caminho que retorna a resposta completa de uma vez.
    result = runner.invoke(cli, ["run", "https://example.com", "--no-stream"])
    assert result.exit_code == 0
    assert "Erros de runtime JS: 1" in result.output
    assert "Solicitando análise via" in result.output
    assert "O erro indica que a variável 'x' não foi declarada." in result.output


@patch("src.cli.explain_errors", new_callable=AsyncMock)
@patch("src.cli.analyze_website", new_callable=AsyncMock)
def test_cli_run_with_errors_streaming(mock_analyze, mock_explain):
    mock_analyze.return_value = {
        "url": "https://example.com",
        "page_errors": [{"message": "Uncaught ReferenceError: x is not defined", "stack": ""}],
        "console_errors": [],
        "network_failures": []
    }

    # Em streaming, o cli passa on_chunk; simulamos a IA emitindo pedaços.
    async def fake_stream(results, model=None, on_chunk=None, **kwargs):
        if on_chunk:
            for piece in ["O erro ", "indica ", "variável 'x'."]:
                on_chunk(piece)
        return "O erro indica variável 'x'."
    mock_explain.side_effect = fake_stream

    runner = CliRunner()
    result = runner.invoke(cli, ["run", "https://example.com"])
    assert result.exit_code == 0
    assert "O erro indica variável 'x'." in result.output

@patch("src.cli.analyze_website", new_callable=AsyncMock)
def test_cli_run_with_errors_no_ai(mock_analyze):
    mock_analyze.return_value = {
        "url": "https://example.com",
        "page_errors": [{"message": "Uncaught ReferenceError: x is not defined", "stack": "stacktrace"}],
        "console_errors": [],
        "network_failures": []
    }

    runner = CliRunner()
    result = runner.invoke(cli, ["run", "https://example.com", "--no-ai"])
    assert result.exit_code == 0
    assert "Erros de runtime JS: 1" in result.output
    assert "Exibindo logs crus" in result.output
    assert "Uncaught ReferenceError: x is not defined" in result.output
