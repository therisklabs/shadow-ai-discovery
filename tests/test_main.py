from __future__ import annotations

import json

from typer.testing import CliRunner

from ai_discovery.main import app

runner = CliRunner()


def test_mock_mode_table_output():
    result = runner.invoke(app, ["--mock"])
    assert result.exit_code == 0, result.output
    assert "AI Discovery" in result.output


def test_mock_mode_json_format():
    result = runner.invoke(app, ["--mock", "--format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "installed_apps" in data
    assert "running_services" in data


def test_mock_mode_json_export(tmp_path):
    out = str(tmp_path / "report.json")
    result = runner.invoke(app, ["--mock", "--output", out])
    assert result.exit_code == 0, result.output
    import pathlib
    content = pathlib.Path(out).read_text()
    data = json.loads(content)
    assert data["metadata"]["hostname"] == "DEMO-PC"


def test_help_text():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--mock" in result.output


def test_scan_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--mock" in result.output


def test_categories_flag_accepted():
    result = runner.invoke(app, ["--mock", "--categories", "apps,gpu"])
    # --mock ignores categories but should not crash
    assert result.exit_code == 0
