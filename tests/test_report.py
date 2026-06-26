from __future__ import annotations

import json

from rich.console import Console

from ai_discovery.mock_data import make_mock_report
from ai_discovery.report.json_export import to_json_str, write_json
from ai_discovery.report.terminal import render_report


def test_terminal_render_does_not_crash():
    report = make_mock_report()
    console = Console(force_terminal=False, width=120)
    # Should not raise
    render_report(report, console)


def test_json_export_valid(tmp_path):
    report = make_mock_report()
    out = tmp_path / "report.json"
    write_json(report, str(out))
    data = json.loads(out.read_text())
    assert "installed_apps" in data
    assert "running_services" in data
    assert "model_files" in data
    assert "python_environments" in data
    assert "gpus" in data


def test_json_str_roundtrip():
    report = make_mock_report()
    s = to_json_str(report)
    data = json.loads(s)
    assert data["metadata"]["hostname"] == "DEMO-PC"
    assert len(data["installed_apps"]) > 0


def test_computed_fields_in_json():
    report = make_mock_report()
    s = to_json_str(report)
    data = json.loads(s)
    # size_human is a computed field that should appear in JSON
    for mf in data.get("model_files", []):
        assert "size_human" in mf

    # vram_human on GPU
    for gpu in data.get("gpus", []):
        if gpu.get("vram_mb"):
            assert "vram_human" in gpu


def test_empty_report_renders():
    from ai_discovery.models import ScanMetadata, ScanReport
    from datetime import datetime
    import socket, getpass

    report = ScanReport(
        metadata=ScanMetadata(
            scan_started_at=datetime.now(),
            hostname="test-host",
            username="user",
            platform="win32",
            tool_version="0.1.0",
        )
    )
    console = Console(force_terminal=False, width=120)
    render_report(report, console)  # should not crash
