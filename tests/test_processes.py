from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ai_discovery.scanner.processes import scan_processes


def _make_proc(pid, name, exe="", cmdline=None):
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": cmdline or [exe],
    }
    return proc


def _make_conn(port, pid, status="LISTEN"):
    conn = MagicMock()
    conn.laddr = MagicMock()
    conn.laddr.port = port
    conn.pid = pid
    conn.status = status
    return conn


def test_ollama_detected_from_process(mocker):
    mock_procs = [_make_proc(1234, "ollama.exe", r"C:\Programs\Ollama\ollama.exe")]
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=mock_procs)
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={})

    services, warnings = scan_processes()
    assert any(s.name == "Ollama" for s in services)


def test_ollama_alive_from_http_probe(mocker):
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=[])
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[
        _make_conn(11434, 1234),
    ])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={
        11434: (True, ["llama3:8b", "mistral:7b"]),
    })

    services, _ = scan_processes()
    ollama = next((s for s in services if s.name == "Ollama"), None)
    assert ollama is not None
    assert ollama.is_alive is True
    assert "llama3:8b" in ollama.loaded_models


def test_dead_port_not_returned(mocker):
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=[])
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={
        11434: (False, []),
    })

    services, _ = scan_processes()
    # No process and not alive → not included
    ollama = next((s for s in services if s.name == "Ollama"), None)
    assert ollama is None


def test_python_process_matched_by_cmdline(mocker):
    cmdline = ["python.exe", "server.py", "--model", "llama3"]
    mock_procs = [_make_proc(9999, "python.exe", r"C:\Python\python.exe", cmdline)]
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=mock_procs)
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={})

    # server.py in cmdline → text-generation-webui
    services, _ = scan_processes()
    tgw = next((s for s in services if "text-generation" in s.name), None)
    assert tgw is not None


def test_access_denied_process_skipped(mocker):
    import psutil

    bad_proc = MagicMock()
    bad_proc.info = None
    bad_proc.__iter__ = MagicMock(side_effect=psutil.AccessDenied(0))

    # process_iter raises on iteration — should not crash scan
    mocker.patch(
        "ai_discovery.scanner.processes.psutil.process_iter",
        return_value=[],
    )
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={})

    services, warnings = scan_processes()
    assert isinstance(services, list)


def test_lm_studio_models_extracted(mocker):
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=[])
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[
        _make_conn(1234, 5678),
    ])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={
        1234: (True, ["meta-llama-3.1-8b-instruct"]),
    })

    services, _ = scan_processes()
    lms = next((s for s in services if s.name == "LM Studio"), None)
    assert lms is not None
    assert lms.is_alive is True
    assert "meta-llama-3.1-8b-instruct" in lms.loaded_models


# ---------------------------------------------------------------------------
# v0.2.0 unknown-port probing tests
# ---------------------------------------------------------------------------

def test_fingerprint_openai_compatible():
    from ai_discovery.scanner.processes import _fingerprint_service
    data = {"data": [{"id": "model-1"}, {"id": "model-2"}]}
    name = _fingerprint_service(data, 8000)
    assert name is not None
    assert "OpenAI" in name or "port 8000" in name


def test_fingerprint_ollama_compatible():
    from ai_discovery.scanner.processes import _fingerprint_service
    data = {"models": [{"name": "llama3"}]}
    name = _fingerprint_service(data, 8000)
    assert name is not None
    assert "Ollama" in name or "port 8000" in name


def test_fingerprint_unknown_returns_none():
    from ai_discovery.scanner.processes import _fingerprint_service
    data = {"random": "garbage"}
    assert _fingerprint_service(data, 8000) is None


def test_probe_unknown_port_openai(mocker):
    from ai_discovery.scanner.processes import _probe_unknown_port
    import requests as req
    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": [{"id": "hermes-3"}]}
    mocker.patch("ai_discovery.scanner.processes.requests.get", return_value=mock_resp)

    svc = _probe_unknown_port(8000, timeout=1)
    assert svc is not None
    assert svc.port == 8000
    assert svc.is_alive is True
    assert "hermes-3" in svc.loaded_models


def test_probe_unknown_port_no_response(mocker):
    from ai_discovery.scanner.processes import _probe_unknown_port
    mocker.patch(
        "ai_discovery.scanner.processes.requests.get",
        side_effect=Exception("connection refused"),
    )
    svc = _probe_unknown_port(9999, timeout=1)
    assert svc is None


def test_unknown_port_discovered_in_scan(mocker):
    """Unknown LISTEN port that speaks OpenAI API is added to services."""
    mocker.patch("ai_discovery.scanner.processes.psutil.process_iter", return_value=[])
    mocker.patch("ai_discovery.scanner.processes.psutil.net_connections", return_value=[
        _make_conn(8000, 1111),  # non-standard port
    ])
    mocker.patch("ai_discovery.scanner.processes._probe_all", return_value={})

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": [{"id": "hermes-3"}]}
    mocker.patch("ai_discovery.scanner.processes.requests.get", return_value=mock_resp)

    services, _ = scan_processes()
    unknown = next((s for s in services if s.port == 8000), None)
    assert unknown is not None
    assert unknown.is_alive is True
