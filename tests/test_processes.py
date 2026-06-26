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
