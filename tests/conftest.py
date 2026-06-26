"""
Shared pytest fixtures. Injects winreg stub and patches sys.platform so all
scanner tests run on Linux without Windows APIs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Inject winreg stub before any scanner imports touch it
from tests.stubs import winreg as _winreg_stub

sys.modules.setdefault("winreg", _winreg_stub)


# ---------------------------------------------------------------------------
# Registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_winreg_stub():
    """Reset the winreg stub state before every test."""
    _winreg_stub.clear()
    yield
    _winreg_stub.clear()


@pytest.fixture()
def winreg_stub():
    return _winreg_stub


# ---------------------------------------------------------------------------
# Platform patch
# ---------------------------------------------------------------------------


@pytest.fixture()
def windows_platform():
    with patch("sys.platform", "win32"):
        yield


# ---------------------------------------------------------------------------
# psutil mocks
# ---------------------------------------------------------------------------


def _make_proc(pid: int, name: str, exe: str = "", cmdline: list[str] | None = None, username: str = "user"):
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.cmdline.return_value = cmdline or [exe]
    proc.username.return_value = username
    proc.info = {"pid": pid, "name": name, "exe": exe, "cmdline": cmdline or [exe], "username": username}
    return proc


def _make_conn(laddr_ip: str, laddr_port: int, pid: int, status: str = "LISTEN"):
    conn = MagicMock()
    conn.laddr = MagicMock()
    conn.laddr.ip = laddr_ip
    conn.laddr.port = laddr_port
    conn.pid = pid
    conn.status = status
    return conn


@pytest.fixture()
def mock_ollama_process():
    return _make_proc(1234, "ollama.exe", r"C:\Users\user\AppData\Local\Programs\Ollama\ollama.exe")


@pytest.fixture()
def mock_ollama_connection():
    return _make_conn("127.0.0.1", 11434, 1234)


# ---------------------------------------------------------------------------
# requests mock helpers (callers use pytest-mock's mocker fixture)
# ---------------------------------------------------------------------------


OLLAMA_TAGS_RESPONSE = {
    "models": [
        {"name": "llama3:8b", "size": 4661211136},
        {"name": "mistral:7b", "size": 4109856768},
    ]
}

OPENAI_MODELS_RESPONSE = {
    "data": [
        {"id": "gpt-3.5-turbo"},
        {"id": "local-model"},
    ]
}

SD_MODELS_RESPONSE = [
    {"title": "v1-5-pruned-emaonly.safetensors", "model_name": "v1-5-pruned-emaonly"},
]
