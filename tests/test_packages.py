from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from ai_discovery.scanner.packages import _query_interpreter, scan_packages


FAKE_OUTPUT = json.dumps({
    "python": "3.11.9",
    "packages": [
        ["torch", "2.3.1+cu121"],
        ["transformers", "4.42.4"],
        ["langchain", "0.2.6"],
    ],
})


def test_query_interpreter_parses_output(mocker):
    mock_run = mocker.patch("ai_discovery.scanner.packages.subprocess.run")
    mock_run.return_value = MagicMock(returncode=0, stdout=FAKE_OUTPUT)

    env = _query_interpreter(sys.executable, "system")
    assert env is not None
    assert env.python_version == "3.11.9"
    assert len(env.packages) == 3
    pkg_names = {p.name for p in env.packages}
    assert "torch" in pkg_names
    assert "transformers" in pkg_names


def test_query_interpreter_gpu_detection(mocker):
    mock_run = mocker.patch("ai_discovery.scanner.packages.subprocess.run")
    mock_run.return_value = MagicMock(returncode=0, stdout=FAKE_OUTPUT)

    env = _query_interpreter(sys.executable, "system")
    torch_pkg = next(p for p in env.packages if p.name == "torch")
    assert torch_pkg.has_gpu_support is True  # +cu121 in version


def test_query_interpreter_bad_output(mocker):
    mock_run = mocker.patch("ai_discovery.scanner.packages.subprocess.run")
    mock_run.return_value = MagicMock(returncode=1, stdout="")

    env = _query_interpreter(sys.executable, "system")
    assert env is None


def test_query_interpreter_no_packages(mocker):
    output = json.dumps({"python": "3.11.9", "packages": []})
    mock_run = mocker.patch("ai_discovery.scanner.packages.subprocess.run")
    mock_run.return_value = MagicMock(returncode=0, stdout=output)

    env = _query_interpreter(sys.executable, "system")
    assert env is None  # empty package list → None


def test_query_interpreter_timeout(mocker):
    import subprocess
    mock_run = mocker.patch(
        "ai_discovery.scanner.packages.subprocess.run",
        side_effect=subprocess.TimeoutExpired("python", 15),
    )
    env = _query_interpreter(sys.executable, "system")
    assert env is None


def test_scan_packages_returns_sorted(mocker):
    rich_output = json.dumps({
        "python": "3.11.9",
        "packages": [["torch", "2.3.1"], ["transformers", "4.42.4"]],
    })
    sparse_output = json.dumps({
        "python": "3.12.0",
        "packages": [["openai", "1.0.0"]],
    })

    call_count = [0]
    def fake_run(cmd, **kwargs):
        call_count[0] += 1
        out = rich_output if call_count[0] == 1 else sparse_output
        return MagicMock(returncode=0, stdout=out)

    mocker.patch("ai_discovery.scanner.packages.subprocess.run", side_effect=fake_run)
    mocker.patch(
        "ai_discovery.scanner.packages._find_python_interpreters",
        return_value=[(sys.executable, "system"), ("/usr/bin/python3", "system")],
    )

    envs, warnings = scan_packages()
    assert len(envs) >= 1
    # Most packages first
    assert len(envs[0].packages) >= len(envs[-1].packages)


# ---------------------------------------------------------------------------
# v0.2.0 Python discovery tests
# ---------------------------------------------------------------------------

def test_find_python_via_where_returns_list(mocker):
    from ai_discovery.scanner.packages import _find_python_via_where
    mock_result = mocker.MagicMock(returncode=0, stdout="/usr/bin/python3\n/usr/local/bin/python3\n")
    mocker.patch("ai_discovery.scanner.packages.subprocess.run", return_value=mock_result)
    mocker.patch("ai_discovery.scanner.packages.os.path.isfile", return_value=True)
    paths = _find_python_via_where()
    assert isinstance(paths, list)
    assert len(paths) >= 1


def test_find_python_via_where_empty_on_error(mocker):
    from ai_discovery.scanner.packages import _find_python_via_where
    mocker.patch(
        "ai_discovery.scanner.packages.subprocess.run",
        side_effect=Exception("no where command"),
    )
    paths = _find_python_via_where()
    assert paths == []


def test_scan_packages_deep_calls_deep_interpreters(mocker):
    """deep=True should call _find_python_interpreters with deep=True."""
    mock_find = mocker.patch(
        "ai_discovery.scanner.packages._find_python_interpreters",
        return_value=[(sys.executable, "system")],
    )
    output = json.dumps({"python": "3.11.9", "packages": [["openai", "1.0.0"]]})
    mocker.patch(
        "ai_discovery.scanner.packages.subprocess.run",
        return_value=mocker.MagicMock(returncode=0, stdout=output),
    )
    envs, _ = scan_packages(deep=True)
    mock_find.assert_called_once_with(deep=True)
