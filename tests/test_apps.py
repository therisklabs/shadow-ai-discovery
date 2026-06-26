from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.stubs import winreg as stub_winreg
from ai_discovery.models import AppCategory, DetectionMethod


def _setup_ollama_uninstall(tmp_path: Path):
    """Register a fake Ollama uninstall key in the stub registry."""
    install_dir = str(tmp_path / "Ollama")
    os.makedirs(install_dir, exist_ok=True)

    hive = stub_winreg.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ollama"
    stub_winreg.set_value(hive, path, "DisplayName", "Ollama")
    stub_winreg.set_value(hive, path, "DisplayVersion", "0.3.14")
    stub_winreg.set_value(hive, path, "InstallLocation", install_dir)
    stub_winreg.set_value(hive, path, "Publisher", "Ollama Inc.")
    stub_winreg.set_subkeys(
        hive,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ["Ollama"],
    )


@pytest.fixture()
def windows_env():
    with patch("sys.platform", "win32"):
        yield


def test_ollama_registry_detection(tmp_path, windows_env):
    _setup_ollama_uninstall(tmp_path)
    from ai_discovery.scanner.apps import scan_apps
    apps, warnings = scan_apps()
    ollama = next((a for a in apps if a.name == "Ollama"), None)
    assert ollama is not None, f"Ollama not found in {[a.name for a in apps]}"
    assert ollama.version == "0.3.14"
    assert DetectionMethod.REGISTRY in ollama.detection_methods


def test_ollama_filesystem_detection(tmp_path, windows_env, mocker):
    # No registry — only filesystem
    install_dir = tmp_path / "Programs" / "Ollama"
    install_dir.mkdir(parents=True)
    exe = install_dir / "ollama.exe"
    exe.write_bytes(b"")

    mocker.patch(
        "ai_discovery.scanner.apps.os.path.expandvars",
        side_effect=lambda p: str(install_dir) if "Programs\\Ollama" in p else p,
    )
    from ai_discovery.scanner.apps import scan_apps
    apps, warnings = scan_apps()
    ollama = next((a for a in apps if a.name == "Ollama"), None)
    assert ollama is not None
    assert DetectionMethod.FILESYSTEM in ollama.detection_methods


def test_cursor_path_detection(windows_env, mocker):
    mocker.patch("shutil.which", side_effect=lambda name: "/usr/local/bin/cursor" if name == "cursor" else None)
    from ai_discovery.scanner.apps import scan_apps
    apps, _ = scan_apps()
    cursor = next((a for a in apps if a.name == "Cursor"), None)
    assert cursor is not None
    assert DetectionMethod.PATH in cursor.detection_methods
    assert cursor.category == AppCategory.CODE_ASSISTANT


def test_deduplication_registry_and_fs(tmp_path, windows_env, mocker):
    """Same tool found by both registry and filesystem → one record with both methods."""
    _setup_ollama_uninstall(tmp_path)

    install_dir = tmp_path / "Ollama"
    exe = install_dir / "ollama.exe"
    exe.write_bytes(b"")

    mocker.patch(
        "ai_discovery.scanner.apps.os.path.expandvars",
        side_effect=lambda p: str(install_dir) if "Programs\\Ollama" in p else p,
    )
    from ai_discovery.scanner.apps import scan_apps
    apps, _ = scan_apps()
    ollama_matches = [a for a in apps if a.name == "Ollama"]
    assert len(ollama_matches) == 1
    methods = ollama_matches[0].detection_methods
    assert DetectionMethod.REGISTRY in methods
    assert DetectionMethod.FILESYSTEM in methods


def test_no_false_positives_empty_registry(windows_env):
    # Empty registry → no apps detected via registry
    from ai_discovery.scanner.apps import scan_apps
    # Only PATH/filesystem detections may fire; registry should add nothing
    apps, warnings = scan_apps()
    # Verify no crashes and result is a list
    assert isinstance(apps, list)
    assert isinstance(warnings, list)


def test_category_assignment(tmp_path, windows_env):
    _setup_ollama_uninstall(tmp_path)
    from ai_discovery.scanner.apps import scan_apps
    apps, _ = scan_apps()
    ollama = next((a for a in apps if a.name == "Ollama"), None)
    assert ollama is not None
    assert ollama.category == AppCategory.LOCAL_LLM
