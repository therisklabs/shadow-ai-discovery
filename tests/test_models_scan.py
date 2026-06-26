from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_discovery.scanner.models_scan import _make_model_file, _should_include, scan_models


def _write(path: Path, size: int = 20 * 1024 * 1024) -> Path:
    """Create a dummy file of the given size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00" * size)
    return path


def test_gguf_file_detected(tmp_path):
    gguf = _write(tmp_path / "models" / "llama3.gguf")
    results, warnings = scan_models(extra_paths=[str(tmp_path / "models")])
    assert any(f.filename == "llama3.gguf" for f in results)


def test_safetensors_detected(tmp_path):
    st = _write(tmp_path / "checkpoints" / "model.safetensors")
    results, _ = scan_models(extra_paths=[str(tmp_path / "checkpoints")])
    assert any(f.extension == ".safetensors" for f in results)


def test_bin_file_excluded_without_marker(tmp_path):
    # A .bin file in a random directory (no model marker in path)
    binf = _write(tmp_path / "random" / "data.bin")
    results, _ = scan_models(extra_paths=[str(tmp_path / "random")])
    assert not any(f.filename == "data.bin" for f in results)


def test_bin_file_included_with_marker(tmp_path):
    binf = _write(tmp_path / "models" / "pytorch_model.bin")
    results, _ = scan_models(extra_paths=[str(tmp_path / "models")])
    assert any(f.filename == "pytorch_model.bin" for f in results)


def test_small_bin_excluded(tmp_path):
    # Under 10 MB minimum size
    small = tmp_path / "models" / "tiny.bin"
    small.parent.mkdir(parents=True, exist_ok=True)
    small.write_bytes(b"\x00" * 100)
    results, _ = scan_models(extra_paths=[str(tmp_path / "models")])
    assert not any(f.filename == "tiny.bin" for f in results)


def test_sorted_by_size_descending(tmp_path):
    _write(tmp_path / "a.gguf", size=5 * 1024 * 1024)
    _write(tmp_path / "b.gguf", size=50 * 1024 * 1024)
    _write(tmp_path / "c.gguf", size=20 * 1024 * 1024)
    results, _ = scan_models(extra_paths=[str(tmp_path)])
    sizes = [f.size_bytes for f in results]
    assert sizes == sorted(sizes, reverse=True)


def test_missing_extra_path_gives_warning(tmp_path):
    _, warnings = scan_models(extra_paths=[str(tmp_path / "does_not_exist")])
    assert any("not found" in w for w in warnings)


def test_model_type_identified():
    from ai_discovery.scanner.models_scan import EXTENSION_TYPES
    assert ".gguf" in EXTENSION_TYPES
    assert ".safetensors" in EXTENSION_TYPES
    assert ".onnx" in EXTENSION_TYPES


def test_probable_app_detection(tmp_path):
    mf_path = tmp_path / ".ollama" / "models" / "test.gguf"
    _write(mf_path)
    results, _ = scan_models(extra_paths=[str(tmp_path / ".ollama" / "models")])
    found = next((f for f in results if f.filename == "test.gguf"), None)
    assert found is not None
    assert found.probable_app == "Ollama"


def test_no_duplicate_files(tmp_path):
    model_dir = tmp_path / "models"
    _write(model_dir / "model.gguf")
    # Scan same directory twice via different paths pointing to same location
    results, _ = scan_models(extra_paths=[str(model_dir), str(model_dir)])
    gguf_files = [f for f in results if f.filename == "model.gguf"]
    assert len(gguf_files) == 1
