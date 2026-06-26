from __future__ import annotations

from unittest.mock import MagicMock, patch

from ai_discovery.models import GPUVendor
from ai_discovery.scanner.gpu import _detect_cpu, scan_gpu


def test_cpu_always_detected():
    gpus, warnings = scan_gpu()
    cpu_entries = [g for g in gpus if "CPU" in g.name]
    assert len(cpu_entries) >= 1


def test_cpu_fields():
    gpu = _detect_cpu()
    assert gpu.vendor == GPUVendor.UNKNOWN
    assert "CPU" in gpu.name
    assert gpu.detection_source == "psutil"


def test_nvidia_smi_parsed(mocker):
    # cmd is a list; first call queries GPU info, second call queries cuda_version
    call_count = [0]
    def fake_run(cmd, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return "NVIDIA GeForce RTX 4090, 24564, 555.85, 8.9"
        return "12.5"

    mocker.patch("ai_discovery.scanner.gpu._run", side_effect=fake_run)
    from ai_discovery.scanner.gpu import _detect_nvidia
    gpus = _detect_nvidia()
    assert len(gpus) == 1
    assert gpus[0].name == "NVIDIA GeForce RTX 4090"
    assert gpus[0].vram_mb == 24564
    assert gpus[0].supports_cuda is True
    assert gpus[0].vendor == GPUVendor.NVIDIA


def test_scan_gpu_errors_isolated(mocker):
    mocker.patch("ai_discovery.scanner.gpu._detect_nvidia", side_effect=RuntimeError("boom"))
    mocker.patch("ai_discovery.scanner.gpu._detect_amd", return_value=[])
    mocker.patch("ai_discovery.scanner.gpu._detect_intel", return_value=[])
    gpus, warnings = scan_gpu()
    assert any("NVIDIA" in w for w in warnings)
    # CPU still present
    assert any("CPU" in g.name for g in gpus)


def test_no_gpu_tools_returns_cpu_only(mocker):
    mocker.patch("ai_discovery.scanner.gpu._run", return_value=None)
    mocker.patch("sys.platform", "linux")
    gpus, warnings = scan_gpu()
    assert any("CPU" in g.name for g in gpus)
