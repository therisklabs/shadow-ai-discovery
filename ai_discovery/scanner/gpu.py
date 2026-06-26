"""GPU hardware detection.

Detection order per vendor:
  NVIDIA  : nvidia-smi → wmic → Windows registry class key
  AMD     : rocm-smi → %PROGRAMFILES%\AMD\ROCm presence → registry
  Intel   : xpu-smi → %PROGRAMFILES%\Intel\oneAPI presence → registry
  CPU     : always emitted via psutil / platform
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from typing import Optional

import psutil

from ai_discovery.models import GPUInfo, GPUVendor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _expandvars(path: str) -> str:
    return os.path.expandvars(path)


# ---------------------------------------------------------------------------
# NVIDIA
# ---------------------------------------------------------------------------


def _detect_nvidia() -> list[GPUInfo]:
    gpus: list[GPUInfo] = []

    # Primary: nvidia-smi
    out = _run([
        "nvidia-smi",
        "--query-gpu=name,memory.total,driver_version,compute_cap",
        "--format=csv,noheader,nounits",
    ])
    if out:
        for line in out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                continue
            name = parts[0]
            try:
                vram_mb = int(parts[1])
            except ValueError:
                vram_mb = None
            driver = parts[2] if len(parts) > 2 else None
            compute = parts[3] if len(parts) > 3 else None
            # Infer CUDA version from nvidia-smi header (separate call)
            cuda_ver = _get_cuda_version()
            gpus.append(GPUInfo(
                name=name,
                vendor=GPUVendor.NVIDIA,
                vram_mb=vram_mb,
                driver_version=driver,
                cuda_version=cuda_ver,
                compute_capability=compute,
                supports_cuda=True,
                detection_source="nvidia-smi",
            ))
        if gpus:
            return gpus

    # Fallback: wmic (Windows only)
    if sys.platform == "win32":
        wmic_out = _run([
            "wmic", "path", "win32_VideoController",
            "get", "Name,AdapterRAM,DriverVersion",
            "/format:csv",
        ])
        if wmic_out:
            for line in wmic_out.splitlines():
                if not line.strip() or "Name" in line:
                    continue
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                name = parts[3].strip()
                if "nvidia" not in name.lower():
                    continue
                try:
                    vram_bytes = int(parts[1].strip())
                    vram_mb = vram_bytes // (1024 * 1024)
                except (ValueError, IndexError):
                    vram_mb = None
                driver = parts[2].strip() if len(parts) > 2 else None
                gpus.append(GPUInfo(
                    name=name,
                    vendor=GPUVendor.NVIDIA,
                    vram_mb=vram_mb,
                    driver_version=driver,
                    supports_cuda=True,
                    detection_source="wmic",
                ))
        if gpus:
            return gpus

        # Fallback: Windows registry
        gpus.extend(_detect_gpu_from_registry("nvidia"))

    return gpus


def _get_cuda_version() -> Optional[str]:
    out = _run(["nvidia-smi", "--query-gpu=cuda_version", "--format=csv,noheader,nounits"])
    if out:
        line = out.splitlines()[0].strip()
        if line and line != "[N/A]":
            return line
    return None


# ---------------------------------------------------------------------------
# AMD
# ---------------------------------------------------------------------------


def _detect_amd() -> list[GPUInfo]:
    gpus: list[GPUInfo] = []

    out = _run(["rocm-smi", "--showproductname", "--showmeminfo", "vram", "--csv"])
    if out:
        for line in out.splitlines():
            if line.startswith("GPU") or not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            name = parts[1] if len(parts) > 1 else "AMD GPU"
            try:
                vram_mb = int(parts[2]) // (1024 * 1024) if len(parts) > 2 else None
            except ValueError:
                vram_mb = None
            gpus.append(GPUInfo(
                name=name,
                vendor=GPUVendor.AMD,
                vram_mb=vram_mb,
                supports_rocm=True,
                detection_source="rocm-smi",
            ))
        if gpus:
            return gpus

    if sys.platform == "win32":
        rocm_dir = _expandvars(r"%PROGRAMFILES%\AMD\ROCm")
        if os.path.isdir(rocm_dir):
            gpus.append(GPUInfo(
                name="AMD GPU (ROCm)",
                vendor=GPUVendor.AMD,
                supports_rocm=True,
                detection_source="filesystem",
            ))
        if not gpus:
            gpus.extend(_detect_gpu_from_registry("advanced micro devices"))

    return gpus


# ---------------------------------------------------------------------------
# Intel
# ---------------------------------------------------------------------------


def _detect_intel() -> list[GPUInfo]:
    gpus: list[GPUInfo] = []

    out = _run(["xpu-smi", "discovery", "--json"])
    if out:
        import json
        try:
            data = json.loads(out)
            for entry in data.get("device_list", []):
                gpus.append(GPUInfo(
                    name=entry.get("device_name", "Intel GPU"),
                    vendor=GPUVendor.INTEL,
                    driver_version=entry.get("driver_version"),
                    detection_source="xpu-smi",
                ))
        except (json.JSONDecodeError, KeyError):
            pass
        if gpus:
            return gpus

    if sys.platform == "win32":
        openvino_dir = _expandvars(r"%PROGRAMFILES%\Intel\oneAPI")
        if os.path.isdir(openvino_dir):
            gpus.append(GPUInfo(
                name="Intel GPU (oneAPI)",
                vendor=GPUVendor.INTEL,
                supports_openvino=True,
                detection_source="filesystem",
            ))
        if not gpus:
            gpus.extend(_detect_gpu_from_registry("intel"))

    return gpus


# ---------------------------------------------------------------------------
# Registry fallback (Windows only)
# ---------------------------------------------------------------------------


def _detect_gpu_from_registry(vendor_keyword: str) -> list[GPUInfo]:
    if sys.platform != "win32":
        return []
    try:
        import winreg
        gpu_class = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        results: list[GPUInfo] = []
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, gpu_class) as base:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(base, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(base, sub) as k:
                        try:
                            provider, _ = winreg.QueryValueEx(k, "ProviderName")
                        except OSError:
                            continue
                        if vendor_keyword.lower() not in str(provider).lower():
                            continue
                        try:
                            desc, _ = winreg.QueryValueEx(k, "DriverDesc")
                        except OSError:
                            desc = f"{vendor_keyword.title()} GPU"
                        try:
                            drv, _ = winreg.QueryValueEx(k, "DriverVersion")
                        except OSError:
                            drv = None
                        vendor_map = {
                            "nvidia": GPUVendor.NVIDIA,
                            "advanced micro devices": GPUVendor.AMD,
                            "intel": GPUVendor.INTEL,
                        }
                        vendor = vendor_map.get(vendor_keyword.lower(), GPUVendor.UNKNOWN)
                        results.append(GPUInfo(
                            name=str(desc),
                            vendor=vendor,
                            driver_version=str(drv) if drv else None,
                            supports_cuda=vendor == GPUVendor.NVIDIA,
                            supports_rocm=vendor == GPUVendor.AMD,
                            detection_source="registry",
                        ))
                except OSError:
                    continue
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CPU fallback
# ---------------------------------------------------------------------------


def _detect_cpu() -> GPUInfo:
    cpu_name = platform.processor() or platform.machine()
    cores = psutil.cpu_count(logical=False) or 0
    threads = psutil.cpu_count(logical=True) or 0
    return GPUInfo(
        name=f"CPU: {cpu_name} ({cores}c/{threads}t)",
        vendor=GPUVendor.UNKNOWN,
        detection_source="psutil",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_gpu() -> tuple[list[GPUInfo], list[str]]:
    """Return (gpu_list, warnings)."""
    gpus: list[GPUInfo] = []
    warnings: list[str] = []

    try:
        gpus.extend(_detect_nvidia())
    except Exception as exc:
        warnings.append(f"NVIDIA detection error: {exc}")

    try:
        gpus.extend(_detect_amd())
    except Exception as exc:
        warnings.append(f"AMD detection error: {exc}")

    try:
        gpus.extend(_detect_intel())
    except Exception as exc:
        warnings.append(f"Intel detection error: {exc}")

    # Always add CPU entry
    try:
        gpus.append(_detect_cpu())
    except Exception as exc:
        warnings.append(f"CPU detection error: {exc}")

    return gpus, warnings
