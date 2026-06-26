from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, computed_field


class DetectionMethod(str, Enum):
    REGISTRY = "registry"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    PATH = "path"


class AppCategory(str, Enum):
    LOCAL_LLM = "local_llm"
    IMAGE_GENERATION = "image_generation"
    CODE_ASSISTANT = "code_assistant"
    AI_INFRASTRUCTURE = "ai_infrastructure"
    OTHER = "other"


class GPUVendor(str, Enum):
    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"
    UNKNOWN = "unknown"


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} PB"


class InstalledApp(BaseModel):
    name: str
    version: Optional[str] = None
    install_path: Optional[str] = None
    exe_path: Optional[str] = None
    category: AppCategory = AppCategory.OTHER
    detection_methods: list[DetectionMethod] = []
    publisher: Optional[str] = None
    extra: dict[str, Any] = {}


class RunningService(BaseModel):
    name: str
    pid: Optional[int] = None
    port: Optional[int] = None
    endpoint_url: Optional[str] = None
    is_alive: bool = False
    loaded_models: list[str] = []
    api_version: Optional[str] = None
    process_name: Optional[str] = None
    process_cmdline: Optional[str] = None


class ModelFile(BaseModel):
    path: str
    filename: str
    extension: str
    model_type: str
    size_bytes: int
    modified_at: datetime
    sha256: Optional[str] = None
    probable_app: Optional[str] = None

    @computed_field  # type: ignore[misc]
    @property
    def size_human(self) -> str:
        return _human_size(self.size_bytes)


class InstalledPackage(BaseModel):
    name: str
    version: str
    category: str
    has_gpu_support: Optional[bool] = None


class PythonEnvironment(BaseModel):
    interpreter_path: str
    python_version: str
    environment_type: str
    environment_name: Optional[str] = None
    packages: list[InstalledPackage] = []


class GPUInfo(BaseModel):
    name: str
    vendor: GPUVendor = GPUVendor.UNKNOWN
    vram_mb: Optional[int] = None
    driver_version: Optional[str] = None
    cuda_version: Optional[str] = None
    rocm_version: Optional[str] = None
    compute_capability: Optional[str] = None
    supports_cuda: bool = False
    supports_rocm: bool = False
    supports_openvino: bool = False
    detection_source: str = "unknown"

    @computed_field  # type: ignore[misc]
    @property
    def vram_human(self) -> Optional[str]:
        if self.vram_mb is None:
            return None
        return _human_size(self.vram_mb * 1024 * 1024)


class ScanMetadata(BaseModel):
    scan_started_at: datetime
    scan_completed_at: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None
    hostname: str
    username: str
    platform: str
    windows_version: Optional[str] = None
    tool_version: str
    categories_scanned: list[str] = []


class ScanReport(BaseModel):
    metadata: ScanMetadata
    installed_apps: list[InstalledApp] = []
    running_services: list[RunningService] = []
    model_files: list[ModelFile] = []
    python_environments: list[PythonEnvironment] = []
    gpus: list[GPUInfo] = []

    @computed_field  # type: ignore[misc]
    @property
    def total_model_size_bytes(self) -> int:
        return sum(f.size_bytes for f in self.model_files)

    @computed_field  # type: ignore[misc]
    @property
    def total_model_count(self) -> int:
        return len(self.model_files)
