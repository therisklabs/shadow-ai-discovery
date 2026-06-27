"""
AI model file discovery.

Scans well-known locations for model file types used by local AI tools.
Guarded .bin scanning avoids false positives from Windows DLLs and game data.
"""

from __future__ import annotations

import hashlib
import os
import string
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from ai_discovery.models import ModelFile

# ---------------------------------------------------------------------------
# Extension → model type mapping
# ---------------------------------------------------------------------------

EXTENSION_TYPES: dict[str, str] = {
    ".gguf": "GGUF (llama.cpp)",
    ".ggml": "GGML (llama.cpp legacy)",
    ".safetensors": "SafeTensors (HuggingFace)",
    ".pt": "PyTorch checkpoint",
    ".pth": "PyTorch checkpoint",
    ".onnx": "ONNX model",
    ".bin": "Binary model (HuggingFace/GGML)",
    ".pkl": "Pickle model (scikit-learn)",
}

# Extensions that need a minimum file size to avoid false positives
_LARGE_ONLY_EXTENSIONS = {".bin", ".pkl", ".pt", ".pth"}
_MIN_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# .bin is only included if the containing path has one of these markers
_BIN_PATH_MARKERS = frozenset(["huggingface", "models", "weights", "checkpoints", "blobs"])

# Don't hash files larger than 100 MB (too slow)
_MAX_HASH_SIZE = 100 * 1024 * 1024

# Ignore files larger than this (not a model)
_MAX_FILE_SIZE = 200 * 1024 * 1024 * 1024  # 200 GB

# App name heuristics from path segments
_PATH_APP_MAP: list[tuple[str, str]] = [
    ("ollama", "Ollama"),
    ("lmstudio", "LM Studio"),
    (".lmstudio", "LM Studio"),
    ("jan", "Jan"),
    ("gpt4all", "GPT4All"),
    ("nomic.ai", "GPT4All"),
    ("stable-diffusion", "Stable Diffusion"),
    ("comfyui", "ComfyUI"),
    ("invokeai", "InvokeAI"),
    ("text-generation-webui", "text-generation-webui"),
    ("anythingllm", "AnythingLLM"),
    ("huggingface", "HuggingFace Hub"),
]


def _probable_app(path: str) -> Optional[str]:
    lower = path.lower().replace("\\", "/")
    for key, name in _PATH_APP_MAP:
        if key in lower:
            return name
    return None


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _should_include(path: str, size: int, ext: str) -> bool:
    if size > _MAX_FILE_SIZE:
        return False
    if ext in _LARGE_ONLY_EXTENSIONS and size < _MIN_SIZE_BYTES:
        return False
    if ext == ".bin":
        lower = path.lower().replace("\\", "/")
        if not any(m in lower for m in _BIN_PATH_MARKERS):
            return False
    return True


def _make_model_file(path: str) -> Optional[ModelFile]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    size = stat.st_size
    p = Path(path)
    ext = p.suffix.lower()
    if not _should_include(path, size, ext):
        return None
    sha = _sha256(path) if size < _MAX_HASH_SIZE else None
    return ModelFile(
        path=str(p.as_posix()),
        filename=p.name,
        extension=ext,
        model_type=EXTENSION_TYPES.get(ext, "Unknown"),
        size_bytes=size,
        modified_at=datetime.fromtimestamp(stat.st_mtime),
        sha256=sha,
        probable_app=_probable_app(str(p)),
    )


# ---------------------------------------------------------------------------
# Scan location builders
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Deep scan helpers
# ---------------------------------------------------------------------------

_SKIP_DIR_NAMES: frozenset[str] = frozenset([
    "windows", "system32", "syswow64", "winsxs", "windowsapps",
    "$recycle.bin", "system volume information", "recovery",
    "perflogs", "intel", "nvidia corporation",
    "node_modules", ".git", "__pycache__", ".npm", ".cargo", ".rustup",
    "temp", "tmp", "cache\\chrome", "cache\\firefox", "cache\\edge",
    "google\\chrome", "mozilla\\firefox", "microsoft\\edge",
])


def _should_skip_dir(dirpath: str) -> bool:
    lower = dirpath.lower().replace("\\", "/")
    name = lower.rstrip("/").rsplit("/", 1)[-1]
    if name in _SKIP_DIR_NAMES:
        return True
    # Skip known OS/browser cache sub-paths
    skip_fragments = (
        "programdata/microsoft",
        "appdata/local/microsoft/windows",
        "appdata/roaming/microsoft",
        "appdata/local/google/chrome",
        "appdata/local/mozilla",
        "appdata/local/temp",
    )
    return any(frag in lower for frag in skip_fragments)


def _all_drives() -> list[str]:
    if sys.platform == "win32":
        return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    return ["/"]


def _deep_scan_dirs() -> list[str]:
    return _all_drives()


def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def _default_scan_dirs() -> list[str]:
    home = os.path.expanduser("~")
    dirs: list[str] = []

    if sys.platform == "win32":
        candidates = [
            r"%USERPROFILE%\.ollama\models",
            r"%USERPROFILE%\.lmstudio\models",
            r"%USERPROFILE%\jan\models",
            r"%USERPROFILE%\.cache\huggingface\hub",
            r"%USERPROFILE%\invokeai\models",
            r"%APPDATA%\anythingllm-desktop\storage\models",
            r"%USERPROFILE%\Downloads",
            r"%USERPROFILE%\Documents",
            r"%USERPROFILE%\Desktop",
        ]
    else:
        candidates = [
            os.path.join(home, ".ollama", "models"),
            os.path.join(home, ".lmstudio", "models"),
            os.path.join(home, "jan", "models"),
            os.path.join(home, ".cache", "huggingface", "hub"),
            os.path.join(home, "invokeai", "models"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
        ]

    for c in candidates:
        expanded = _expand(c)
        if os.path.isdir(expanded):
            dirs.append(expanded)
    return dirs


def _walk(directory: str, seen_inodes: set, deep: bool = False) -> list[ModelFile]:
    results: list[ModelFile] = []
    target_exts = set(EXTENSION_TYPES.keys())
    try:
        for root, dirs, files in os.walk(directory, onerror=lambda _: None, followlinks=False):
            if deep:
                dirs[:] = [d for d in dirs if not _should_skip_dir(os.path.join(root, d))]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = Path(fname).suffix.lower()
                if ext not in target_exts:
                    continue
                try:
                    inode = os.stat(fpath).st_ino
                    if inode and inode in seen_inodes:
                        continue
                    if inode:
                        seen_inodes.add(inode)
                except OSError:
                    pass
                mf = _make_model_file(fpath)
                if mf is not None:
                    results.append(mf)
    except OSError:
        pass
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_models(
    extra_paths: Optional[list[str]] = None,
    deep: bool = False,
) -> tuple[list[ModelFile], list[str]]:
    """Return (model_files, warnings) sorted by size descending.

    When deep=True, walk every available drive (skipping OS dirs) instead of
    just the 9 well-known locations.
    """
    warnings: list[str] = []

    if deep:
        dirs = _deep_scan_dirs()
    else:
        dirs = _default_scan_dirs()

    if extra_paths:
        for p in extra_paths:
            expanded = os.path.expandvars(os.path.expanduser(p))
            if os.path.isdir(expanded):
                dirs.append(expanded)
            else:
                warnings.append(f"Model path not found: {p}")

    # Deduplicate paths by real path
    seen_dirs: set[str] = set()
    unique_dirs: list[str] = []
    for d in dirs:
        real = os.path.realpath(d)
        if real not in seen_dirs:
            seen_dirs.add(real)
            unique_dirs.append(d)

    seen_inodes: set = set()
    seen_paths: set[str] = set()
    all_files: list[ModelFile] = []

    for d in unique_dirs:
        for mf in _walk(d, seen_inodes, deep=deep):
            real_path = os.path.realpath(mf.path)
            if real_path not in seen_paths:
                seen_paths.add(real_path)
                all_files.append(mf)

    all_files.sort(key=lambda f: f.size_bytes, reverse=True)
    return all_files, warnings
