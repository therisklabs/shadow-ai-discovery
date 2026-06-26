"""
AI Python package detection.

Finds all Python interpreters on the system, then queries each one for
installed AI-related packages using importlib.metadata via a subprocess.
All interpreter queries run concurrently via ThreadPoolExecutor.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from ai_discovery.models import InstalledPackage, PythonEnvironment

# ---------------------------------------------------------------------------
# Target packages with their categories
# ---------------------------------------------------------------------------

PACKAGES: list[tuple[str, str]] = [
    # Deep learning frameworks
    ("torch", "Deep Learning"),
    ("tensorflow", "Deep Learning"),
    ("tensorflow-gpu", "Deep Learning"),
    ("jax", "Deep Learning"),
    ("jaxlib", "Deep Learning"),
    ("keras", "Deep Learning"),
    ("paddle", "Deep Learning"),
    ("paddlepaddle", "Deep Learning"),
    # HuggingFace ecosystem
    ("transformers", "HuggingFace"),
    ("diffusers", "HuggingFace"),
    ("accelerate", "HuggingFace"),
    ("datasets", "HuggingFace"),
    ("huggingface_hub", "HuggingFace"),
    ("peft", "HuggingFace"),
    ("trl", "HuggingFace"),
    ("optimum", "HuggingFace"),
    ("tokenizers", "HuggingFace"),
    # Quantization / inference bindings
    ("llama_cpp_python", "Local Inference"),
    ("ctransformers", "Local Inference"),
    ("bitsandbytes", "Quantization"),
    ("auto_gptq", "Quantization"),
    ("autoawq", "Quantization"),
    ("xformers", "Optimization"),
    ("einops", "Optimization"),
    # LLM orchestration
    ("langchain", "Orchestration"),
    ("langchain_community", "Orchestration"),
    ("langchain_openai", "Orchestration"),
    ("llama_index", "Orchestration"),
    ("dspy-ai", "Orchestration"),
    ("guidance", "Orchestration"),
    ("outlines", "Orchestration"),
    ("haystack-ai", "Orchestration"),
    # API SDKs
    ("openai", "API SDK"),
    ("anthropic", "API SDK"),
    ("google-generativeai", "API SDK"),
    ("cohere", "API SDK"),
    ("mistralai", "API SDK"),
    ("ollama", "API SDK"),
    ("tiktoken", "API SDK"),
    # Agents / multi-agent
    ("crewai", "Agents"),
    ("autogen", "Agents"),
    ("semantic_kernel", "Agents"),
    ("pydantic_ai", "Agents"),
    # Vector databases
    ("chromadb", "Vector DB"),
    ("qdrant_client", "Vector DB"),
    ("faiss-cpu", "Vector DB"),
    ("faiss-gpu", "Vector DB"),
    ("pinecone-client", "Vector DB"),
    ("weaviate-client", "Vector DB"),
    # Serving
    ("vllm", "Serving"),
    ("litellm", "Serving"),
    ("text_generation", "Serving"),
    # Runtimes
    ("onnxruntime", "Runtime"),
    ("onnxruntime-gpu", "Runtime"),
    ("openvino", "Runtime"),
    ("tensorrt", "Runtime"),
    ("triton", "Runtime"),
    # Embeddings / NLP
    ("sentence_transformers", "Embeddings"),
    ("spacy", "NLP"),
    ("nltk", "NLP"),
    ("gensim", "NLP"),
    # ML / vision
    ("scikit-learn", "ML"),
    ("timm", "Vision"),
    ("ultralytics", "Vision"),
]

_PACKAGE_NAMES = [p for p, _ in PACKAGES]
_PACKAGE_CATS = {p: c for p, c in PACKAGES}


def _has_gpu_support(pkg_name: str, version: str) -> Optional[bool]:
    """Heuristic: detect GPU support from package name or version string."""
    if "gpu" in pkg_name.lower():
        return True
    if "+cu" in version or "+rocm" in version or "cuda" in version.lower():
        return True
    if pkg_name in ("tensorflow-gpu", "onnxruntime-gpu", "faiss-gpu"):
        return True
    return None


# ---------------------------------------------------------------------------
# Python interpreter discovery
# ---------------------------------------------------------------------------


def _find_python_interpreters() -> list[tuple[str, str]]:
    """Return list of (interpreter_path, env_type) tuples."""
    found: dict[str, str] = {}

    def _add(path: str, env_type: str) -> None:
        real = os.path.realpath(path)
        if real not in found:
            found[real] = env_type

    # Current interpreter is always included
    _add(sys.executable, "system")

    home = os.path.expanduser("~")

    if sys.platform == "win32":
        # System Python installations
        for pattern in [
            r"%LOCALAPPDATA%\Programs\Python\Python3*\python.exe",
            r"%PROGRAMFILES%\Python3*\python.exe",
            r"%PROGRAMFILES(X86)%\Python3*\python.exe",
        ]:
            for path in glob.glob(os.path.expandvars(pattern)):
                _add(path, "system")

        # Conda / Anaconda / Miniconda / Miniforge
        conda_roots = [
            os.path.expandvars(r"%USERPROFILE%\anaconda3"),
            os.path.expandvars(r"%USERPROFILE%\miniconda3"),
            os.path.expandvars(r"%LOCALAPPDATA%\miniforge3"),
            os.path.expandvars(r"%LOCALAPPDATA%\anaconda3"),
        ]
        for root in conda_roots:
            base_py = os.path.join(root, "python.exe")
            if os.path.isfile(base_py):
                _add(base_py, "conda")
            for env_py in glob.glob(os.path.join(root, "envs", "*", "python.exe")):
                _add(env_py, "conda")

        # Virtualenvs
        for pattern in [
            os.path.join(home, "venvs", "*", "Scripts", "python.exe"),
            os.path.join(home, ".venvs", "*", "Scripts", "python.exe"),
        ]:
            for path in glob.glob(pattern):
                _add(path, "venv")

        # Poetry virtualenvs
        for path in glob.glob(os.path.expandvars(
            r"%APPDATA%\pypoetry\Cache\virtualenvs\*\Scripts\python.exe"
        )):
            _add(path, "poetry")

    else:
        # Linux / macOS paths for testing
        for candidate in ["/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"]:
            if os.path.isfile(candidate):
                _add(candidate, "system")

        for root in [
            os.path.join(home, "anaconda3"),
            os.path.join(home, "miniconda3"),
            "/opt/conda",
        ]:
            for path in glob.glob(os.path.join(root, "envs", "*", "bin", "python")):
                _add(path, "conda")

        for pattern in [
            os.path.join(home, ".venvs", "*", "bin", "python"),
            os.path.join(home, "venvs", "*", "bin", "python"),
        ]:
            for path in glob.glob(pattern):
                _add(path, "venv")

    return list(found.items())


# ---------------------------------------------------------------------------
# Per-interpreter package query
# ---------------------------------------------------------------------------

_QUERY_SCRIPT = """
import json, sys
try:
    import importlib.metadata as im
except ImportError:
    import importlib_metadata as im

results = []
target = {names}
for pkg in target:
    try:
        v = im.version(pkg)
        results.append((pkg, v))
    except Exception:
        pass

print(json.dumps({{"python": sys.version.split()[0], "packages": results}}))
""".strip()


def _query_interpreter(interpreter: str, env_type: str) -> Optional[PythonEnvironment]:
    pkg_list = json.dumps(_PACKAGE_NAMES)
    script = _QUERY_SCRIPT.replace("{names}", pkg_list)
    try:
        result = subprocess.run(
            [interpreter, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        data = json.loads(result.stdout.strip())
    except Exception:
        return None

    packages = [
        InstalledPackage(
            name=name,
            version=ver,
            category=_PACKAGE_CATS.get(name, "Other"),
            has_gpu_support=_has_gpu_support(name, ver),
        )
        for name, ver in data.get("packages", [])
    ]

    if not packages:
        return None

    env_name: Optional[str] = None
    if env_type == "conda":
        parts = interpreter.replace("\\", "/").split("/")
        try:
            idx = parts.index("envs")
            env_name = parts[idx + 1]
        except (ValueError, IndexError):
            env_name = None

    return PythonEnvironment(
        interpreter_path=interpreter,
        python_version=data.get("python", "unknown"),
        environment_type=env_type,
        environment_name=env_name,
        packages=packages,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_packages() -> tuple[list[PythonEnvironment], list[str]]:
    """Return (environments, warnings)."""
    interpreters = _find_python_interpreters()
    warnings: list[str] = []
    envs: list[PythonEnvironment] = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_query_interpreter, path, etype): path for path, etype in interpreters}
        for future in as_completed(futures):
            path = futures[future]
            try:
                env = future.result()
                if env is not None:
                    envs.append(env)
            except Exception as exc:
                warnings.append(f"Package scan failed for {path}: {exc}")

    # Sort by number of packages (richest env first)
    envs.sort(key=lambda e: len(e.packages), reverse=True)
    return envs, warnings
