"""
Running AI service detection.

Three-step approach:
  1. psutil process scan — match process names / cmdlines
  2. psutil TCP port scan — find LISTEN sockets on known AI ports
  3. HTTP endpoint probing — confirm services are alive and extract loaded models
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import psutil
import requests

from ai_discovery.models import RunningService

# ---------------------------------------------------------------------------
# Known AI service definitions
# ---------------------------------------------------------------------------


class _ServiceDef:
    def __init__(
        self,
        name: str,
        exe_names: list[str],
        default_port: int,
        probe_path: str,
        model_extractor,
        cmdline_markers: Optional[list[str]] = None,
    ):
        self.name = name
        self.exe_names = [e.lower() for e in exe_names]
        self.default_port = default_port
        self.probe_path = probe_path
        self.model_extractor = model_extractor
        self.cmdline_markers = [m.lower() for m in (cmdline_markers or [])]


def _extract_openai_models(data: dict) -> list[str]:
    return [entry.get("id", "") for entry in data.get("data", [])]


def _extract_ollama_models(data: dict) -> list[str]:
    return [m.get("name", "") for m in data.get("models", [])]


def _extract_sd_models(data) -> list[str]:
    if isinstance(data, list):
        return [m.get("title", m.get("model_name", "")) for m in data]
    return []


def _extract_kobold_version(data: dict) -> list[str]:
    result = data.get("result", "")
    if result:
        return [f"KoboldCpp {result}"]
    return []


def _extract_textgen_model(data: dict) -> list[str]:
    result = data.get("result", "")
    return [result] if result else []


def _extract_comfyui(data: dict) -> list[str]:
    ver = data.get("system", {}).get("comfyui_version", "")
    return [f"ComfyUI {ver}"] if ver else ["ComfyUI"]


def _extract_version_field(data: dict) -> list[str]:
    ver = data.get("version", data.get("app_version", ""))
    return [str(ver)] if ver else []


SERVICE_DEFS: list[_ServiceDef] = [
    _ServiceDef(
        name="Ollama",
        exe_names=["ollama.exe", "ollama", "ollama_llama_server.exe"],
        default_port=11434,
        probe_path="/api/tags",
        model_extractor=_extract_ollama_models,
    ),
    _ServiceDef(
        name="LM Studio",
        exe_names=["lm studio.exe", "lmstudio.exe", "lms.exe"],
        default_port=1234,
        probe_path="/v1/models",
        model_extractor=_extract_openai_models,
    ),
    _ServiceDef(
        name="Jan",
        exe_names=["jan.exe", "jan"],
        default_port=1337,
        probe_path="/v1/models",
        model_extractor=_extract_openai_models,
    ),
    _ServiceDef(
        name="GPT4All",
        exe_names=["gpt4all.exe", "gpt4all-backend.exe"],
        default_port=4891,
        probe_path="/v1/models",
        model_extractor=_extract_openai_models,
    ),
    _ServiceDef(
        name="KoboldCpp",
        exe_names=["koboldcpp.exe", "koboldcpp_cu12.exe", "koboldcpp_rocm.exe", "koboldcpp"],
        default_port=5001,
        probe_path="/api/v1/info",
        model_extractor=_extract_kobold_version,
    ),
    _ServiceDef(
        name="text-generation-webui",
        exe_names=["python.exe", "python", "python3"],
        default_port=5000,
        probe_path="/api/v1/model",
        model_extractor=_extract_textgen_model,
        cmdline_markers=["server.py", "text-generation-webui"],
    ),
    _ServiceDef(
        name="AUTOMATIC1111",
        exe_names=["python.exe", "python", "python3"],
        default_port=7860,
        probe_path="/sdapi/v1/sd-models",
        model_extractor=_extract_sd_models,
        cmdline_markers=["webui.py", "stable-diffusion-webui"],
    ),
    _ServiceDef(
        name="ComfyUI",
        exe_names=["python.exe", "python", "python3"],
        default_port=8188,
        probe_path="/system_stats",
        model_extractor=_extract_comfyui,
        cmdline_markers=["main.py", "comfyui"],
    ),
    _ServiceDef(
        name="InvokeAI",
        exe_names=["invokeai.exe", "invokeai", "python.exe", "python"],
        default_port=9090,
        probe_path="/api/v1/app/version",
        model_extractor=_extract_version_field,
        cmdline_markers=["invokeai"],
    ),
    _ServiceDef(
        name="AnythingLLM",
        exe_names=["anythingllmdesktop.exe", "anythingllm.exe"],
        default_port=3001,
        probe_path="/api/ping",
        model_extractor=lambda d: [],
    ),
    _ServiceDef(
        name="Open WebUI",
        exe_names=["open-webui", "open_webui"],
        default_port=3000,
        probe_path="/health",
        model_extractor=lambda d: [],
    ),
    _ServiceDef(
        name="LocalAI",
        exe_names=["local-ai.exe", "local-ai", "localai"],
        default_port=8080,
        probe_path="/v1/models",
        model_extractor=_extract_openai_models,
    ),
]

_PORT_TO_DEF: dict[int, _ServiceDef] = {s.default_port: s for s in SERVICE_DEFS}
_EXE_TO_DEFS: dict[str, list[_ServiceDef]] = {}
for _sdef in SERVICE_DEFS:
    for _exe in _sdef.exe_names:
        _EXE_TO_DEFS.setdefault(_exe, []).append(_sdef)


# ---------------------------------------------------------------------------
# Step 1 — Process enumeration
# ---------------------------------------------------------------------------


def _scan_processes() -> dict[int, RunningService]:
    """Return {pid: RunningService} for processes that look like AI services."""
    results: dict[int, RunningService] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            exe = (proc.info.get("exe") or "").lower()
            cmdline_parts = proc.info.get("cmdline") or []
            cmdline = " ".join(str(p) for p in cmdline_parts).lower()

            matching_def: Optional[_ServiceDef] = None

            # Direct exe name match
            for exe_key, defs in _EXE_TO_DEFS.items():
                if exe_key in pname or exe_key in exe:
                    for sdef in defs:
                        # For python.exe matches, require cmdline markers
                        if "python" in exe_key:
                            if any(m in cmdline for m in sdef.cmdline_markers):
                                matching_def = sdef
                                break
                        else:
                            matching_def = sdef
                            break

            if matching_def is None:
                continue

            pid = proc.info["pid"]
            results[pid] = RunningService(
                name=matching_def.name,
                pid=pid,
                port=matching_def.default_port,
                endpoint_url=f"http://127.0.0.1:{matching_def.default_port}",
                process_name=proc.info.get("name"),
                process_cmdline=(cmdline[:200] if cmdline else None),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


# ---------------------------------------------------------------------------
# Step 2 — Port enumeration
# ---------------------------------------------------------------------------


def _scan_ports() -> tuple[dict[int, int], list[int]]:
    """Return ({known_port: pid}, [unknown_listen_ports]) for all TCP LISTEN sockets."""
    known: dict[int, int] = {}
    unknown: list[int] = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != "LISTEN":
                continue
            port = conn.laddr.port
            if port in _PORT_TO_DEF:
                known[port] = conn.pid or -1
            else:
                unknown.append(port)
    except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
        pass
    return known, unknown


# ---------------------------------------------------------------------------
# Step 3 — HTTP endpoint probing (known services)
# ---------------------------------------------------------------------------

_GENERIC_PROBE_PATHS = [
    ("/v1/models", _extract_openai_models),
    ("/api/tags", _extract_ollama_models),
    ("/api/v1/info", _extract_kobold_version),
    ("/health", lambda d: []),
]


def _fingerprint_service(data: dict, port: int) -> Optional[str]:
    if isinstance(data.get("models"), list):
        return f"Ollama-compatible service (port {port})"
    if isinstance(data.get("data"), list):
        return f"OpenAI-compatible API (port {port})"
    if "result" in data:
        return f"KoboldCpp-compatible service (port {port})"
    if "version" in data or "app_version" in data:
        return f"AI Service (port {port})"
    if data.get("status") == "ok" or data.get("ok") is True:
        return f"AI Service (port {port})"
    return None


def _probe_unknown_port(port: int, timeout: int) -> Optional[RunningService]:
    for path, extractor in _GENERIC_PROBE_PATHS:
        url = f"http://127.0.0.1:{port}{path}"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    continue
                name = _fingerprint_service(data, port)
                if name:
                    models = extractor(data) if extractor else []
                    return RunningService(
                        name=name,
                        port=port,
                        endpoint_url=f"http://127.0.0.1:{port}",
                        is_alive=True,
                        loaded_models=[m for m in models if m],
                    )
        except Exception:
            continue
    return None


def _probe_endpoint(sdef: _ServiceDef, port: int, timeout: int) -> tuple[bool, list[str], Optional[str]]:
    """Return (is_alive, loaded_models, api_version)."""
    url = f"http://127.0.0.1:{port}{sdef.probe_path}"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        models = sdef.model_extractor(data)
        return True, [m for m in models if m], None
    except (requests.ConnectionError, requests.Timeout, requests.HTTPError, ValueError):
        return False, [], None


def _probe_all(ports_to_probe: list[tuple[_ServiceDef, int]], timeout: int) -> dict[int, tuple[bool, list[str]]]:
    results: dict[int, tuple[bool, list[str]]] = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {
            pool.submit(_probe_endpoint, sdef, port, timeout): (sdef, port)
            for sdef, port in ports_to_probe
        }
        for future in as_completed(futures):
            sdef, port = futures[future]
            try:
                alive, models, _ = future.result()
                results[port] = (alive, models)
            except Exception:
                results[port] = (False, [])
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_processes(http_timeout: int = 3) -> tuple[list[RunningService], list[str]]:
    """Return (running_services, warnings)."""
    warnings: list[str] = []

    # Step 1: processes
    proc_services = _scan_processes()

    # Step 2: ports — all LISTEN sockets, split into known and unknown
    port_pids, unknown_ports = _scan_ports()

    # Merge: start from process-detected services, then add port-only detections
    services: dict[str, RunningService] = {}
    for pid, svc in proc_services.items():
        services[svc.name] = svc

    for port, pid in port_pids.items():
        sdef = _PORT_TO_DEF[port]
        if sdef.name not in services:
            services[sdef.name] = RunningService(
                name=sdef.name,
                pid=pid if pid > 0 else None,
                port=port,
                endpoint_url=f"http://127.0.0.1:{port}",
            )
        else:
            existing = services[sdef.name]
            if existing.port is None:
                services[sdef.name] = existing.model_copy(update={"port": port})

    # Step 3a: probe all known ports concurrently
    ports_to_probe = [(_PORT_TO_DEF[port], port) for port in _PORT_TO_DEF]
    probe_results = _probe_all(ports_to_probe, http_timeout)

    for port, (alive, models) in probe_results.items():
        sdef = _PORT_TO_DEF[port]
        if alive and sdef.name not in services:
            services[sdef.name] = RunningService(
                name=sdef.name,
                port=port,
                endpoint_url=f"http://127.0.0.1:{port}",
                is_alive=True,
                loaded_models=models,
            )
        elif sdef.name in services:
            existing = services[sdef.name]
            services[sdef.name] = existing.model_copy(update={
                "is_alive": alive,
                "loaded_models": models if models else existing.loaded_models,
            })

    # Step 3b: probe unknown LISTEN ports concurrently for generic AI fingerprinting
    if unknown_ports:
        with ThreadPoolExecutor(max_workers=20) as pool:
            future_to_port = {
                pool.submit(_probe_unknown_port, port, http_timeout): port
                for port in unknown_ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    svc = future.result()
                    if svc is not None:
                        # Use port-keyed name to avoid clobbering known services
                        key = svc.name
                        if key not in services:
                            services[key] = svc
                except Exception:
                    pass

    # Only return services that are either alive or have a running process
    final = [
        svc for svc in services.values()
        if svc.is_alive or svc.pid is not None
    ]
    final.sort(key=lambda s: (not s.is_alive, s.name))
    return final, warnings
