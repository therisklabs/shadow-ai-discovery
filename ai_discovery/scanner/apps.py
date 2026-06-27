"""
Installed AI application detection.

Three-layer approach:
  1. Windows Registry — enumerate uninstall keys and tool-specific keys
  2. Filesystem probe — check well-known install paths
  3. PATH probe — shutil.which() for CLI tools

All Windows-specific code is guarded by sys.platform == "win32".
"""

from __future__ import annotations

import glob
import os
import shutil
import sys
from typing import Any, Optional

from ai_discovery.models import AppCategory, DetectionMethod, InstalledApp

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class _ToolDef:
    def __init__(
        self,
        name: str,
        category: AppCategory,
        display_name_patterns: list[str],
        registry_keys: Optional[list[str]] = None,
        fs_paths: Optional[list[str]] = None,
        which_names: Optional[list[str]] = None,
        exe_name: Optional[str] = None,
        publisher_patterns: Optional[list[str]] = None,
    ):
        self.name = name
        self.category = category
        self.display_name_patterns = [p.lower() for p in display_name_patterns]
        self.registry_keys = registry_keys or []
        self.fs_paths = fs_paths or []
        self.which_names = which_names or []
        self.exe_name = exe_name
        self.publisher_patterns = [p.lower() for p in (publisher_patterns or [])]


TOOL_DEFS: list[_ToolDef] = [
    # ------------------------------------------------------------------
    # Local LLM runtimes
    # ------------------------------------------------------------------
    _ToolDef(
        name="Ollama",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["ollama"],
        registry_keys=[r"SOFTWARE\Ollama"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\Ollama",
            r"%PROGRAMFILES%\Ollama",
            r"C:\Program Files\Ollama",
        ],
        which_names=["ollama"],
        exe_name="ollama.exe",
    ),
    _ToolDef(
        name="LM Studio",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["lm studio"],
        registry_keys=[r"SOFTWARE\LM Studio"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\LM-Studio",
            r"%LOCALAPPDATA%\LM-Studio",
            r"%LOCALAPPDATA%\Programs\lm-studio",
        ],
        which_names=["lms"],
        exe_name="LM Studio.exe",
    ),
    _ToolDef(
        name="Jan",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["jan"],
        fs_paths=[r"%LOCALAPPDATA%\Programs\jan"],
        which_names=["jan"],
        exe_name="Jan.exe",
    ),
    _ToolDef(
        name="GPT4All",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["gpt4all"],
        registry_keys=[r"SOFTWARE\GPT4All"],
        fs_paths=[
            r"%LOCALAPPDATA%\nomic.ai\GPT4All",
            r"%PROGRAMFILES%\GPT4All",
        ],
        which_names=["gpt4all"],
        exe_name="GPT4All.exe",
        publisher_patterns=["nomic"],
    ),
    _ToolDef(
        name="KoboldCpp",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["koboldcpp", "kobold"],
        which_names=["koboldcpp"],
        exe_name="koboldcpp.exe",
    ),
    _ToolDef(
        name="LocalAI",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["localai", "local-ai"],
        fs_paths=[r"%APPDATA%\LocalAI"],
        which_names=["local-ai"],
        exe_name="local-ai.exe",
    ),
    # ------------------------------------------------------------------
    # Image generation
    # ------------------------------------------------------------------
    _ToolDef(
        name="InvokeAI",
        category=AppCategory.IMAGE_GENERATION,
        display_name_patterns=["invokeai"],
        fs_paths=[r"%USERPROFILE%\invokeai"],
        which_names=["invokeai"],
    ),
    _ToolDef(
        name="AnythingLLM",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["anythingllm"],
        fs_paths=[r"%LOCALAPPDATA%\Programs\anythingllm-desktop"],
        which_names=["anythingllm"],
        exe_name="AnythingLLMDesktop.exe",
    ),
    # ------------------------------------------------------------------
    # Code assistants
    # ------------------------------------------------------------------
    _ToolDef(
        name="Cursor",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["cursor"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\cursor",
            r"%LOCALAPPDATA%\Programs\Cursor",
        ],
        which_names=["cursor"],
        exe_name="Cursor.exe",
    ),
    _ToolDef(
        name="Claude Desktop",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["claude"],
        registry_keys=[
            r"SOFTWARE\AnthropicPBC\Claude",
            r"SOFTWARE\Anthropic\Claude",
        ],
        fs_paths=[r"%LOCALAPPDATA%\AnthropicClaude"],
        exe_name="Claude.exe",
        publisher_patterns=["anthropic"],
    ),
    _ToolDef(
        name="ChatGPT Desktop",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["chatgpt"],
        fs_paths=[r"%LOCALAPPDATA%\Microsoft\WindowsApps"],
        exe_name="ChatGPT.exe",
        publisher_patterns=["openai"],
    ),
    _ToolDef(
        name="Windsurf",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["windsurf"],
        fs_paths=[r"%LOCALAPPDATA%\Programs\windsurf"],
        which_names=["windsurf"],
        exe_name="Windsurf.exe",
    ),
    _ToolDef(
        name="GitHub Copilot (VS Code)",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["github copilot"],
        fs_paths=[r"%USERPROFILE%\.vscode\extensions"],
        publisher_patterns=["github"],
    ),
    _ToolDef(
        name="Tabnine",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["tabnine"],
        fs_paths=[
            r"%USERPROFILE%\.vscode\extensions",
            r"%APPDATA%\Tabnine",
        ],
        exe_name="TabNine.exe",
    ),
    _ToolDef(
        name="Codeium",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["codeium"],
        fs_paths=[r"%USERPROFILE%\.vscode\extensions"],
        exe_name="codeium_language_server.exe",
    ),
    _ToolDef(
        name="Amazon Q",
        category=AppCategory.CODE_ASSISTANT,
        display_name_patterns=["amazon q", "codewhisperer"],
        fs_paths=[
            r"%USERPROFILE%\.aws\amazonq",
            r"%USERPROFILE%\.vscode\extensions",
        ],
        publisher_patterns=["amazon"],
    ),
    _ToolDef(
        name="Microsoft Copilot",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["microsoft copilot", "copilot"],
        fs_paths=[r"%WINDIR%\System32"],
        exe_name="Copilot.exe",
        publisher_patterns=["microsoft"],
    ),
    # ------------------------------------------------------------------
    # New tools added in v0.2.0
    # ------------------------------------------------------------------
    _ToolDef(
        name="Cowork",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["cowork"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\cowork",
            r"%LOCALAPPDATA%\Programs\Cowork",
            r"%APPDATA%\cowork",
        ],
        which_names=["cowork"],
        exe_name="Cowork.exe",
    ),
    _ToolDef(
        name="Hugging Face CLI",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["huggingface", "hugging face"],
        fs_paths=[r"%USERPROFILE%\.cache\huggingface"],
        which_names=["huggingface-cli"],
    ),
    _ToolDef(
        name="vLLM",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["vllm"],
        fs_paths=[r"%LOCALAPPDATA%\vllm"],
        which_names=["vllm"],
    ),
    _ToolDef(
        name="Msty",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["msty"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\msty",
            r"%LOCALAPPDATA%\Programs\Msty",
        ],
        exe_name="Msty.exe",
    ),
    _ToolDef(
        name="LLM CLI",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["llm (simon", "simon willison"],
        which_names=["llm"],
    ),
    _ToolDef(
        name="Pinokio",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["pinokio"],
        fs_paths=[
            r"%USERPROFILE%\pinokio",
            r"%LOCALAPPDATA%\Programs\pinokio",
            r"%LOCALAPPDATA%\Programs\Pinokio",
        ],
        exe_name="Pinokio.exe",
    ),
    _ToolDef(
        name="Lobe Chat",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["lobe chat", "lobechat"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\lobe-chat",
            r"%LOCALAPPDATA%\Programs\Lobe Chat",
        ],
        exe_name="Lobe Chat.exe",
    ),
    _ToolDef(
        name="Open WebUI",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["open webui", "openwebui"],
        fs_paths=[r"%APPDATA%\open-webui"],
        which_names=["open-webui"],
    ),
    _ToolDef(
        name="NVIDIA CUDA Toolkit",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["nvidia cuda", "cuda toolkit"],
        fs_paths=[r"%PROGRAMFILES%\NVIDIA GPU Computing Toolkit\CUDA"],
        publisher_patterns=["nvidia"],
    ),
    _ToolDef(
        name="Docker Desktop",
        category=AppCategory.AI_INFRASTRUCTURE,
        display_name_patterns=["docker desktop"],
        fs_paths=[r"%PROGRAMFILES%\Docker\Docker"],
        exe_name="Docker Desktop.exe",
    ),
    _ToolDef(
        name="Hermes",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["hermes"],
        fs_paths=[
            r"%LOCALAPPDATA%\Programs\Hermes",
            r"%LOCALAPPDATA%\Programs\hermes",
        ],
        which_names=["hermes"],
        exe_name="Hermes.exe",
    ),
    _ToolDef(
        name="Enchanted",
        category=AppCategory.LOCAL_LLM,
        display_name_patterns=["enchanted"],
        fs_paths=[r"%LOCALAPPDATA%\Programs\Enchanted"],
        exe_name="Enchanted.exe",
    ),
]

_UNINSTALL_PATHS = [
    (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (0x80000002, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def _try_read_value(key, name: str) -> Optional[str]:
    try:
        import winreg
        val, _ = winreg.QueryValueEx(key, name)
        return str(val) if val else None
    except OSError:
        return None


def _open_key_safe(hive, path: str):
    try:
        import winreg
        return winreg.OpenKey(hive, path)
    except OSError:
        return None


def _matches_tool(display_name: str, publisher: str, tdef: _ToolDef) -> bool:
    dn_lower = display_name.lower()
    pub_lower = publisher.lower()
    for pat in tdef.display_name_patterns:
        if pat in dn_lower:
            return True
    for pat in tdef.publisher_patterns:
        if pat in pub_lower:
            return True
    return False


def _scan_registry_uninstall() -> list[tuple[_ToolDef, str, Optional[str], Optional[str], Optional[str]]]:
    """Yield (tool_def, display_name, version, install_path, publisher) from uninstall keys."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    results = []
    for hive_const, path in _UNINSTALL_PATHS:
        try:
            hive = winreg.ConnectRegistry(None, hive_const)
            base = _open_key_safe(hive, path)
            if base is None:
                continue
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(base, i)
                    i += 1
                except OSError:
                    break
                sub = _open_key_safe(base, subkey_name)
                if sub is None:
                    continue
                display_name = _try_read_value(sub, "DisplayName") or ""
                publisher = _try_read_value(sub, "Publisher") or ""
                version = _try_read_value(sub, "DisplayVersion")
                install_path = _try_read_value(sub, "InstallLocation")
                winreg.CloseKey(sub)

                if not display_name:
                    continue

                for tdef in TOOL_DEFS:
                    if _matches_tool(display_name, publisher, tdef):
                        results.append((tdef, display_name, version, install_path, publisher))
                        break
            winreg.CloseKey(base)
        except OSError:
            continue
    return results


def _scan_tool_specific_registry_keys() -> list[tuple[_ToolDef, Optional[str]]]:
    """Check tool-specific registry keys (not uninstall keys)."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    results = []
    for tdef in TOOL_DEFS:
        for reg_path in tdef.registry_keys:
            for hive_const in (0x80000002, 0x80000001):
                try:
                    hive = winreg.ConnectRegistry(None, hive_const)
                    key = _open_key_safe(hive, reg_path)
                    if key is None:
                        continue
                    install_path = _try_read_value(key, "InstallLocation")
                    winreg.CloseKey(key)
                    results.append((tdef, install_path))
                    break
                except OSError:
                    continue
    return results


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def _resolve_fs_path(raw: str) -> str:
    return os.path.expandvars(os.path.expanduser(raw))


def _scan_filesystem() -> list[tuple[_ToolDef, str]]:
    """Return (tool_def, found_path) for tools with existing install paths."""
    results = []
    for tdef in TOOL_DEFS:
        for raw_path in tdef.fs_paths:
            expanded = _resolve_fs_path(raw_path)

            # VS Code extension glob check
            if ".vscode\\extensions" in raw_path or ".vscode/extensions" in raw_path:
                ext_dir = expanded
                if not os.path.isdir(ext_dir):
                    continue
                search_term = tdef.name.lower().replace(" ", "").replace("(vs code)", "")
                # Map to known extension publisher prefixes
                prefix_map = {
                    "githubcopilot": "github.copilot",
                    "tabnine": "tabnine.tabnine",
                    "codeium": "codeium.codeium",
                    "amazonq": "amazonwebservices.amazon-q",
                    "continue": "continue.continue",
                }
                prefix = prefix_map.get(search_term)
                if prefix:
                    matches = glob.glob(os.path.join(ext_dir, f"{prefix}-*"))
                    if matches:
                        results.append((tdef, matches[0]))
                        break
                continue

            if os.path.isdir(expanded):
                # Check for exe if specified
                if tdef.exe_name:
                    exe_path = os.path.join(expanded, tdef.exe_name)
                    if os.path.isfile(exe_path):
                        results.append((tdef, expanded))
                        break
                    # Check one level deep
                    for root, dirs, files in os.walk(expanded):
                        if tdef.exe_name.lower() in [f.lower() for f in files]:
                            results.append((tdef, expanded))
                            break
                        break
                else:
                    results.append((tdef, expanded))
                    break
    return results


# ---------------------------------------------------------------------------
# AI-keyword registry scan (catches tools not in TOOL_DEFS)
# ---------------------------------------------------------------------------

_AI_KEYWORDS = [
    "llm", "gpt", " ai ", "ollama", "stable diffusion", "copilot",
    "neural", "inference", "cuda", "hugging", "langchain", "diffusion",
    "generative", "embedding", "llama", "mistral", "gemini", "claude",
    "whisper", "midjourney", "comfyui", "kobold", "oobabooga",
]

_KNOWN_TOOL_NAMES = {t.name.lower() for t in TOOL_DEFS}


def _scan_registry_for_unknown_ai_apps() -> list[InstalledApp]:
    """Return apps whose registry DisplayName matches AI keywords but aren't in TOOL_DEFS."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    results: list[InstalledApp] = []
    seen: set[str] = set()

    for hive_const, path in _UNINSTALL_PATHS:
        try:
            hive = winreg.ConnectRegistry(None, hive_const)
            base = _open_key_safe(hive, path)
            if base is None:
                continue
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(base, i)
                    i += 1
                except OSError:
                    break
                sub = _open_key_safe(base, subkey_name)
                if sub is None:
                    continue
                display_name = _try_read_value(sub, "DisplayName") or ""
                publisher = _try_read_value(sub, "Publisher") or ""
                version = _try_read_value(sub, "DisplayVersion")
                install_path = _try_read_value(sub, "InstallLocation")
                winreg.CloseKey(sub)

                if not display_name:
                    continue

                dn_lower = display_name.lower()
                if dn_lower in seen:
                    continue
                if any(dn_lower == t for t in _KNOWN_TOOL_NAMES):
                    continue
                # Check if already matched by TOOL_DEFS patterns
                if any(_matches_tool(display_name, publisher, t) for t in TOOL_DEFS):
                    continue
                # Check AI keyword match
                if any(kw in dn_lower for kw in _AI_KEYWORDS):
                    seen.add(dn_lower)
                    results.append(InstalledApp(
                        name=display_name,
                        version=version,
                        install_path=install_path or None,
                        category=AppCategory.OTHER,
                        detection_methods=[DetectionMethod.REGISTRY],
                        publisher=publisher or None,
                    ))
            winreg.CloseKey(base)
        except OSError:
            continue
    return results


# ---------------------------------------------------------------------------
# PATH probe
# ---------------------------------------------------------------------------


def _scan_path() -> list[tuple[_ToolDef, str]]:
    results = []
    for tdef in TOOL_DEFS:
        for which_name in tdef.which_names:
            found = shutil.which(which_name)
            if found:
                results.append((tdef, found))
                break
    return results


# ---------------------------------------------------------------------------
# Deduplication and assembly
# ---------------------------------------------------------------------------


def _build_app(tdef: _ToolDef, install_path: Optional[str], version: Optional[str],
               publisher: Optional[str], methods: list[DetectionMethod]) -> InstalledApp:
    exe_path: Optional[str] = None
    if install_path and tdef.exe_name:
        candidate = os.path.join(install_path, tdef.exe_name)
        if os.path.isfile(candidate):
            exe_path = candidate

    return InstalledApp(
        name=tdef.name,
        version=version,
        install_path=install_path,
        exe_path=exe_path,
        category=tdef.category,
        detection_methods=methods,
        publisher=publisher,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_apps() -> tuple[list[InstalledApp], list[str]]:
    """Return (installed_apps, warnings)."""
    warnings: list[str] = []
    # Key: tool name → partial InstalledApp data
    found: dict[str, dict[str, Any]] = {}

    def _add(tdef: _ToolDef, method: DetectionMethod,
             install_path: Optional[str] = None,
             version: Optional[str] = None,
             publisher: Optional[str] = None) -> None:
        key = tdef.name
        if key not in found:
            found[key] = {
                "tdef": tdef,
                "methods": [],
                "install_path": None,
                "version": None,
                "publisher": None,
            }
        entry = found[key]
        if method not in entry["methods"]:
            entry["methods"].append(method)
        if install_path and not entry["install_path"]:
            entry["install_path"] = install_path
        if version and not entry["version"]:
            entry["version"] = version
        if publisher and not entry["publisher"]:
            entry["publisher"] = publisher

    # Layer 1: Uninstall registry
    try:
        for tdef, display_name, version, install_path, publisher in _scan_registry_uninstall():
            _add(tdef, DetectionMethod.REGISTRY, install_path, version, publisher)
    except Exception as exc:
        warnings.append(f"Registry uninstall scan error: {exc}")

    # Layer 1b: Tool-specific registry keys
    try:
        for tdef, install_path in _scan_tool_specific_registry_keys():
            _add(tdef, DetectionMethod.REGISTRY, install_path)
    except Exception as exc:
        warnings.append(f"Registry tool-key scan error: {exc}")

    # Layer 2: Filesystem
    try:
        for tdef, fs_path in _scan_filesystem():
            _add(tdef, DetectionMethod.FILESYSTEM, fs_path)
    except Exception as exc:
        warnings.append(f"Filesystem scan error: {exc}")

    # Layer 3: PATH
    try:
        for tdef, exe_path in _scan_path():
            _add(tdef, DetectionMethod.PATH, os.path.dirname(exe_path))
    except Exception as exc:
        warnings.append(f"PATH scan error: {exc}")

    apps = [
        _build_app(
            entry["tdef"],
            entry["install_path"],
            entry["version"],
            entry["publisher"],
            entry["methods"],
        )
        for entry in found.values()
    ]

    # Layer 4: AI-keyword registry scan for unknown tools
    try:
        known_names_lower = {a.name.lower() for a in apps}
        for unknown_app in _scan_registry_for_unknown_ai_apps():
            if unknown_app.name.lower() not in known_names_lower:
                apps.append(unknown_app)
                known_names_lower.add(unknown_app.name.lower())
    except Exception as exc:
        warnings.append(f"AI-keyword registry scan error: {exc}")

    # Sort by category, then name
    apps.sort(key=lambda a: (a.category.value, a.name))
    return apps, warnings
