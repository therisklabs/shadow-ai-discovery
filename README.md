# AI Discovery Tool

Scan a Windows PC and identify all AI tools, running models, and infrastructure — in under 2 minutes.

## What It Detects

| Category | Examples |
|----------|---------|
| **Local LLM runtimes** | Ollama, LM Studio, Jan, GPT4All, KoboldCpp, LocalAI |
| **Image generation** | AUTOMATIC1111, ComfyUI, InvokeAI, Fooocus |
| **Code assistants** | Cursor, Windsurf, GitHub Copilot, Tabnine, Codeium, Amazon Q |
| **AI infrastructure** | Claude Desktop, ChatGPT Desktop, AnythingLLM, Microsoft Copilot |
| **Running services** | Any of the above with a live HTTP API; extracts loaded model names |
| **Model files** | `.gguf`, `.ggml`, `.safetensors`, `.pt`, `.pth`, `.onnx`, `.bin` |
| **Python AI packages** | torch, transformers, langchain, openai, anthropic, vllm, and ~60 more |
| **GPU hardware** | NVIDIA (CUDA), AMD (ROCm), Intel Arc / oneAPI |

## Quick Start

```bash
# Install
pip install -e .

# Full scan
ai-discovery scan

# Demo mode (works on Linux / macOS too)
ai-discovery scan --mock

# Export JSON report
ai-discovery scan --output report.json

# Scan specific categories only
ai-discovery scan --categories apps,gpu

# Add extra directories to scan for model files
ai-discovery scan --model-paths "D:\Models;E:\AI\weights"
```

## Installation

**Requirements:** Python 3.10+ on Windows (detection works best on Windows; runs in mock mode on other platforms)

```bash
pip install rich psutil requests typer pydantic
pip install -e .
```

## Build Windows Executable

```bash
pip install pyinstaller
pyinstaller build/ai_discovery.spec --distpath dist/
# Output: dist/ai-discovery.exe (~20 MB, no Python required)
```

## CLI Options

```
ai-discovery scan [OPTIONS]

  -o, --output PATH          Write JSON report to this path
  --format [table|json]      stdout format (default: table)
  --categories TEXT          Comma-separated: apps,processes,models,packages,gpu
  --model-paths TEXT         Extra directories to scan (semicolon-separated on Windows)
  --timeout INTEGER          HTTP probe timeout in seconds (default: 3)
  --no-progress              Disable spinners (for CI / piped output)
  --mock                     Demo mode with synthetic data
```

## Development

```bash
pip install -e ".[dev]"
pytest                       # all tests pass on Linux (no Windows required)
pytest -v tests/test_main.py # just CLI tests
```

## Detection Methods

The tool uses three layers for application detection:

1. **Windows Registry** — uninstall keys + tool-specific keys
2. **Filesystem probe** — well-known install paths per tool
3. **PATH probe** — `shutil.which()` for CLI tools

Running service detection:
1. psutil process scan (matches exe names and Python cmdlines)
2. psutil TCP port scan (known AI service ports)
3. Concurrent HTTP probing (extracts actually-loaded model names from APIs)

## Privacy

- Runs entirely locally — no data is sent to any server
- Does not require admin/elevated privileges (some registry keys may be skipped without elevation)
- Model file SHA256 hashes are only computed for files under 100 MB
