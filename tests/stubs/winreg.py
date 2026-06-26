"""
Minimal winreg stub for running Windows registry code on Linux in tests.
Tests inject this module via sys.modules["winreg"] before importing scanners.
"""

from __future__ import annotations

HKEY_LOCAL_MACHINE = 0x80000002
HKEY_CURRENT_USER = 0x80000001
HKEY_CLASSES_ROOT = 0x80000000

KEY_READ = 0x20019
KEY_WOW64_32KEY = 0x0200

REG_SZ = 1
REG_DWORD = 4
REG_EXPAND_SZ = 2

# Thread-local registry state populated by test fixtures
_registry: dict[tuple, Any] = {}
_subkeys: dict[tuple, list[str]] = {}

from typing import Any


def _key_tuple(hive: int, path: str) -> tuple:
    return (hive, path.lower())


class HKEYType:
    """Represents an open registry key handle."""

    def __init__(self, hive: int, path: str):
        self.hive = hive
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class error(OSError):
    pass


def set_value(hive: int, path: str, name: str, value: Any) -> None:
    """Test helper: set a registry value in the stub."""
    _registry[(hive, path.lower(), name.lower())] = value
    # Ensure all parent subkeys are registered
    parts = path.split("\\")
    for i in range(len(parts)):
        parent_path = "\\".join(parts[:i]) if i > 0 else ""
        child = parts[i]
        parent_key = (hive, parent_path.lower())
        if parent_key not in _subkeys:
            _subkeys[parent_key] = []
        if child not in _subkeys[parent_key]:
            _subkeys[parent_key].append(child)


def set_subkeys(hive: int, path: str, children: list[str]) -> None:
    """Test helper: register subkeys under a path."""
    _subkeys[(hive, path.lower())] = list(children)


def clear() -> None:
    """Test helper: reset all stub state."""
    _registry.clear()
    _subkeys.clear()


def ConnectRegistry(computer: Any, hive: int) -> HKEYType:
    return HKEYType(hive, "")


def OpenKey(key: Any, sub_key: str, reserved: int = 0, access: int = KEY_READ) -> HKEYType:
    if isinstance(key, HKEYType):
        full_path = f"{key.path}\\{sub_key}".strip("\\")
        hive = key.hive
    else:
        full_path = sub_key.strip("\\")
        hive = key
    # Check path exists (has values or subkeys)
    k = (hive, full_path.lower())
    has_values = any(r[0] == hive and r[1] == full_path.lower() for r in _registry)
    has_subkeys = k in _subkeys
    if not has_values and not has_subkeys:
        raise error(2, "The system cannot find the file specified")
    return HKEYType(hive, full_path)


def OpenKeyEx(key: Any, sub_key: str, reserved: int = 0, access: int = KEY_READ) -> HKEYType:
    return OpenKey(key, sub_key, reserved, access)


def QueryValueEx(key: HKEYType, value_name: str) -> tuple[Any, int]:
    k = (key.hive, key.path.lower(), value_name.lower())
    if k in _registry:
        val = _registry[k]
        reg_type = REG_DWORD if isinstance(val, int) else REG_SZ
        return (val, reg_type)
    raise error(2, "The system cannot find the file specified")


def EnumKey(key: HKEYType, index: int) -> str:
    k = (key.hive, key.path.lower())
    children = _subkeys.get(k, [])
    if index >= len(children):
        raise error(259, "No more data is available")
    return children[index]


def EnumValue(key: HKEYType, index: int) -> tuple[str, Any, int]:
    prefix = (key.hive, key.path.lower())
    matches = [(k[2], v) for k, v in _registry.items() if k[0] == prefix[0] and k[1] == prefix[1]]
    if index >= len(matches):
        raise error(259, "No more data is available")
    name, val = matches[index]
    reg_type = REG_DWORD if isinstance(val, int) else REG_SZ
    return (name, val, reg_type)


def CloseKey(key: Any) -> None:
    pass


def QueryInfoKey(key: HKEYType) -> tuple[int, int, int]:
    k = (key.hive, key.path.lower())
    num_subkeys = len(_subkeys.get(k, []))
    prefix = (key.hive, key.path.lower())
    num_values = sum(1 for k in _registry if k[0] == prefix[0] and k[1] == prefix[1])
    return (num_subkeys, num_values, 0)
