# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for ai-discovery.exe
# Build: pyinstaller build/ai_discovery.spec --distpath dist/

block_cipher = None

a = Analysis(
    ['../ai_discovery/main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'winreg',
        'psutil._pswindows',
        'psutil._psutil_windows',
        'rich',
        'rich.console',
        'rich.table',
        'rich.panel',
        'rich.rule',
        'rich.progress',
        'rich.columns',
        'rich.text',
        'typer',
        'pydantic',
        'pydantic.v1',
        'requests',
        'urllib3',
        'charset_normalizer',
        'certifi',
        'ai_discovery',
        'ai_discovery.scanner.apps',
        'ai_discovery.scanner.processes',
        'ai_discovery.scanner.models_scan',
        'ai_discovery.scanner.packages',
        'ai_discovery.scanner.gpu',
        'ai_discovery.report.terminal',
        'ai_discovery.report.json_export',
        'ai_discovery.mock_data',
    ],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'PIL',
        'cv2',
        'scipy',
        'pandas',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ai-discovery',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
