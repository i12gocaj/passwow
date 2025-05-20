# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules


a = Analysis(
    ['src/vault/gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=collect_submodules('cryptography') + collect_submodules('cryptography.hazmat.primitives.ciphers.aead') + collect_submodules('cryptography.hazmat.bindings._rust') + collect_submodules('cryptography.hazmat.bindings._openssl') + collect_submodules('secretsharing') + [
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.primitives',
        'requests',
        'tkinter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
app = BUNDLE(
    exe,
    name='gui.app',
    icon='icon.icns',
    bundle_identifier=None,
)
