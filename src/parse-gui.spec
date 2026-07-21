# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.building.splash import Splash

hiddenimports = (
    collect_submodules('parsers') +
    ['tkinter', 'openpyxl', 'xml.etree.ElementTree', 'json', 'html', 'csv', 'fnmatch', 'matplotlib', 'requests', 'urllib']
)

a = Analysis(
    ['parse-gui.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('parsers', 'parsers'),
        ('assets/logos/sarp-logo-256.png', 'assets/logos')
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

splash = Splash(
    "assets/logos/sarp-splash.png",
    binaries=a.binaries,
    datas=a.datas
)

exe = EXE(
    pyz,
    a.scripts,
    splash,
    a.binaries,
    a.datas,
    splash.binaries,
    name='sarp-gui',
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
    icon='assets/logos/sarp-icon.ico'
)
