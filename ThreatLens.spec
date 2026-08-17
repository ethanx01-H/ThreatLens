# -*- mode: python ; coding: utf-8 -*-
"""
ThreatLens v1.0 — PyInstaller build spec (AV-optimized)

Changes from original to reduce AV false positives:
  - onefolder mode (no single-file self-extracting archive)
  - UPX disabled (packed binaries trigger ~70% of AV engines)
  - strip=False (unstripped binaries are less suspicious)
  - Version info added (CompanyName, FileDescription, LegalCopyright)
  - console=True for dev; change to False for final release
"""

a = Analysis(
    ['rep_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('logo_512.png', '.'),
        ('logo_64.png', '.'),
    ],
    hiddenimports=[
        'dns.resolver', 'dns.rdatatype', 'dns.rdataclass', 'dns.exception',
        'whois', 'requests', 'docx', 'docx.oxml', 'docx.oxml.ns',
        'docx.shared', 'docx.enum.text', 'docx.enum.table',
        'shodan', 'tkinter', 'tkinter.ttk', 'ctypes', 'json', 'ssl',
        'PIL', 'PIL.Image', 'PIL.ImageTk', 'ipaddress',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy'],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ThreatLens',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app.ico'],
    version='version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ThreatLens',
)
