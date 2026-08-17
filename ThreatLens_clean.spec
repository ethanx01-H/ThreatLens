# -*- mode: python ; coding: utf-8 -*-
"""
ThreatLens v1.0 — PyInstaller build spec (AV-safe config)

Changes from original to reduce false positives:
  - onefolder mode (no single-file self-extracting archive)
  - UPX disabled (packed binaries trigger ~70% of AV engines)
  - Version info added (signed metadata increases trust score)
  - Console=True for debugging; change to False for release
"""

import sys

a = Analysis(
    ['rep_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.py', '.'),
        ('api_sources.py', '.'),
        ('dns_recon.py', '.'),
        ('risk_engine.py', '.'),
        ('report_gen.py', '.'),
        ('subdomain_enum.py', '.'),
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
    exclude_binaries=True,   # onefolder: binaries go to dist/ alongside
    name='ThreatLens',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,             # Don't strip — unstripped binaries have more debug info, less suspicious
    upx=False,               # CRITICAL: disable UPX — packed .exe triggers 70% of AV engines
    runtime_tmpdir=None,
    console=True,            # True for debugging; set False for release
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app.ico'],
    version='version_info.txt',  # Windows PE version metadata
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
