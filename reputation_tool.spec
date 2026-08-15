# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for IP/Domain Reputation Tool - GUI Edition

import sys
import os

block_cipher = None

a = Analysis(
    ['rep_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'config',
        'api_sources',
        'dns_recon',
        'risk_engine',
        'report_gen',
        'dns.resolver',
        'dns.rdatatype',
        'dns.rdataclass',
        'dns.exception',
        'whois',
        'requests',
        'docx',
        'docx.oxml',
        'docx.oxml.ns',
        'docx.shared',
        'docx.enum.text',
        'docx.enum.table',
        'shodan',
        'json',
        're',
        'ssl',
        'socket',
        'subprocess',
        'ctypes',
        'tkinter',
        'tkinter.ttk',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
        'torch',
        'tensorflow',
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
    name='IPDomain-Reputation-Tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # No console window (GUI only)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,                # Set to 'icon.ico' if you have one
)
