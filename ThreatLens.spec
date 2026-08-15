# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['rep_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('config.py', '.'), ('api_sources.py', '.'), ('dns_recon.py', '.'), ('risk_engine.py', '.'), ('report_gen.py', '.'), ('subdomain_enum.py', '.'), ('logo_512.png', '.'), ('logo_64.png', '.'), ('logo_watermark.png', '.')],
    hiddenimports=['dns.resolver', 'dns.rdatatype', 'dns.rdataclass', 'dns.exception', 'whois', 'requests', 'docx', 'docx.oxml', 'docx.oxml.ns', 'docx.shared', 'docx.enum.text', 'docx.enum.table', 'shodan', 'tkinter', 'tkinter.ttk', 'ctypes', 'json', 'ssl', 'PIL', 'PIL.Image', 'PIL.ImageTk', 'ipaddress'],
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
    a.binaries,
    a.datas,
    [],
    name='ThreatLens',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app.ico'],
)
