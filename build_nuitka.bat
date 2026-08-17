@echo off
REM ═══════════════════════════════════════════════════════════════
REM  ThreatLens Nuitka Build — Maximum AV Cleanliness
REM
REM  Nuitka compiles Python to C, then to a native .exe.
REM  Unlike PyInstaller, it does NOT:
REM    - Extract to _MEI* temp directories
REM    - Use RC4 encryption on bytecode
REM    - Spawn suspended child processes
REM    - Contain anti-VM / anti-analysis strings
REM    - Parse PE headers at runtime
REM
REM  This produces a genuine Windows PE that passes most AV engines.
REM ═══════════════════════════════════════════════════════════════

echo.
echo  ThreatLens v1.0 — Nuitka Build (AV-Clean)
echo  ===========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ and add to PATH.
    pause
    exit /b 1
)

REM Install Nuitka if needed
python -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo Installing Nuitka...
    pip install nuitka ordered-set zstandard
)

REM Clean previous build
echo Cleaning previous artifacts...
if exist dist\ThreatLens.exe del /q dist\ThreatLens.exe
if exist dist\ThreatLens.dist rmdir /s /q dist\ThreatLens.dist
if exist dist\ThreatLens.build rmdir /s /q dist\ThreatLens.build

echo.
echo Building with Nuitka (this may take 3-10 minutes)...
echo.

python -m nuitka ^
    --standalone ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico=app.ico ^
    --company-name="ThreatLens Project" ^
    --product-name="ThreatLens" ^
    --product-version=1.0.0 ^
    --file-version=1.0.0 ^
    --file-description="ThreatLens - Threat Intelligence Investigation Tool" ^
    --copyright="Copyright (c) 2025 ThreatLens Project" ^
    --include-data-file=config.py=config.py ^
    --include-data-file=api_sources.py=api_sources.py ^
    --include-data-file=dns_recon.py=dns_recon.py ^
    --include-data-file=risk_engine.py=risk_engine.py ^
    --include-data-file=report_gen.py=report_gen.py ^
    --include-data-file=subdomain_enum.py=subdomain_enum.py ^
    --include-data-file=logo_512.png=logo_512.png ^
    --include-data-file=logo_64.png=logo_64.png ^
    --include-module=dns.resolver ^
    --include-module=dns.rdatatype ^
    --include-module=dns.rdataclass ^
    --include-module=dns.exception ^
    --include-module=whois ^
    --include-module=shodan ^
    --include-module=docx ^
    --include-module=docx.oxml ^
    --include-module=docx.oxml.ns ^
    --include-module=docx.shared ^
    --include-module=docx.enum.text ^
    --include-module=docx.enum.table ^
    --include-module=PIL ^
    --include-module=PIL.Image ^
    --include-module=PIL.ImageTk ^
    --nofollow-import-to=matplotlib ^
    --nofollow-import-to=numpy ^
    --nofollow-import-to=pandas ^
    --nofollow-import-to=scipy ^
    --output-filename=ThreatLens.exe ^
    --output-dir=dist ^
    rep_gui.py

if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    echo.
    echo If Nuitka fails, fall back to PyInstaller build.bat instead.
    pause
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo  BUILD SUCCESSFUL
echo  Output: dist\ThreatLens.dist\ThreatLens.exe
echo.
echo  The Nuitka build produces a native C-compiled .exe.
echo  No PyInstaller bootloader = no RC4/XOR/PE-parsing heuristics.
echo.
echo  Next steps:
echo    1. Test run dist\ThreatLens.dist\ThreatLens.exe
echo    2. Upload to VirusTotal — should have significantly fewer detections
echo    3. Zip the entire dist\ThreatLens.dist folder for distribution
echo    4. (Recommended) Code sign for maximum trust:
echo       signtool sign /a /tr http://timestamp.digicert.com /td sha256 /fd sha256 dist\ThreatLens.dist\ThreatLens.exe
echo ═══════════════════════════════════════════════════════════════
echo.

pause
