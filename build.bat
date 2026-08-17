@echo off
REM ═══════════════════════════════════════════════════════════════
REM  ThreatLens Build Script — AV-Safe Configuration
REM  Run this from the ThreatLens project directory on Windows
REM ═══════════════════════════════════════════════════════════════

echo.
echo  ThreatLens v1.0 — Build Script
echo  ================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ and add to PATH.
    pause
    exit /b 1
)

REM Check PyInstaller is installed
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Clean previous build
echo Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist dist\ThreatLens rmdir /s /q dist\ThreatLens
if exist dist\ThreatLens.exe del /q dist\ThreatLens.exe

REM Build with the clean spec (onefolder, no UPX, version info)
echo.
echo Building ThreatLens (onefolder, no UPX, version info)...
echo.
python -m PyInstaller ThreatLens.spec --noconfirm --clean

if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    pause
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo  BUILD SUCCESSFUL
echo  Output: dist\ThreatLens\ThreatLens.exe
echo.
echo  Next steps:
echo    1. Test run dist\ThreatLens\ThreatLens.exe
echo    2. Upload to VirusTotal to verify clean detections
echo    3. Zip the dist\ThreatLens folder for distribution
echo    4. (Optional) Sign with code signing certificate:
echo       signtool sign /a /tr http://timestamp.digicert.com /td sha256 /fd sha256 dist\ThreatLens\ThreatLens.exe
echo ═══════════════════════════════════════════════════════════════
echo.

pause
