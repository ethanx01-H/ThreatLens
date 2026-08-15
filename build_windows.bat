@echo off
setlocal EnableDelayedExpansion

echo.
echo ============================================================
echo   ThreatLens - Windows Build Script
echo ============================================================
echo.

:: ─── Locate Python ────────────────────────────────────────────
set "PYTHON="
where python >nul 2>&1 && set "PYTHON=python"
if "%PYTHON%"=="" (
    where python3 >nul 2>&1 && set "PYTHON=python3"
)
if "%PYTHON%"=="" (
    if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    )
)
if "%PYTHON%"=="" (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    )
)
if "%PYTHON%"=="" (
    echo [ERROR] Python not found. Install Python 3.11+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [OK] Using Python: %PYTHON%
%PYTHON% --version
echo.

:: ─── Install Dependencies ─────────────────────────────────────
echo [1/3] Installing dependencies...
%PYTHON% -m pip install --upgrade pip -q
%PYTHON% -m pip install -r requirements.txt --break-system-packages -q
%PYTHON% -m pip install pyinstaller --break-system-packages -q
echo [OK] Dependencies installed.
echo.

:: ─── Build .exe ───────────────────────────────────────────────
echo [2/3] Building .exe with PyInstaller...

:: Clean previous build
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

%PYTHON% -m PyInstaller ^
    --noconfirm ^
    --onefile ^
    --windowed ^
    --name "ThreatLens" ^
    --add-data "config.py;." ^
    --add-data "api_sources.py;." ^
    --add-data "dns_recon.py;." ^
    --add-data "risk_engine.py;." ^
    --add-data "report_gen.py;." ^
    --hidden-import "dns.resolver" ^
    --hidden-import "dns.rdatatype" ^
    --hidden-import "dns.rdataclass" ^
    --hidden-import "dns.exception" ^
    --hidden-import "whois" ^
    --hidden-import "requests" ^
    --hidden-import "docx" ^
    --hidden-import "docx.oxml" ^
    --hidden-import "docx.oxml.ns" ^
    --hidden-import "docx.shared" ^
    --hidden-import "docx.enum.text" ^
    --hidden-import "docx.enum.table" ^
    --hidden-import "shodan" ^
    --hidden-import "tkinter" ^
    --hidden-import "tkinter.ttk" ^
    --hidden-import "ctypes" ^
    --hidden-import "json" ^
    --hidden-import "ssl" ^
    --exclude-module "matplotlib" ^
    --exclude-module "numpy" ^
    --exclude-module "pandas" ^
    --exclude-module "scipy" ^
    --exclude-module "PIL" ^
    --exclude-module "cv2" ^
    --strip ^
    --upx-dir . ^
    rep_gui.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed! Check the output above.
    pause
    exit /b 1
)

echo [OK] Build complete.
echo.

:: ─── Copy Output ──────────────────────────────────────────────
echo [3/3] Finalizing...

:: Copy .exe to main directory
if not exist "release" mkdir "release"
copy /y "dist\ThreatLens.exe" "release\" >nul

:: Copy config files to release folder
copy /y ".env.example" "release\.env.example" >nul 2>nul
copy /y "README.md" "release\" >nul 2>nul

:: Get file size
for %%A in ("release\ThreatLens.exe") do set "SIZE=%%~zA"
set /a "SIZE_MB=!SIZE! / 1048576"

echo.
echo ============================================================
echo   BUILD SUCCESSFUL
echo ============================================================
echo.
echo   Output:  release\ThreatLens.exe
echo   Size:    !SIZE_MB! MB
echo.
echo   The .exe is a standalone executable - no Python required
echo   on the target machine. Just copy and run.
echo.
echo   To set API keys, create a .env file next to the .exe
echo   or set environment variables on the target system.
echo ============================================================
echo.

pause
