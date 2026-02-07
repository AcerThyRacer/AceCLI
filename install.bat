@echo off
REM ============================================================
REM  AceCLI Installer for Windows
REM  Usage: Right-click → Run as Administrator
REM     or: Open PowerShell → .\install.bat
REM ============================================================
title AceCLI Installer

echo.
echo   ╔══════════════════════════════════════╗
echo   ║      AceCLI Installer (Windows)      ║
echo   ╚══════════════════════════════════════╝
echo.

REM 1. Check Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo   [X] Node.js not found.
    echo       Install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo   [OK] Node.js %NODE_VER%

REM 2. Check npm
where npm >nul 2>&1
if errorlevel 1 (
    echo   [X] npm not found.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('npm -v') do set NPM_VER=%%i
echo   [OK] npm v%NPM_VER%

REM 3. Check git
where git >nul 2>&1
if errorlevel 1 (
    echo   [X] git not found. Install git from https://git-scm.com
    pause
    exit /b 1
)
echo   [OK] git found

REM 4. Set install directory
set INSTALL_DIR=%USERPROFILE%\.acecli

REM 5. Clone or update
if exist "%INSTALL_DIR%\.git" (
    echo.
    echo   → Updating existing installation...
    cd /d "%INSTALL_DIR%"
    git pull --ff-only
) else (
    echo.
    echo   → Cloning AceCLI...
    git clone https://github.com/AcerThyRacer/AceCLI.git "%INSTALL_DIR%"
    cd /d "%INSTALL_DIR%"
)

REM 6. Install dependencies
echo.
echo   → Installing dependencies...
call npm install --production

REM 7. Link globally
echo.
echo   → Linking 'ace' command globally...
call npm link

REM 8. Verify
where ace >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [OK] AceCLI installed to %INSTALL_DIR%
    echo        Run directly: node "%INSTALL_DIR%\src\index.js"
) else (
    echo.
    echo   ╔══════════════════════════════════════╗
    echo   ║    AceCLI installed successfully!    ║
    echo   ╚══════════════════════════════════════╝
    echo.
    echo   Run:  ace
    echo   Help: ace --help
)

echo.
pause
