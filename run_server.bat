@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [Server Launcher] Auto-detecting Python environment for Windows...

set "PYTHON_BIN="

:: 1. Check virtualenv paths
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_BIN=.venv\Scripts\python.exe"
    echo [Server Launcher] Found virtual environment: .venv\Scripts\python.exe
    goto :RUN
)

if exist "venv\Scripts\python.exe" (
    set "PYTHON_BIN=venv\Scripts\python.exe"
    echo [Server Launcher] Found virtual environment: venv\Scripts\python.exe
    goto :RUN
)

:: 2. Check system 'python' command
where python >nul 2>&1
if %errorlevel% equ 0 (
    python -c "import sys; exit(0 if sys.version_info[0] >= 3 else 1)" >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_BIN=python"
        echo [Server Launcher] Using system command: python
        goto :RUN
    )
)

:: 3. Check system 'python3' command
where python3 >nul 2>&1
if %errorlevel% equ 0 (
    python3 -c "import sys; exit(0 if sys.version_info[0] >= 3 else 1)" >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_BIN=python3"
        echo [Server Launcher] Using system command: python3
        goto :RUN
    )
)

:: 4. Check system 'py' launcher
where py >nul 2>&1
if %errorlevel% equ 0 (
    py -3 -c "import sys; exit(0 if sys.version_info[0] >= 3 else 1)" >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_BIN=py -3"
        echo [Server Launcher] Using Windows Python Launcher: py -3
        goto :RUN
    )
)

echo [ERROR] No suitable Python 3 installation found in PATH!
echo Please install Python 3 or activate a virtual environment.
pause
exit /b 1

:RUN
echo [Server Launcher] Starting app.py using %PYTHON_BIN%...
%PYTHON_BIN% app.py
