#!/usr/bin/env python3
"""
Python Executable Auto-Detector
Automatically detects the appropriate Python binary command ('python', 'python3', 'py', or sys.executable)
across Windows, Linux, and macOS platforms.
"""

import os
import sys
import shutil
import subprocess
import platform
from typing import Dict, Any, Optional


def get_python_executable() -> str:
    """
    Returns the absolute path or command name of the working Python 3 executable.
    
    Priority order:
    1. sys.executable (if valid and running inside Python)
    2. Virtual Environment (.venv or venv relative to CWD or VIRTUAL_ENV)
    3. System command ('python3', 'python', 'py') verified to execute Python 3
    """
    # 1. Active runtime sys.executable
    if sys.executable and os.path.isfile(sys.executable):
        return sys.executable

    # 2. Check virtual environment paths
    cwd = os.getcwd()
    venv_candidates = [
        os.environ.get("VIRTUAL_ENV", ""),
        os.path.join(cwd, ".venv"),
        os.path.join(cwd, "venv")
    ]
    
    for venv_dir in venv_candidates:
        if not venv_dir:
            continue
        # Windows venv path
        win_py = os.path.join(venv_dir, "Scripts", "python.exe")
        if os.path.isfile(win_py):
            return win_py
        # Linux/macOS venv path
        unix_py = os.path.join(venv_dir, "bin", "python")
        if os.path.isfile(unix_py):
            return unix_py

    # 3. System command candidates based on OS
    system_name = platform.system().lower()
    if "windows" in system_name:
        candidates = ["python", "python3", "py"]
    else:
        candidates = ["python3", "python"]

    for cmd in candidates:
        exe_path = shutil.which(cmd)
        if exe_path:
            try:
                res = subprocess.run(
                    [exe_path, "-c", "import sys; print(sys.version_info[0])"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0 and res.stdout.strip() == "3":
                    return cmd
            except Exception:
                continue

    # Fallback
    return "python" if os.name == "nt" else "python3"


def get_system_python_info() -> Dict[str, Any]:
    """
    Get detailed information about OS and available Python interpreters.
    """
    system_os = platform.system()
    os_version = platform.version()
    current_python = sys.executable
    current_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    commands_tested = {}
    test_cmds = ["python", "python3", "py"]
    for cmd in test_cmds:
        path = shutil.which(cmd)
        if path:
            try:
                res = subprocess.run(
                    [path, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    commands_tested[cmd] = {"path": path, "version": res.stdout.strip(), "available": True}
                else:
                    commands_tested[cmd] = {"path": path, "version": None, "available": False}
            except Exception as e:
                commands_tested[cmd] = {"path": path, "error": str(e), "available": False}
        else:
            commands_tested[cmd] = {"path": None, "available": False}

    recommended_cmd = get_python_executable()

    return {
        "os": system_os,
        "os_release": platform.release(),
        "os_version": os_version,
        "is_windows": os.name == "nt",
        "current_executable": current_python,
        "current_python_version": current_version,
        "recommended_command": recommended_cmd,
        "available_commands": commands_tested
    }


if __name__ == "__main__":
    info = get_system_python_info()
    print("========================================")
    print("      PYTHON ENVIRONMENT DETECTOR      ")
    print("========================================")
    print(f"OS Platform         : {info['os']} ({info['os_release']})")
    print(f"Current Interpreter : {info['current_executable']}")
    print(f"Current Python Ver  : {info['current_python_version']}")
    print(f"Recommended Command : {info['recommended_command']}")
    print("----------------------------------------")
    print("Detected Commands in PATH:")
    for cmd_name, details in info["available_commands"].items():
        if details["available"]:
            print(f"  - {cmd_name:8s} -> {details['path']} (v{details['version']})")
        else:
            print(f"  - {cmd_name:8s} -> Not available or invalid")
    print("========================================")
