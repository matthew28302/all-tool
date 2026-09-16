#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

detect_python() {
    # 1. Virtual environment checks (Linux/macOS and Windows)
    if [ -x ".venv/bin/python" ]; then
        echo ".venv/bin/python"
        return 0
    elif [ -x ".venv/Scripts/python.exe" ]; then
        echo ".venv/Scripts/python.exe"
        return 0
    elif [ -x "venv/bin/python" ]; then
        echo "venv/bin/python"
        return 0
    elif [ -x "venv/Scripts/python.exe" ]; then
        echo "venv/Scripts/python.exe"
        return 0
    fi

    # 2. Check active VIRTUAL_ENV
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        if [ -x "$VIRTUAL_ENV/bin/python" ]; then
            echo "$VIRTUAL_ENV/bin/python"
            return 0
        elif [ -x "$VIRTUAL_ENV/Scripts/python.exe" ]; then
            echo "$VIRTUAL_ENV/Scripts/python.exe"
            return 0
        fi
    fi

    # 3. Detect system commands based on OS
    local candidates=()
    if [[ "${OSTYPE:-}" == "msys" || "${OSTYPE:-}" == "cygwin" || "${OSTYPE:-}" == "win32" ]]; then
        candidates=("python" "python3" "py")
    else
        candidates=("python3" "python")
    fi

    for cmd in "${candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if "$cmd" -c "import sys; exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
                echo "$cmd"
                return 0
            fi
        fi
    done

    # Default fallback
    echo "python"
}

PYTHON_BIN=$(detect_python)

echo "[Server Launcher] Detected Python interpreter: ${PYTHON_BIN}"
if command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "[Server Launcher] Resolved binary path: $(command -v "${PYTHON_BIN}")"
fi

exec ${PYTHON_BIN} app.py
