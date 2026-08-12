#!/usr/bin/env bash
# Script to run connector tests. Works on both Linux and Windows (Git Bash).
set -e

# Resolve script directory path
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "=== Setting up Python Virtual Environment ==="
# Check if python3 or python is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python is not installed or not in PATH."
    exit 1
fi

if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
fi

# Activate venv depending on platform structure (bin on Linux/macOS, Scripts on Windows)
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Error: Could not find activation script under venv/Scripts/activate or venv/bin/activate."
    exit 1
fi

echo "=== Installing Dependencies ==="
pip install --upgrade pip
pip install -r requirements.txt

echo "=== Running Integration Tests ==="
export PYTHONPATH="$SCRIPT_DIR"
pytest -v -s tests/

echo "=== Tests completed successfully ==="
