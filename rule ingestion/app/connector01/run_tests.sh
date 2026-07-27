#!/usr/bin/env bash
# Script to run connector tests on Linux.
# Exits immediately if any command fails.
set -e

# Resolve script directory path
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "=== Setting up Python Virtual Environment ==="
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

echo "=== Installing Dependencies ==="
pip install --upgrade pip
pip install -r requirements.txt

echo "=== Running Integration Tests ==="
export PYTHONPATH="$SCRIPT_DIR"
pytest -v -s tests/

echo "=== Tests completed successfully ==="
