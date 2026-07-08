#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "=== PortFootprint Development Environment Bootstrap ==="

# 1. Check Python version
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 is required but could not be found. Exiting."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[*] Found Python version: $PYTHON_VERSION"

# 2. Create virtual environment if not present
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment in '.venv'..."
    python3 -m venv .venv
else
    echo "[*] Virtual environment already exists."
fi

# 3. Activate virtual environment
echo "[*] Activating virtual environment..."
source .venv/bin/activate

# 4. Install dependencies
echo "[*] Installing dev dependencies..."
pip install --upgrade pip
pip install -e ".[dev]"

# 5. Initialize pre-commit
if command -v pre-commit &>/dev/null; then
    echo "[*] Registering Git pre-commit hooks..."
    pre-commit install
else
    echo "[!] Warning: pre-commit command not found. Skipping hook setup."
fi

echo "======================================================="
echo "[*] Bootstrap successful! Run: source .venv/bin/activate"
echo "======================================================="
