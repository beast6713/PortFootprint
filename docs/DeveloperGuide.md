# Developer Guide

This document describes how to set up, develop, and contribute to **PortFootprint**.

## Workspace Bootstrap

We provide a bootstrap utility script to initialize development environments:

```bash
# Run bootstrap configuration
chmod +x bootstrap.sh
./bootstrap.sh
```

This script:
1. Verifies python version constraints.
2. Allocates a virtual environment (`.venv`).
3. Installs requirements in editable mode (`pip install -e ".[dev]"`).
4. Configures Git pre-commit hooks.

## Static Analysis Checks
Run these tools locally to ensure code quality passes CI checks:

```bash
# Lint checks
ruff check .

# Format checks
ruff format .

# Type checks
mypy portfootprint/

# Security scans
bandit -r portfootprint/
```
