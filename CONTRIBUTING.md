# Contributing to PortFootprint

First off, thank you for considering contributing to PortFootprint! We welcome your help in making this tool better.

## Development Workflow

1. **Fork the Repository**: Create a personal fork of the project on GitHub.
2. **Setup Local Workspace**: Clone the repository and install development dependencies:
   ```bash
   git clone https://github.com/username/PortFootprint.git
   cd PortFootprint
   pip install -r requirements.txt
   ```
3. **Create a Feature Branch**: Work on your changes in a descriptive branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
4. **Implement Coding Quality Guidelines**:
   - Write clean, SOLID-compliant code.
   - Enforce Python type annotations on all public functions.
   - Confrom to PEP 8 style formatting.
5. **Run Verification Tests**: Ensure all existing and new unit tests pass successfully:
   ```bash
   python -m pytest tests/
   ```
6. **Submit a Pull Request**: Push your branch to GitHub and open a pull request against the main branch.

## Bug Reports and Feature Requests

Please use our GitHub Issue templates to file bugs or request enhancements. Ensure you include:
- A clear description of the issue or feature.
- Steps to reproduce (if a bug).
- Environment details (OS, Python version).
