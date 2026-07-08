# Security Hardening & Safe Operations

This document describes the security model, risk mitigations, and safe network scanning practices in **PortFootprint**.

## Path Traversal Mitigations
Exporters (`ReportManager`) and history loaders (`ScanHistoryManager`) sanitize destination file paths against Directory Traversal and Path Traversal exploits:
- Checks for null-byte injections (`\x00`).
- Resolves paths using `os.path.realpath` to follow symlinks safely.
- Bypasses writing to sensitive operating system folders (such as `/etc`, `/bin`, `/lib`, and `C:\Windows`).

## Resource Protection
To avoid local resource starvation:
- **Maximum Thread limits**: Constrained to `1000` worker threads to prevent thread pool starvation or Out-Of-Memory crashes.
- **Outbound Rate Limiting**: Timeouts and retries can be configured dynamically to prevent saturating local gateways.
