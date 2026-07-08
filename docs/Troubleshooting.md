# Troubleshooting Guide

This document describes how to troubleshoot common issues when executing **PortFootprint**.

## Common Errors & Fixes

### 1. TargetResolutionError: Failed to resolve target
- **Reason**: The DNS lookup failed to resolve the target hostname or the host is offline.
- **Fix**: Verify internet connectivity. Double check hostname spellings, and check if you can resolve it using `nslookup` or `dig`.

### 2. OSError: [Errno 24] Too many open files
- **Reason**: The configured threads limit is exceeding the OS's file descriptor limits.
- **Fix**: Decrease concurrency using `--threads 50` or increase system limits (e.g. `ulimit -n 2048` on Linux/macOS).

### 3. Exporter Security Failure
- **Reason**: A requested report path resolved to a forbidden system directory.
- **Fix**: Select an output path located inside the project workspace directory or a local user folder (such as Desktop).
