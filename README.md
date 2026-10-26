# PortFootprint

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Architecture-Clean%20%26%20SOLID-orange" alt="Architecture: Clean & SOLID">
  <img src="https://img.shields.io/badge/Runtime%20Dependencies-Zero%20(Pure%20Stdlib)-brightgreen" alt="Dependencies: Zero Required">
  <img src="https://img.shields.io/badge/Tests-81%20Passed%20(100%25)-success" alt="Tests">
  <img src="https://img.shields.io/badge/Code%20Style-Ruff-black" alt="Code Style: Ruff">
  <img src="https://img.shields.io/badge/Type%20Check-Mypy%20Strict-blue" alt="Type Check: Mypy Strict">
</p>

**PortFootprint** is a production-grade, highly modular, cross-platform TCP port scanner, service fingerprinting engine, and interactive security console implemented in Python.

Operating purely within user-space socket APIs, PortFootprint runs reliably on **Windows**, **macOS**, and **Linux** without requiring root or administrator privileges. Designed using **Clean Architecture** and **SOLID** principles, it decouples scanning, fingerprinting, reporting, and CLI presentation into distinct layers that can be run interactively, driven through standard CLI commands, or embedded as a reusable library.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture & Directory Structure](#architecture--directory-structure)
- [Requirements & Installation](#requirements--installation)
- [Interactive Security Console (REPL)](#interactive-security-console-repl)
- [Complete CLI Command Cheat Sheet](#complete-cli-command-cheat-sheet)
  - [1. Launch Interactive Security Console](#1-launch-interactive-security-console)
  - [2. High-Level Convenience Subcommands](#2-high-level-convenience-subcommands)
  - [3. Diagnostics & Information](#3-diagnostics--information)
  - [4. Standard Target Scans](#4-standard-target-scans)
  - [5. Custom Port Specification](#5-custom-port-specification)
  - [6. Performance & Concurrency Tuning](#6-performance--concurrency-tuning)
  - [7. Structured Report Generation](#7-structured-report-generation)
  - [8. Scan History & Differential Comparisons](#8-scan-history--differential-comparisons)
  - [9. Comprehensive Integrated Scan Command](#9-comprehensive-integrated-scan-command)
- [Console & Report Previews](#console--report-previews)
- [Configuration File (`config.json`)](#configuration-file-configjson)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Documentation Index](#documentation-index)
- [Current Limitations](#current-limitations)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## Overview

PortFootprint provides security researchers, penetration testers, and system administrators with a fast, zero-dependency TCP scanning and service analysis tool:

* **Dual Execution Modes**: Work seamlessly in an **Interactive Security Shell (REPL)** with command auto-completion and ASCII diagnostics, or run direct **UNIX-style CLI subcommands** inside automated CI/CD and script environments.
* **Smart Service Fingerprinting**: Identifies services through active and passive banner grabbing, protocol-specific probes, and TLS certificate inspection.
* **Executive Dashboards**: Exports scan findings into flattened CSV spreadsheets, structured JSON data, and interactive, responsive, single-file HTML dashboards with built-in dark mode and search filtering.
* **Local Listening Port Discovery**: Instantly inspects local network sockets to discover all open listening ports on the machine and fingerprinters them with a single command (`local`).

---

## Key Features

### Phase 1: Concurrency & Scanning Engine
- **Robust DNS & IP Resolution**: Validates target hostnames and handles both IPv4 and IPv6 address resolution.
- **Flexible Port Range Parser**: Supports individual ports (`80`), comma-separated lists (`22,80,443`), ranges (`20-100`), and mixed combinations (`21-25,80,443,8000-8080`) with automatic deduplication and sorting.
- **Multi-Threaded Scanner**: Executes concurrent TCP Connect scans using a configurable `ThreadPoolExecutor`.
- **Granular Socket Controls**: Customizable connection timeout thresholds and automatic retry policies on connection drops.
- **Thread-Safe Live Progress**: Dynamic, non-interfering terminal progress indicators and Rich progress bars.

### Phase 2: Service Discovery & Protocol Probing
- **Passive & Active Banner Grabbing**: Reads initial socket welcome banners; safely falls back to non-destructive ASCII probe requests if silent.
- **Dynamic Protocol Registry**: Extensible registry pattern allowing protocol handlers to self-register with port matches, execution priority, and banner keywords.
- **Integrated Protocol Handlers**:
  - **HTTP / HTTPS**: Status code, Server banner, TLS/SSL certificate metadata (issuer, subject, cipher suite, validity period).
  - **SSH**: Protocol version and daemon identification (OpenSSH, Dropbear, etc.).
  - **FTP & SMTP**: Server daemon banners, EHLO/HELO response verification.
  - **Databases**: Detection signatures for MySQL, PostgreSQL, Redis, and MongoDB.
  - **Network Services**: DNS and IRC daemon identification.
- **Safe Unicode Decoding**: Automatically recovers from character set anomalies using UTF-8 with Latin-1 fallbacks.

### Phase 3: Reporting & Operational Analytics
- **Dynamic Export Registry**: Dynamically routes scan summaries to selected exporters based on requested report flags.
- **Multi-Format Reporting**:
  - **HTML Dashboard**: Self-contained, responsive single-file report featuring dark mode, summary cards, real-time search filtering, and collapsible protocol handshake views.
  - **JSON Report**: Comprehensive structured data model with machine-readable timestamps, summary metrics, and raw metadata.
  - **CSV Report**: Tabular spreadsheet listing for direct Excel / auditing workflows.
- **Performance & Metrics Engine**: Tracks scan duration, ports scanned per second, state distributions (Open, Filtered, Closed), and top detected protocols.
- **Local Scan History**: Automatically persists scan execution metrics in `.portfootprint_history.json`.
- **Differential Scan Comparison**: Compares two historical JSON scans (`compare old.json new.json`) to surface newly opened ports, closed ports, or service version changes.
- **Centralized Configuration**: Supports default overrides through an optional `config.json` file.
- **Structured Logging**: Configurable log levels, thread names, timestamps, and log file outputs.

### Phase 4: Interactive Security Console & High-Level Workflows
- **Interactive Console (REPL)**: Dedicated interactive shell with stylized ASCII art banners, live system readiness status, and command autocompletion.
- **System Doctor Diagnostics (`doctor`)**: Automated 5-point subsystem health check verifying Python environment, socket readiness, DNS resolution, protocol modules, and report exporters.
- **Local Port Discovery (`local`)**: Discovers all active listening TCP ports on the local machine and immediately fingerprints them.
- **Fast Scan Profile (`quick`)**: Rapidly scans top common service ports without entering verbose flag configurations.
- **Windows One-Click Launcher**: Includes `launch_cli.bat` for instant console startup on Windows workstations.

---

## Architecture & Directory Structure

PortFootprint follows Clean Architecture principles, ensuring that business logic, network scanning, service fingerprinters, and presentation layers remain cleanly separated:

```text
Port_Scanner_footprinter/
├── portfootprint/
│   ├── cli/                     # CLI parsing, interactive shell, doctor, commands, & formatting
│   │   ├── banner.py            # ASCII art banner & status rendering
│   │   ├── commands.py          # Modular command definitions (scan, quick, local, doctor, etc.)
│   │   ├── console.py           # Interactive REPL console coordinator
│   │   ├── doctor.py            # 5-point subsystem diagnostic health check
│   │   ├── formatter.py         # Terminal output tables and comparison diff formatting
│   │   ├── parser.py            # Argparse CLI options and flag definition
│   │   └── shell.py             # Prompt-toolkit & readline REPL loop with auto-completion
│   ├── common/                  # Shared utilities (logging, validators, path sanitizers)
│   ├── core/                    # Core orchestration, data models, history, and config
│   │   ├── comparison.py        # Differential scan comparison engine
│   │   ├── config.py            # Scan configuration dataclasses
│   │   ├── history.py           # Scan history manager (.portfootprint_history.json)
│   │   ├── models.py            # Domain data classes (HostResult, PortResult, ScanResult)
│   │   └── orchestrator.py      # ScanManager orchestrator
│   ├── reports/                 # Reporting engine & export registry
│   │   ├── csv_exporter.py      # Flat CSV export
│   │   ├── html_exporter.py     # Interactive responsive HTML dashboard export
│   │   └── json_exporter.py     # Structured JSON export
│   ├── scanner/                 # Low-level network scanning engine
│   │   ├── dns_resolver.py      # IPv4/IPv6 host lookup and validation
│   │   ├── engine.py            # ThreadPoolExecutor multi-threaded socket engine
│   │   └── port_parser.py       # Port string expression parser and validator
│   ├── services/                # Protocol detection & probe engine
│   │   ├── banner.py            # Passive & active socket banner grabbing
│   │   ├── registry.py          # Protocol dynamic self-registration registry
│   │   └── protocols/           # Specialized protocol modules (HTTP, SSH, DBs, etc.)
│   └── main.py                  # CLI application entrypoint
├── docs/                        # Technical architecture documentation & report snapshots
├── tests/                       # Complete pytest unit, integration, and CLI test suite
├── launch_cli.bat               # Windows one-click interactive console launcher
├── main.py                      # Root launcher redirect
└── pyproject.toml               # Package build, linting (Ruff), and typing (Mypy) config
```

---

## Requirements & Installation

### Runtime Requirements
- **Python Version**: Python 3.9 or higher.
- **Runtime Dependencies**: **Zero required external dependencies**. The entire scanning engine, protocol fingerprinters, and report exporters run on the standard Python library alone.

### Optional UI Enhancements
Installing `rich` and `prompt-toolkit` unlocks advanced console capabilities:
- Interactive command completion, command history, and styled interactive prompts.
- Styled terminal tables, colored status badges, and Rich progress bars.
- *Note: If these packages are not installed, PortFootprint seamlessly and automatically falls back to clean, zero-dependency standard I/O.*

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/username/PortFootprint.git
   cd PortFootprint
   ```

2. **(Optional) Set up a virtual environment and install UI / development packages**:
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate

   # On macOS / Linux
   python3 -m venv venv
   source venv/bin/activate

   # Install development and enhanced console dependencies
   pip install -r requirements.txt
   ```

---

## Interactive Security Console (REPL)

PortFootprint provides a dedicated, interactive security console with an ASCII banner, subsystem diagnostics, and real-time command suggestions.

### Launching the Console
* **Direct Python command**:
  ```bash
  python main.py
  # or explicitly:
  python main.py console
  ```
* **On Windows**: Double-click [`launch_cli.bat`](launch_cli.bat) to launch the console immediately.

### Available Console Commands

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **`local`** | `local [--all-reports] [--html FILE]` | Auto-detect active listening ports on this machine and fingerprint them |
| **`quick`** | `quick <target> [--all-reports]` | Rapid scan on common top service ports |
| **`scan`** | `scan <target> [-p PORTS] [-t THREADS] [-w TIMEOUT] [--all-reports]` | Scan target host with customizable ports, concurrency, and reports |
| **`doctor`** | `doctor` | Run 5-point subsystem health checks (sockets, DNS, modules, exporters) |
| **`history`** | `history` | Display previous scans index in a formatted table |
| **`compare`** | `compare <old.json> <new.json>` | Compare two historical JSON scans to detect state changes |
| **`help`** | `help [command]` | Display command documentation and usage examples |
| **`clear`** | `clear` | Clear the terminal screen |
| **`version`** | `version` | Display current framework release version |
| **`exit`** | `exit` | Exit the interactive security console |

---

## Complete CLI Command Cheat Sheet

Commands can be run directly from the command line without entering the interactive shell:

### 1. Launch Interactive Security Console
Launch the interactive shell with ASCII banner and auto-completion:
```bash
python main.py
# or
python main.py console
```

### 2. High-Level Convenience Subcommands
Run automated convenience workflows with simplified syntax:
```bash
# Auto-detect all listening ports on your machine and fingerprint them
python main.py local

# Quick scan of common ports on a target
python main.py quick scanme.nmap.org

# Run 5-point subsystem diagnostic health check
python main.py doctor

# View past scan history index
python main.py history

# Compare two scan reports to identify newly opened/closed ports
python main.py compare old_scan.json new_scan.json
```

### 3. Diagnostics & Information
Inspect CLI parameters and version metadata:
```bash
# Display help menu with all options and flags
python main.py --help

# Output framework release version
python main.py --version
```

### 4. Standard Target Scans
Scan a target using default top service ports:
```bash
# Scan a remote hostname
python main.py scanme.nmap.org

# Scan a raw IP address
python main.py 127.0.0.1
```

### 5. Custom Port Specification
Select exactly which ports or port ranges to scan:
```bash
# Single port
python main.py localhost -p 80

# Comma-separated list of ports
python main.py localhost -p 22,80,443,8080

# Inclusive range of ports
python main.py localhost -p 20-100

# Mixed port list combining single ports and ranges
python main.py localhost -p 21-25,80,443,8080-8090
```

### 6. Performance & Concurrency Tuning
Tune network socket connection behavior and thread pool allocation:
```bash
# Configure worker thread concurrency (default: 30)
python main.py localhost --threads 50

# Set socket connection timeout in seconds (default: 1.5)
python main.py localhost --timeout 1.0

# Set connection retry attempts for dropped packets (default: 1)
python main.py localhost --retries 2

# Enable verbose mode (logs per-thread events and timestamps)
python main.py localhost --verbose
```

### 7. Structured Report Generation
Export scan findings into various file formats:
```bash
# Export structured JSON report
python main.py localhost --json my_scan.json

# Export flat CSV spreadsheet table
python main.py localhost --csv my_scan.csv

# Export interactive responsive HTML dashboard
python main.py localhost --html my_scan.html

# Automatically generate all three reports (JSON, CSV, HTML)
python main.py localhost --all-reports

# Write execution tracking log to a custom file
python main.py localhost --log-file activity.log
```

### 8. Scan History & Differential Comparisons
Track execution history and compare scan results over time:
```bash
# Print scan history index list
python main.py --history

# Compare two JSON reports to inspect opened, closed, or changed services
python main.py --compare scan_v1.json scan_v2.json
```

### 9. Comprehensive Integrated Scan Command
Execute an end-to-end scan combining mixed port ranges, custom concurrency limits, timeouts, retries, verbose logs, and all report outputs:
```bash
python main.py scanme.nmap.org -p 21-25,80,100-200,443,3306,8080 --threads 60 --timeout 1.2 --retries 2 --verbose --all-reports --log-file scan.log
```

---

## Console & Report Previews

### Interactive HTML Report Dashboard
The scanner generates a self-contained, responsive HTML dashboard featuring dark-mode styling, key summary cards, real-time search filtering, and collapsible protocol details:

![Interactive HTML Report Dashboard](docs/images/dashboard_dark.png)

### Terminal Snapshot Logs
Recorded command outputs are available in the repository for review:
* [CLI Scan Table Output](docs/snapshots/cli_scan_output.txt) - Formatted terminal table output of an active scan.
* [CLI History Output](docs/snapshots/cli_history_output.txt) - Saved scan index records.
* [CLI Comparison Output](docs/snapshots/cli_compare_output.txt) - Differential state comparison between two scans.

---

## Configuration File (`config.json`)

To standardize scanner defaults without repeating CLI flags, place a `config.json` file in your working directory:

```json
{
    "threads": 50,
    "timeout": 1.5,
    "retries": 2,
    "verbose": false,
    "log_file": "scan.log",
    "default_reports": {
        "json": "report.json",
        "csv": "report.csv",
        "html": "report.html"
    }
}
```

CLI arguments explicitly passed at invocation will override these configuration file values.

---

## Testing & Quality Assurance

The codebase includes an extensive suite of unit and integration tests covering all scanner components, protocol modules, report exporters, and CLI console commands.

```bash
# Run complete test suite (81 tests)
pytest

# Run tests with test coverage reporting
pytest --cov=portfootprint

# Lint code with Ruff
ruff check .

# Validate static typing with Mypy
mypy portfootprint
```

---

## Documentation Index

Detailed architectural and developer guides are available in the [`docs/`](docs/) directory:

- [Architecture & Design Decisions](docs/Architecture.md)
- [API Reference](docs/API.md)
- [Execution Flow & Lifecycles](docs/ExecutionFlow.md)
- [Protocol Registry Guide](docs/ProtocolRegistry.md)
- [Service Detection Engine](docs/ServiceDetection.md)
- [Report System Documentation](docs/ReportSystem.md)
- [Threading & Concurrency Model](docs/ThreadingModel.md)
- [Performance Benchmarks](docs/Performance.md)
- [Troubleshooting Guide](docs/Troubleshooting.md)
- [Security Guidelines](docs/Security.md)
- [Developer & Extension Guide](docs/DeveloperGuide.md)
- [Contributing Guide](docs/Contributing.md)

---

## Current Limitations

- **TCP Connect Scans Only**: Performs a complete TCP 3-way handshake on connections. This guarantees accuracy in user-space across non-root environments, but is slower and more visible than raw SYN stealth scans.
- **Host Discovery**: Assumes the target host is reachable; pre-scan ICMP ping sweeps are not currently performed.

---

## Roadmap

- [x] **Phase 1**: Core TCP multi-threaded scanner, CLI flag validation, thread pooling, and progress formatting.
- [x] **Phase 2**: Deep active/passive banner grabbing and protocol self-registration registry.
- [x] **Phase 3**: Multi-format reporting (HTML, JSON, CSV), scan metrics, execution history, and differential scan comparison.
- [x] **Phase 4**: Interactive security console (REPL), subsystem doctor diagnostics, local port auto-discovery, and Windows quick launcher.
- [ ] **Phase 5**: Dynamic third-party plugin loader and vulnerability database (CVE) correlation integration.

---

## Disclaimer

This software is developed strictly for educational purposes, security research, and authorized auditing. Do not execute scans against systems without explicit, prior authorization from the system owner. The authors and maintainers assume no liability for unauthorized usage or secondary damages.
