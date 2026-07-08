# Execution Flow

This document details the dynamic execution steps from initialization to final outputs formatting.

## Standard Scanning Flow

```mermaid
sequenceDiagram
    participant CLI as CLI Layer
    participant Manager as ScanManager Orchestrator
    participant Resolver as TargetResolver
    participant Scheduler as ScanScheduler
    participant Worker as ScanWorker Thread
    participant Detector as ServiceDetector
    participant Exporters as ReportManager

    CLI->>CLI: Parse Arguments & Load config.json
    CLI->>Manager: Instantiate ScanConfiguration
    Manager->>Resolver: Resolve Target Host DNS
    Resolver-->>Manager: Return Target IP & Address Family
    Manager->>Scheduler: Run Ports Check Schedule
    Scheduler->>Worker: Submit Worker Tasks to Pool
    activate Worker
    Worker->>Worker: connection_handler.scan_port() (connect_ex)
    Note over Worker: If port state is OPEN:
    Worker->>Detector: detect(result, socket, banner)
    Detector->>Detector: Query ProtocolRegistry candidates
    Detector-->>Worker: Return ServiceMetadata
    Worker->>Manager: add_port_result(result)
    deactivate Worker
    Scheduler-->>Manager: Finish Scan Queue
    Manager->>Exporters: generate_reports(scan_result)
    Manager->>CLI: Print Scan Results Terminal Output
```

## Key Phases

### 1. Startup & Config Load
Loads defaults from `config.json` configuration blocks, prioritizing command-line flags.

### 2. Resolution Check
Resolves hostname using `socket.getaddrinfo`. If it resolves, proceeds with the scan; otherwise, reports error.

### 3. Execution Threads Loops
Executes port scans in parallel using `concurrent.futures.ThreadPoolExecutor`.

### 4. Compilations and Reporting
Summarizes counts, records scan history logs locally, and exports requested file formats.
