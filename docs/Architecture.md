# PortFootprint Architecture

This document describes the high-level architecture design of **PortFootprint**.

## Design Philosophy
PortFootprint is built using **Clean Architecture** and **SOLID** principles. It enforces strict separation of concerns through modular layers:

```
+-------------------------------------------------------+
|                       CLI Layer                       |
|        (CommandLineParser, TerminalFormatter)         |
+--------------------------+----------------------------+
                           |
                           v
+--------------------------+----------------------------+
|                       Core Layer                      |
|         (ScanManager, ScanStatistics, Models)         |
+--------------------------+----------------------------+
                           |
                           v
+--------------------------+----------------------------+
|                     Scanner Layer                     |
|      (TargetResolver, ScanWorker, ScanScheduler)      |
+--------------------------+----------------------------+
                           |
                           v
+--------------------------+----------------------------+
|                     Services Layer                    |
|      (BannerGrabber, ServiceDetector, Registry)       |
+-------------------------------------------------------+
```

## Layer Responsibilities

### 1. CLI Layer
- Matches user commands and parameters arguments.
- Formats final results outputs cleanly using tables.
- Renders thread-safe real-time carriage-return progress bars.

### 2. Core Layer
- Configures, parses, and validates the immutable `ScanConfiguration` models.
- Orchestrates overall scanning workflow execution sequences (`ScanManager`).
- Logs execution statistics metrics (`ScanStatistics`).
- Manages scan history logs and differential comparison reports.

### 3. Scanner Layer
- Resolves host DNS targets to IPv4 or IPv6 families securely.
- Manages thread scheduling resource structures (`ScanScheduler`).
- Executes workers checks loops.

### 4. Services Layer
- Performs active and passive welcome greetings reads.
- Dispatches connections through a dynamic lookup `ProtocolRegistry` routing mappings.
- Runs protocol specific queries (HTTP, Database handshakes, DNS packets transaction).
