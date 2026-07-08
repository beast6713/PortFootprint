# Report Exporter System

This document details the architecture and features of the reporting engine.

## Exporters Architecture
Report generation is orchestrated by the `ReportManager` and resolved dynamically via the `ExportRegistry`:

```
 [ScanManager] --> [ReportManager]
                         |
                         v
                  [ExportRegistry]
                         |
           +-------------+-------------+
           |             |             |
     (json_report)  (csv_report)  (html_report)
```

## Formats Details

### 1. JSON Exporter
Stores scan configuration fields, execution durations, total ports stats, and a list of scanned ports with nested service certificates/headers data.

### 2. CSV Exporter
Generates a flat spreadsheet table with columns: `Port`, `State`, `Protocol`, `Version`, `Banner`, and `Service Name`.

### 3. HTML Exporter
Outputs a premium, interactive single-file HTML dashboard:
- Embedded CSS with dark-mode styling.
- Client-side search filters and state selection tabs using vanilla JavaScript.
- Collapsible detail drawers showing complete JSON parameters.
- Print-friendly formats support.
