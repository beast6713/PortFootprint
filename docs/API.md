# API Documentation

This document describes the public Python API of **PortFootprint**.

## Using PortFootprint Programmatically

The core scanner engine is fully decoupled from the command line parser interface. You can import and invoke it in Python scripts directly:

```python
from portfootprint.core.config import ScanConfiguration
from portfootprint.core.orchestrator import ScanManager

# 1. Setup configurations parameters
config = ScanConfiguration(
    target="scanme.nmap.org",
    ports=[22, 80, 443],
    threads=10,
    timeout=1.5,
    retries=1,
    verbose=False
)

# 2. Trigger ScanManager execution orchestrator
manager = ScanManager(config)
scan_result = manager.execute()

# 3. Process compiled data structures
print(f"Target Resolved: {scan_result.resolved_ip}")
host = scan_result.hosts[0]
for port in host.ports:
    print(f"Port {port.port}: {port.state}")
    if port.service:
        print(f"  Service: {port.service.service_name} (v{port.service.version})")
```
