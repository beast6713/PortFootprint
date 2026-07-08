# Protocol Registry Pattern

This document details the registry patterns implementing decoupled service detection handshakes.

## Registry Decorator architecture
Instead of hardcoding hundreds of conditions inside a single detector class, PortFootprint uses a decorator-based registration pattern:

```python
from portfootprint.services.registry import registry

@registry.register(ports=[80, 8080], keywords=["http", "nginx"], priority=10)
class HttpFingerprinter(BaseFingerprintModule):
    # ...
```

## Candidate Selection Algorithm
When a port is verified as open:
1. `ServiceDetector` calls `registry.get_candidates(port, banner)`.
2. The registry loops through all registered classes:
   - If the port number matches, the candidate is selected.
   - If the lowercase banner string contains any of the registered keywords, the candidate is selected.
3. Candidate classes are sorted by priority weight:
   - Banner signature matches add a weight of `+100` to prioritize signature lookups over generic port assignments.
4. The candidate classes list is returned sorted descending.
