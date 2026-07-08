"""
Dataclasses representing Port, Host, and Scan execution results.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ServiceMetadata:
    """Represents protocol-specific fingerprinting details for a service."""
    service_name: str
    protocol: str = "tcp"
    version: str = ""
    banner: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    certificate: dict[str, Any] = field(default_factory=dict)
    title: str = ""
    extra_details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PortResult:
    """Represents the scan results of a single destination port."""
    port: int
    state: str
    reason: str = ""
    duration: float = 0.0
    service: Optional[ServiceMetadata] = None


@dataclass(frozen=True)
class HostResult:
    """Represents the accumulated scanning state of a target host."""
    target: str
    ip_address: str
    ports: list[PortResult] = field(default_factory=list)


@dataclass(frozen=True)
class ScanResult:
    """Represents the global metrics of a port scan execution run."""
    target: str
    resolved_ip: str
    total_ports: int
    hosts: list[HostResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
