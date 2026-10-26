"""
ProtocolRegistry coordinating dynamic registrations of fingerprinters.
"""

from typing import Any, Optional


class ProtocolRegistry:
    """
    Manages registered protocol fingerprint modules.
    Matches modules based on port numbers, banner keywords, and priority constraints.
    """

    def __init__(self) -> None:
        # Holds registered protocols configuration maps
        self._entries: list[dict[str, Any]] = []

    def register(
        self, ports: Optional[list[int]] = None, keywords: Optional[list[str]] = None, priority: int = 10
    ) -> Any:
        """
        Decorator registering a fingerprinter class.
        """

        def decorator(cls: type[Any]) -> type[Any]:
            self._entries.append(
                {
                    "class": cls,
                    "ports": ports or [],
                    "keywords": [kw.lower() for kw in (keywords or [])],
                    "priority": priority,
                }
            )
            return cls

        return decorator

    def get_candidates(self, port: int, banner: str) -> list[type[Any]]:
        """
        Retrieves matching protocol classes sorted by priority.
        Matches if port is listed or banner contains registered keywords.
        """
        candidates = []
        lower_banner = banner.strip().lower()

        for entry in self._entries:
            port_matches = port in entry["ports"]
            keyword_matches = False

            if lower_banner and entry["keywords"]:
                keyword_matches = any(kw in lower_banner for kw in entry["keywords"])

            if port_matches or keyword_matches:
                # Add check priority parameters
                # If matched by banner keyword, elevate priority
                weight = entry["priority"]
                if keyword_matches:
                    weight += 100  # Stronger correlation
                candidates.append((entry["class"], weight))

        # Sort candidates by weight descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        return [c[0] for c in candidates]


# Global protocol registry instance
registry = ProtocolRegistry()
