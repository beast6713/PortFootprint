"""
ExportRegistry coordinating format registrations of different exporters.
"""

from typing import Any

from portfootprint.reports.base import BaseReportExporter


class ExportRegistry:
    """
    Registry for dynamic report format exporters.
    Allows format exporters to self-register.
    """

    def __init__(self) -> None:
        self._exporters: dict[str, type[BaseReportExporter]] = {}

    def register(self, format_name: str) -> Any:
        """
        Decorator registering an exporter class under specified format name.
        """

        def decorator(cls: type[BaseReportExporter]) -> type[BaseReportExporter]:
            self._exporters[format_name.lower()] = cls
            return cls

        return decorator

    def get_exporter(self, format_name: str) -> type[BaseReportExporter]:
        """
        Retrieves the registered exporter class for the format name.
        Raises KeyError if the format is unregistered.
        """
        fmt = format_name.lower().strip()
        if fmt not in self._exporters:
            raise KeyError(f"No exporter registered for format: '{format_name}'")
        return self._exporters[fmt]

    def list_formats(self) -> list[str]:
        """Returns all registered format identifiers."""
        return list(self._exporters.keys())


# Global report exporters registry
export_registry = ExportRegistry()
