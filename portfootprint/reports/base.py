"""
BaseReportExporter interface defining reporting exporter contract.
"""

from abc import ABC, abstractmethod

from portfootprint.core.models import ScanResult


class BaseReportExporter(ABC):
    """
    Abstract interface for all report format exporters.
    All format specific exporters must inherit from this class.
    """
    @abstractmethod
    def export(self, scan_result: ScanResult, output_path: str) -> None:
        """
        Exports ScanResult content to the specified file output path.
        Must handle file IO errors and raise appropriate exceptions.
        """
        pass
