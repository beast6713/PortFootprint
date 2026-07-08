"""
Registers all report format exporters inside the global ExportRegistry.
"""

from portfootprint.reports.csv_report import CsvReportExporter
from portfootprint.reports.html_report import HtmlReportExporter
from portfootprint.reports.json_report import JsonReportExporter
from portfootprint.reports.registry import export_registry
from portfootprint.reports.report_manager import ReportManager

__all__ = [
    "CsvReportExporter",
    "HtmlReportExporter",
    "JsonReportExporter",
    "ReportManager",
    "export_registry"
]
