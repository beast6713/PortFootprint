"""
HtmlReportExporter generating premium, interactive single-file HTML reports.
"""

import html
import json
import logging

from portfootprint.core.models import ScanResult
from portfootprint.core.statistics import ScanStatistics
from portfootprint.reports.base import BaseReportExporter
from portfootprint.reports.registry import export_registry

logger = logging.getLogger("portfootprint.reports.html")


@export_registry.register("html")
class HtmlReportExporter(BaseReportExporter):
    """
    HTML Exporter.
    Outputs interactive dashboard reports with search filters and collapsible details.
    """

    def export(self, scan_result: ScanResult, output_path: str) -> None:
        stats = ScanStatistics.calculate(scan_result)

        # Build list of ports details
        ports_html_rows = []
        for host in scan_result.hosts:
            for port in host.ports:
                state_upper = port.state.upper()
                state_badge_cls = f"badge-{state_upper.lower()}"

                srv_name = "Unknown"
                srv_proto = "tcp"
                srv_ver = ""
                srv_banner = ""
                details_json = "{}"

                if port.service:
                    s = port.service
                    srv_name = s.service_name
                    srv_proto = s.protocol
                    srv_ver = s.version
                    srv_banner = s.banner

                    # Convert full service details to stringified json for collapsible div
                    details_dict = {
                        "banner": s.banner,
                        "headers": s.headers,
                        "certificate": s.certificate,
                        "title": s.title,
                        "extra_details": s.extra_details,
                    }
                    details_json = html.escape(json.dumps(details_dict, indent=2))

                row_id = f"port-row-{port.port}"

                # Check if expandable
                expand_btn = ""
                if port.service:
                    expand_btn = f'<button class="btn-expand" onclick="toggleDetails(\'{row_id}-details\')">View Details</button>'

                ports_html_rows.append(f"""
                <tr id="{row_id}" class="port-row" data-state="{state_upper.lower()}" data-port="{port.port}" data-service="{html.escape(srv_name.lower())}">
                    <td>{port.port}/{srv_proto}</td>
                    <td><span class="badge {state_badge_cls}">{state_upper}</span></td>
                    <td><strong>{html.escape(srv_name)}</strong></td>
                    <td>{html.escape(srv_ver)}</td>
                    <td class="banner-cell">{html.escape(srv_banner)}</td>
                    <td>{expand_btn}</td>
                </tr>
                """)

                if port.service:
                    ports_html_rows.append(f"""
                    <tr id="{row_id}-details" class="details-row" style="display: none;">
                        <td colspan="6">
                            <div class="details-container">
                                <h4>Service Discovery Details</h4>
                                <pre><code>{details_json}</code></pre>
                            </div>
                        </td>
                    </tr>
                    """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PortFootprint Scan Report - {html.escape(scan_result.target)}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
        }}

        @media (prefers-color-scheme: light) {{
            :root {{
                --bg-color: #f8fafc;
                --card-bg: #ffffff;
                --text-color: #0f172a;
                --text-muted: #64748b;
                --border-color: #e2e8f0;
                --primary: #2563eb;
            }}
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}

        header {{
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
        }}

        h1 {{ margin: 0; font-size: 2.25rem; font-weight: 800; }}
        .subtitle {{ color: var(--text-muted); font-size: 1.1rem; margin: 0.5rem 0 0 0; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }}

        .card-title {{ font-size: 0.875rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0; }}
        .card-value {{ font-size: 2rem; font-weight: 700; margin: 0.5rem 0 0 0; }}

        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
            align-items: center;
        }}

        .search-input {{
            flex: 1;
            min-width: 250px;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            padding: 0.5rem 1rem;
            color: var(--text-color);
            font-size: 1rem;
        }}

        .btn-filter {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            cursor: pointer;
            font-weight: 500;
        }}

        .btn-filter.active {{
            background-color: var(--primary);
            border-color: var(--primary);
            color: #ffffff;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            overflow: hidden;
        }}

        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background-color: rgba(0,0,0,0.05);
            font-weight: 600;
            color: var(--text-muted);
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 700;
        }}

        .badge-open {{ background-color: rgba(16, 185, 129, 0.15); color: var(--success); }}
        .badge-closed {{ background-color: rgba(239, 68, 68, 0.15); color: var(--danger); }}
        .badge-filtered {{ background-color: rgba(245, 158, 11, 0.15); color: var(--warning); }}

        .btn-expand {{
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--primary);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.875rem;
        }}

        .details-container {{
            background-color: rgba(0,0,0,0.1);
            padding: 1.5rem;
            border-radius: 0.375rem;
            margin: 0.5rem 0;
            border-left: 4px solid var(--primary);
        }}

        .details-container h4 {{ margin: 0 0 1rem 0; }}

        pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            border-radius: 0.25rem;
        }}

        .banner-cell {{
            font-family: monospace;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        @media print {{
            body {{ background: white; color: black; padding: 0; }}
            .card, table {{ box-shadow: none; border: 1px solid #ddd; }}
            .filter-bar {{ display: none; }}
            .btn-expand {{ display: none; }}
        }}
    </style>
</head>
<body>

<header>
    <h1>PortFootprint Security Scan</h1>
    <p class="subtitle">Target: <strong>{html.escape(scan_result.target)}</strong> ({html.escape(scan_result.resolved_ip)}) | Duration: {scan_result.duration:.2f} seconds</p>
</header>

<div class="stats-grid">
    <div class="card">
        <p class="card-title">Total Ports</p>
        <p class="card-value">{stats.total_ports}</p>
    </div>
    <div class="card" style="border-top: 4px solid var(--success);">
        <p class="card-title">Open</p>
        <p class="card-value">{stats.open_count}</p>
    </div>
    <div class="card" style="border-top: 4px solid var(--warning);">
        <p class="card-title">Filtered</p>
        <p class="card-value">{stats.filtered_count}</p>
    </div>
    <div class="card" style="border-top: 4px solid var(--danger);">
        <p class="card-title">Closed</p>
        <p class="card-value">{stats.closed_count}</p>
    </div>
    <div class="card">
        <p class="card-title">Services Detected</p>
        <p class="card-value">{stats.services_detected}</p>
    </div>
    <div class="card">
        <p class="card-title">Scan Speed</p>
        <p class="card-value" style="font-size: 1.5rem;">{stats.scan_speed:.1f} p/s</p>
    </div>
</div>

<div class="filter-bar">
    <input type="text" id="searchInput" class="search-input" placeholder="Search port or service name..." onkeyup="filterPorts()">
    <button class="btn-filter active" onclick="setStatusFilter('all', this)">All</button>
    <button class="btn-filter" onclick="setStatusFilter('open', this)">Open</button>
    <button class="btn-filter" onclick="setStatusFilter('filtered', this)">Filtered</button>
    <button class="btn-filter" onclick="setStatusFilter('closed', this)">Closed</button>
</div>

<table>
    <thead>
        <tr>
            <th>Port/Protocol</th>
            <th>State</th>
            <th>Service Name</th>
            <th>Version</th>
            <th>Service Banner</th>
            <th>Action</th>
        </tr>
    </thead>
    <tbody id="portsTableBody">
        {"".join(ports_html_rows)}
    </tbody>
</table>

<script>
    let activeFilter = 'all';

    function setStatusFilter(filter, element) {{
        activeFilter = filter;
        document.querySelectorAll('.btn-filter').forEach(btn => btn.classList.remove('active'));
        element.classList.add('active');
        filterPorts();
    }}

    function filterPorts() {{
        const searchVal = document.getElementById('searchInput').value.toLowerCase().trim();
        const rows = document.querySelectorAll('.port-row');

        rows.forEach(row => {{
            const detailsRow = document.getElementById(row.id + '-details');
            const state = row.getAttribute('data-state');
            const port = row.getAttribute('data-port');
            const service = row.getAttribute('data-service');

            const matchFilter = (activeFilter === 'all' || state === activeFilter);
            const matchSearch = (port.includes(searchVal) || service.includes(searchVal));

            if (matchFilter && matchSearch) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
                if (detailsRow) detailsRow.style.display = 'none';
            }}
        }});
    }}

    function toggleDetails(id) {{
        const row = document.getElementById(id);
        if (row) {{
            row.style.display = row.style.display === 'none' ? '' : 'none';
        }}
    }}
</script>

</body>
</html>
"""

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_template)
            logger.info(f"HTML report successfully exported to '{output_path}'.")
        except OSError as e:
            logger.exception(f"Failed to write HTML report to '{output_path}': {e!s}")
            raise
