"""
HTML generator for vulnerability assessment summaries.

Generates professional HTML assessment summary reports optimized for PDF conversion.
These reports provide an executive overview of vulnerability findings, comparing
Chainguard images against alternatives, with executive summaries and appendixes.
"""

import logging
from pathlib import Path
from typing import Optional

from core.models import ScanResult
from outputs.base import OutputGenerator

logger = logging.getLogger(__name__)

# NOTE: This is a placeholder for the full HTML generator
# The actual implementation would be ported from cg_assessment/cve_scanner.py
# For now, we'll reference the existing implementation

class HTMLGenerator(OutputGenerator):
    """
    Vulnerability assessment summary generator (HTML format).

    Generates professional Chainguard-branded assessment summaries with:
    - Executive summary (from markdown file)
    - Vulnerability count comparisons
    - CVE reduction metrics
    - Side-by-side image analysis
    - Custom appendix support
    - PDF-optimized styling

    This generator focuses on presenting vulnerability findings and reduction
    metrics, not cost analysis. For ROI and cost calculations, use XLSXGenerator.
    """

    def supports_format(self) -> str:
        """Return format identifier."""
        return "html"

    def generate(
        self,
        results: list[ScanResult],
        output_path: Path,
        customer_name: str = "Customer",
        exec_summary_path: Optional[Path] = None,
        appendix_path: Optional[Path] = None,
        **kwargs,
    ) -> None:
        """
        Generate vulnerability assessment summary report (HTML).

        Args:
            results: Scan results for image pairs
            output_path: Output file path
            customer_name: Customer name for branding
            exec_summary_path: Path to markdown executive summary
            appendix_path: Path to custom appendix markdown
            **kwargs: Additional options
        """
        logger.info(f"Generating vulnerability assessment summary: {output_path}")

        # Filter successful scans
        successful = [r for r in results if r.scan_successful]
        if not successful:
            raise ValueError("No successful scan results to report")

        # Build HTML report
        html_content = self._build_html(
            successful,
            customer_name,
            exec_summary_path,
            appendix_path,
        )

        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Vulnerability assessment summary generated: {output_path}")

    def _build_html(
        self,
        results: list[ScanResult],
        customer_name: str,
        exec_summary_path: Optional[Path],
        appendix_path: Optional[Path],
    ) -> str:
        """Build complete HTML document."""

        # Calculate summary statistics
        total_customer_vulns = sum(
            r.alternative_analysis.vulnerabilities.total for r in results
        )
        total_cgr_vulns = sum(
            r.chainguard_analysis.vulnerabilities.total for r in results
        )
        reduction = total_customer_vulns - total_cgr_vulns
        reduction_pct = (reduction / total_customer_vulns * 100) if total_customer_vulns > 0 else 0

        # Calculate images with reduction
        images_with_reduction = sum(
            1 for r in results
            if r.alternative_analysis.vulnerabilities.total > r.chainguard_analysis.vulnerabilities.total
        )

        # Calculate average reduction per image
        average_reduction = reduction / len(results) if len(results) > 0 else 0

        # Template variables for exec summary and appendix
        template_vars = {
            "customer_name": customer_name,
            "images_scanned": str(len(results)),
            "total_customer_vulns": str(total_customer_vulns),
            "total_chainguard_vulns": str(total_cgr_vulns),
            "reduction_percentage": f"{reduction_pct:.1f}%",
            "images_with_reduction": str(images_with_reduction),
            "average_reduction_per_image": f"{average_reduction:.1f}",
        }

        # Build HTML sections
        html_parts = [
            self._html_header(),
            self._html_banner(),
        ]

        if exec_summary_path:
            html_parts.append(self._html_exec_summary(exec_summary_path, template_vars))

        html_parts.extend([
            self._html_reduction_summary(reduction, reduction_pct, len(results)),
            self._html_comparison_table(results),
        ])

        if appendix_path:
            html_parts.append(self._html_appendix(appendix_path, template_vars))

        html_parts.extend([
            self._html_methodology(),
            self._html_footer(customer_name),
            self._html_closing(),
        ])

        return "\n".join(html_parts)

    def _html_header(self) -> str:
        """Generate HTML header with styling."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chainguard Vulnerability Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #4285f4 0%, #0066cc 100%);
            color: white;
            padding: 30px;
            text-align: center;
            margin: -40px -40px 40px -40px;
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #4285f4; padding-bottom: 10px; }
        h3 { color: #333; margin-top: 20px; margin-bottom: 10px; }
        .summary {
            background: #e8f4f8;
            border-left: 4px solid #4285f4;
            padding: 20px;
            margin: 20px 0;
        }
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #0066cc;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background: #4285f4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #f0f7ff; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; font-weight: bold; }
        .severity-low { color: #388e3c; }
        .chainguard-row { background: #e8f5e9; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
<div class="container">"""

    def _html_banner(self) -> str:
        """Generate Chainguard banner."""
        return """
<div class="header">
    <h1>🔒 Container Vulnerability Assessment</h1>
    <p>Powered by Chainguard</p>
</div>"""

    def _html_exec_summary(self, path: Path, template_vars: dict[str, str]) -> str:
        """Load and format executive summary with template variable substitution."""
        try:
            with open(path, "r") as f:
                content = f.read()

            # Replace template variables ({{variable_name}})
            for key, value in template_vars.items():
                content = content.replace(f"{{{{{key}}}}}", value)

            return f"<div class='summary'>{content}</div>"
        except Exception as e:
            logger.warning(f"Could not load executive summary: {e}")
            return ""

    def _html_reduction_summary(self, reduction: int, reduction_pct: float, num_images: int) -> str:
        """Generate reduction summary section."""
        return f"""
<h2>Key Findings</h2>
<div class="summary">
    <p><span class="metric">{reduction_pct:.1f}%</span> reduction in vulnerabilities</p>
    <p>Across {num_images} container images, Chainguard alternatives eliminate <strong>{reduction} CVEs</strong></p>
</div>"""

    def _html_comparison_table(self, results: list[ScanResult]) -> str:
        """Generate comparison table."""
        rows = []
        for result in results:
            alt = result.alternative_analysis
            cgr = result.chainguard_analysis

            # Alternative image row
            rows.append(f"""
<tr>
    <td><strong>{alt.name}</strong></td>
    <td>{alt.size_mb:.0f} MB</td>
    <td>{alt.package_count}</td>
    <td>{alt.vulnerabilities.total}</td>
    <td class="severity-critical">{alt.vulnerabilities.critical}</td>
    <td class="severity-high">{alt.vulnerabilities.high}</td>
    <td class="severity-medium">{alt.vulnerabilities.medium}</td>
    <td class="severity-low">{alt.vulnerabilities.low}</td>
</tr>""")

            # Chainguard image row
            rows.append(f"""
<tr class="chainguard-row">
    <td><strong>{cgr.name}</strong> ✓</td>
    <td>{cgr.size_mb:.0f} MB</td>
    <td>{cgr.package_count}</td>
    <td>{cgr.vulnerabilities.total}</td>
    <td class="severity-critical">{cgr.vulnerabilities.critical}</td>
    <td class="severity-high">{cgr.vulnerabilities.high}</td>
    <td class="severity-medium">{cgr.vulnerabilities.medium}</td>
    <td class="severity-low">{cgr.vulnerabilities.low}</td>
</tr>""")

        return f"""
<h2>Detailed Comparison</h2>
<table>
    <thead>
        <tr>
            <th>Image</th>
            <th>Size</th>
            <th>Packages</th>
            <th>Total CVEs</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
    </thead>
    <tbody>
        {"".join(rows)}
    </tbody>
</table>"""

    def _html_appendix(self, path: Path, template_vars: dict[str, str]) -> str:
        """Load and format appendix with template variable substitution."""
        try:
            with open(path, "r") as f:
                content = f.read()

            # Replace template variables ({{variable_name}})
            for key, value in template_vars.items():
                content = content.replace(f"{{{{{key}}}}}", value)

            return f"<h2>Appendix</h2>{content}"
        except Exception as e:
            logger.warning(f"Could not load appendix: {e}")
            return ""

    def _html_methodology(self) -> str:
        """Generate methodology section."""
        return """
<h2>Methodology</h2>
<p>This assessment was conducted using industry-standard vulnerability scanning tools:</p>
<ul>
    <li><strong>Syft</strong>: Software Bill of Materials (SBOM) generation</li>
    <li><strong>Grype</strong>: Vulnerability detection and classification</li>
</ul>
<p>All images were scanned at the time of report generation. Vulnerability counts reflect known CVEs in the National Vulnerability Database (NVD).</p>"""

    def _html_footer(self, customer_name: str) -> str:
        """Generate footer."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""
<div class="footer">
    <p>This report is {customer_name} & Chainguard Confidential | Generated on {timestamp}</p>
    <p>Generated with <a href="https://claude.com/claude-code">Claude Code</a></p>
</div>"""

    def _html_closing(self) -> str:
        """Close HTML document."""
        return """
</div>
</body>
</html>"""
