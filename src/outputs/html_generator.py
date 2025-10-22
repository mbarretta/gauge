"""
HTML generator for vulnerability assessment summaries.

Generates professional HTML assessment summary reports optimized for PDF conversion.
These reports provide an executive overview of vulnerability findings, comparing
Chainguard images against alternatives, with executive summaries and appendixes.
"""

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import markdown

from core.models import ScanResult, ImageAnalysis

logger = logging.getLogger(__name__)

# Chainguard logo URL
CHAINGUARD_LOGO_URL = "resources/linky-white.png"

class HTMLGenerator:
    """
    Vulnerability assessment summary generator (HTML format).

    Generates professional Chainguard-branded assessment summaries matching
    the cg_assessment template with:
    - Executive summary (from markdown file)
    - CVE reduction metrics with large reduction percentage display
    - Side-by-side vulnerability count comparison
    - Images scanned table with vulnerability badges
    - CHPS scoring section (when available)
    - Custom appendix support
    - PDF-optimized styling
    """

    # Severity order for consistent display
    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible"]

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

        # Calculate metrics
        metrics = self._calculate_metrics(successful)

        # Load executive summary and appendix
        exec_summary = self._load_exec_summary(exec_summary_path, metrics, customer_name)
        appendix_content = self._load_appendix(appendix_path, metrics, customer_name)

        # Build image pairs for table
        image_pairs = []
        for result in successful:
            image_pairs.append({
                'customer': result.alternative_analysis,
                'chainguard': result.chainguard_analysis
            })

        # Get CSS
        css_content = self._get_embedded_css()

        # Build HTML
        html_content = self._build_html_template(
            customer_name=customer_name,
            css_content=css_content,
            exec_summary=exec_summary,
            metrics=metrics,
            image_pairs=image_pairs,
            appendix_content=appendix_content,
            results=successful,
        )

        # Clean up chainguard image references
        html_content = re.sub(r'cgr\.dev/chainguard-private/([^<\s]+)', r'\1', html_content)
        html_content = re.sub(r'cgr\.dev/chainguard/([^<\s]+)', r'\1', html_content)
        html_content = re.sub(r'cgr\.dev/cg/([^<\s]+)', r'\1', html_content)

        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Vulnerability assessment summary generated: {output_path}")

    def _calculate_metrics(self, results: list[ScanResult]) -> dict:
        """Calculate CVE reduction metrics."""
        total_customer_vulns = sum(
            r.alternative_analysis.vulnerabilities.total for r in results
        )
        total_cgr_vulns = sum(
            r.chainguard_analysis.vulnerabilities.total for r in results
        )
        total_reduction = total_customer_vulns - total_cgr_vulns

        reduction_percentage = 0.0
        if total_customer_vulns > 0:
            reduction_percentage = (total_reduction / total_customer_vulns) * 100

        # Per-severity summary
        customer_summary = {severity: 0 for severity in self.SEVERITY_ORDER}
        cgr_summary = {severity: 0 for severity in self.SEVERITY_ORDER}

        for result in results:
            alt = result.alternative_analysis
            cgr = result.chainguard_analysis

            customer_summary["Critical"] += alt.vulnerabilities.critical
            customer_summary["High"] += alt.vulnerabilities.high
            customer_summary["Medium"] += alt.vulnerabilities.medium
            customer_summary["Low"] += alt.vulnerabilities.low
            customer_summary["Negligible"] += alt.vulnerabilities.negligible

            cgr_summary["Critical"] += cgr.vulnerabilities.critical
            cgr_summary["High"] += cgr.vulnerabilities.high
            cgr_summary["Medium"] += cgr.vulnerabilities.medium
            cgr_summary["Low"] += cgr.vulnerabilities.low
            cgr_summary["Negligible"] += cgr.vulnerabilities.negligible

        return {
            'total_customer_vulns': total_customer_vulns,
            'total_chainguard_vulns': total_cgr_vulns,
            'total_reduction': total_reduction,
            'reduction_percentage': round(reduction_percentage, 2),
            'images_scanned': len(results),
            'customer_summary': customer_summary,
            'cgr_summary': cgr_summary,
        }

    def _format_number(self, num: int) -> str:
        """Format number with thousands separators."""
        return f"{num:,}"

    def _build_html_template(
        self,
        customer_name: str,
        css_content: str,
        exec_summary: Optional[str],
        metrics: dict,
        image_pairs: list,
        appendix_content: Optional[str],
        results: list[ScanResult],
    ) -> str:
        """Build complete HTML document."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check if we have CHPS scores
        has_chps = any(
            (r.chainguard_analysis and r.chainguard_analysis.chps_score) or
            (r.alternative_analysis and r.alternative_analysis.chps_score)
            for r in results
        )

        chps_section = ""
        if has_chps:
            logger.info("CHPS scores detected, adding CHPS section to HTML report")
            chps_section = self._generate_chps_section(results)

        # Build executive summary section if provided
        exec_summary_section = ""
        if exec_summary:
            exec_summary_section = f"""
        <!-- Executive Summary -->
        <div class="image-comparison-section no-break">
            <h2>Executive Summary</h2>
            {exec_summary}
        </div>"""

        # Build appendix section if provided
        appendix_section = ""
        if appendix_content:
            appendix_section = f"""
        <!-- Appendix Section -->
        <div class="appendix-content">
            <h2>Appendix</h2>
            {appendix_content}

            <!-- Footer integrated within appendix container -->
            <div class="footer">
                <p>This report is {customer_name} & Chainguard Confidential | Generated on {timestamp}</p>
            </div>
        </div>"""
        else:
            # If no appendix, add footer outside appendix container
            appendix_section = f"""
        <!-- Footer -->
        <div class="footer">
            <p>This report is {customer_name} & Chainguard Confidential | Generated on {timestamp}</p>
        </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Chainguard Vulnerability Report</title>
    <style>
{css_content}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-section">
            <img class="header-logo" src="{CHAINGUARD_LOGO_URL}" alt="Chainguard Logo">
            <h1>Vulnerability Comparison Report</h1>
            <p>A comprehensive analysis comparing vulnerabilities in your container images versus Chainguard's hardened alternatives.</p>
        </div>
{exec_summary_section}

        <!-- CVE Reduction Metrics -->
        <div class="image-comparison-section no-break cve-reduction-section">
            <h2>CVE Reduction Analysis</h2>
            <div style="text-align: center; margin-bottom: 30px;">
                <div class="total-box reduction-box" style="display: block; margin: 0 auto 20px auto; width: 300px;">
                    {metrics['reduction_percentage']}%
                    <span>CVE Reduction</span>
                </div>
                <p style="text-align: center; margin: 0; font-size: 16px; color: var(--cg-primary);"><strong>{self._format_number(metrics['total_reduction'])}</strong> fewer vulnerabilities with Chainguard images</p>
            </div>

            <!-- Overview Section within CVE Reduction Analysis -->
            <div class="overview-grid" style="margin-top: 40px;">
                <!-- Customer Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Your Images</h2>
                        <div class="total-box customer-total">
                            {self._format_number(metrics['total_customer_vulns'])}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_table(metrics['customer_summary'])}
                    </div>
                </div>

                <!-- Chainguard Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Chainguard Images</h2>
                        <div class="total-box chainguard-total">
                            {self._format_number(metrics['total_chainguard_vulns'])}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_table(metrics['cgr_summary'])}
                    </div>
                </div>
            </div>
        </div>

        <!-- Image Comparison Table -->
        <div class="images-scanned-section">
            <h2>Images Scanned</h2>
            {self._generate_vulnerability_legend()}
            <div class="image-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Your Image</th>
                            <th>Total Vulnerabilities</th>
                            <th>Chainguard Image <span style="font-size: 0.8em; font-weight: normal;">(cgr.dev)</span></th>
                            <th>Total Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_comparison_table_rows(image_pairs)}
                    </tbody>
                </table>
            </div>
        </div>

        {chps_section}
{appendix_section}
    </div>
</body>
</html>"""

    def _generate_severity_table(self, summary: dict) -> str:
        """Generate HTML for severity summary table."""
        rows = []
        for severity in self.SEVERITY_ORDER:
            count = summary.get(severity, 0)
            severity_lower = severity.lower()
            rows.append(f'''                                <tr>
                                    <td><span class="severity-indicator {severity_lower}"></span>{severity}</td>
                                    <td class="severity-count">{self._format_number(count)}</td>
                                </tr>''')

        return f'''<table class="summary-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
{chr(10).join(rows)}
                            </tbody>
                        </table>'''

    def _generate_comparison_table_rows(self, image_pairs: list) -> str:
        """Generate HTML table rows for image comparisons."""
        rows = []
        for pair in image_pairs:
            customer = pair['customer']
            chainguard = pair['chainguard']

            # Format vulnerability breakdowns with badges
            customer_breakdown = self._format_vulnerability_breakdown(customer)
            chainguard_breakdown = self._format_vulnerability_breakdown(chainguard)

            rows.append(f"""
                <tr class="image-comparison-row">
                    <td class="image-name-cell">
                        <code class="image-name">{customer.name}</code>
                    </td>
                    <td class="vulnerability-count">{customer_breakdown}</td>
                    <td class="image-name-cell">
                        <code class="image-name">{chainguard.name}</code>
                    </td>
                    <td class="vulnerability-count">{chainguard_breakdown}</td>
                </tr>
            """)
        return ''.join(rows)

    def _format_vulnerability_breakdown(self, analysis: ImageAnalysis) -> str:
        """Format vulnerability count with severity breakdown badges."""
        if analysis.vulnerabilities.total == 0:
            return '<div class="vuln-breakdown-container"><span class="vuln-badge vuln-clean">Clean</span></div>'

        # Create badges for each severity with count > 0
        badges = []
        if analysis.vulnerabilities.critical > 0:
            badges.append(f'<span class="vuln-badge vuln-critical">{self._format_number(analysis.vulnerabilities.critical)}</span>')
        if analysis.vulnerabilities.high > 0:
            badges.append(f'<span class="vuln-badge vuln-high">{self._format_number(analysis.vulnerabilities.high)}</span>')
        if analysis.vulnerabilities.medium > 0:
            badges.append(f'<span class="vuln-badge vuln-medium">{self._format_number(analysis.vulnerabilities.medium)}</span>')
        if analysis.vulnerabilities.low > 0:
            badges.append(f'<span class="vuln-badge vuln-low">{self._format_number(analysis.vulnerabilities.low)}</span>')
        if analysis.vulnerabilities.negligible > 0:
            badges.append(f'<span class="vuln-badge vuln-negligible">{self._format_number(analysis.vulnerabilities.negligible)}</span>')

        if not badges:
            return '<div class="vuln-breakdown-container"><span class="vuln-badge vuln-clean">Clean</span></div>'

        return f'<div class="vuln-breakdown-container">{"".join(badges)}</div>'

    def _generate_vulnerability_legend(self) -> str:
        """Generate HTML for vulnerability severity color legend."""
        return """
            <div class="vulnerability-legend">
                <h3>Vulnerability Severity Legend</h3>
                <div class="legend-items">
                    <div class="legend-item">
                        <span class="vuln-badge vuln-critical legend-badge">C</span>
                        <span class="legend-label">Critical</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-high legend-badge">H</span>
                        <span class="legend-label">High</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-medium legend-badge">M</span>
                        <span class="legend-label">Medium</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-low legend-badge">L</span>
                        <span class="legend-label">Low</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-negligible legend-badge">N</span>
                        <span class="legend-label">Negligible</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge vuln-clean legend-badge">Clean</span>
                        <span class="legend-label">No Vulnerabilities</span>
                    </div>
                </div>
            </div>
        """

    def _generate_chps_section(self, results: list[ScanResult]) -> str:
        """Generate CHPS scoring section."""
        rows = []
        for result in results:
            alt = result.alternative_analysis
            cgr = result.chainguard_analysis

            # Alternative image row
            alt_score = alt.chps_score if alt and alt.chps_score else None
            alt_display = f"{alt_score.score:.1f} ({alt_score.grade})" if alt_score else "N/A"

            # Chainguard image row
            cgr_score = cgr.chps_score if cgr and cgr.chps_score else None
            cgr_display = f"{cgr_score.score:.1f} ({cgr_score.grade})" if cgr_score else "N/A"

            # Calculate improvement
            improvement = ""
            if alt_score and cgr_score:
                score_diff = cgr_score.score - alt_score.score
                if score_diff > 0:
                    improvement = f'<span style="color: #28a745;">+{score_diff:.1f}</span>'
                elif score_diff < 0:
                    improvement = f'<span style="color: #dc3545;">{score_diff:.1f}</span>'
                else:
                    improvement = "—"

            rows.append(f"""
<tr>
    <td class="image-name-cell"><code class="image-name">{alt.name if alt else 'N/A'}</code></td>
    <td>{alt_display}</td>
    <td></td>
</tr>
<tr style="background-color: #e8f5e9;">
    <td class="image-name-cell"><code class="image-name">{cgr.name if cgr else 'N/A'}</code> ✓</td>
    <td>{cgr_display}</td>
    <td>{improvement}</td>
</tr>""")

        return f"""
        <!-- CHPS Scoring Section -->
        <div class="images-scanned-section">
            <h2>CHPS Hardening & Provenance Scores</h2>
            <p>CHPS (Container Hardening and Provenance Scanner) evaluates container images for security hardening and provenance best practices. Scores range from 0-100, with higher scores indicating better security posture.</p>
            <div class="image-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Image</th>
                            <th>CHPS Score (Grade)</th>
                            <th>Improvement</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
            <p><em>Note: CHPS scoring evaluates non-CVE security factors including provenance, SBOM quality, signing, and container hardening practices.</em></p>
        </div>
"""

    def _load_exec_summary(self, path: Optional[Path], metrics: dict, customer_name: str) -> Optional[str]:
        """Load and format executive summary with template variable substitution."""
        if not path or not path.exists():
            return None

        try:
            with open(path, "r") as f:
                content = f.read()

            # Replace template variables
            template_vars = {
                "customer_name": customer_name,
                "images_scanned": str(metrics['images_scanned']),
                "total_customer_vulns": str(metrics['total_customer_vulns']),
                "total_chainguard_vulns": str(metrics['total_chainguard_vulns']),
                "reduction_percentage": f"{metrics['reduction_percentage']:.1f}%",
                "total_reduction": str(metrics['total_reduction']),
            }

            for key, value in template_vars.items():
                content = content.replace(f"{{{{{key}}}}}", value)

            # Convert markdown to HTML
            html_content = markdown.markdown(content)
            return html_content

        except Exception as e:
            logger.warning(f"Could not load executive summary: {e}")
            return None

    def _load_appendix(self, path: Optional[Path], metrics: dict, customer_name: str) -> Optional[str]:
        """Load and format appendix with template variable substitution."""
        if not path or not path.exists():
            return None

        try:
            with open(path, "r") as f:
                content = f.read()

            # Replace template variables
            template_vars = {
                "customer_name": customer_name,
                "images_scanned": str(metrics['images_scanned']),
                "total_customer_vulns": str(metrics['total_customer_vulns']),
                "total_chainguard_vulns": str(metrics['total_chainguard_vulns']),
                "reduction_percentage": f"{metrics['reduction_percentage']:.1f}%",
                "total_reduction": str(metrics['total_reduction']),
            }

            for key, value in template_vars.items():
                content = content.replace(f"{{{{{key}}}}}", value)

            # Convert markdown to HTML
            html_content = markdown.markdown(content)
            return html_content

        except Exception as e:
            logger.warning(f"Could not load appendix: {e}")
            return None

    def _get_embedded_css(self) -> str:
        """Return embedded CSS content optimized for PDF conversion with Chainguard theme."""
        return """/* PDF-optimized styles with Chainguard branding */
@page {
    margin: 0.75in;
    size: A4;
}

@page appendix {
    margin: 0.75in 0.75in 0.75in 0.75in;
    size: A4;
    @top-center {
        content: "Appendix";
        font-size: 16px;
        font-weight: 600;
        color: #14003d;
        border-bottom: 2px solid #7545fb;
        padding-bottom: 8px;
        margin-bottom: 20px;
    }
}

@media print {
    body { -webkit-print-color-adjust: exact; color-adjust: exact; }
    .navbar { display: none; }
    .container { padding-top: 0; }

    /* Enhanced table page breaking for new structure */
    .image-table-container {
        page-break-inside: avoid;
        break-inside: avoid;
        box-shadow: 0 4px 8px rgba(20, 0, 61, 0.15);
    }

    .image-table-container table {
        page-break-inside: auto;
        border: 2px solid var(--cg-primary);
    }

    .image-table-container thead {
        display: table-header-group;
        page-break-after: avoid;
    }

    .image-table-container thead th {
        border-bottom: 3px solid var(--cg-primary);
    }

    .image-comparison-row {
        page-break-inside: avoid;
        break-inside: avoid;
        page-break-after: auto;
    }

    .image-table-container tbody td {
        page-break-inside: avoid;
        break-inside: avoid;
    }

    /* Enhanced badge visibility in PDF */
    .vuln-badge {
        border: 1px solid currentColor !important;
        box-shadow: none !important;
        font-size: 10px !important;
        padding: 1px 3px !important;
        min-width: 16px !important;
        line-height: 1 !important;
        flex-shrink: 0 !important;
    }

    .vuln-breakdown-container {
        gap: 1px !important;
        padding: 2px !important;
        flex-wrap: nowrap !important;
        white-space: nowrap !important;
    }

    /* Prevent orphaned text */
    p, li {
        orphans: 3;
        widows: 3;
    }

    /* Improve severity table for PDF */
    .summary-table {
        page-break-inside: avoid;
    }

    .severity-count {
        font-size: 12px;
        font-weight: 700;
    }

    .severity-indicator {
        width: 16px;
        height: 16px;
    }
}

/* Chainguard Brand Colors */
:root {
    --cg-primary: #14003d;        /* Deep purple - primary text/backgrounds */
    --cg-secondary: #3443f4;      /* Bright blue - secondary elements */
    --cg-accent: #7545fb;         /* Purple accent - highlights */
    --cg-success: #7af0fe;        /* Light cyan - success/positive */
    --cg-light: #d0cfee;          /* Light purple - subtle backgrounds */
    --cg-white: #ffffff;
    --cg-black: #000000;
    --cg-gray-light: #f8f9fc;
    --cg-gray-medium: #e5e7f0;
    --cg-gray-dark: #6b7280;
}

/* Base styles */
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: var(--cg-white);
    color: var(--cg-primary);
    margin: 0;
    padding: 24px;
    line-height: 1.6;
    font-size: 13px;
    font-weight: 400;
}

.container {
    max-width: 100%;
    margin: 0;
    padding: 0;
}

/* Typography */
h1 {
    color: var(--cg-white);
    font-size: 28px;
    font-weight: 700;
    margin: 0 0 8px 0;
    text-align: center;
    letter-spacing: -0.025em;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

h2 {
    color: var(--cg-primary);
    font-size: 20px;
    font-weight: 600;
    margin: 32px 0 20px 0;
    text-align: left;
    border-bottom: 3px solid var(--cg-accent);
    padding-bottom: 8px;
    letter-spacing: -0.015em;
}

h3 {
    color: var(--cg-primary);
    font-size: 16px;
    font-weight: 600;
    margin: 24px 0 12px 0;
    border-bottom: 1px solid var(--cg-light);
    padding-bottom: 6px;
}

p {
    margin: 12px 0;
    line-height: 1.7;
    color: var(--cg-primary);
}

/* Code styling */
code {
    background-color: var(--cg-gray-light);
    color: var(--cg-secondary);
    padding: 3px 6px;
    border: 1px solid var(--cg-light);
    border-radius: 4px;
    font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", "Courier New", monospace;
    font-size: 12px;
    font-weight: 500;
}

/* Layout sections */
.header-section {
    text-align: center;
    margin-bottom: 0;
    border-bottom: 4px solid var(--cg-accent);
    padding: 20px 32px 20px 32px;
    background: #14003d;
    border-radius: 12px;
    box-shadow: 0 8px 16px -2px rgba(20, 0, 61, 0.15);
    position: relative;
    color: var(--cg-white);
}

.header-logo {
    position: absolute;
    top: 20px;
    left: 20px;
    width: 60px;
    height: auto;
    max-height: 45px;
}

.header-section p {
    font-size: 14px;
    color: var(--cg-light);
    margin-top: 8px;
    font-weight: 400;
    opacity: 0.95;
}

.overview-grid {
    display: table;
    width: 100%;
    margin-bottom: 40px;
    border-spacing: 20px;
    table-layout: fixed;
}

.summary-column {
    display: table-cell;
    width: 50%;
    vertical-align: top;
    padding: 0;
}

.summary-column-content {
    background: var(--cg-white);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    min-height: 400px;
}

.summary-column h2 {
    text-align: center;
    font-size: 18px;
    margin-bottom: 24px;
    color: var(--cg-primary);
}

/* Total boxes with enhanced Chainguard styling */
.total-box {
    padding: 24px;
    border: 2px solid var(--cg-light);
    text-align: center;
    font-size: 36px;
    font-weight: 700;
    margin-bottom: 24px;
    background: var(--cg-white);
    border-radius: 8px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    flex-shrink: 0;
}

.total-box span {
    display: block;
    font-size: 13px;
    font-weight: 500;
    margin-top: 8px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.customer-total {
    background: linear-gradient(135deg, #f8f9fc 0%, #e5e7f0 100%);
    border-color: #d0cfee;
    color: #14003d;
}

.chainguard-total {
    background: linear-gradient(135deg, #7af0fe 0%, #a7f3d0 100%);
    border-color: #7af0fe;
    color: var(--cg-primary);
}

.reduction-box {
    background: linear-gradient(135deg, var(--cg-success) 0%, #a7f3d0 100%);
    border-color: #7af0fe;
    color: var(--cg-primary);
    font-size: 40px;
}

/* Summary table styling */
.summary-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    border-radius: 6px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(20, 0, 61, 0.08);
}

.summary-table th,
.summary-table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--cg-light);
    font-size: 13px;
}

.summary-table th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 11px;
}

.summary-table tbody tr:nth-child(even) {
    background-color: var(--cg-gray-light);
}

.severity-count {
    font-weight: 700;
    font-size: 14px;
    color: var(--cg-primary);
}

.severity-indicator {
    display: inline-block;
    width: 18px;
    height: 18px;
    border-radius: 3px;
    margin-right: 8px;
    vertical-align: middle;
}

/* Severity indicator colors with new color scheme */
.severity-indicator.critical {
    background: #f2e4f8;
    color: #82349d;
    border: 1px solid #c08ad5;
}
.severity-indicator.high {
    background: #fbe7e8;
    color: #98362e;
    border: 1px solid #ee7f78;
}
.severity-indicator.medium {
    background: #fcebcc;
    color: #a1531e;
    border: 1px solid #f3ad56;
}
.severity-indicator.low {
    background: #fefad3;
    color: #76651d;
    border: 1px solid #f7d959;
}
.severity-indicator.negligible {
    background: #e8ecef;
    color: #4d5b6a;
    border: 1px solid #b8c2ca;
}

/* Enhanced sections */
.image-comparison-section {
    margin-top: 40px;
    margin-bottom: 40px;
    padding: 20px;
    border: 2px solid var(--cg-light);
    background: var(--cg-white);
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    page-break-inside: avoid;
    page-break-before: avoid;
}

/* CVE Reduction section should start on new page */
.cve-reduction-section {
    page-break-before: always;
}

/* Images Scanned section - keep everything together */
.images-scanned-section {
    margin-top: 40px;
    margin-bottom: 40px;
    padding: 20px;
    border: 2px solid var(--cg-light);
    background: var(--cg-white);
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(20, 0, 61, 0.08);
    page-break-inside: avoid;
}

.images-scanned-section h2 {
    page-break-after: avoid;
}

.image-comparison-section h2 {
    margin-top: 0;
    color: var(--cg-primary);
    page-break-after: avoid;
}

/* Make first section directly adjacent to header */
.header-section + .image-comparison-section {
    margin-top: 0 !important;
    page-break-before: avoid !important;
    break-before: avoid !important;
}

/* Enhanced Professional table styling */
.image-table-container {
    width: 100%;
    overflow: visible;
    margin: 30px 0;
    page-break-inside: avoid;
    page-break-before: avoid;
    break-inside: avoid;
    border-radius: 12px;
    box-shadow: 0 8px 16px -4px rgba(20, 0, 61, 0.12);
    background: var(--cg-white);
}

.image-table-container table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    border-radius: 12px;
    overflow: hidden;
    table-layout: fixed;
    page-break-inside: auto;
    border: 2px solid var(--cg-light);
}

.image-table-container th,
.image-table-container td {
    padding: 16px 12px;
    border-bottom: 1px solid var(--cg-gray-medium);
    text-align: left;
    font-size: 12px;
    vertical-align: middle;
    word-wrap: break-word;
    overflow-wrap: break-word;
    page-break-inside: avoid;
    break-inside: avoid;
    line-height: 1.5;
}

.image-table-container thead th {
    background: var(--cg-primary);
    color: var(--cg-white);
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    page-break-after: avoid;
    border-bottom: 3px solid var(--cg-accent);
}

.image-table-container tbody tr {
    page-break-inside: avoid;
    break-inside: avoid;
    page-break-after: auto;
    transition: background-color 0.2s ease;
}

.image-table-container tbody tr:nth-child(even) {
    background-color: var(--cg-gray-light);
}

.image-table-container tbody tr:nth-child(odd) {
    background-color: var(--cg-white);
}

.image-table-container tbody tr:hover {
    background-color: rgba(116, 69, 251, 0.08);
}

/* Simplified table cell styling */
.image-name {
    font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", "Courier New", monospace;
    font-size: 11px;
    font-weight: 600;
    color: var(--cg-primary);
    background: rgba(255, 255, 255, 0.8);
    padding: 4px 8px;
    border-radius: 6px;
    border: 1px solid var(--cg-light);
}

.image-name-cell {
    width: 40%;
}

.vulnerability-count {
    font-weight: 700;
    font-size: 14px;
    color: var(--cg-primary);
    text-align: left;
}

/* Enhanced vulnerability breakdown styling for table cells */
.vuln-breakdown-container {
    display: flex;
    flex-wrap: wrap;
    gap: 2px;
    justify-content: flex-start;
    align-items: center;
    padding: 4px 2px;
    line-height: 1.2;
}

.vuln-badge {
    display: inline-flex;
    align-items: center;
    gap: 1px;
    padding: 3px 4px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    border: 1px solid;
    white-space: nowrap;
    min-width: 20px;
    justify-content: center;
    line-height: 1;
}

/* Severity-specific badge colors with new color scheme */
.vuln-critical {
    background: #f2e4f8;
    color: #82349d;
    border-color: #c08ad5;
}

.vuln-high {
    background: #fbe7e8;
    color: #98362e;
    border-color: #ee7f78;
}

.vuln-medium {
    background: #fcebcc;
    color: #a1531e;
    border-color: #f3ad56;
}

.vuln-low {
    background: #fefad3;
    color: #76651d;
    border-color: #f7d959;
}

.vuln-negligible {
    background: #e8ecef;
    color: #4d5b6a;
    border-color: #b8c2ca;
}

.vuln-clean {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border-color: #10b981;
    font-weight: 700;
}

/* Vulnerability legend styling */
.vulnerability-legend {
    margin: 20px 0 30px 0;
    padding: 16px 20px;
    background: var(--cg-gray-light);
    border: 2px solid var(--cg-light);
    border-radius: 8px;
    page-break-inside: avoid;
    page-break-after: avoid;
}

.vulnerability-legend h3 {
    margin: 0 0 12px 0;
    font-size: 14px;
    font-weight: 600;
    color: var(--cg-primary);
    border: none;
    padding: 0;
    text-align: left;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    justify-content: flex-start;
    align-items: center;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
}

.legend-badge {
    transform: scale(1.1);
}

.legend-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--cg-primary);
}

@media print {
    .vulnerability-legend {
        page-break-inside: avoid;
        page-break-after: avoid;
        break-inside: avoid;
        break-after: avoid;
        margin: 15px 0 20px 0;
        padding: 12px 16px;
    }

    .legend-items {
        gap: 12px;
    }

    .legend-item {
        gap: 4px;
    }

    .legend-badge {
        transform: scale(1.0);
    }

    .legend-label {
        font-size: 11px;
    }
}

/* Enhanced Appendix with better page break handling */
.appendix-content {
    text-align: left;
    padding: 24px;
    background: var(--cg-gray-light);
    border-radius: 8px;
    border: 2px solid var(--cg-light);
    page-break-before: always;
}

.appendix-content h2 {
    page-break-after: avoid;
    margin-top: 0 !important;
    margin-bottom: 20px;
}

.appendix-content h3 {
    font-size: 16px;
    margin-top: 28px;
    color: var(--cg-primary);
    border-bottom-color: var(--cg-accent);
    page-break-after: avoid;
    page-break-before: auto;
}

.appendix-content ul {
    margin: 16px 0;
    padding-left: 24px;
    page-break-inside: auto;
}

.appendix-content li {
    margin-bottom: 8px;
    line-height: 1.6;
    font-size: 12px;
    color: var(--cg-primary);
    page-break-inside: avoid;
}

.appendix-content p {
    orphans: 2;
    widows: 2;
    page-break-inside: auto;
}

.appendix-content strong {
    color: var(--cg-accent);
    font-weight: 600;
}

/* Appendix section grouping for better page breaks */
.appendix-section {
    page-break-inside: avoid;
    margin-bottom: 32px;
}

.appendix-section:last-child {
    margin-bottom: 0;
}

@media print {
    .appendix-content {
        page-break-before: always;
        break-before: always;
        background: transparent;
        border: none;
        border-radius: 0;
        box-shadow: none;
        page: appendix;
        page-break-inside: auto;
        break-inside: auto;
    }

    .appendix-content h3 {
        page-break-after: avoid;
        break-after: avoid;
        page-break-before: auto;
        break-before: auto;
    }

    .appendix-content ul {
        page-break-inside: auto;
        break-inside: auto;
    }

    .appendix-content li {
        page-break-inside: avoid;
        break-inside: avoid;
        orphans: 2;
        widows: 2;
    }

    .appendix-content p {
        orphans: 2;
        widows: 2;
        page-break-inside: auto;
        break-inside: auto;
    }

    .appendix-section {
        page-break-inside: avoid;
        break-inside: avoid;
    }

    /* Strategic page break with continuation header */
    .appendix-page-break {
        page-break-before: always;
        break-before: always;
        margin-top: 0;
        padding-top: 0;
    }

    .appendix-continuation {
        color: var(--cg-primary);
        font-size: 20px;
        font-weight: 600;
        margin: 0 0 20px 0 !important;
        text-align: left;
        border-bottom: 3px solid var(--cg-accent);
        padding-bottom: 8px;
        letter-spacing: -0.015em;
        page-break-after: avoid;
    }

    /* Chrome PDF export specific footer behavior - now inside appendix */
    .appendix-content .footer {
        page-break-before: avoid;
        break-before: avoid;
        page-break-inside: avoid;
        break-inside: avoid;
        margin-top: 30px;
        border-radius: 8px;
        background: var(--cg-white);
        border: 2px solid var(--cg-light);
    }
}

/* Professional Footer */
.footer {
    text-align: center;
    margin-top: 40px;
    padding: 20px;
    font-size: 11px;
    color: var(--cg-gray-dark);
    border-top: 2px solid var(--cg-light);
    background: var(--cg-gray-light);
    border-radius: 0 0 8px 8px;
    font-weight: 500;
    page-break-before: avoid;
    page-break-inside: avoid;
}

/* Utility classes */
.no-break {
    page-break-inside: avoid;
}

/* Additional professional touches */
strong {
    color: var(--cg-primary);
    font-weight: 600;
}

em {
    color: var(--cg-accent);
    font-style: normal;
    font-weight: 500;
}
"""
