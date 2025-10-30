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

from constants import CHAINGUARD_LOGO_PATH, DEFAULT_PLATFORM, GRADE_TO_CSS_CLASS
from core.models import ScanResult, ImageAnalysis

logger = logging.getLogger(__name__)


def _apply_template_variables(content: str, metrics: dict, customer_name: str) -> str:
    """
    Apply template variable substitution to content.

    Replaces {{variable_name}} placeholders with actual values.

    Args:
        content: Content string with template variables
        metrics: Dictionary containing metric values
        customer_name: Customer name for substitution

    Returns:
        Content with variables replaced
    """
    template_vars = {
        "customer_name": customer_name,
        "images_scanned": str(metrics["images_scanned"]),
        "total_customer_vulns": str(metrics["total_customer_vulns"]),
        "total_chainguard_vulns": str(metrics["total_chainguard_vulns"]),
        "reduction_percentage": f"{metrics['reduction_percentage']:.1f}%",
        "total_reduction": str(metrics["total_reduction"]),
        "images_with_reduction": str(metrics["images_with_reduction"]),
        "average_reduction_per_image": f"{metrics['average_reduction_per_image']:.1f}",
        # KEV-related variables (available when --with-kevs is used)
        "total_customer_kevs": str(metrics.get("total_customer_kevs", 0)),
        "total_chainguard_kevs": str(metrics.get("total_chainguard_kevs", 0)),
        "kev_reduction": str(metrics.get("kev_reduction", 0)),
        "images_with_customer_kevs": str(metrics.get("images_with_customer_kevs", 0)),
        "images_with_chainguard_kevs": str(
            metrics.get("images_with_chainguard_kevs", 0)
        ),
    }

    for key, value in template_vars.items():
        content = content.replace(f"{{{{{key}}}}}", value)

    return content


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
        config: "HTMLGeneratorConfig",
    ) -> None:
        """
        Generate vulnerability assessment summary report (HTML).

        Args:
            results: Scan results for image pairs
            output_path: Output file path
            config: HTML generator configuration
        """
        from core.exceptions import OutputException
        from outputs.config import HTMLGeneratorConfig

        # Validate config
        if not isinstance(config, HTMLGeneratorConfig):
            raise OutputException(
                "html", f"Expected HTMLGeneratorConfig, got {type(config).__name__}"
            )

        config.validate()

        logger.info(f"Generating vulnerability assessment summary: {output_path}")

        # Filter successful scans
        successful = [r for r in results if r.scan_successful]
        if not successful:
            raise OutputException("html", "No successful scan results to report")

        # Calculate metrics
        metrics = self._calculate_metrics(successful)

        # Load executive summary and appendix
        exec_summary = self._load_exec_summary(
            config.exec_summary_path, metrics, config.customer_name
        )
        appendix_content = self._load_appendix(
            config.appendix_path, metrics, config.customer_name
        )

        # Build image pairs for table
        image_pairs = []
        for result in successful:
            image_pairs.append(
                {
                    "customer": result.alternative_analysis,
                    "chainguard": result.chainguard_analysis,
                }
            )

        # Get CSS
        css_content = self._get_embedded_css()

        # Build HTML
        html_content = self._build_html_template(
            customer_name=config.customer_name,
            css_content=css_content,
            exec_summary=exec_summary,
            metrics=metrics,
            image_pairs=image_pairs,
            appendix_content=appendix_content,
            results=successful,
            platform=config.platform,
            kev_catalog=config.kev_catalog,
        )

        # Clean up chainguard image references
        html_content = re.sub(
            r"cgr\.dev/chainguard-private/([^<\s]+)", r"\1", html_content
        )
        html_content = re.sub(r"cgr\.dev/chainguard/([^<\s]+)", r"\1", html_content)
        html_content = re.sub(r"cgr\.dev/cg/([^<\s]+)", r"\1", html_content)

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

        # Count images with reduction (where Chainguard has fewer CVEs)
        images_with_reduction = sum(
            1
            for r in results
            if r.chainguard_analysis.vulnerabilities.total
            < r.alternative_analysis.vulnerabilities.total
        )

        # Calculate average reduction per image
        images_scanned = len(results)
        average_reduction_per_image = (
            total_reduction / images_scanned if images_scanned > 0 else 0.0
        )

        # Per-severity summary
        alternative_summary = {severity: 0 for severity in self.SEVERITY_ORDER}
        chainguard_summary = {severity: 0 for severity in self.SEVERITY_ORDER}

        for result in results:
            alternative = result.alternative_analysis
            chainguard = result.chainguard_analysis

            alternative_summary["Critical"] += alternative.vulnerabilities.critical
            alternative_summary["High"] += alternative.vulnerabilities.high
            alternative_summary["Medium"] += alternative.vulnerabilities.medium
            alternative_summary["Low"] += alternative.vulnerabilities.low
            alternative_summary["Negligible"] += alternative.vulnerabilities.negligible

            chainguard_summary["Critical"] += chainguard.vulnerabilities.critical
            chainguard_summary["High"] += chainguard.vulnerabilities.high
            chainguard_summary["Medium"] += chainguard.vulnerabilities.medium
            chainguard_summary["Low"] += chainguard.vulnerabilities.low
            chainguard_summary["Negligible"] += chainguard.vulnerabilities.negligible

        # KEV metrics (if available)
        total_customer_kevs = sum(
            getattr(r.alternative_analysis, "kev_count", 0) for r in results
        )
        total_chainguard_kevs = sum(
            getattr(r.chainguard_analysis, "kev_count", 0) for r in results
        )
        kev_reduction = total_customer_kevs - total_chainguard_kevs

        # Count images with KEVs
        images_with_customer_kevs = sum(
            1 for r in results if getattr(r.alternative_analysis, "kev_count", 0) > 0
        )
        images_with_chainguard_kevs = sum(
            1 for r in results if getattr(r.chainguard_analysis, "kev_count", 0) > 0
        )

        return {
            "total_customer_vulns": total_customer_vulns,
            "total_chainguard_vulns": total_cgr_vulns,
            "total_reduction": total_reduction,
            "reduction_percentage": round(reduction_percentage, 2),
            "images_scanned": images_scanned,
            "images_with_reduction": images_with_reduction,
            "average_reduction_per_image": round(average_reduction_per_image, 1),
            "alternative_summary": alternative_summary,
            "chainguard_summary": chainguard_summary,
            "total_customer_kevs": total_customer_kevs,
            "total_chainguard_kevs": total_chainguard_kevs,
            "kev_reduction": kev_reduction,
            "images_with_customer_kevs": images_with_customer_kevs,
            "images_with_chainguard_kevs": images_with_chainguard_kevs,
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
        platform: str = "linux/amd64",
        kev_catalog: Optional["KEVCatalog"] = None,
    ) -> str:
        """Build complete HTML document."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build document sections
        header_section = self._build_header_section(platform)
        exec_summary_section = self._build_exec_summary_section(exec_summary)
        cve_reduction_section = self._build_cve_reduction_section(metrics)
        images_scanned_section = self._build_images_scanned_section(image_pairs)
        chps_section = self._build_chps_section_if_needed(results)
        kev_section = self._build_kev_section_if_needed(results, kev_catalog)
        footer_section = self._build_footer_section(
            customer_name, timestamp, appendix_content
        )

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
{header_section}
{exec_summary_section}
{cve_reduction_section}
{images_scanned_section}
{chps_section}
{kev_section}
{footer_section}
    </div>
</body>
</html>"""

    def _build_header_section(self, platform: str) -> str:
        """Build the header section of the HTML document."""
        return f"""        <div class="header-section">
            <img class="header-logo" src="{CHAINGUARD_LOGO_PATH}" alt="Chainguard Logo">
            <h1>Vulnerability Comparison Report</h1>
            <p>A comprehensive analysis comparing vulnerabilities in your container images versus Chainguard's hardened alternatives. <em>(Platform: {platform})</em></p>
        </div>"""

    def _build_exec_summary_section(self, exec_summary: Optional[str]) -> str:
        """Build the executive summary section if content is provided."""
        if not exec_summary:
            return ""

        return f"""
        <!-- Executive Summary -->
        <div class="image-comparison-section no-break">
            <h2>Executive Summary</h2>
            {exec_summary}
        </div>"""

    def _build_cve_reduction_section(self, metrics: dict) -> str:
        """Build the CVE reduction analysis section."""
        return f"""
        <!-- CVE Reduction Metrics -->
        <div class="image-comparison-section no-break cve-reduction-section">
            <h2>CVE Reduction Analysis</h2>
            <div style="text-align: center; margin-bottom: 30px;">
                <div class="total-box reduction-box" style="display: block; margin: 0 auto 20px auto; width: 300px;">
                    {metrics["reduction_percentage"]}%
                    <span>CVE Reduction</span>
                </div>
                <p style="text-align: center; margin: 0; font-size: 16px; color: var(--cg-primary);"><strong>{self._format_number(metrics["total_reduction"])}</strong> fewer vulnerabilities with Chainguard images</p>
            </div>

            <!-- Overview Section within CVE Reduction Analysis -->
            <div class="overview-grid" style="margin-top: 40px;">
                <!-- Customer Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Your Images</h2>
                        <div class="total-box customer-total">
                            {self._format_number(metrics["total_customer_vulns"])}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_table(metrics["alternative_summary"])}
                    </div>
                </div>

                <!-- Chainguard Images Column -->
                <div class="summary-column">
                    <div class="summary-column-content">
                        <h2>Chainguard Images</h2>
                        <div class="total-box chainguard-total">
                            {self._format_number(metrics["total_chainguard_vulns"])}
                            <span>Total Vulnerabilities</span>
                        </div>
                        {self._generate_severity_table(metrics["chainguard_summary"])}
                    </div>
                </div>
            </div>
        </div>"""

    def _generate_fallback_note(
        self, has_fallback: bool, margin_top: str = "20px"
    ) -> str:
        """
        Generate fallback note HTML if needed.

        Args:
            has_fallback: Whether any images used fallback
            margin_top: CSS margin-top value for the note

        Returns:
            HTML string for fallback note, or empty string if not needed
        """
        if not has_fallback:
            return ""

        return (
            f'<p style="margin-top: {margin_top}; font-size: 12px; color: #6b7280;">'
            '<span style="color: #7545fb; font-weight: bold;">*</span> '
            "Image was not built in the last 30 days; <code>:latest</code> tag was used for comparison."
            "</p>"
        )

    def _build_images_scanned_section(self, image_pairs: list) -> str:
        """Build the images scanned comparison table section."""
        # Check if any Chainguard images used fallback
        has_fallback = any(
            pair["chainguard"].used_latest_fallback for pair in image_pairs
        )
        fallback_note = self._generate_fallback_note(has_fallback, margin_top="20px")

        return f"""
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
            {fallback_note}
        </div>"""

    def _build_chps_section_if_needed(self, results: list[ScanResult]) -> str:
        """Build CHPS section if any results have CHPS scores."""
        has_chps = any(
            (r.chainguard_analysis and r.chainguard_analysis.chps_score)
            or (r.alternative_analysis and r.alternative_analysis.chps_score)
            for r in results
        )

        if has_chps:
            logger.info("CHPS scores detected, adding CHPS section to HTML report")
            return self._generate_chps_section(results)

        return ""

    def _build_footer_section(
        self, customer_name: str, timestamp: str, appendix_content: Optional[str]
    ) -> str:
        """Build the footer section, optionally with appendix."""
        footer_text = f"This report is {customer_name} & Chainguard Confidential | Generated on {timestamp}"

        if appendix_content:
            return f"""
        <!-- Appendix Section -->
        <div class="appendix-content">
            <h2>Appendix</h2>
            {appendix_content}

            <!-- Footer integrated within appendix container -->
            <div class="footer">
                <p>{footer_text}</p>
            </div>
        </div>"""
        else:
            return f"""
        <!-- Footer -->
        <div class="footer">
            <p>{footer_text}</p>
        </div>"""

    def _generate_severity_table(self, summary: dict) -> str:
        """Generate HTML for severity summary table."""
        rows = []
        for severity in self.SEVERITY_ORDER:
            count = summary.get(severity, 0)
            severity_lower = severity.lower()
            rows.append(f"""                                <tr>
                                    <td><span class="severity-indicator {severity_lower}"></span>{severity}</td>
                                    <td class="severity-count">{self._format_number(count)}</td>
                                </tr>""")

        return f"""<table class="summary-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
{chr(10).join(rows)}
                            </tbody>
                        </table>"""

    def _generate_comparison_table_rows(self, image_pairs: list) -> str:
        """Generate HTML table rows for image comparisons."""
        rows = []
        for pair in image_pairs:
            customer = pair["customer"]
            chainguard = pair["chainguard"]

            # Format vulnerability breakdowns with badges
            customer_breakdown = self._format_vulnerability_breakdown(customer)
            chainguard_breakdown = self._format_vulnerability_breakdown(chainguard)

            # Add asterisk if Chainguard image used fallback to :latest
            chainguard_name = chainguard.name
            if chainguard.used_latest_fallback:
                chainguard_name += (
                    ' <span style="color: #7545fb; font-weight: bold;">*</span>'
                )

            rows.append(f"""
                <tr class="image-comparison-row">
                    <td class="image-name-cell">
                        <code class="image-name">{customer.name}</code>
                    </td>
                    <td class="vulnerability-count">{customer_breakdown}</td>
                    <td class="image-name-cell">
                        <code class="image-name">{chainguard_name}</code>
                    </td>
                    <td class="vulnerability-count">{chainguard_breakdown}</td>
                </tr>
            """)
        return "".join(rows)

    def _format_vulnerability_breakdown(self, analysis: ImageAnalysis) -> str:
        """Format vulnerability count with severity breakdown badges."""
        if analysis.vulnerabilities.total == 0:
            return '<div class="vuln-breakdown-container"><span class="vuln-badge vuln-clean">Clean</span></div>'

        # Create badges for each severity with count > 0
        badges = []
        if analysis.vulnerabilities.critical > 0:
            badges.append(
                f'<span class="vuln-badge vuln-critical">{self._format_number(analysis.vulnerabilities.critical)}</span>'
            )
        if analysis.vulnerabilities.high > 0:
            badges.append(
                f'<span class="vuln-badge vuln-high">{self._format_number(analysis.vulnerabilities.high)}</span>'
            )
        if analysis.vulnerabilities.medium > 0:
            badges.append(
                f'<span class="vuln-badge vuln-medium">{self._format_number(analysis.vulnerabilities.medium)}</span>'
            )
        if analysis.vulnerabilities.low > 0:
            badges.append(
                f'<span class="vuln-badge vuln-low">{self._format_number(analysis.vulnerabilities.low)}</span>'
            )
        if analysis.vulnerabilities.negligible > 0:
            badges.append(
                f'<span class="vuln-badge vuln-negligible">{self._format_number(analysis.vulnerabilities.negligible)}</span>'
            )

        # Add KEV badge if KEVs are present
        if hasattr(analysis, "kev_count") and analysis.kev_count > 0:
            badges.append(
                f'<span class="vuln-badge vuln-kev" title="{analysis.kev_count} Known Exploited Vulnerabilities">KEV:{analysis.kev_count}</span>'
            )

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
                    <div class="legend-item">
                        <span class="vuln-badge vuln-kev legend-badge">KEV</span>
                        <span class="legend-label">Known Exploited Vulnerability</span>
                    </div>
                </div>
            </div>
        """

    def _get_grade_badge_class(self, grade: str) -> str:
        """Get CSS class for CHPS grade badge."""
        grade_upper = grade.upper()
        return GRADE_TO_CSS_CLASS.get(grade_upper, "vuln-critical")

    def _format_chps_score_display(self, chps_score) -> str:
        """Format CHPS score for display with styled grade badge and component breakdown."""
        if not chps_score:
            return "N/A"

        # Get all score components from details
        scores = chps_score.details.get("scores", {})

        # Build component lines
        components = []
        component_order = ["minimalism", "provenance", "configuration"]
        component_labels = {
            "minimalism": "Minimalism",
            "provenance": "Provenance",
            "configuration": "Configuration",
        }

        for component in component_order:
            if component in scores:
                comp_data = scores[component]
                comp_grade = comp_data.get("grade", "F")
                # Fix E→F for components too
                if comp_grade == "E":
                    comp_grade = "F"
                grade_class = self._get_grade_badge_class(comp_grade)
                components.append(
                    f'<div style="width: 250px; display: flex; justify-content: space-between; align-items: center;">'
                    f"<span>{component_labels[component]}:</span>"
                    f'<span class="vuln-badge {grade_class}">{comp_grade}</span>'
                    f"</div>"
                )

        # Build the overall grade (larger)
        overall_grade_class = self._get_grade_badge_class(chps_score.grade)
        # Overall uses chps-overall-badge (not vuln-badge)
        overall_classes = f"chps-overall-badge {overall_grade_class}"
        overall = (
            f'<div style="width: 250px; display: flex; justify-content: space-between; align-items: center; margin-top: 8px;">'
            f"<strong>Overall:</strong>"
            f'<span class="{overall_classes}" style="font-size: 1.2em; padding: 4px 6px;">{chps_score.grade}</span>'
            f"</div>"
        )

        # Combine all components
        return "".join(components) + overall

    def _generate_chps_section(self, results: list[ScanResult]) -> str:
        """Generate CHPS scoring section."""
        rows = []
        has_fallback = False
        for result in results:
            alternative = result.alternative_analysis
            chainguard = result.chainguard_analysis

            # Format CHPS displays for both images
            alternative_score = (
                alternative.chps_score
                if alternative and alternative.chps_score
                else None
            )
            alternative_display = self._format_chps_score_display(alternative_score)

            chainguard_score = (
                chainguard.chps_score if chainguard and chainguard.chps_score else None
            )
            chainguard_display = self._format_chps_score_display(chainguard_score)

            # Add asterisk if Chainguard image used fallback to :latest
            chainguard_name = chainguard.name if chainguard else "N/A"
            if chainguard and chainguard.used_latest_fallback:
                chainguard_name += (
                    ' <span style="color: #7545fb; font-weight: bold;">*</span>'
                )
                has_fallback = True

            # Build single row with image pair
            rows.append(f"""
                <tr class="image-comparison-row">
                    <td class="image-name-cell">
                        <code class="image-name">{alternative.name if alternative else "N/A"}</code>
                    </td>
                    <td class="vulnerability-count">{alternative_display}</td>
                    <td class="image-name-cell">
                        <code class="image-name">{chainguard_name}</code>
                    </td>
                    <td class="vulnerability-count">{chainguard_display}</td>
                </tr>
            """)

        fallback_note = self._generate_fallback_note(has_fallback, margin_top="10px")

        return f"""
        <!-- CHPS Scoring Section -->
        <div class="images-scanned-section">
            <h2>CHPS Hardening & Provenance Scores</h2>
            <p>CHPS (Container Hardening and Provenance Scanner) evaluates container images for security hardening and provenance best practices. Grades range from A+ (best) to F (worst).</p>
            <div class="image-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Your Image</th>
                            <th>CHPS Grade</th>
                            <th>Chainguard Image <span style="font-size: 0.8em; font-weight: normal;">(cgr.dev)</span></th>
                            <th>CHPS Grade</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
            {fallback_note}
            <p><em>Note: CHPS scoring evaluates non-CVE security factors including provenance, SBOM quality, signing, and container hardening practices.</em></p>
        </div>
"""

    def _build_kev_section_if_needed(
        self, results: list[ScanResult], kev_catalog: Optional["KEVCatalog"]
    ) -> str:
        """Build KEV section if KEV catalog is provided (always shows table when --with-kevs is used)."""
        if not kev_catalog:
            return ""

        # Always generate the section when kev_catalog is provided (--with-kevs was used)
        logger.info("KEV checking enabled, adding KEV section to HTML report")
        return self._generate_kev_section(results, kev_catalog)

    def _generate_kev_section(
        self, results: list[ScanResult], kev_catalog: "KEVCatalog"
    ) -> str:
        """Generate KEV details section with table of all found KEVs."""
        rows = []

        for result in results:
            # Check alternative/customer image
            alt_analysis = result.alternative_analysis
            if alt_analysis and getattr(alt_analysis, "kev_cves", []):
                for cve_id in alt_analysis.kev_cves:
                    kev_entry = kev_catalog.get_kev_entry(cve_id)
                    if kev_entry:
                        cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
                        kev_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
                        rows.append(f"""
                <tr>
                    <td class="image-name-cell"><code class="image-name">{alt_analysis.name}</code></td>
                    <td><a href="{cve_url}" target="_blank" class="kev-link">{cve_id}</a></td>
                    <td><a href="{kev_url}" target="_blank" class="kev-link">{kev_entry.vulnerability_name}</a></td>
                    <td>{kev_entry.vendor}</td>
                    <td>{kev_entry.product}</td>
                    <td>{kev_entry.date_added}</td>
                </tr>
                        """)

            # Check Chainguard image
            cg_analysis = result.chainguard_analysis
            if cg_analysis and getattr(cg_analysis, "kev_cves", []):
                for cve_id in cg_analysis.kev_cves:
                    kev_entry = kev_catalog.get_kev_entry(cve_id)
                    if kev_entry:
                        cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
                        kev_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
                        rows.append(f"""
                <tr>
                    <td class="image-name-cell"><code class="image-name">{cg_analysis.name}</code></td>
                    <td><a href="{cve_url}" target="_blank" class="kev-link">{cve_id}</a></td>
                    <td><a href="{kev_url}" target="_blank" class="kev-link">{kev_entry.vulnerability_name}</a></td>
                    <td>{kev_entry.vendor}</td>
                    <td>{kev_entry.product}</td>
                    <td>{kev_entry.date_added}</td>
                </tr>
                        """)

        # If no KEVs found, show a positive message
        if not rows:
            table_body = """
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 20px; color: #059669; font-weight: 600;">
                                ✓ No Known Exploited Vulnerabilities found in scanned images
                            </td>
                        </tr>
"""
        else:
            table_body = "".join(rows)

        return f"""
        <!-- KEV Details Section -->
        <div class="images-scanned-section">
            <h2>Known Exploited Vulnerabilities (KEV)</h2>
            <p>The following CVEs are listed in CISA's Known Exploited Vulnerabilities catalog, indicating they are actively being exploited in the wild.</p>
            <div class="image-table-container kev-table">
                <table>
                    <thead>
                        <tr>
                            <th>Image</th>
                            <th>CVE ID</th>
                            <th>Vulnerability Name</th>
                            <th>Vendor</th>
                            <th>Product</th>
                            <th>Date Added to KEV</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_body}
                    </tbody>
                </table>
            </div>
            <p><em>Source: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA Known Exploited Vulnerabilities Catalog</a></em></p>
        </div>
"""

    def _load_exec_summary(
        self, path: Optional[Path], metrics: dict, customer_name: str
    ) -> Optional[str]:
        """Load and format executive summary with template variable substitution."""
        if not path or not path.exists():
            return None

        try:
            with open(path, "r") as f:
                content = f.read()

            # Apply template variables
            content = _apply_template_variables(content, metrics, customer_name)

            # Convert markdown to HTML
            html_content = markdown.markdown(content)
            return html_content

        except Exception as e:
            logger.warning(f"Could not load executive summary: {e}")
            return None

    def _load_appendix(
        self, path: Optional[Path], metrics: dict, customer_name: str
    ) -> Optional[str]:
        """Load and format appendix with template variable substitution."""
        if not path or not path.exists():
            return None

        try:
            with open(path, "r") as f:
                content = f.read()

            # Apply template variables
            content = _apply_template_variables(content, metrics, customer_name)

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
    margin-right: 2px;
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

.vuln-kev {
    background: #ffe5e5;
    color: #c41e3a;
    border-color: #ff6b6b;
    font-weight: bold;
}

/* KEV Table Styling */
.kev-table table {
    font-size: 0.9em;
}

.kev-table th {
    background: #c41e3a;
    color: white;
}

.kev-table tbody tr:hover {
    background: #fff9f9;
}

.kev-link {
    color: #c41e3a;
    text-decoration: underline;
    font-weight: 600;
}

.kev-link:hover {
    text-decoration: underline;
    color: #a01828;
}

.vuln-clean {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border-color: #10b981;
    font-weight: 700;
}

.chps-overall-badge {
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
