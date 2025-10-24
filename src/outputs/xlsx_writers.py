"""
Specialized XLSX section writers.

Provides modular section writers for different parts of the vulnerability
cost analysis report, following single-responsibility principle.
"""

import xlsxwriter
from typing import Optional

from xlsxwriter.utility import xl_rowcol_to_cell

from constants import DEFAULT_PLATFORM
from core.models import ImageAnalysis, ScanResult, CHPSScore
from outputs.xlsx_formats import OutputFormatter
from utils.cve_ratios import get_cve_monthly_ratios
from utils.fips_calculator import FIPSCalculator


class BaseSectionWriter:
    """Base class for XLSX section writers."""

    def __init__(
        self,
        worksheet: xlsxwriter.worksheet.Worksheet,
        formatter: OutputFormatter,
        row: int,
        col: int = 0,
    ):
        """
        Initialize section writer.

        Args:
            worksheet: XlsxWriter worksheet
            formatter: Format provider
            row: Starting row number
            col: Starting column number (default: 0)
        """
        self.worksheet = worksheet
        self.formatter = formatter
        self.row = row
        self.col = col

    def get_current_row(self) -> int:
        """Get the current row position."""
        return self.row


class ImageComparisonWriter(BaseSectionWriter):
    """Writes image comparison section with vulnerability counts."""

    def write(
        self,
        alternative_analyses: list[ImageAnalysis],
        chainguard_analyses: list[ImageAnalysis],
        platform: str = DEFAULT_PLATFORM,
    ) -> tuple[dict, dict, int]:
        """
        Write image comparison section.

        Args:
            alternative_analyses: Alternative image analyses
            chainguard_analyses: Chainguard image analyses
            platform: Platform architecture string

        Returns:
            Tuple of (alternative_cells, chainguard_cells, final_row)
        """
        # Platform info row
        self.worksheet.write(
            self.row, self.col, f"Platform: {platform}", self.formatter.get("body_lightgrey")
        )
        self.row += 2  # Skip a row for spacing

        # Header
        header = [
            "Image",
            "Size (MB)",
            "Packages",
            "CVEs",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Negligible/Unknown",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_blue")
        )
        self.row += 1

        # Alternative images
        alternative_cells = self._write_image_data(alternative_analyses, "body_white")

        # Chainguard images
        chainguard_cells = self._write_image_data(chainguard_analyses, "body_green")

        # Roll-up metrics section
        self._write_rollup_section(alternative_cells, chainguard_cells, len(alternative_analyses))

        return alternative_cells, chainguard_cells, self.row

    def _write_image_data(self, analyses: list[ImageAnalysis], format_key: str) -> dict:
        """
        Write image data rows and return cell references.

        Args:
            analyses: List of image analyses
            format_key: Format name to use

        Returns:
            Dictionary with start and end cell references
        """
        start_cells = {
            "size": xl_rowcol_to_cell(self.row, self.col + 1),
            "packages": xl_rowcol_to_cell(self.row, self.col + 2),
            "cves": xl_rowcol_to_cell(self.row, self.col + 3),
            "critical": xl_rowcol_to_cell(self.row, self.col + 4),
            "high": xl_rowcol_to_cell(self.row, self.col + 5),
            "medium": xl_rowcol_to_cell(self.row, self.col + 6),
            "low": xl_rowcol_to_cell(self.row, self.col + 7),
            "negligible": xl_rowcol_to_cell(self.row, self.col + 8),
        }

        for analysis in analyses:
            vuln = analysis.vulnerabilities

            # Image name
            self.worksheet.write(
                self.row, self.col, analysis.name, self.formatter.get(format_key)
            )

            # Size and packages
            self.worksheet.write(
                self.row, self.col + 1, int(analysis.size_mb), self.formatter.get(format_key)
            )
            self.worksheet.write(
                self.row, self.col + 2, analysis.package_count, self.formatter.get(format_key)
            )

            # CVE formula (sum of severities)
            critical_cell = xl_rowcol_to_cell(self.row, self.col + 4)
            high_cell = xl_rowcol_to_cell(self.row, self.col + 5)
            medium_cell = xl_rowcol_to_cell(self.row, self.col + 6)
            low_cell = xl_rowcol_to_cell(self.row, self.col + 7)
            negligible_cell = xl_rowcol_to_cell(self.row, self.col + 8)

            cves_formula = f"={critical_cell}+{high_cell}+{medium_cell}+{low_cell}+{negligible_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 3, cves_formula, self.formatter.get(format_key)
            )

            # Severity counts
            self.worksheet.write(
                self.row, self.col + 4, vuln.critical, self.formatter.get(format_key)
            )
            self.worksheet.write(
                self.row, self.col + 5, vuln.high, self.formatter.get(format_key)
            )
            self.worksheet.write(
                self.row, self.col + 6, vuln.medium, self.formatter.get(format_key)
            )
            self.worksheet.write(
                self.row, self.col + 7, vuln.low, self.formatter.get(format_key)
            )
            self.worksheet.write(
                self.row, self.col + 8, vuln.negligible, self.formatter.get(format_key)
            )

            self.row += 1

        end_cells = {
            "size": xl_rowcol_to_cell(self.row - 1, self.col + 1),
            "packages": xl_rowcol_to_cell(self.row - 1, self.col + 2),
            "cves": xl_rowcol_to_cell(self.row - 1, self.col + 3),
            "critical": xl_rowcol_to_cell(self.row - 1, self.col + 4),
            "high": xl_rowcol_to_cell(self.row - 1, self.col + 5),
            "medium": xl_rowcol_to_cell(self.row - 1, self.col + 6),
            "low": xl_rowcol_to_cell(self.row - 1, self.col + 7),
            "negligible": xl_rowcol_to_cell(self.row - 1, self.col + 8),
        }

        return {"start": start_cells, "end": end_cells}

    def _write_rollup_section(self, alt_cells: dict, cgr_cells: dict, num_images: int):
        """
        Write roll-up metrics section with summary statistics.

        Args:
            alt_cells: Cell references for alternative images
            cgr_cells: Cell references for Chainguard images
            num_images: Number of images in the comparison
        """
        # Define metrics that will be summarized
        all_metrics = ["size", "packages", "cves", "critical", "high", "medium", "low", "negligible"]
        reduction_metrics = ["size", "packages", "cves"]
        num_columns = len(all_metrics) + 1  # +1 for label column

        self.row += 1

        # Section header
        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + num_columns - 1,
            "Roll-up metrics",
            self.formatter.get("header_lightgrey")
        )
        self.row += 1

        # Column headers
        header = [
            f"Images (set of {num_images} images)",
            "Total Size (MB)",
            "Total Packages",
            "Total CVEs",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Negligible/Unknown",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_blue")
        )
        self.row += 1

        # Row 1: Alternative images summary
        alt_total_cells = self._write_summary_row(
            f"Current set of {num_images} images used",
            alt_cells,
            all_metrics,
            "body_white"
        )

        # Row 2: Chainguard images summary
        cgr_total_cells = self._write_summary_row(
            "Chainguard equivalent set of images",
            cgr_cells,
            all_metrics,
            "body_green"
        )

        # Row 3: Reduction percentage
        self._write_reduction_row(alt_total_cells, cgr_total_cells, reduction_metrics)

    def _write_summary_row(
        self, label: str, cells: dict, metrics: list[str], format_key: str
    ) -> dict[str, str]:
        """
        Write a summary row with SUM formulas for each metric.

        Args:
            label: Row label text
            cells: Cell references with 'start' and 'end' keys
            metrics: List of metric names to sum
            format_key: Format name to use

        Returns:
            Dictionary mapping metric names to their total cell references
        """
        self.worksheet.write(self.row, self.col, label, self.formatter.get(format_key))

        total_cells = {}
        for i, metric in enumerate(metrics):
            formula = f"=SUM({cells['start'][metric]}:{cells['end'][metric]})"
            self.worksheet.write_formula(
                self.row, self.col + i + 1, formula, self.formatter.get(format_key)
            )
            total_cells[metric] = xl_rowcol_to_cell(self.row, self.col + i + 1)

        self.row += 1
        return total_cells

    def _write_reduction_row(
        self, alt_cells: dict[str, str], cgr_cells: dict[str, str], metrics: list[str]
    ):
        """
        Write reduction percentage row comparing alternative vs Chainguard.

        Args:
            alt_cells: Cell references for alternative image totals
            cgr_cells: Cell references for Chainguard image totals
            metrics: List of metric names to calculate reduction for
        """
        self.worksheet.write(
            self.row, self.col, "Reduction %", self.formatter.get("body_white")
        )

        for i, metric in enumerate(metrics):
            alt_cell = alt_cells[metric]
            cgr_cell = cgr_cells[metric]
            formula = f'=CONCATENATE(ROUND((({cgr_cell} - {alt_cell}) / {alt_cell}) * 100, 2), "%")'
            self.worksheet.write_formula(
                self.row, self.col + i + 1, formula, self.formatter.get("body_white")
            )

        self.row += 1


class ROISectionWriter(BaseSectionWriter):
    """Writes ROI estimation sections."""

    def __init__(
        self,
        worksheet: xlsxwriter.worksheet.Worksheet,
        formatter: OutputFormatter,
        row: int,
        hours_per_vuln: float,
        hourly_rate: float,
        col: int = 0,
    ):
        """
        Initialize ROI section writer.

        Args:
            worksheet: XlsxWriter worksheet
            formatter: Format provider
            row: Starting row number
            hours_per_vuln: Hours to remediate one CVE
            hourly_rate: Engineering hourly rate
            col: Starting column number (default: 0)
        """
        super().__init__(worksheet, formatter, row, col)
        self.hours_per_vuln = hours_per_vuln
        self.hourly_rate = hourly_rate
        self.time_per_vuln_cell = None
        self.hourly_rate_cell = None
        self.backlog_cost_cell = None
        self.yearly_cost_cell = None

    def write(self, scan_results: list["ScanResult"]) -> tuple[str, str, int]:
        """
        Write ROI estimation sections.

        Args:
            scan_results: Scan results with image pair information

        Returns:
            Tuple of (backlog_cost_cell, yearly_cost_cell, final_row)
        """
        self.row += 2

        # Header
        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + 8,
            "ROI Estimate for Using Chainguard images vs upstream (Annually)",
            self.formatter.get("header_blue"),
        )
        self.row += 2

        # Assumptions header
        self.worksheet.write_row(
            self.row,
            self.col,
            ["Assumptions", "Estimates", "Metrics"],
            self.formatter.get("header_lightgrey"),
        )
        self.row += 1

        # Time per CVE
        self.worksheet.write(
            self.row, self.col, "Time spent per CVE", self.formatter.get("body_white")
        )
        self.worksheet.write(
            self.row, self.col + 1, self.hours_per_vuln, self.formatter.get("body_yellow_hours")
        )
        self.worksheet.write(
            self.row, self.col + 2, "hours", self.formatter.get("body_white")
        )
        self.time_per_vuln_cell = xl_rowcol_to_cell(self.row, self.col + 1)
        self.row += 1

        # Hourly rate
        self.worksheet.write(
            self.row, self.col, "Eng hourly rate", self.formatter.get("body_white")
        )
        self.worksheet.write(
            self.row, self.col + 1, self.hourly_rate, self.formatter.get("body_yellow_money")
        )
        self.worksheet.write(
            self.row, self.col + 2, "dollars", self.formatter.get("body_white")
        )
        self.hourly_rate_cell = xl_rowcol_to_cell(self.row, self.col + 1)
        self.row += 2

        # Backlog section
        self._write_backlog_section(scan_results)

        # Estimated future CVEs section
        self._write_estimated_cves_section(scan_results)

        return self.backlog_cost_cell, self.yearly_cost_cell, self.row

    def _write_backlog_section(self, scan_results: list["ScanResult"]):
        """Write CVE backlog remediation section."""
        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + 8,
            "Clear the CVE Backlog Effort",
            self.formatter.get("header_darkgrey"),
        )
        self.row += 1

        # Header
        header = [
            "Image",
            "CVEs today",
            "Criticals",
            "Highs",
            "Mediums",
            "Lows",
            "Negligible/Unknown",
            "Hours",
            "Cost",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_lightgrey")
        )
        self.row += 1

        backlog_hours_start = xl_rowcol_to_cell(self.row, self.col + 7)
        backlog_cost_start = xl_rowcol_to_cell(self.row, self.col + 8)

        for result in scan_results:
            analysis = result.alternative_analysis
            vuln = analysis.vulnerabilities

            # Image name
            self.worksheet.write(
                self.row, self.col, analysis.name, self.formatter.get("body_white")
            )

            # Severity cells
            critical_cell = xl_rowcol_to_cell(self.row, self.col + 2)
            high_cell = xl_rowcol_to_cell(self.row, self.col + 3)
            medium_cell = xl_rowcol_to_cell(self.row, self.col + 4)
            low_cell = xl_rowcol_to_cell(self.row, self.col + 5)
            negligible_cell = xl_rowcol_to_cell(self.row, self.col + 6)

            # CVEs today formula
            cves_formula = f"={critical_cell}+{high_cell}+{medium_cell}+{low_cell}+{negligible_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 1, cves_formula, self.formatter.get("body_white")
            )
            cves_cell = xl_rowcol_to_cell(self.row, self.col + 1)

            # Severity counts
            self.worksheet.write(
                self.row, self.col + 2, vuln.critical, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 3, vuln.high, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 4, vuln.medium, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 5, vuln.low, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 6, vuln.negligible, self.formatter.get("body_white")
            )

            # Hours formula
            hours_formula = f"={self.time_per_vuln_cell} * {cves_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 7, hours_formula, self.formatter.get("body_white_hours")
            )
            hours_cell = xl_rowcol_to_cell(self.row, self.col + 7)

            # Cost formula
            cost_formula = f"={self.hourly_rate_cell} * {hours_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 8, cost_formula, self.formatter.get("body_white_money")
            )

            self.row += 1

        backlog_hours_end = xl_rowcol_to_cell(self.row - 1, self.col + 7)
        backlog_cost_end = xl_rowcol_to_cell(self.row - 1, self.col + 8)

        # Totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"=SUM({backlog_hours_start}:{backlog_hours_end})",
            self.formatter.get("body_green_hours"),
        )

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"=SUM({backlog_cost_start}:{backlog_cost_end})",
            self.formatter.get("body_green_money"),
        )
        self.backlog_cost_cell = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (backlog)", self.formatter.get("body_green")
        )
        self.row += 2

    def _write_estimated_cves_section(self, scan_results: list["ScanResult"]):
        """Write estimated future CVEs section."""
        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + 8,
            "Estimated New CVEs Effort (next month)",
            self.formatter.get("header_darkgrey"),
        )
        self.row += 1

        header = [
            "Image",
            "Est. New CVEs",
            "Est. Criticals",
            "Est. Highs",
            "Est. Mediums",
            "Est. Lows",
            "Est. Negligible/Unknown",
            "Hours",
            "Cost",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_lightgrey")
        )
        self.row += 1

        est_hours_start = xl_rowcol_to_cell(self.row, self.col + 7)
        est_cost_start = xl_rowcol_to_cell(self.row, self.col + 8)

        for result in scan_results:
            analysis = result.alternative_analysis
            vuln = analysis.vulnerabilities

            # Get CVE growth ratios from Chainguard image data (dynamic from API or static fallback)
            ratios = get_cve_monthly_ratios(
                image_name=analysis.name,
                chainguard_image_name=result.pair.chainguard_image,
                use_api=True
            )

            # Calculate estimates
            est_critical = vuln.critical * ratios["CRITICAL"]
            est_high = vuln.high * ratios["HIGH"]
            est_medium = vuln.medium * ratios["MEDIUM"]
            est_low = vuln.low * ratios["LOW"]
            est_negligible = vuln.negligible * ratios["NEGLIGIBLE"]

            self.worksheet.write(
                self.row, self.col, analysis.name, self.formatter.get("body_white")
            )

            # Estimated severity cells
            est_critical_cell = xl_rowcol_to_cell(self.row, self.col + 2)
            est_high_cell = xl_rowcol_to_cell(self.row, self.col + 3)
            est_medium_cell = xl_rowcol_to_cell(self.row, self.col + 4)
            est_low_cell = xl_rowcol_to_cell(self.row, self.col + 5)
            est_negligible_cell = xl_rowcol_to_cell(self.row, self.col + 6)

            # Est. New CVEs formula
            est_total_formula = f"={est_critical_cell}+{est_high_cell}+{est_medium_cell}+{est_low_cell}+{est_negligible_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 1, est_total_formula, self.formatter.get("body_white")
            )
            est_total_cell = xl_rowcol_to_cell(self.row, self.col + 1)

            # Write estimates
            self.worksheet.write(
                self.row, self.col + 2, round(est_critical, 2), self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 3, round(est_high, 2), self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 4, round(est_medium, 2), self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 5, round(est_low, 2), self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 6, round(est_negligible, 2), self.formatter.get("body_white")
            )

            # Hours and cost formulas
            hours_formula = f"={self.time_per_vuln_cell} * {est_total_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 7, hours_formula, self.formatter.get("body_white_hours")
            )
            hours_cell = xl_rowcol_to_cell(self.row, self.col + 7)

            cost_formula = f"={self.hourly_rate_cell} * {hours_cell}"
            self.worksheet.write_formula(
                self.row, self.col + 8, cost_formula, self.formatter.get("body_white_money")
            )

            self.row += 1

        est_hours_end = xl_rowcol_to_cell(self.row - 1, self.col + 7)
        est_cost_end = xl_rowcol_to_cell(self.row - 1, self.col + 8)

        # Monthly totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"=SUM({est_hours_start}:{est_hours_end})",
            self.formatter.get("body_lightblue_hours"),
        )
        monthly_hours_cell = xl_rowcol_to_cell(self.row, self.col + 7)

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"=SUM({est_cost_start}:{est_cost_end})",
            self.formatter.get("body_lightblue_money"),
        )
        monthly_cost_cell = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (next month)", self.formatter.get("body_lightblue")
        )
        self.row += 1

        # Yearly totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"={monthly_hours_cell} * 12",
            self.formatter.get("body_green_hours"),
        )

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"={monthly_cost_cell} * 12",
            self.formatter.get("body_green_money"),
        )
        self.yearly_cost_cell = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (next year)", self.formatter.get("body_green")
        )


class CHPSSectionWriter(BaseSectionWriter):
    """Writes CHPS hardening and provenance scoring section."""

    def write(
        self, alternative_analyses: list[ImageAnalysis], chainguard_analyses: list[ImageAnalysis]
    ) -> int:
        """
        Write CHPS section.

        Args:
            alternative_analyses: Alternative image analyses
            chainguard_analyses: Chainguard image analyses

        Returns:
            Final row number
        """
        self.row += 2

        # Section header
        self.worksheet.write(
            self.row,
            self.col,
            "CHPS Hardening & Provenance Scores",
            self.formatter.get("header_blue"),
        )
        self.row += 1

        # Description
        self.worksheet.write(
            self.row,
            self.col,
            "CHPS evaluates hardening best practices; CVE scoring has been omitted.",
            self.formatter.get("body_white"),
        )
        self.row += 1

        # Column headers
        headers = [
            "Image",
            "Minimalism",
            "Provenance",
            "Configuration",
            "Overall Score (max 16)",
            "Overall Grade",
            "Overall Improvement"
        ]
        self.worksheet.write_row(
            self.row, self.col, headers, self.formatter.get("header_lightgrey")
        )
        self.row += 1

        # Write image scores
        for alternative, chainguard in zip(alternative_analyses, chainguard_analyses):
            # Alternative image
            alternative_score = alternative.chps_score.score if alternative.chps_score else 0
            alternative_grade = alternative.chps_score.grade if alternative.chps_score else "N/A"

            # Get component scores for alternative (as "X of Y" format)
            alt_min = self._get_component_score(alternative.chps_score, "minimalism")
            alt_prov = self._get_component_score(alternative.chps_score, "provenance")
            alt_conf = self._get_component_score(alternative.chps_score, "configuration")

            self.worksheet.write(self.row, self.col, alternative.name, self.formatter.get("body_white"))
            self.worksheet.write(
                self.row, self.col + 1, alt_min, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 2, alt_prov, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 3, alt_conf, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 4, alternative_score, self.formatter.get("body_white")
            )
            self.worksheet.write(
                self.row, self.col + 5, alternative_grade, self.formatter.get("body_white")
            )
            # Write empty cell for improvement column to maintain border
            self.worksheet.write(
                self.row, self.col + 6, "", self.formatter.get("body_white")
            )
            self.row += 1

            # Chainguard image
            chainguard_score = chainguard.chps_score.score if chainguard.chps_score else 0
            chainguard_grade = chainguard.chps_score.grade if chainguard.chps_score else "N/A"
            improvement = chainguard_score - alternative_score if alternative.chps_score and chainguard.chps_score else 0

            # Get component scores for chainguard (as "X of Y" format)
            cgr_min = self._get_component_score(chainguard.chps_score, "minimalism")
            cgr_prov = self._get_component_score(chainguard.chps_score, "provenance")
            cgr_conf = self._get_component_score(chainguard.chps_score, "configuration")

            self.worksheet.write(
                self.row, self.col, f"{chainguard.name} (Chainguard)", self.formatter.get("body_green")
            )
            self.worksheet.write(
                self.row, self.col + 1, cgr_min, self.formatter.get("body_green")
            )
            self.worksheet.write(
                self.row, self.col + 2, cgr_prov, self.formatter.get("body_green")
            )
            self.worksheet.write(
                self.row, self.col + 3, cgr_conf, self.formatter.get("body_green")
            )
            self.worksheet.write(
                self.row, self.col + 4, chainguard_score, self.formatter.get("body_green")
            )
            self.worksheet.write(
                self.row, self.col + 5, chainguard_grade, self.formatter.get("body_green")
            )
            if improvement != 0:
                self.worksheet.write(
                    self.row, self.col + 6, improvement, self.formatter.get("body_green")
                )
            self.row += 1

        return self.row

    def _get_component_score(self, chps_score: Optional["CHPSScore"], component: str) -> str:
        """
        Extract component score from CHPS score details in "X of Y" format.

        Args:
            chps_score: CHPS score object
            component: Component name (minimalism, provenance, configuration)

        Returns:
            Component score as "X of Y" format or "N/A" if not available
        """
        if not chps_score or not chps_score.details:
            return "N/A"

        scores = chps_score.details.get("scores", {})
        component_data = scores.get(component, {})

        score = component_data.get("score", 0)
        max_score = component_data.get("max", 0)

        if max_score == 0:
            return "N/A"

        return f"{score} of {max_score}"

    def _get_component_grade(self, chps_score: Optional["CHPSScore"], component: str) -> str:
        """
        Extract component grade from CHPS score details.

        Args:
            chps_score: CHPS score object
            component: Component name (minimalism, provenance, configuration)

        Returns:
            Component grade or "N/A" if not available
        """
        if not chps_score or not chps_score.details:
            return "N/A"

        scores = chps_score.details.get("scores", {})
        component_data = scores.get(component, {})
        grade = component_data.get("grade", "N/A")

        # Fix E→F mapping
        if grade == "E":
            grade = "F"

        return grade


class FIPSSectionWriter(BaseSectionWriter):
    """Writes FIPS implementation and maintenance sections."""

    def __init__(
        self,
        worksheet: xlsxwriter.worksheet.Worksheet,
        formatter: OutputFormatter,
        row: int,
        hourly_rate: float,
        hourly_rate_cell: str,
        col: int = 0,
    ):
        """
        Initialize FIPS section writer.

        Args:
            worksheet: XlsxWriter worksheet
            formatter: Format provider
            row: Starting row number
            hourly_rate: Engineering hourly rate
            hourly_rate_cell: Cell reference for hourly rate
            col: Starting column number (default: 0)
        """
        super().__init__(worksheet, formatter, row, col)
        self.hourly_rate = hourly_rate
        self.hourly_rate_cell = hourly_rate_cell
        self.fips_initial_cost_cell = None
        self.fips_yearly_cost_cell = None

    def write(self, fips_count: int) -> tuple[str, str, int]:
        """
        Write FIPS sections.

        Args:
            fips_count: Number of FIPS images

        Returns:
            Tuple of (initial_cost_cell, yearly_cost_cell, final_row)
        """
        if fips_count == 0:
            return None, None, self.row

        calculator = FIPSCalculator(self.hourly_rate)

        # Initial implementation section
        self._write_initial_section(fips_count, calculator)

        # Maintenance section
        self._write_maintenance_section(fips_count, calculator)

        return self.fips_initial_cost_cell, self.fips_yearly_cost_cell, self.row

    def _write_initial_section(self, fips_count: int, calculator: FIPSCalculator):
        """Write FIPS initial implementation section."""
        self.row += 2

        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + 8,
            f"Initial FIPS Implementation Hours ({fips_count} images)",
            self.formatter.get("header_lightyellow"),
        )
        self.row += 1

        # Header
        header = [
            "Initial Assessment Phase",
            "Before Min",
            "Before Max",
            "After Min",
            "After Max",
            "Hours Saved Min",
            "Hours Saved Max",
            "Hours",
            "Cost",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_white")
        )
        self.row += 1

        fips_initial_hours_start = xl_rowcol_to_cell(self.row, self.col + 7)

        # Write phases
        phases = calculator.get_initial_phases()
        for phase in phases:
            self.worksheet.write(
                self.row, self.col, phase.name, self.formatter.get("body_white")
            )

            # Before hours
            self.worksheet.write_row(
                self.row,
                self.col + 1,
                [phase.before_min_hours, phase.before_max_hours],
                self.formatter.get("body_yellow"),
            )
            before_min_cell = xl_rowcol_to_cell(self.row, self.col + 1)
            before_max_cell = xl_rowcol_to_cell(self.row, self.col + 2)

            # After hours
            self.worksheet.write_row(
                self.row,
                self.col + 3,
                [phase.after_min_hours, phase.after_max_hours],
                self.formatter.get("body_lightgrey"),
            )
            after_min_cell = xl_rowcol_to_cell(self.row, self.col + 3)
            after_max_cell = xl_rowcol_to_cell(self.row, self.col + 4)

            # Hours saved
            self.worksheet.write_formula(
                self.row,
                self.col + 5,
                f"={before_min_cell} - {after_min_cell}",
                self.formatter.get("body_lightgrey"),
            )
            self.worksheet.write_formula(
                self.row,
                self.col + 6,
                f"={before_max_cell} - {after_max_cell}",
                self.formatter.get("body_lightgrey"),
            )

            hours_saved_min_cell = xl_rowcol_to_cell(self.row, self.col + 5)
            hours_saved_max_cell = xl_rowcol_to_cell(self.row, self.col + 6)

            # Total hours
            self.worksheet.write_formula(
                self.row,
                self.col + 7,
                f"=AVERAGE({hours_saved_min_cell}:{hours_saved_max_cell}) * {fips_count}",
                self.formatter.get("body_white_hours"),
            )
            hours_cell = xl_rowcol_to_cell(self.row, self.col + 7)

            # Cost
            self.worksheet.write_formula(
                self.row,
                self.col + 8,
                f"={hours_cell} * {self.hourly_rate_cell}",
                self.formatter.get("body_white_money"),
            )

            self.row += 1

        fips_initial_hours_end = xl_rowcol_to_cell(self.row - 1, self.col + 7)
        fips_initial_cost_end = xl_rowcol_to_cell(self.row - 1, self.col + 8)

        # Totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"=SUM({fips_initial_hours_start}:{fips_initial_hours_end})",
            self.formatter.get("body_green_hours"),
        )

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"=SUM({fips_initial_hours_start}:{fips_initial_cost_end})",
            self.formatter.get("body_green_money"),
        )
        self.fips_initial_cost_cell = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (initial)", self.formatter.get("body_green")
        )
        self.row += 2

    def _write_maintenance_section(self, fips_count: int, calculator: FIPSCalculator):
        """Write FIPS maintenance section."""
        self.worksheet.merge_range(
            self.row,
            self.col,
            self.row,
            self.col + 8,
            "FIPS Maintenance Hours (next month)",
            self.formatter.get("header_lightyellow"),
        )
        self.row += 1

        header = [
            "Phase",
            "Before Min",
            "Before Max",
            "After Min",
            "After Max",
            "Hours Saved Min",
            "Hours Saved Max",
            "Hours",
            "Cost",
        ]
        self.worksheet.write_row(
            self.row, self.col, header, self.formatter.get("header_white")
        )
        self.row += 1

        fips_monthly_hours_start = xl_rowcol_to_cell(self.row, self.col + 7)

        phases = calculator.get_maintenance_phases()
        for phase in phases:
            self.worksheet.write(
                self.row, self.col, phase.name, self.formatter.get("body_white")
            )

            # Before hours
            self.worksheet.write_row(
                self.row,
                self.col + 1,
                [phase.before_min_hours, phase.before_max_hours],
                self.formatter.get("body_yellow"),
            )
            before_min_cell = xl_rowcol_to_cell(self.row, self.col + 1)
            before_max_cell = xl_rowcol_to_cell(self.row, self.col + 2)

            # After hours
            self.worksheet.write_row(
                self.row,
                self.col + 3,
                [phase.after_min_hours, phase.after_max_hours],
                self.formatter.get("body_lightgrey"),
            )
            after_min_cell = xl_rowcol_to_cell(self.row, self.col + 3)
            after_max_cell = xl_rowcol_to_cell(self.row, self.col + 4)

            # Hours saved
            self.worksheet.write_formula(
                self.row,
                self.col + 5,
                f"={before_min_cell} - {after_min_cell}",
                self.formatter.get("body_lightgrey"),
            )
            self.worksheet.write_formula(
                self.row,
                self.col + 6,
                f"={before_max_cell} - {after_max_cell}",
                self.formatter.get("body_lightgrey"),
            )

            hours_saved_min_cell = xl_rowcol_to_cell(self.row, self.col + 5)
            hours_saved_max_cell = xl_rowcol_to_cell(self.row, self.col + 6)

            # Total hours
            self.worksheet.write_formula(
                self.row,
                self.col + 7,
                f"=AVERAGE({hours_saved_min_cell}:{hours_saved_max_cell}) * {fips_count}",
                self.formatter.get("body_white_hours"),
            )
            hours_cell = xl_rowcol_to_cell(self.row, self.col + 7)

            # Cost
            self.worksheet.write_formula(
                self.row,
                self.col + 8,
                f"={hours_cell} * {self.hourly_rate_cell}",
                self.formatter.get("body_white_money"),
            )

            self.row += 1

        fips_monthly_hours_end = xl_rowcol_to_cell(self.row - 1, self.col + 7)
        fips_monthly_cost_end = xl_rowcol_to_cell(self.row - 1, self.col + 8)

        # Monthly totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"=SUM({fips_monthly_hours_start}:{fips_monthly_hours_end})",
            self.formatter.get("body_lightblue_hours"),
        )
        fips_monthly_hours_total = xl_rowcol_to_cell(self.row, self.col + 7)

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"=SUM({fips_monthly_hours_start}:{fips_monthly_cost_end})",
            self.formatter.get("body_lightblue_money"),
        )
        fips_monthly_cost_total = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (next month)", self.formatter.get("body_lightblue")
        )
        self.row += 1

        # Yearly totals
        self.worksheet.write_formula(
            self.row,
            self.col + 7,
            f"={fips_monthly_hours_total} * 12",
            self.formatter.get("body_green_hours"),
        )

        self.worksheet.write_formula(
            self.row,
            self.col + 8,
            f"={fips_monthly_cost_total} * 12",
            self.formatter.get("body_green_money"),
        )
        self.fips_yearly_cost_cell = xl_rowcol_to_cell(self.row, self.col + 8)

        self.worksheet.write(
            self.row, self.col + 9, "Total (next year)", self.formatter.get("body_green")
        )
