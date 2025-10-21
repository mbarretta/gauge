"""
ROI (Return on Investment) calculations for vulnerability remediation.

Estimates costs of CVE remediation based on engineering time,
both for existing backlog and projected future vulnerabilities.
"""

from dataclasses import dataclass

from core.models import ImageAnalysis, ScanResult


# Historical CVE monthly ratios (fallback when API data unavailable)
# These represent the average monthly new CVE rate as a ratio of current CVEs
CVE_MONTHLY_RATIOS = {
    "CRITICAL": 0.06226879415733905,
    "HIGH": 0.048255074492743404,
    "MEDIUM": 0.09295663633080238,
    "LOW": 0.039432287834430285,
    "NEGLIGIBLE": 0.30331818635773494,
}


@dataclass
class ROIMetrics:
    """ROI calculation results."""

    backlog_hours: float
    backlog_cost: float
    monthly_hours: float
    monthly_cost: float
    yearly_hours: float
    yearly_cost: float
    total_cost: float


class ROICalculator:
    """
    Calculate ROI for using Chainguard images vs alternatives.

    Estimates both the cost of remediating the current CVE backlog
    and the ongoing cost of handling new CVEs that appear over time.
    """

    def __init__(
        self,
        hours_per_vulnerability: float = 3.0,
        hourly_rate: float = 100.0,
    ):
        """
        Initialize ROI calculator.

        Args:
            hours_per_vulnerability: Average hours to remediate one CVE
            hourly_rate: Engineering hourly rate in USD
        """
        self.hours_per_vuln = hours_per_vulnerability
        self.hourly_rate = hourly_rate

    def calculate_backlog_cost(
        self, analyses: list[ImageAnalysis]
    ) -> tuple[float, float]:
        """
        Calculate cost to clear current CVE backlog.

        Args:
            analyses: List of image analyses

        Returns:
            Tuple of (total_hours, total_cost)
        """
        total_cves = sum(a.vulnerabilities.total for a in analyses)
        hours = total_cves * self.hours_per_vuln
        cost = hours * self.hourly_rate
        return hours, cost

    def estimate_monthly_new_cves(self, analysis: ImageAnalysis) -> float:
        """
        Estimate new CVEs per month for an image based on historical ratios.

        Args:
            analysis: Image analysis

        Returns:
            Estimated new CVEs per month
        """
        vuln = analysis.vulnerabilities

        estimated_critical = vuln.critical * CVE_MONTHLY_RATIOS["CRITICAL"]
        estimated_high = vuln.high * CVE_MONTHLY_RATIOS["HIGH"]
        estimated_medium = vuln.medium * CVE_MONTHLY_RATIOS["MEDIUM"]
        estimated_low = vuln.low * CVE_MONTHLY_RATIOS["LOW"]
        estimated_negligible = vuln.negligible * CVE_MONTHLY_RATIOS["NEGLIGIBLE"]

        return (
            estimated_critical
            + estimated_high
            + estimated_medium
            + estimated_low
            + estimated_negligible
        )

    def calculate_ongoing_cost(
        self, analyses: list[ImageAnalysis]
    ) -> tuple[float, float, float, float]:
        """
        Calculate ongoing cost of handling new CVEs.

        Args:
            analyses: List of image analyses

        Returns:
            Tuple of (monthly_hours, monthly_cost, yearly_hours, yearly_cost)
        """
        monthly_cves = sum(self.estimate_monthly_new_cves(a) for a in analyses)
        monthly_hours = monthly_cves * self.hours_per_vuln
        monthly_cost = monthly_hours * self.hourly_rate

        yearly_hours = monthly_hours * 12
        yearly_cost = monthly_cost * 12

        return monthly_hours, monthly_cost, yearly_hours, yearly_cost

    def calculate_full_roi(
        self, alternative_analyses: list[ImageAnalysis]
    ) -> ROIMetrics:
        """
        Calculate complete ROI metrics.

        Args:
            alternative_analyses: Analyses of alternative (non-Chainguard) images

        Returns:
            ROIMetrics with all cost calculations
        """
        backlog_hours, backlog_cost = self.calculate_backlog_cost(
            alternative_analyses
        )
        monthly_hours, monthly_cost, yearly_hours, yearly_cost = (
            self.calculate_ongoing_cost(alternative_analyses)
        )

        total_cost = backlog_cost + yearly_cost

        return ROIMetrics(
            backlog_hours=backlog_hours,
            backlog_cost=backlog_cost,
            monthly_hours=monthly_hours,
            monthly_cost=monthly_cost,
            yearly_hours=yearly_hours,
            yearly_cost=yearly_cost,
            total_cost=total_cost,
        )

    def calculate_savings(
        self,
        alternative_cost: float,
        chainguard_image_cost: float,
        num_images: int,
    ) -> tuple[float, float]:
        """
        Calculate cost savings.

        Args:
            alternative_cost: Total cost of DIY approach
            chainguard_image_cost: Cost per Chainguard image
            num_images: Number of images

        Returns:
            Tuple of (absolute_savings, percent_savings)
        """
        cgr_total_cost = chainguard_image_cost * num_images
        absolute_savings = alternative_cost - cgr_total_cost
        percent_savings = (absolute_savings / alternative_cost) * 100 if alternative_cost > 0 else 0.0

        return absolute_savings, percent_savings
