"""
Chainguard API client for historical vulnerability data.

Provides access to Chainguard's vulnerability tracking API for
historical CVE trends and projections.
"""

import logging
import subprocess
from datetime import datetime, timezone
from typing import Optional

import requests

from constants import CHAINGUARD_API_URL
from core.exceptions import IntegrationException

logger = logging.getLogger(__name__)


class ChainguardAPI:
    """
    Client for Chainguard's vulnerability API.

    Requires authentication via chainctl (Chainguard CLI tool).
    """

    def __init__(self):
        """Initialize Chainguard API client."""
        self._verify_chainctl()

    def _verify_chainctl(self) -> None:
        """Verify chainctl is available and authenticated."""
        try:
            result = subprocess.run(
                ["chainctl", "auth", "token"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError("chainctl authentication failed")
            logger.debug("chainctl authentication verified")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            raise RuntimeError(
                "chainctl is required for Chainguard API access but not found in PATH"
            )

    def get_vulnerability_counts(
        self,
        repo: str,
        tag: str,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
    ) -> dict:
        """
        Get historical vulnerability counts for an image.

        Args:
            repo: Repository name (e.g., "python")
            tag: Image tag (e.g., "latest")
            from_date: Start date (ISO format, e.g., "2024-01-01T00:00:00Z")
            to_date: End date (ISO format)

        Returns:
            API response with historical vulnerability data
        """
        if not from_date:
            from_date = "2024-01-01T00:00:00Z"

        if not to_date:
            to_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            # Get auth token from chainctl
            result = subprocess.run(
                ["chainctl", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise IntegrationException("chainctl", "Failed to get auth token")

            token = result.stdout.strip()

            # Make API request using requests library
            response = requests.post(
                f"{CHAINGUARD_API_URL}/registry/v1/vuln_reports/counts",
                headers={"Authorization": f"Bearer {token}"},
                data={
                    "repo": repo,
                    "tag": tag,
                    "from": from_date,
                    "to": to_date,
                },
                timeout=30,
            )
            response.raise_for_status()

            return response.json()

        except requests.Timeout:
            logger.warning(f"Timeout fetching vulnerability data for {repo}:{tag}")
            return {"items": []}
        except requests.RequestException as e:
            logger.warning(
                f"Failed to fetch vulnerability data for {repo}:{tag}: {e}"
            )
            return {"items": []}
        except Exception as e:
            logger.warning(
                f"Unexpected error fetching vulnerability data for {repo}:{tag}: {e}"
            )
            return {"items": []}

    def calculate_cve_growth_rate(
        self, repo: str, tag: str
    ) -> Optional[dict[str, float]]:
        """
        Calculate monthly CVE growth rate for an image.

        Args:
            repo: Repository name
            tag: Image tag

        Returns:
            Dictionary of severity -> monthly growth ratio, or None if data unavailable
        """
        data = self.get_vulnerability_counts(repo, tag)

        if not data.get("items"):
            return None

        items = data["items"]

        # Get starting point
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        for count in items[0].get("vulnCounts", []):
            severity = count.get("severity")
            if severity in severity_counts:
                severity_counts[severity] = count.get("count", 0)

        # Track changes over time
        changes = {sev: 0.0 for sev in severity_counts.keys()}

        prev_counts = severity_counts.copy()
        for item in items:
            for count in item.get("vulnCounts", []):
                severity = count.get("severity")
                if severity in changes:
                    current = count.get("count", 0)
                    changes[severity] += abs(current - prev_counts[severity])
                    prev_counts[severity] = current

        # Calculate average daily change, then convert to monthly ratio
        num_days = len(items)
        if num_days == 0:
            return None

        ratios = {}
        for severity, total_change in changes.items():
            avg_daily_change = total_change / num_days
            monthly_change = avg_daily_change * 30

            # Convert to ratio of current count
            current_count = prev_counts[severity]
            if current_count > 0:
                ratios[severity] = monthly_change / current_count
            else:
                ratios[severity] = 0.0

        return ratios
