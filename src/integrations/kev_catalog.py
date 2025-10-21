"""
CISA Known Exploited Vulnerabilities (KEV) Catalog integration.

Fetches and checks CVEs against CISA's official KEV catalog.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional, Set

from core.models import KEVEntry

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVCatalog:
    """
    Client for CISA's Known Exploited Vulnerabilities catalog.

    Provides methods to fetch the KEV catalog and check if specific
    CVEs are known to be exploited in the wild.
    """

    def __init__(self):
        """Initialize KEV catalog."""
        self.vulnerabilities: List[KEVEntry] = []
        self.cve_ids: Set[str] = set()
        self.loaded = False

    def load(self) -> bool:
        """
        Fetch KEV catalog from CISA.

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            logger.info("Fetching KEV catalog from CISA...")
            result = subprocess.run(
                f'curl -s "{KEV_URL}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )

            data = json.loads(result.stdout.strip())

            # Parse KEV entries
            for vuln in data.get("vulnerabilities", []):
                entry = KEVEntry(
                    cve_id=vuln.get("cveID", ""),
                    vendor=vuln.get("vendorProject", ""),
                    product=vuln.get("product", ""),
                    vulnerability_name=vuln.get("vulnerabilityName", ""),
                    date_added=vuln.get("dateAdded", ""),
                )
                self.vulnerabilities.append(entry)
                self.cve_ids.add(entry.cve_id)

            self.loaded = True
            logger.info(f"Loaded {len(self.vulnerabilities)} KEV entries")
            return True

        except subprocess.TimeoutExpired:
            logger.warning("Timeout loading KEV data")
            return False
        except Exception as e:
            logger.warning(f"Failed to load KEV data: {e}")
            return False

    def is_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            True if CVE is a known exploited vulnerability
        """
        return cve_id in self.cve_ids

    def get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """
        Get KEV catalog entry for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            KEVEntry if found, None otherwise
        """
        for entry in self.vulnerabilities:
            if entry.cve_id == cve_id:
                return entry
        return None

    def check_image_for_kevs(
        self, image_name: str, cve_ids: List[str]
    ) -> List[str]:
        """
        Check which CVEs from an image are KEVs.

        Args:
            image_name: Image being checked
            cve_ids: List of CVE IDs from the image

        Returns:
            List of CVE IDs that are KEVs
        """
        if not self.loaded:
            return []

        kevs_found = []
        for cve_id in cve_ids:
            if self.is_kev(cve_id):
                logger.warning(f"KEV found in {image_name}: {cve_id}")
                kevs_found.append(cve_id)

        return kevs_found
