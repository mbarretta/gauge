"""
Core vulnerability scanning engine.

Orchestrates image scanning using Syft (for SBOM) and Grype (for vulnerabilities),
with intelligent caching and parallel execution support.
"""

import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from core.cache import ScanCache
from core.models import (
    ImageAnalysis,
    ImagePair,
    ScanResult,
    SeverityLevel,
    VulnerabilityCount,
)
from utils.docker_utils import DockerClient
from utils.chps_utils import CHPSScanner

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Vulnerability scanner using Syft and Grype.

    Provides intelligent caching, parallel scanning, and comprehensive
    error handling for production use.
    """

    def __init__(
        self,
        cache: ScanCache,
        docker_client: DockerClient,
        max_workers: int = 4,
        platform: Optional[str] = None,
        check_fresh_images: bool = True,
        with_chps: bool = False,
    ):
        """
        Initialize vulnerability scanner.

        Args:
            cache: Scan cache instance
            docker_client: Docker/Podman client
            max_workers: Maximum parallel scanning threads
            platform: Platform specification for scans (e.g., "linux/amd64")
            check_fresh_images: Whether to ensure images are up-to-date
            with_chps: Whether to include CHPS scoring
        """
        self.cache = cache
        self.docker = docker_client
        self.max_workers = max_workers
        self.platform = platform
        self.check_fresh_images = check_fresh_images
        self.with_chps = with_chps
        self.chps_scanner = CHPSScanner(docker_client.runtime) if with_chps else None
        self._verify_tools()

    def _verify_tools(self) -> None:
        """Verify required scanning tools are available."""
        for tool in ["syft", "grype"]:
            try:
                result = subprocess.run(
                    [tool, "version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    raise RuntimeError(f"{tool} not found or not working")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                raise RuntimeError(f"{tool} is required but not found in PATH")

        logger.info("Scanner tools verified: syft, grype")

    def scan_image(self, image: str) -> ImageAnalysis:
        """
        Scan a single image for vulnerabilities.

        Args:
            image: Image reference to scan

        Returns:
            ImageAnalysis with scan results
        """
        # Check if we should update the image first
        if self.check_fresh_images:
            self.docker.ensure_fresh_image(image)

        # Get image digest for caching
        digest = self.docker.get_image_digest(image)

        # Check cache
        cached = self.cache.get(image, digest)
        if cached:
            logger.info(f"✓ {image} (cached)")
            return cached

        # Perform fresh scan
        logger.info(f"🔍 Scanning {image}")

        try:
            # Get image size
            size_mb = self.docker.get_image_size_mb(image)

            # Run Syft to generate SBOM
            package_count, sbom_json = self._run_syft(image)

            # Run Grype on SBOM to get vulnerabilities
            vulnerabilities = self._run_grype_on_sbom(sbom_json, image)

            # Run CHPS scoring if requested
            chps_score = None
            if self.chps_scanner:
                chps_score = self.chps_scanner.scan_image(image)

            # Create analysis result
            analysis = ImageAnalysis(
                name=image,
                size_mb=size_mb,
                package_count=package_count,
                vulnerabilities=vulnerabilities,
                scan_timestamp=datetime.now(timezone.utc),
                digest=digest,
                cache_hit=False,
                chps_score=chps_score,
            )

            # Cache the result
            self.cache.put(analysis)

            logger.info(
                f"✓ {image} - {vulnerabilities.total} CVEs "
                f"(C:{vulnerabilities.critical} H:{vulnerabilities.high} "
                f"M:{vulnerabilities.medium})"
            )

            return analysis

        except Exception as e:
            logger.error(f"Failed to scan {image}: {e}")
            # Return empty analysis on failure
            return ImageAnalysis(
                name=image,
                size_mb=0.0,
                package_count=0,
                vulnerabilities=VulnerabilityCount(),
                scan_timestamp=datetime.now(timezone.utc),
                digest=digest,
            )

    def _run_syft(self, image: str) -> tuple[int, str]:
        """
        Run Syft to generate SBOM.

        Args:
            image: Image to scan

        Returns:
            Tuple of (package_count, sbom_json_string)
        """
        cmd = ["syft", image, "-o", "json"]
        if self.platform:
            cmd.extend(["--platform", self.platform])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=True
        )

        syft_data = json.loads(result.stdout)
        package_count = len(syft_data.get("artifacts", []))

        return package_count, result.stdout

    def _run_grype_on_sbom(self, sbom_json: str, image_name: str) -> VulnerabilityCount:
        """
        Run Grype on SBOM to detect vulnerabilities.

        Args:
            sbom_json: SBOM in JSON format from Syft
            image_name: Image name (for logging)

        Returns:
            VulnerabilityCount with severity breakdown
        """
        result = subprocess.run(
            ["grype", "-o", "json"],
            input=sbom_json,
            capture_output=True,
            text=True,
            timeout=300,
            check=True
        )

        grype_data = json.loads(result.stdout)

        # Count vulnerabilities by severity
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.NEGLIGIBLE.value: 0,
        }

        for match in grype_data.get("matches", []):
            severity = match["vulnerability"]["severity"]
            if severity in counts:
                counts[severity] += 1
            else:
                # Unknown or Negligible go into negligible bucket
                counts[SeverityLevel.NEGLIGIBLE.value] += 1

        total = sum(counts.values())

        return VulnerabilityCount(
            total=total,
            critical=counts[SeverityLevel.CRITICAL.value],
            high=counts[SeverityLevel.HIGH.value],
            medium=counts[SeverityLevel.MEDIUM.value],
            low=counts[SeverityLevel.LOW.value],
            negligible=counts[SeverityLevel.NEGLIGIBLE.value],
        )

    def scan_image_pair(self, pair: ImagePair) -> ScanResult:
        """
        Scan both images in a pair.

        Args:
            pair: ImagePair to scan

        Returns:
            ScanResult with both analyses
        """
        logger.info(f"Scanning pair: {pair}")

        try:
            alt_analysis = self.scan_image(pair.alternative_image)
            cgr_analysis = self.scan_image(pair.chainguard_image)

            return ScanResult(
                pair=pair,
                alternative_analysis=alt_analysis,
                chainguard_analysis=cgr_analysis,
                scan_successful=True,
            )

        except Exception as e:
            logger.error(f"Failed to scan pair {pair}: {e}")
            return ScanResult(
                pair=pair,
                alternative_analysis=None,
                chainguard_analysis=None,
                scan_successful=False,
                error_message=str(e),
            )

    def scan_image_pairs_parallel(
        self, pairs: list[ImagePair]
    ) -> list[ScanResult]:
        """
        Scan multiple image pairs in parallel.

        Args:
            pairs: List of image pairs to scan

        Returns:
            List of scan results
        """
        logger.info(f"Scanning {len(pairs)} image pairs with {self.max_workers} workers")

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pair = {
                executor.submit(self.scan_image_pair, pair): pair
                for pair in pairs
            }

            for i, future in enumerate(as_completed(future_to_pair), 1):
                pair = future_to_pair[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Progress: {i}/{len(pairs)} pairs completed")
                except Exception as e:
                    logger.error(f"Exception scanning {pair}: {e}")
                    results.append(
                        ScanResult(
                            pair=pair,
                            alternative_analysis=None,
                            chainguard_analysis=None,
                            scan_successful=False,
                            error_message=str(e),
                        )
                    )

        # Log summary
        successful = sum(1 for r in results if r.scan_successful)
        failed = len(results) - successful
        logger.info(f"Scan complete: {successful} succeeded, {failed} failed")

        return results
