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

from constants import DEFAULT_MAX_WORKERS, DEFAULT_PLATFORM
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
        max_workers: int = DEFAULT_MAX_WORKERS,
        platform: Optional[str] = DEFAULT_PLATFORM,
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

        if with_chps:
            logger.info("CHPS scoring enabled, initializing CHPS scanner...")
            self.chps_scanner = CHPSScanner(docker_client.runtime)
            if self.chps_scanner.chps_available:
                logger.info("CHPS scanner initialized successfully")
            else:
                logger.warning("CHPS scanner initialized but CHPS image not available")
        else:
            logger.debug("CHPS scoring disabled")
            self.chps_scanner = None

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
            self.docker.ensure_fresh_image(image, self.platform)

        # Get image digest for caching
        digest = self.docker.get_image_digest(image)

        # Check cache (with CHPS requirement if CHPS scanner is enabled)
        require_chps = self.chps_scanner is not None
        cached = self.cache.get(image, digest, require_chps=require_chps)
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
                logger.debug(f"Running CHPS scan for {image}")
                chps_score = self.chps_scanner.scan_image(image)
                if chps_score:
                    logger.info(f"CHPS score for {image}: {chps_score.score} ({chps_score.grade})")
                else:
                    logger.warning(f"No CHPS score returned for {image}")

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
        # Note: We don't pass --platform to Syft because we've already pulled
        # the correct platform-specific image using ensure_fresh_image().
        # Syft will scan whatever local image is available.
        cmd = ["syft", image, "-o", "json"]

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

    def _is_chainguard_image(self, image: str) -> bool:
        """
        Check if an image is from Chainguard registry.

        Args:
            image: Image reference to check

        Returns:
            True if image is from cgr.dev, False otherwise
        """
        return "cgr.dev" in image

    def _check_and_fallback_if_old(self, image: str) -> tuple[str, bool, Optional[str]]:
        """
        Check if Chainguard image is older than 30 days and fallback to :latest if needed.

        Args:
            image: Chainguard image reference to check

        Returns:
            Tuple of (image_to_use, used_fallback, original_image)
        """
        from dateutil import parser as date_parser
        from datetime import timedelta

        try:
            # Pull the image first to ensure we have it locally
            if self.check_fresh_images:
                self.docker.ensure_fresh_image(image, self.platform)

            # Get the creation date
            created_str = self.docker.get_image_created_date(image)
            if not created_str:
                logger.warning(f"Could not get creation date for {image}, using as-is")
                return image, False, None

            # Parse the creation date
            created_date = date_parser.parse(created_str)
            now = datetime.now(timezone.utc)

            # Make created_date timezone-aware if it isn't
            if created_date.tzinfo is None:
                created_date = created_date.replace(tzinfo=timezone.utc)

            # Calculate age in days
            age_days = (now - created_date).days

            logger.debug(f"Image {image} is {age_days} days old")

            # If older than 30 days, fallback to :latest
            if age_days > 30:
                # Extract the base image without tag
                if ":" in image:
                    base_image = image.rsplit(":", 1)[0]
                    latest_image = f"{base_image}:latest"
                    logger.warning(
                        f"Image {image} is {age_days} days old (> 30 days), "
                        f"falling back to {latest_image}"
                    )
                    return latest_image, True, image
                else:
                    # No tag specified, already using latest
                    return image, False, None

            return image, False, None

        except Exception as e:
            logger.warning(f"Error checking image age for {image}: {e}, using as-is")
            return image, False, None

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
            alternative_analysis = self.scan_image(pair.alternative_image)

            # For Chainguard images, check if image is older than 30 days
            # and fallback to :latest if needed
            chainguard_image = pair.chainguard_image
            used_fallback = False
            original_image = None

            if self._is_chainguard_image(chainguard_image):
                chainguard_image, used_fallback, original_image = self._check_and_fallback_if_old(
                    chainguard_image
                )

            chainguard_analysis = self.scan_image(chainguard_image)

            # Update the analysis with fallback information if needed
            if used_fallback:
                chainguard_analysis = ImageAnalysis(
                    name=chainguard_analysis.name,
                    size_mb=chainguard_analysis.size_mb,
                    package_count=chainguard_analysis.package_count,
                    vulnerabilities=chainguard_analysis.vulnerabilities,
                    scan_timestamp=chainguard_analysis.scan_timestamp,
                    digest=chainguard_analysis.digest,
                    cache_hit=chainguard_analysis.cache_hit,
                    chps_score=chainguard_analysis.chps_score,
                    used_latest_fallback=True,
                    original_image=original_image,
                )

            return ScanResult(
                pair=pair,
                alternative_analysis=alternative_analysis,
                chainguard_analysis=chainguard_analysis,
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
