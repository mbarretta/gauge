"""
Core vulnerability scanning engine.

Orchestrates image scanning using Syft (for SBOM) and Grype (for vulnerabilities),
with intelligent caching and parallel execution support.
"""

import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
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
        kev_catalog: Optional['KEVCatalog'] = None,
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
            kev_catalog: KEV catalog for checking known exploited vulnerabilities
        """
        self.cache = cache
        self.docker = docker_client
        self.max_workers = max_workers
        self.platform = platform
        self.check_fresh_images = check_fresh_images
        self.with_chps = with_chps
        self.kev_catalog = kev_catalog

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

        Raises:
            RuntimeError: If image cannot be pulled or scan fails
        """
        original_image = image
        used_fallback = False
        pull_successful = True

        # Check if we should update the image first
        if self.check_fresh_images:
            image, used_fallback, pull_successful = self.docker.ensure_fresh_image(image, self.platform)
            if used_fallback:
                logger.warning(
                    f"Using {image} as fallback for {original_image}"
                )
            if not pull_successful:
                logger.error(f"Failed to pull image {original_image} - cannot scan")
                raise RuntimeError(f"Failed to pull image {original_image} and all fallback strategies failed")

        # Get image digest for caching
        digest = self.docker.get_image_digest(image)

        # Check cache (with CHPS requirement if CHPS scanner is enabled)
        require_chps = self.chps_scanner is not None
        cached = self.cache.get(image, digest, require_chps=require_chps)
        if cached:
            logger.info(f"✓ {image} (cached)")
            # If we used fallback, update the cached result to reflect that
            if used_fallback:
                cached = replace(
                    cached,
                    used_latest_fallback=True,
                    original_image=original_image,
                )
            return cached

        # Perform fresh scan
        logger.info(f"🔍 Scanning {image}")

        try:
            # Get image size
            size_mb = self.docker.get_image_size_mb(image)

            # Run Syft to generate SBOM
            package_count, sbom_json = self._run_syft(image)

            # Run Grype on SBOM to get vulnerabilities
            vulnerabilities, cve_ids = self._run_grype_on_sbom(sbom_json, image)

            # Check for KEVs if catalog is available
            kev_cves = []
            if self.kev_catalog and cve_ids:
                for cve_id in cve_ids:
                    if self.kev_catalog.is_kev(cve_id):
                        kev_cves.append(cve_id)

                if kev_cves:
                    logger.warning(f"⚠️  {len(kev_cves)} Known Exploited Vulnerabilities found in {image}")

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
                used_latest_fallback=used_fallback,
                original_image=original_image if used_fallback else None,
                kev_count=len(kev_cves),
                kev_cves=kev_cves,
            )

            # Cache the result
            self.cache.put(analysis)

            kev_info = f", KEVs:{len(kev_cves)}" if kev_cves else ""
            logger.info(
                f"✓ {image} - {vulnerabilities.total} CVEs "
                f"(C:{vulnerabilities.critical} H:{vulnerabilities.high} "
                f"M:{vulnerabilities.medium}{kev_info})"
            )

            return analysis

        except Exception as e:
            logger.error(f"Failed to scan {image}: {e}")
            raise

    def _run_syft(self, image: str) -> tuple[int, str]:
        """
        Run Syft to generate SBOM.

        Args:
            image: Image to scan

        Returns:
            Tuple of (package_count, sbom_json_string)

        Raises:
            RuntimeError: If syft command fails
        """
        # Note: We don't pass --platform to Syft because we've already pulled
        # the correct platform-specific image using ensure_fresh_image().
        # Syft will scan whatever local image is available.
        cmd = ["syft", image, "-o", "json"]

        try:
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

        except subprocess.CalledProcessError as e:
            # Capture and include stderr in error message for better debugging
            error_msg = f"Syft command failed with exit code {e.returncode}"
            if e.stderr:
                error_msg += f"\nStderr: {e.stderr.strip()}"
            if e.stdout:
                error_msg += f"\nStdout: {e.stdout.strip()}"
            raise RuntimeError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Syft scan timed out after 300 seconds") from e

    def _run_grype_on_sbom(self, sbom_json: str, image_name: str) -> tuple[VulnerabilityCount, list[str]]:
        """
        Run Grype on SBOM to detect vulnerabilities.

        Args:
            sbom_json: SBOM in JSON format from Syft
            image_name: Image name (for logging)

        Returns:
            Tuple of (VulnerabilityCount, list of CVE IDs)

        Raises:
            RuntimeError: If grype command fails
        """
        try:
            result = subprocess.run(
                ["grype", "-o", "json"],
                input=sbom_json,
                capture_output=True,
                text=True,
                timeout=300,
                check=True
            )

            grype_data = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            # Capture and include stderr in error message for better debugging
            error_msg = f"Grype command failed with exit code {e.returncode}"
            if e.stderr:
                error_msg += f"\nStderr: {e.stderr.strip()}"
            if e.stdout:
                error_msg += f"\nStdout: {e.stdout.strip()}"
            raise RuntimeError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Grype scan timed out after 300 seconds") from e

        # Count vulnerabilities by severity and collect CVE IDs
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.NEGLIGIBLE.value: 0,
        }
        cve_ids = []

        for match in grype_data.get("matches", []):
            severity = match["vulnerability"]["severity"]
            if severity in counts:
                counts[severity] += 1
            else:
                # Unknown or Negligible go into negligible bucket
                counts[SeverityLevel.NEGLIGIBLE.value] += 1

            # Collect CVE ID
            cve_id = match.get("vulnerability", {}).get("id")
            if cve_id and cve_id.startswith("CVE-"):
                cve_ids.append(cve_id)

        total = sum(counts.values())

        vuln_count = VulnerabilityCount(
            total=total,
            critical=counts[SeverityLevel.CRITICAL.value],
            high=counts[SeverityLevel.HIGH.value],
            medium=counts[SeverityLevel.MEDIUM.value],
            low=counts[SeverityLevel.LOW.value],
            negligible=counts[SeverityLevel.NEGLIGIBLE.value],
        )

        return vuln_count, cve_ids


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
            chainguard_analysis = self.scan_image(pair.chainguard_image)

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
