"""
Upstream image discovery for finding public equivalents of private/internal images.

This module helps convert private or internal image names to their public upstream
equivalents before matching to Chainguard images.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from utils.docker_utils import image_exists_in_registry

logger = logging.getLogger(__name__)


@dataclass
class UpstreamResult:
    """Result of upstream image discovery."""

    upstream_image: Optional[str]
    """Discovered upstream image reference"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    method: str
    """Discovery method used (manual, registry_strip, common_registry, base_extract, none)"""


class UpstreamImageFinder:
    """
    Discovers public upstream equivalents for private/internal images.

    Uses a 4-strategy approach:
    1. Manual Mappings (100% confidence) - Explicit overrides
    2. Registry Strip (90% confidence) - Remove private registry prefix
    3. Common Registries (80% confidence) - Check docker.io, quay.io, ghcr.io
    4. Base Name Extract (70% confidence) - Extract base image from internal names
    """

    # Common public registries to check
    COMMON_REGISTRIES = [
        "docker.io/library",
        "docker.io",
        "quay.io",
        "ghcr.io",
    ]

    # Known private registry patterns
    PRIVATE_REGISTRY_PATTERNS = [
        r"^[a-z0-9.-]+\.(io|com|net|org|dev)/",  # company.io/image, multi-level domains
        r"^gcr\.io/[a-z0-9-]+/",  # gcr.io/project/image
        r"^[a-z0-9-]+\.gcr\.io/",  # project.gcr.io/image
        r"^[0-9]+\.dkr\.ecr\.",  # AWS ECR
        r"^.*\.azurecr\.io/",  # Azure ACR
    ]

    def __init__(
        self,
        manual_mappings_file: Optional[Path] = None,
        min_confidence: float = 0.7,
    ):
        """
        Initialize upstream image finder.

        Args:
            manual_mappings_file: Optional manual upstream mappings file
            min_confidence: Minimum confidence threshold (0.0 - 1.0)
        """
        self.manual_mappings_file = manual_mappings_file or Path("config/upstream_mappings.yaml")
        self.min_confidence = min_confidence
        self.manual_mappings: dict[str, str] = {}

        # Load manual mappings if available
        self._load_manual_mappings()

    def find_upstream(self, alternative_image: str) -> UpstreamResult:
        """
        Find public upstream equivalent for alternative image.

        Tries strategies in order of confidence:
        1. Manual mappings
        2. Registry strip
        3. Common registries
        4. Base name extraction

        Args:
            alternative_image: Alternative/internal image reference

        Returns:
            UpstreamResult with discovered image and metadata
        """
        # Strategy 1: Check manual mappings (100% confidence)
        if alternative_image in self.manual_mappings:
            upstream = self.manual_mappings[alternative_image]
            logger.debug(f"Manual mapping found for {alternative_image}: {upstream}")
            return UpstreamResult(
                upstream_image=upstream,
                confidence=1.0,
                method="manual"
            )

        # Strategy 2: Strip private registry prefix (90% confidence)
        stripped_result = self._try_strip_registry(alternative_image)
        if stripped_result and stripped_result.confidence >= self.min_confidence:
            return stripped_result

        # Strategy 3: Check common registries (80% confidence)
        registry_result = self._try_common_registries(alternative_image)
        if registry_result and registry_result.confidence >= self.min_confidence:
            return registry_result

        # Strategy 4: Extract base image name (70% confidence)
        base_result = self._try_base_extraction(alternative_image)
        if base_result and base_result.confidence >= self.min_confidence:
            return base_result

        # No upstream found
        logger.debug(f"No upstream found for {alternative_image}")
        return UpstreamResult(
            upstream_image=None,
            confidence=0.0,
            method="none"
        )

    def _load_manual_mappings(self) -> None:
        """Load manual upstream mappings from YAML file."""
        if not self.manual_mappings_file.exists():
            logger.debug(f"No manual upstream mappings file found at {self.manual_mappings_file}")
            return

        try:
            with open(self.manual_mappings_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                logger.debug("Manual upstream mappings file is empty")
                return

            if not isinstance(data, dict):
                logger.warning(f"Invalid manual upstream mappings format in {self.manual_mappings_file}")
                return

            self.manual_mappings = data
            logger.info(f"Loaded {len(self.manual_mappings)} manual upstream mappings")

        except Exception as e:
            logger.warning(f"Failed to load manual upstream mappings: {e}")

    def _try_strip_registry(self, image: str) -> Optional[UpstreamResult]:
        """
        Try stripping private registry prefix.

        Examples:
            mycompany.io/python:3.12 → python:3.12
            gcr.io/myproject/nginx:latest → nginx:latest
            artifactory.com/jenkins/jenkins:2.426 → jenkins/jenkins:2.426

        Args:
            image: Image reference

        Returns:
            UpstreamResult if successful, None otherwise
        """
        # Check if image matches private registry pattern
        is_private = any(re.match(pattern, image) for pattern in self.PRIVATE_REGISTRY_PATTERNS)

        if not is_private:
            return None

        # Extract image name after registry (preserve path structure)
        parts = image.split("/")
        if len(parts) < 2:
            return None

        # Strip registry (first part), keep the rest of the path
        # Example: docker.artifactory.com/jenkins/jenkins:tag → jenkins/jenkins:tag
        stripped_image = "/".join(parts[1:])

        # Extract just the image name (last part) for fallback attempts
        image_name_only = parts[-1]

        # Try multiple variations in order of likelihood:

        # 1. Try with full path preserved (for multi-part names like jenkins/jenkins)
        candidate = f"docker.io/{stripped_image}"
        if self._verify_upstream_exists(candidate):
            logger.debug(f"Registry strip successful: {image} → {stripped_image}")
            return UpstreamResult(
                upstream_image=stripped_image,
                confidence=0.90,
                method="registry_strip"
            )

        # 2. Try with library/ prefix if it's a single-part name
        if "/" not in stripped_image.split(":")[0]:  # Check base name has no /
            candidate = f"docker.io/library/{stripped_image}"
            if self._verify_upstream_exists(candidate):
                logger.debug(f"Registry strip successful: {image} → {stripped_image}")
                return UpstreamResult(
                    upstream_image=stripped_image,
                    confidence=0.90,
                    method="registry_strip"
                )

        # 3. Try just the image name (last part) with docker.io
        # Handles cases like eks/coredns → coredns or jenkins/exporter → exporter
        if stripped_image != image_name_only:  # Only if they're different
            candidate = f"docker.io/{image_name_only}"
            if self._verify_upstream_exists(candidate):
                logger.debug(f"Registry strip successful: {image} → {image_name_only}")
                return UpstreamResult(
                    upstream_image=image_name_only,
                    confidence=0.85,
                    method="registry_strip"
                )

            # Try with library/ prefix for single-part
            candidate = f"docker.io/library/{image_name_only}"
            if self._verify_upstream_exists(candidate):
                logger.debug(f"Registry strip successful: {image} → {image_name_only}")
                return UpstreamResult(
                    upstream_image=image_name_only,
                    confidence=0.85,
                    method="registry_strip"
                )

        # 4. If verification fails, return the full stripped path (best guess)
        # This allows pull fallback to attempt it even if we can't verify existence
        logger.debug(
            f"Registry strip (unverified): {image} → {stripped_image} "
            f"(will attempt during pull fallback)"
        )
        return UpstreamResult(
            upstream_image=stripped_image,
            confidence=0.70,  # Lower confidence since unverified
            method="registry_strip_unverified"
        )

    def _try_common_registries(self, image: str) -> Optional[UpstreamResult]:
        """
        Try finding image in common public registries.

        Checks docker.io, quay.io, ghcr.io in order.

        Args:
            image: Image reference

        Returns:
            UpstreamResult if successful, None otherwise
        """
        # Extract base name without registry/tag
        base_name = self._extract_base_name(image)

        # Try each common registry
        for registry in self.COMMON_REGISTRIES:
            candidate = f"{registry}/{base_name}"

            if self._verify_upstream_exists(candidate):
                logger.debug(f"Found in common registry: {candidate}")
                return UpstreamResult(
                    upstream_image=candidate,
                    confidence=0.80,
                    method="common_registry"
                )

        return None

    def _try_base_extraction(self, image: str) -> Optional[UpstreamResult]:
        """
        Try extracting base image name from internal naming patterns.

        Examples:
            internal-python-app:v1 → python:latest
            company-nginx-prod:latest → nginx:latest
            my-postgres-db → postgres:latest

        Args:
            image: Image reference

        Returns:
            UpstreamResult if successful, None otherwise
        """
        # Common base images to look for
        common_bases = [
            "python", "node", "nginx", "postgres", "postgresql", "mysql", "mariadb",
            "redis", "mongo", "mongodb", "golang", "go", "java", "openjdk",
            "ruby", "php", "perl", "alpine", "ubuntu", "debian", "centos",
            "httpd", "apache", "tomcat", "rabbitmq", "kafka", "elasticsearch",
        ]

        # Extract base name and check if it contains common base image names
        base_name = self._extract_base_name(image).lower()

        for base in common_bases:
            if base in base_name:
                # Try with latest tag
                candidate = f"docker.io/library/{base}:latest"
                if self._verify_upstream_exists(candidate):
                    logger.debug(f"Base extraction successful: {image} → {base}:latest")
                    return UpstreamResult(
                        upstream_image=f"{base}:latest",
                        confidence=0.70,
                        method="base_extract"
                    )

                # Try without library prefix
                candidate = f"docker.io/{base}:latest"
                if self._verify_upstream_exists(candidate):
                    logger.debug(f"Base extraction successful: {image} → {base}:latest")
                    return UpstreamResult(
                        upstream_image=f"{base}:latest",
                        confidence=0.70,
                        method="base_extract"
                    )

        return None

    def _extract_base_name(self, image: str) -> str:
        """
        Extract base image name from full reference.

        Examples:
            mycompany.io/python:3.12 → python
            internal-python-app:v1 → internal-python-app
            gcr.io/project/nginx → nginx

        Args:
            image: Image reference

        Returns:
            Base image name
        """
        # Remove registry
        if "/" in image:
            parts = image.split("/")
            image = parts[-1]

        # Remove tag
        if ":" in image:
            image = image.split(":")[0]

        # Remove digest
        if "@" in image:
            image = image.split("@")[0]

        return image.lower()

    def _verify_upstream_exists(self, image: str) -> bool:
        """
        Verify upstream image exists in registry.

        Uses docker/podman manifest inspect for verification.

        Args:
            image: Full image reference with registry

        Returns:
            True if image exists, False otherwise
        """
        try:
            return image_exists_in_registry(image)
        except Exception as e:
            logger.debug(f"Failed to verify upstream {image}: {e}")
            return False
