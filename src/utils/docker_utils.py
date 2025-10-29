"""
Docker/Podman utility functions for image operations.

Provides a unified interface for working with container images,
supporting both Docker and Podman automatically.
"""

import json
import logging
import os
import subprocess
from typing import Optional

from constants import DEFAULT_PLATFORM

logger = logging.getLogger(__name__)


class DockerClient:
    """
    Unified client for Docker/Podman operations.

    Automatically detects available container runtime (docker or podman)
    and provides a consistent interface for image operations.
    """

    def __init__(self):
        """Initialize Docker client and detect available runtime."""
        self.runtime = self._detect_runtime()
        if not self.runtime:
            raise RuntimeError("Neither docker nor podman found in PATH")
        logger.debug(f"Using container runtime: {self.runtime}")

    def _detect_runtime(self) -> Optional[str]:
        """Detect available container runtime."""
        for cmd in ["docker", "podman"]:
            try:
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return cmd
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def get_image_digest(self, image: str) -> Optional[str]:
        """
        Get the digest (sha256) of an image.

        Args:
            image: Image reference (registry/repo:tag)

        Returns:
            Image digest or None if unavailable
        """
        try:
            # Try to get local image digest first
            result = subprocess.run(
                [self.runtime, "inspect", "--format={{.Id}}", image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                digest = result.stdout.strip()
                if digest.startswith("sha256:"):
                    return digest
                return f"sha256:{digest}"

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"Failed to get digest for {image}: {e}")

        return None

    def get_remote_digest(self, image: str) -> Optional[str]:
        """
        Get the digest of an image from the remote registry (linux/amd64 platform).

        Args:
            image: Image reference (registry/repo:tag)

        Returns:
            Remote image digest for linux/amd64 or None if unavailable
        """
        try:
            result = subprocess.run(
                [self.runtime, "manifest", "inspect", image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return None

            manifest = json.loads(result.stdout)

            # Handle multi-arch manifests
            if "manifests" in manifest and isinstance(manifest["manifests"], list):
                # Find linux/amd64 platform
                for m in manifest["manifests"]:
                    platform = m.get("platform", {})
                    if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
                        return m.get("digest")

                # Fallback to first manifest if amd64 not found
                if manifest["manifests"]:
                    logger.debug(f"Could not find linux/amd64 manifest for {image}, using first available")
                    return manifest["manifests"][0].get("digest")

            # Single-arch manifest
            if "config" in manifest and "digest" in manifest["config"]:
                return manifest["config"]["digest"]

            return manifest.get("digest")

        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.debug(f"Failed to get remote digest for {image}: {e}")
            return None

    def ensure_fresh_image(self, image: str, platform: Optional[str] = None) -> tuple[str, bool, bool]:
        """
        Ensure local image is up-to-date with remote, with intelligent fallback strategies.

        Args:
            image: Image reference to check/pull
            platform: Platform specification (default: "linux/amd64")

        Returns:
            Tuple of (image_used, used_fallback, pull_successful) where:
                - image_used: The actual image reference that was used
                - used_fallback: True if any fallback was used, False otherwise
                - pull_successful: True if image was successfully pulled, False otherwise
        """
        try:
            # Default to linux/amd64 for consistency across environments
            platform = platform or DEFAULT_PLATFORM

            remote_digest = self.get_remote_digest(image)
            if not remote_digest:
                logger.debug(f"Could not get remote digest for {image}, attempting pull with fallback")
                # Image might not exist, try pulling with fallback
                return self.pull_image_with_fallback(image, platform)

            local_digest = self.get_image_digest(image)

            if not local_digest or local_digest != remote_digest:
                logger.info(f"Pulling fresh copy of {image} ({platform})")
                return self.pull_image_with_fallback(image, platform)

            logger.debug(f"Image {image} is up-to-date")
            return image, False, True

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout pulling {image}")
            return image, False, False

    def get_image_size_mb(self, image: str) -> float:
        """
        Get image size in megabytes.

        Args:
            image: Image reference

        Returns:
            Size in MB, rounded to nearest integer
        """
        try:
            result = subprocess.run(
                [self.runtime, "inspect", "--format={{.Size}}", image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                size_bytes = int(result.stdout.strip())
                size_mb = size_bytes / (1024 * 1024)
                return round(size_mb)

        except (subprocess.TimeoutExpired, ValueError) as e:
            logger.debug(f"Failed to get size for {image}: {e}")

        return 0.0

    def get_image_created_date(self, image: str) -> Optional[str]:
        """
        Get image creation timestamp.

        Args:
            image: Image reference

        Returns:
            ISO 8601 timestamp string (e.g., "2024-10-27T12:31:00.000Z") or None if unavailable
        """
        try:
            result = subprocess.run(
                [self.runtime, "inspect", "--format={{.Created}}", image],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                created = result.stdout.strip()
                return created if created else None

        except (subprocess.TimeoutExpired, ValueError) as e:
            logger.debug(f"Failed to get creation date for {image}: {e}")

        return None

    def pull_image(self, image: str, platform: Optional[str] = None) -> bool:
        """
        Pull an image from registry.

        Args:
            image: Image reference to pull
            platform: Platform specification (default: "linux/amd64")

        Returns:
            True if pull succeeded, False otherwise
        """
        try:
            # Default to linux/amd64 for consistency across environments
            platform = platform or DEFAULT_PLATFORM

            cmd = [self.runtime, "pull", "--platform", platform, image]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            return result.returncode == 0

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout pulling {image}")
            return False

    def image_exists_in_registry(self, image: str) -> bool:
        """
        Check if an image exists in the remote registry.

        Args:
            image: Image reference to check

        Returns:
            True if image exists in registry, False otherwise
        """
        try:
            result = subprocess.run(
                [self.runtime, "manifest", "inspect", image],
                capture_output=True,
                timeout=30
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _has_registry_prefix(self, image: str) -> bool:
        """
        Check if an image already has a registry prefix.

        Args:
            image: Image reference to check

        Returns:
            True if image has a registry prefix, False otherwise
        """
        # If there's no slash, it's a simple image name (e.g., "ubuntu")
        if "/" not in image:
            return False

        # Split on first slash to get potential registry part
        first_part = image.split("/")[0]

        # If first part contains a dot or colon, it's likely a registry
        # (e.g., "gcr.io", "registry.example.com:5000")
        return "." in first_part or ":" in first_part

    def _try_mirror_gcr_fallback(self, image: str) -> Optional[str]:
        """
        Try to construct a mirror.gcr.io fallback URL for Docker Hub images.

        Args:
            image: Original image reference

        Returns:
            mirror.gcr.io URL if applicable, None otherwise
        """
        # Only apply to Docker Hub images (no existing registry prefix)
        if self._has_registry_prefix(image):
            logger.debug(f"Image {image} already has registry prefix, skipping mirror.gcr.io fallback")
            return None

        # Skip digest-based images
        if "@sha256:" in image:
            logger.debug(f"Image {image} is digest-based, skipping mirror.gcr.io fallback")
            return None

        # Transform official images: ubuntu:20.04 -> mirror.gcr.io/library/ubuntu:20.04
        # Transform user/org images: user/repo:tag -> mirror.gcr.io/user/repo:tag
        if "/" not in image:
            # Official image (e.g., ubuntu, node, python)
            mirror_image = f"mirror.gcr.io/library/{image}"
        else:
            # User/org image (e.g., user/repo:tag)
            mirror_image = f"mirror.gcr.io/{image}"

        logger.debug(f"Mirror.gcr.io fallback for {image}: {mirror_image}")
        return mirror_image

    def pull_image_with_fallback(self, image: str, platform: Optional[str] = None) -> tuple[str, bool, bool]:
        """
        Pull an image from registry with intelligent fallback strategies.

        Strategy order:
        1. Try exact image as specified
        2. If Docker Hub image and failed, try mirror.gcr.io fallback FIRST
        3. If that fails, try with :latest tag as last resort

        Args:
            image: Image reference to pull
            platform: Platform specification (default: "linux/amd64")

        Returns:
            Tuple of (image_used, used_fallback, pull_successful) where:
                - image_used: The actual image reference that was pulled (or attempted)
                - used_fallback: True if any fallback was used, False otherwise
                - pull_successful: True if image was successfully pulled, False otherwise
        """
        platform = platform or DEFAULT_PLATFORM
        original_image = image

        # Strategy 1: Try to pull the exact image
        logger.debug(f"Attempting to pull {image}")

        try:
            result = subprocess.run(
                [self.runtime, "pull", "--platform", platform, image],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                logger.debug(f"Successfully pulled {image}")
                return image, False, True

            # Check error type
            stderr = result.stderr.lower()
            is_not_found = any(msg in stderr for msg in [
                "not found",
                "manifest unknown",
                "does not exist",
                "no such image",
                "404"
            ])
            is_rate_limited = any(msg in stderr for msg in [
                "toomanyrequests",
                "rate limit",
                "too many requests"
            ])

            # If not found OR rate limited, try fallbacks
            if is_not_found or is_rate_limited:
                if is_rate_limited:
                    logger.warning(f"Rate limited accessing {image}, trying fallback strategies")
                else:
                    logger.warning(f"Image {image} not found, trying fallback strategies")

                # Strategy 2: Try mirror.gcr.io fallback FIRST for Docker Hub images
                mirror_image = self._try_mirror_gcr_fallback(original_image)
                if mirror_image:
                    logger.warning(
                        f"Trying mirror.gcr.io fallback for {original_image} -> {mirror_image}"
                    )

                    result = subprocess.run(
                        [self.runtime, "pull", "--platform", platform, mirror_image],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    if result.returncode == 0:
                        logger.info(f"✓ Mirror.gcr.io fallback successful for {mirror_image}")
                        return mirror_image, True, True

                    logger.debug(f"Mirror.gcr.io fallback also failed: {result.stderr}")

                # Strategy 3: Try fallback to :latest as last resort (if not already using it and not digest-based)
                if not image.endswith(":latest") and "@sha256:" not in image and ":" in image:
                    base_image = image.rsplit(":", 1)[0]
                    latest_image = f"{base_image}:latest"

                    logger.warning(
                        f"Trying :latest fallback: {latest_image}"
                    )

                    result = subprocess.run(
                        [self.runtime, "pull", "--platform", platform, latest_image],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    if result.returncode == 0:
                        logger.info(f"✓ Successfully fell back to {latest_image}")
                        return latest_image, True, True

                    logger.debug(f"Fallback to {latest_image} also failed: {result.stderr}")

                # All fallback strategies failed
                logger.error(f"All fallback strategies failed for {original_image}")
                return original_image, False, False
            else:
                # Not a "not found" or rate limit error
                logger.error(f"Failed to pull {image}: {result.stderr}")
                return image, False, False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout pulling {image}")
            return image, False, False

    def ensure_chainguard_auth(self) -> bool:
        """
        Ensure authentication to cgr.dev is configured.

        For local execution: Checks if chainctl is authenticated
        For containers: Trusts that Docker credential helper is configured on host

        Returns:
            True if authentication is configured or chainctl not available (container mode)
        """
        try:
            # Check if chainctl is available
            result = subprocess.run(
                ["chainctl", "version"],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                # chainctl not found - assume running in container with host Docker auth
                logger.info("✓ Running in container mode, using host Docker authentication")
                return True

            # chainctl available - check if authenticated
            token_result = subprocess.run(
                ["chainctl", "auth", "token"],
                capture_output=True,
                timeout=10
            )

            if token_result.returncode == 0:
                logger.info("✓ Chainguard authentication configured")
                return True

            # Not authenticated, try to login
            logger.info("Authenticating to Chainguard...")
            login_result = subprocess.run(
                ["chainctl", "auth", "login"],
                capture_output=True,
                timeout=60
            )

            if login_result.returncode == 0:
                logger.info("✓ Authenticated to Chainguard")
                return True

            logger.debug("chainctl auth login failed")
            return False

        except (subprocess.TimeoutExpired, FileNotFoundError):
            # chainctl not available - assume container mode
            logger.info("✓ Running in container mode, using host Docker authentication")
            return True
        except Exception as e:
            logger.debug(f"Error checking Chainguard authentication: {e}")
            # On error, assume container mode and let Docker handle auth
            return True
