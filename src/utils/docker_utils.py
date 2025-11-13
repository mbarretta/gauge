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

    def ensure_fresh_image(self, image: str, platform: Optional[str] = None, upstream_image: Optional[str] = None) -> tuple[str, bool, bool]:
        """
        Ensure local image is up-to-date with remote, with intelligent fallback strategies.

        Args:
            image: Image reference to check/pull
            platform: Platform specification (default: "linux/amd64")
            upstream_image: Optional upstream image to try as fallback (e.g., docker.io equivalent)

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
                return self.pull_image_with_fallback(image, platform, upstream_image=upstream_image)

            local_digest = self.get_image_digest(image)

            if not local_digest or local_digest != remote_digest:
                logger.info(f"Pulling fresh copy of {image} ({platform})")
                return self.pull_image_with_fallback(image, platform, upstream_image=upstream_image)

            logger.debug(f"Image {image} is up-to-date")
            return image, False, True

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout pulling {image}")
            return image, False, False

    def get_image_size_mb(self, image: str) -> float:
        """
        Get image size in megabytes.

        Uses 'docker images' command instead of 'inspect' because the .Size field
        in inspect returns only the top layer size, not the full image size.

        Args:
            image: Image reference

        Returns:
            Size in MB, rounded to nearest integer
        """
        def parse_size(size_str: str) -> float:
            """Parse human-readable size string to MB."""
            if not size_str:
                return 0.0
            
            # Parse human-readable size (e.g., "1.25GB", "234MB", "45.3kB")
            size_str = size_str.upper()
            
            # Extract numeric value
            numeric_part = ""
            unit = ""
            for char in size_str:
                if char.isdigit() or char == '.':
                    numeric_part += char
                elif char.isalpha():
                    unit += char
            
            if not numeric_part:
                return 0.0
            
            value = float(numeric_part)
            
            # Convert to MB
            if "GB" in unit:
                return round(value * 1024)
            elif "MB" in unit:
                return round(value)
            elif "KB" in unit or "K" in unit:
                return round(value / 1024)
            elif "TB" in unit:
                return round(value * 1024 * 1024)
            elif "B" in unit and "KB" not in unit and "MB" not in unit and "GB" not in unit:
                # Just bytes
                return round(value / (1024 * 1024))
            else:
                # Unknown unit, assume MB
                return round(value)
        
        # Try multiple image name variations
        # Docker stores images with short names (e.g., "alpine") but we might query with full names
        image_variations = [image]
        
        # Add short name variation for docker.io/library/* images
        if image.startswith("docker.io/library/"):
            short_name = image.replace("docker.io/library/", "")
            image_variations.append(short_name)
        elif image.startswith("docker.io/"):
            # For other docker.io images, try without the registry prefix
            short_name = image.replace("docker.io/", "")
            image_variations.append(short_name)
        
        for img_name in image_variations:
            try:
                # Use docker images command which reports actual image size
                # Format: {{.Size}} returns human-readable format like "1.25GB" or "234MB"
                result = subprocess.run(
                    [self.runtime, "images", img_name, "--format", "{{.Size}}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    size_str = result.stdout.strip()
                    if size_str:
                        # Take first line in case multiple images match
                        first_line = size_str.split('\n')[0].strip()
                        if first_line:
                            size_mb = parse_size(first_line)
                            if size_mb > 0:
                                logger.debug(f"Got size for {img_name}: {size_mb} MB")
                                return size_mb
                        
            except (subprocess.TimeoutExpired, ValueError) as e:
                logger.debug(f"Failed to get size for {img_name}: {e}")
                continue
        
        # If all variations failed
        logger.debug(f"Could not get size for {image} (tried: {image_variations})")
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

    def _attempt_pull(self, image: str, platform: str) -> tuple[bool, str]:
        """
        Attempt to pull a single image.

        Args:
            image: Image reference to pull
            platform: Platform specification

        Returns:
            Tuple of (success, stderr)
        """
        try:
            result = subprocess.run(
                [self.runtime, "pull", "--platform", platform, image],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0, result.stderr
        except subprocess.TimeoutExpired:
            return False, "timeout"

    def _is_recoverable_error(self, stderr: str) -> bool:
        """Check if error is recoverable with fallback strategies."""
        stderr_lower = stderr.lower()

        not_found_errors = ["not found", "manifest unknown", "does not exist", "no such image", "404"]
        rate_limit_errors = ["toomanyrequests", "rate limit", "too many requests"]
        connection_errors = ["no such host", "connection refused", "dial tcp", "no basic auth credentials", "unauthorized"]

        return any(msg in stderr_lower for msg in not_found_errors + rate_limit_errors + connection_errors)

    def _get_latest_fallback_image(self, image: str) -> str | None:
        """
        Get :latest fallback image if applicable.

        Returns:
            Latest image reference or None if not applicable
        """
        if image.endswith(":latest") or "@sha256:" in image or ":" not in image:
            return None

        base_image = image.rsplit(":", 1)[0]
        return f"{base_image}:latest"

    def pull_image_with_fallback(self, image: str, platform: Optional[str] = None, upstream_image: Optional[str] = None) -> tuple[str, bool, bool]:
        """
        Pull an image from registry with intelligent fallback strategies.

        Strategy order:
        1. Try exact image as specified
        2. If upstream image provided (e.g., from --find-upstream), try that
        3. If Docker Hub image and failed, try mirror.gcr.io fallback
        4. If that fails, try with :latest tag as last resort

        Args:
            image: Image reference to pull
            platform: Platform specification (default: "linux/amd64")
            upstream_image: Optional upstream image to try as fallback (e.g., docker.io equivalent)

        Returns:
            Tuple of (image_used, used_fallback, pull_successful)
        """
        platform = platform or DEFAULT_PLATFORM
        original_image = image

        # Strategy 1: Try to pull the exact image
        logger.debug(f"Attempting to pull {image}")
        success, stderr = self._attempt_pull(image, platform)

        if success:
            logger.debug(f"Successfully pulled {image}")
            return image, False, True

        # Check if error is recoverable
        if not self._is_recoverable_error(stderr):
            logger.error(f"Failed to pull {image}: {stderr}")
            return image, False, False

        logger.warning(f"Image {image} not found or rate limited, trying fallback strategies")

        # Strategy 2: Try upstream image if provided (e.g., docker.io equivalent for private registry)
        if upstream_image:
            logger.warning(f"Trying upstream fallback: {upstream_image}")
            success, stderr = self._attempt_pull(upstream_image, platform)

            if success:
                logger.info(f"✓ Upstream fallback successful: {original_image} → {upstream_image}")
                return upstream_image, True, True

            logger.debug(f"Upstream fallback failed: {stderr}")

        # Strategy 3: Try mirror.gcr.io fallback for Docker Hub images
        mirror_image = self._try_mirror_gcr_fallback(original_image)
        if mirror_image:
            logger.warning(f"Trying mirror.gcr.io fallback: {mirror_image}")
            success, stderr = self._attempt_pull(mirror_image, platform)

            if success:
                logger.info(f"✓ Mirror.gcr.io fallback successful for {mirror_image}")
                return mirror_image, True, True

            logger.debug(f"Mirror.gcr.io fallback failed: {stderr}")

        # Strategy 4: Try :latest fallback as last resort
        latest_image = self._get_latest_fallback_image(image)
        if latest_image:
            logger.warning(f"Trying :latest fallback: {latest_image}")
            success, stderr = self._attempt_pull(latest_image, platform)

            if success:
                logger.info(f"✓ Successfully fell back to {latest_image}")
                return latest_image, True, True

            logger.debug(f"Fallback to {latest_image} failed: {stderr}")

        # All strategies failed
        logger.error(f"All fallback strategies failed for {original_image}")
        return original_image, False, False

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


# Module-level helper functions for convenience
_client = None


def image_exists_in_registry(image: str) -> bool:
    """
    Check if an image exists in the registry.

    Module-level convenience function that creates a shared DockerClient instance.

    Args:
        image: Image reference to check

    Returns:
        True if image exists in registry, False otherwise
    """
    global _client
    if _client is None:
        _client = DockerClient()
    return _client.image_exists_in_registry(image)
