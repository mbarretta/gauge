"""
Docker/Podman utility functions for image operations.

Provides a unified interface for working with container images,
supporting both Docker and Podman automatically.
"""

import json
import logging
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

    def ensure_fresh_image(self, image: str, platform: Optional[str] = None) -> bool:
        """
        Ensure local image is up-to-date with remote.

        Args:
            image: Image reference to check/pull
            platform: Platform specification (default: "linux/amd64")

        Returns:
            True if image was updated, False otherwise
        """
        try:
            # Default to linux/amd64 for consistency across environments
            platform = platform or DEFAULT_PLATFORM

            remote_digest = self.get_remote_digest(image)
            if not remote_digest:
                logger.debug(f"Could not get remote digest for {image}")
                return False

            local_digest = self.get_image_digest(image)

            if not local_digest or local_digest != remote_digest:
                logger.info(f"Pulling fresh copy of {image} ({platform})")
                result = subprocess.run(
                    [self.runtime, "pull", "--platform", platform, image],
                    capture_output=True,
                    timeout=300
                )
                return result.returncode == 0

            logger.debug(f"Image {image} is up-to-date")
            return False

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout pulling {image}")
            return False

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
                timeout=300
            )

            return result.returncode == 0

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout pulling {image}")
            return False

    def ensure_chainguard_auth(self) -> bool:
        """
        Ensure authentication to cgr.dev/chainguard-private via chainctl.

        This prevents multiple threads from spawning separate authentication
        requests when pulling Chainguard private images.

        Returns:
            True if authenticated successfully, False otherwise
        """
        try:
            # Check if chainctl is available
            result = subprocess.run(
                ["chainctl", "version"],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.debug("chainctl not found, skipping Chainguard authentication")
                return False

            # Perform authentication via chainctl auth login with org-name
            logger.info("Authenticating to cgr.dev/chainguard-private via chainctl...")
            result = subprocess.run(
                ["chainctl", "auth", "login", "--org-name", "chainguard-private"],
                capture_output=True,
                timeout=60
            )

            if result.returncode == 0:
                logger.info("✓ Authenticated to cgr.dev/chainguard-private")
                return True
            else:
                stderr = result.stderr.decode('utf-8') if result.stderr else ""
                logger.warning(f"chainctl auth login failed: {stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Timeout during chainctl auth login")
            return False
        except FileNotFoundError:
            logger.debug("chainctl not found in PATH")
            return False
        except Exception as e:
            logger.error(f"Error during Chainguard authentication: {e}")
            return False
