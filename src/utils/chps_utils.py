"""
Utility functions for integrating with CHPS (Container Hardening and Provenance Scanner).

CHPS is a tool that scores container images based on hardening and provenance best practices.
See: https://github.com/chps-dev/chps-scorer

This implementation runs chps-scorer in a container, eliminating the need for local installation.
"""

import json
import logging
import subprocess
from typing import Optional

from core.models import CHPSScore

logger = logging.getLogger(__name__)

# CHPS scorer container image
CHPS_IMAGE = "ghcr.io/chps-dev/chps-scorer:latest"


class CHPSScanner:
    """
    Scanner for running CHPS (Container Hardening and Provenance Scanner).

    CHPS evaluates container images for security hardening and provenance practices,
    providing a score and grade based on various security criteria.

    Runs chps-scorer in a container to avoid requiring local installation.
    """

    def __init__(self, docker_command: str = "docker"):
        """
        Initialize CHPS scanner.

        Args:
            docker_command: Docker/Podman command to use (default: "docker")
        """
        self.docker_command = docker_command
        self.chps_available = self._check_chps_available()
        if not self.chps_available:
            logger.warning(
                f"CHPS container image not available. CHPS scoring will be skipped. "
                f"Run: {docker_command} pull {CHPS_IMAGE}"
            )

    def _check_chps_available(self) -> bool:
        """Check if CHPS container image is available."""
        try:
            logger.info(f"Checking CHPS image availability: {CHPS_IMAGE}")
            # Try to pull the CHPS image if not already present
            result = subprocess.run(
                [self.docker_command, "pull", CHPS_IMAGE],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"✓ CHPS scorer container image ready: {CHPS_IMAGE}")
                return True
            else:
                logger.warning(f"✗ Failed to pull CHPS image: {result.stderr}")
                logger.warning(f"CHPS stdout: {result.stdout}")
                return False
        except FileNotFoundError as e:
            logger.warning(f"✗ Docker/Podman command not found: {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"✗ Timeout pulling CHPS image (120s)")
            return False
        except Exception as e:
            logger.warning(f"✗ CHPS availability check failed: {e}")
            return False

    def scan_image(self, image_name: str) -> Optional[CHPSScore]:
        """
        Run CHPS scoring on a local image using containerized chps-scorer.

        Args:
            image_name: Name/reference of the local image to score

        Returns:
            CHPSScore object with score, grade, and details, or None if scan fails
        """
        if not self.chps_available:
            logger.debug(f"CHPS not available, skipping scan for {image_name}")
            return None

        try:
            logger.info(f"Running CHPS scan on {image_name}...")

            # Run chps-scorer in a container with access to Docker socket
            # chps-scorer uses Docker-in-Docker, requires --privileged
            # Syntax: chps-scorer -o json --skip-cves --local <image>
            cmd = [
                self.docker_command,
                "run",
                "--rm",
                "--privileged",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                CHPS_IMAGE,
                "-o", "json",
                "--skip-cves",
                "--local",
                image_name,
            ]

            logger.debug(f"CHPS command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                logger.warning(f"CHPS scan failed for {image_name}: {result.stderr}")
                logger.debug(f"CHPS stdout: {result.stdout}")
                return None

            # Parse JSON output
            # CHPS output has "Using local image: ..." prefix before JSON, skip it
            output_text = result.stdout.strip()

            # Find the start of JSON (first '{')
            json_start = output_text.find('{')
            if json_start == -1:
                logger.warning(f"No JSON found in CHPS output for {image_name}")
                return None

            json_text = output_text[json_start:]
            logger.debug(f"CHPS JSON output for {image_name}: {json_text[:200]}...")

            output_data = json.loads(json_text)

            # Extract score and grade from the JSON structure
            # CHPS returns: {"scores": {"minimalism": {"score": X, "grade": "A"}}}
            scores = output_data.get("scores", {})
            minimalism = scores.get("minimalism", {})

            score = minimalism.get("score", 0.0)
            grade = minimalism.get("grade", "F")

            # Fix grade mapping - CHPS returns "E" for 0, but spec says it should be "F"
            # Spec: 100=A+, 75-99=A, 50-74=B, 40-49=C, 1-39=D, 0=F
            if grade == "E" or score == 0:
                grade = "F"

            # Store detailed breakdown
            details = {
                "scores": scores,  # Include all scores
                "image": output_data.get("image", ""),
                "digest": output_data.get("digest", ""),
            }

            logger.info(f"CHPS scan complete for {image_name}: Score={score}, Grade={grade}")

            return CHPSScore(
                score=score,
                grade=grade,
                details=details,
            )

        except subprocess.TimeoutExpired:
            logger.warning(f"CHPS scan timeout for {image_name}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse CHPS output for {image_name}: {e}")
            return None
        except Exception as e:
            logger.warning(f"CHPS scan error for {image_name}: {e}")
            return None
