"""
Automatic image matching for Chainguard equivalents.

Implements a 4-tier matching strategy to automatically find Chainguard images
corresponding to alternative/customer images.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from integrations.dfc_mappings import DFCMappings
from integrations.github_metadata import GitHubMetadataClient

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of an image matching attempt."""

    chainguard_image: Optional[str]
    """Matched Chainguard image reference"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    method: str
    """Matching method used (dfc, manual, heuristic, fuzzy, none)"""

    alternatives: list[str] = None
    """Alternative matches (for fuzzy results)"""


class ImageMatcher:
    """
    Automatic image matcher using 4-tier strategy.

    Tier 1: DFC Mappings (95% confidence)
    Tier 2: Local Manual Overrides (100% confidence)
    Tier 3: Heuristic Rules (85% confidence)
    Tier 4: Fuzzy Search (70%+ confidence)
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        dfc_mappings_file: Optional[Path] = None,
        manual_mappings_file: Optional[Path] = None,
        github_token: Optional[str] = None,
    ):
        """
        Initialize image matcher.

        Args:
            cache_dir: Cache directory for DFC mappings
            dfc_mappings_file: Optional local DFC mappings file
            manual_mappings_file: Optional local manual overrides file
            github_token: GitHub token for metadata API access
        """
        self.dfc = DFCMappings(cache_dir=cache_dir, local_file=dfc_mappings_file)
        self.manual_mappings_file = manual_mappings_file or Path("config/image_mappings.yaml")
        self.manual_mappings: dict[str, str] = {}
        self.github_metadata = GitHubMetadataClient(github_token=github_token)

        # Load mappings
        self.dfc.load_mappings()
        self._load_manual_mappings()

    def match(self, alternative_image: str) -> MatchResult:
        """
        Find Chainguard image match for alternative image.

        Uses 4-tier strategy with confidence scoring.

        Args:
            alternative_image: Alternative/source image reference

        Returns:
            MatchResult with matched image and metadata
        """
        # Tier 1: Check DFC mappings
        dfc_match = self.dfc.match_image(alternative_image)
        if dfc_match:
            logger.debug(f"DFC match found for {alternative_image}: {dfc_match}")
            return MatchResult(
                chainguard_image=dfc_match,
                confidence=0.95,
                method="dfc"
            )

        # Tier 2: Check local manual overrides
        if alternative_image in self.manual_mappings:
            manual_match = self.manual_mappings[alternative_image]
            logger.debug(f"Manual mapping found for {alternative_image}: {manual_match}")
            return MatchResult(
                chainguard_image=manual_match,
                confidence=1.0,
                method="manual"
            )

        # Tier 3: Apply heuristic rules
        heuristic_match = self._apply_heuristics(alternative_image)
        if heuristic_match:
            logger.debug(f"Heuristic match found for {alternative_image}: {heuristic_match}")
            return MatchResult(
                chainguard_image=heuristic_match,
                confidence=0.85,
                method="heuristic"
            )

        # Tier 4: Fuzzy search (not implemented yet - return no match)
        logger.debug(f"No match found for {alternative_image}")
        return MatchResult(
            chainguard_image=None,
            confidence=0.0,
            method="none"
        )

    def _load_manual_mappings(self) -> None:
        """Load manual override mappings from YAML file."""
        if not self.manual_mappings_file.exists():
            logger.debug(f"No manual mappings file found at {self.manual_mappings_file}")
            return

        try:
            with open(self.manual_mappings_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                logger.debug("Manual mappings file is empty")
                return

            if not isinstance(data, dict):
                logger.warning(f"Invalid manual mappings format in {self.manual_mappings_file}")
                return

            self.manual_mappings = data
            logger.info(f"Loaded {len(self.manual_mappings)} manual image mappings")

        except Exception as e:
            logger.warning(f"Failed to load manual mappings: {e}")

    def _apply_heuristics(self, alternative_image: str) -> Optional[str]:
        """
        Apply heuristic transformation rules.

        Generates candidate Chainguard images and verifies existence.

        Args:
            alternative_image: Source image to transform

        Returns:
            Matched Chainguard image if found and verified, else None
        """
        base_name = self._extract_base_name(alternative_image)
        candidates = self._generate_candidates(base_name, alternative_image)

        # Try each candidate and verify existence
        for candidate in candidates:
            if self._verify_image_exists(candidate):
                return candidate

        return None

    def _generate_candidates(self, base_name: str, full_image: str) -> list[str]:
        """
        Generate candidate Chainguard image names.

        Args:
            base_name: Base image name (e.g., 'nginx', 'python')
            full_image: Full alternative image reference

        Returns:
            List of candidate Chainguard images to try
        """
        candidates = []

        # Check if it's a bitnami image
        is_bitnami = "bitnami" in full_image.lower()

        # Rule 1: Direct with -fips suffix
        candidates.append(f"cgr.dev/chainguard/{base_name}-fips:latest")

        # Rule 2: Direct without -fips (for images that don't have FIPS variant)
        candidates.append(f"cgr.dev/chainguard/{base_name}:latest")

        # Rule 3: Bitnami variant (renamed to iamguarded)
        if is_bitnami:
            candidates.append(f"cgr.dev/chainguard/{base_name}-iamguarded-fips:latest")
            candidates.append(f"cgr.dev/chainguard/{base_name}-iamguarded:latest")
            # Also try without iamguarded (some bitnami images might not have this suffix)
            candidates.append(f"cgr.dev/chainguard/{base_name}-bitnami-fips:latest")

        # Rule 4: Flatten complex paths (e.g., kube-state-metrics/kube-state-metrics → kube-state-metrics)
        if "/" in full_image:
            parts = full_image.split("/")
            # Try last component
            last_component = parts[-1].split(":")[0].split("@")[0]
            if last_component != base_name:
                candidates.append(f"cgr.dev/chainguard/{last_component}-fips:latest")
                candidates.append(f"cgr.dev/chainguard/{last_component}:latest")

            # Try last two components joined with hyphen
            if len(parts) >= 2:
                second_last = parts[-2]
                hyphenated = f"{second_last}-{last_component}"
                candidates.append(f"cgr.dev/chainguard/{hyphenated}-fips:latest")
                candidates.append(f"cgr.dev/chainguard/{hyphenated}:latest")

        # Rule 5: Common name variations
        name_variations = self._get_name_variations(base_name)
        for variation in name_variations:
            candidates.append(f"cgr.dev/chainguard/{variation}-fips:latest")
            candidates.append(f"cgr.dev/chainguard/{variation}:latest")

        return candidates

    def _extract_base_name(self, image: str) -> str:
        """
        Extract base image name from full reference.

        Examples:
            docker.io/library/python:3.12 → python
            gcr.io/kaniko-project/executor:latest → executor
            nginx:1.25 → nginx
            bitnami/postgresql → postgresql
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

    def _get_name_variations(self, base_name: str) -> list[str]:
        """
        Get common name variations for base image.

        Handles common naming differences between upstream and Chainguard.

        Args:
            base_name: Base image name

        Returns:
            List of name variations to try
        """
        variations = []

        # Common variations
        name_map = {
            "mongo": "mongodb",
            "postgresql": "postgres",
            "node-chrome": "node-chromium",
            # Add more as discovered
        }

        if base_name in name_map:
            variations.append(name_map[base_name])

        return variations

    def _verify_image_exists(self, image: str) -> bool:
        """
        Verify if Chainguard image exists.

        Uses GitHub metadata API to check if image exists in catalog.

        Args:
            image: Full Chainguard image reference

        Returns:
            True if image exists, False otherwise
        """
        # Extract image name from reference
        # cgr.dev/chainguard/python:latest → python
        # cgr.dev/chainguard-private/nginx-fips:latest → nginx-fips
        if "cgr.dev/chainguard" in image:
            parts = image.split("/")
            if len(parts) >= 3:
                image_name = parts[2].split(":")[0]

                # Try to fetch metadata
                try:
                    tier = self.github_metadata.get_image_tier(image_name)
                    return tier is not None
                except Exception as e:
                    logger.debug(f"Failed to verify image {image_name}: {e}")
                    return False

        return False
