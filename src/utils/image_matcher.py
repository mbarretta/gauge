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

from constants import (
    CHAINGUARD_PRIVATE_REGISTRY,
    CHAINGUARD_PUBLIC_REGISTRY,
    MATCH_CONFIDENCE_DFC,
    MATCH_CONFIDENCE_HEURISTIC,
    MATCH_CONFIDENCE_MANUAL,
)
from integrations.dfc_mappings import DFCMappings
from integrations.github_metadata import GitHubMetadataClient
from utils.upstream_finder import UpstreamImageFinder

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of an image matching attempt."""

    chainguard_image: Optional[str]
    """Matched Chainguard image reference"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    method: str
    """Matching method used (dfc, manual, heuristic, llm, none)"""

    alternatives: list[str] = None
    """Alternative matches (for fuzzy results)"""

    upstream_image: Optional[str] = None
    """Discovered upstream image (if upstream finding was enabled)"""

    upstream_confidence: Optional[float] = None
    """Upstream discovery confidence score"""

    upstream_method: Optional[str] = None
    """Upstream discovery method used"""

    reasoning: Optional[str] = None
    """LLM reasoning (if method is llm)"""


class CandidateStrategy:
    """
    Base strategy for generating candidate Chainguard image names.

    Each strategy implements a specific heuristic for transforming
    alternative image names into potential Chainguard equivalents.
    """

    def generate(self, base_name: str, full_image: str, has_fips: bool) -> list[str]:
        """
        Generate candidate Chainguard images.

        Args:
            base_name: Extracted base image name (e.g., 'nginx', 'python')
            full_image: Full alternative image reference
            has_fips: Whether the image has FIPS indicators

        Returns:
            List of candidate Chainguard image references
        """
        raise NotImplementedError


class BitnamiStrategy(CandidateStrategy):
    """Strategy for Bitnami images → -iamguarded variants."""

    def generate(self, base_name: str, full_image: str, has_fips: bool) -> list[str]:
        """Generate candidates for Bitnami images."""
        if "bitnami" not in full_image.lower():
            return []

        candidates = []

        if has_fips:
            # Rule 1: Bitnami FIPS → -iamguarded-fips (priority)
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-iamguarded-fips:latest")
            # Rule 2: Fallback to -fips
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-fips:latest")
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-bitnami-fips:latest")
            # Rule 3: Fallback to non-FIPS -iamguarded
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-iamguarded:latest")
        else:
            # Rule 4: Bitnami → -iamguarded (priority)
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-iamguarded:latest")

        # Rule 5: Direct match as fallback for Bitnami
        candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}:latest")

        return candidates


class DirectMatchStrategy(CandidateStrategy):
    """Strategy for direct base name matching (non-Bitnami)."""

    def generate(self, base_name: str, full_image: str, has_fips: bool) -> list[str]:
        """Generate direct match candidates."""
        # Only apply to non-Bitnami images
        if "bitnami" in full_image.lower():
            return []

        candidates = []

        if has_fips:
            # Rule 6: Non-Bitnami FIPS → direct -fips
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}-fips:latest")

        # Rule 7: Direct match without -fips
        candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{base_name}:latest")

        return candidates


class PathFlatteningStrategy(CandidateStrategy):
    """Strategy for flattening complex image paths."""

    def generate(self, base_name: str, full_image: str, has_fips: bool) -> list[str]:
        """Generate candidates from complex paths."""
        # Rule 8: Flatten complex paths (e.g., kube-state-metrics/kube-state-metrics → kube-state-metrics)
        if "/" not in full_image:
            return []

        candidates = []
        parts = full_image.split("/")

        # Try last component
        last_component = parts[-1].split(":")[0].split("@")[0].lower()
        # Strip FIPS suffix to avoid double-suffixing
        last_component = re.sub(r"[-_]fips$", "", last_component)

        if last_component != base_name:
            if has_fips:
                candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{last_component}-fips:latest")
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{last_component}:latest")

        # Try last two components joined with hyphen
        # (e.g., ghcr.io/kyverno/background-controller → kyverno-background-controller)
        if len(parts) >= 2:
            second_last = parts[-2]
            hyphenated = f"{second_last}-{last_component}"
            if has_fips:
                candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{hyphenated}-fips:latest")
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{hyphenated}:latest")

        return candidates


class NameVariationStrategy(CandidateStrategy):
    """Strategy for common name variations (mongo → mongodb, etc.)."""

    # Common variations mapping
    NAME_MAP = {
        "mongo": "mongodb",
        "postgresql": "postgres",
        "node-chrome": "node-chromium",
        # Add more as discovered
    }

    def generate(self, base_name: str, full_image: str, has_fips: bool) -> list[str]:
        """Generate candidates from name variations."""
        # Rule 9: Common name variations
        if base_name not in self.NAME_MAP:
            return []

        candidates = []
        variation = self.NAME_MAP[base_name]

        if has_fips:
            candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{variation}-fips:latest")
        candidates.append(f"{CHAINGUARD_PRIVATE_REGISTRY}/{variation}:latest")

        return candidates


class TierMatcher:
    """
    Base class for tier-based image matchers.

    Each tier implements a specific matching strategy with associated confidence level.
    """

    def match(self, image: str) -> Optional[MatchResult]:
        """
        Attempt to match image using this tier's strategy.

        Args:
            image: Image reference to match

        Returns:
            MatchResult if match found, None otherwise
        """
        raise NotImplementedError


class Tier1DFCMatcher(TierMatcher):
    """Tier 1: DFC (Directory-for-Chainguard) Mappings - 95% confidence."""

    def __init__(self, cache_dir: Optional[Path] = None, dfc_mappings_file: Optional[Path] = None):
        """
        Initialize DFC matcher.

        Args:
            cache_dir: Cache directory for DFC mappings
            dfc_mappings_file: Optional local DFC mappings file
        """
        self.dfc = DFCMappings(cache_dir=cache_dir, local_file=dfc_mappings_file)
        self.dfc.load_mappings()

    def match(self, image: str) -> Optional[MatchResult]:
        """Match using DFC mappings."""
        dfc_match = self.dfc.match_image(image)
        if dfc_match:
            # Convert public registry to private
            if dfc_match.startswith(f"{CHAINGUARD_PUBLIC_REGISTRY}/"):
                dfc_match = dfc_match.replace(f"{CHAINGUARD_PUBLIC_REGISTRY}/", f"{CHAINGUARD_PRIVATE_REGISTRY}/", 1)

            logger.debug(f"DFC match found for {image}: {dfc_match}")
            return MatchResult(
                chainguard_image=dfc_match,
                confidence=MATCH_CONFIDENCE_DFC,
                method="dfc",
            )
        return None


class Tier2ManualMatcher(TierMatcher):
    """Tier 2: Local Manual Overrides - 100% confidence."""

    def __init__(self, manual_mappings_file: Optional[Path] = None):
        """
        Initialize manual matcher.

        Args:
            manual_mappings_file: Optional local manual overrides file
        """
        self.manual_mappings_file = manual_mappings_file or Path("config/image_mappings.yaml")
        self.manual_mappings: dict[str, str] = {}
        self._load_manual_mappings()

    def match(self, image: str) -> Optional[MatchResult]:
        """Match using manual mappings."""
        if image in self.manual_mappings:
            manual_match = self.manual_mappings[image]
            # Convert public registry to private
            if manual_match.startswith(f"{CHAINGUARD_PUBLIC_REGISTRY}/"):
                manual_match = manual_match.replace(f"{CHAINGUARD_PUBLIC_REGISTRY}/", f"{CHAINGUARD_PRIVATE_REGISTRY}/", 1)

            logger.debug(f"Manual mapping found for {image}: {manual_match}")
            return MatchResult(
                chainguard_image=manual_match,
                confidence=MATCH_CONFIDENCE_MANUAL,
                method="manual",
            )
        return None

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


class Tier3HeuristicMatcher(TierMatcher):
    """Tier 3: Heuristic Rules - 85% confidence."""

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize heuristic matcher.

        Args:
            github_token: GitHub token for metadata API access (for image verification)
        """
        self.github_metadata = GitHubMetadataClient(github_token=github_token)
        # Initialize candidate generation strategies
        self.strategies = [
            BitnamiStrategy(),
            DirectMatchStrategy(),
            PathFlatteningStrategy(),
            NameVariationStrategy(),
        ]

    def match(self, image: str) -> Optional[MatchResult]:
        """Match using heuristic rules."""
        base_name = self._extract_base_name(image)
        candidates = self._generate_candidates(base_name, image)

        # Try each candidate and verify existence
        for candidate in candidates:
            if self._verify_image_exists(candidate):
                logger.debug(f"Heuristic match found for {image}: {candidate}")
                return MatchResult(
                    chainguard_image=candidate,
                    confidence=MATCH_CONFIDENCE_HEURISTIC,
                    method="heuristic",
                )

        return None

    def _has_fips_indicator(self, image: str) -> bool:
        """Check if image name/tag has FIPS indicators."""
        image_lower = image.lower()
        fips_patterns = [
            "-fips",
            "_fips",
            ":fips",
            "fips-",
            "fips_",
            "/fips",
        ]
        return any(pattern in image_lower for pattern in fips_patterns)

    def _generate_candidates(self, base_name: str, full_image: str) -> list[str]:
        """Generate candidate Chainguard image names using strategy pattern."""
        has_fips = self._has_fips_indicator(full_image)

        # Apply all strategies and collect candidates
        candidates = []
        for strategy in self.strategies:
            strategy_candidates = strategy.generate(base_name, full_image, has_fips)
            candidates.extend(strategy_candidates)

        return candidates

    def _extract_base_name(self, image: str) -> str:
        """Extract base image name from full reference."""
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

        image = image.lower()

        # Strip FIPS suffixes to avoid double-suffixing
        image = re.sub(r"[-_]fips$", "", image)

        return image

    def _verify_image_exists(self, image: str) -> bool:
        """Verify if Chainguard image exists."""
        # Extract image name from reference
        if image.startswith(f"{CHAINGUARD_PRIVATE_REGISTRY}/") or image.startswith(f"{CHAINGUARD_PUBLIC_REGISTRY}/"):
            parts = image.split("/")
            if len(parts) >= 3:
                image_name = parts[2].split(":")[0]

                # Try to fetch metadata from GitHub API
                try:
                    tier = self.github_metadata.get_image_tier(image_name)
                    if tier is not None:
                        return True
                except Exception as e:
                    logger.debug(f"GitHub metadata not found for {image_name}: {e}")

                # Fallback to docker manifest inspect
                logger.debug(f"Falling back to docker verification for {image}")
                from utils.docker_utils import image_exists_in_registry
                try:
                    return image_exists_in_registry(image)
                except Exception as e:
                    logger.debug(f"Docker verification failed for {image}: {e}")
                    return False

        return False


class Tier4LLMMatcher(TierMatcher):
    """Tier 4: LLM-Powered Fuzzy Matching - 70%+ confidence."""

    def __init__(self, llm_matcher, github_token: Optional[str] = None):
        """
        Initialize LLM matcher.

        Args:
            llm_matcher: Configured LLMMatcher instance
            github_token: GitHub token for image verification
        """
        self.llm_matcher = llm_matcher
        self.github_metadata = GitHubMetadataClient(github_token=github_token)

    def match(self, image: str) -> Optional[MatchResult]:
        """Match using LLM fuzzy matching."""
        if not self.llm_matcher:
            return None

        llm_result = self.llm_matcher.match(image)
        if llm_result.chainguard_image and llm_result.confidence >= self.llm_matcher.confidence_threshold:
            # Verify the LLM-suggested image actually exists
            if self._verify_image_exists(llm_result.chainguard_image):
                logger.debug(
                    f"LLM match found and verified for {image}: {llm_result.chainguard_image} "
                    f"(confidence: {llm_result.confidence:.0%})"
                )
                return MatchResult(
                    chainguard_image=llm_result.chainguard_image,
                    confidence=llm_result.confidence,
                    method="llm",
                    reasoning=llm_result.reasoning,
                )
            else:
                logger.warning(
                    f"LLM suggested {llm_result.chainguard_image} for {image}, "
                    f"but image does not exist (hallucination)"
                )

        return None

    def _verify_image_exists(self, image: str) -> bool:
        """Verify if Chainguard image exists."""
        # Extract image name from reference
        if image.startswith(f"{CHAINGUARD_PRIVATE_REGISTRY}/") or image.startswith(f"{CHAINGUARD_PUBLIC_REGISTRY}/"):
            parts = image.split("/")
            if len(parts) >= 3:
                image_name = parts[2].split(":")[0]

                # Try to fetch metadata from GitHub API
                try:
                    tier = self.github_metadata.get_image_tier(image_name)
                    if tier is not None:
                        return True
                except Exception as e:
                    logger.debug(f"GitHub metadata not found for {image_name}: {e}")

                # Fallback to docker manifest inspect
                logger.debug(f"Falling back to docker verification for {image}")
                from utils.docker_utils import image_exists_in_registry
                try:
                    return image_exists_in_registry(image)
                except Exception as e:
                    logger.debug(f"Docker verification failed for {image}: {e}")
                    return False

        return False


class ImageMatcher:
    """
    Orchestrates 4-tier image matching strategy.

    Coordinates tier-based matchers to find Chainguard equivalents
    for alternative container images.

    Tier 1: DFC Mappings (95% confidence)
    Tier 2: Local Manual Overrides (100% confidence)
    Tier 3: Heuristic Rules (85% confidence)
    Tier 4: LLM-Powered Fuzzy Matching (70%+ confidence)
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        dfc_mappings_file: Optional[Path] = None,
        manual_mappings_file: Optional[Path] = None,
        github_token: Optional[str] = None,
        upstream_finder: Optional[UpstreamImageFinder] = None,
        llm_matcher=None,
    ):
        """
        Initialize image matcher coordinator.

        Args:
            cache_dir: Cache directory for DFC mappings
            dfc_mappings_file: Optional local DFC mappings file
            manual_mappings_file: Optional local manual overrides file
            github_token: GitHub token for metadata API access
            upstream_finder: Optional upstream image finder for discovering public equivalents
            llm_matcher: Optional LLM matcher for Tier 4 fuzzy matching
        """
        self.upstream_finder = upstream_finder

        # Initialize tier-based matchers
        self.tier1 = Tier1DFCMatcher(cache_dir=cache_dir, dfc_mappings_file=dfc_mappings_file)
        self.tier2 = Tier2ManualMatcher(manual_mappings_file=manual_mappings_file)
        self.tier3 = Tier3HeuristicMatcher(github_token=github_token)
        self.tier4 = Tier4LLMMatcher(llm_matcher=llm_matcher, github_token=github_token) if llm_matcher else None

    def match(self, alternative_image: str) -> MatchResult:
        """
        Find Chainguard image match for alternative image.

        Orchestrates 4-tier matching strategy with upstream discovery support.

        Args:
            alternative_image: Alternative/source image reference

        Returns:
            MatchResult with matched image and metadata
        """
        # Step 0: Try upstream discovery first (if enabled)
        upstream_result = None
        image_to_match = alternative_image

        if self.upstream_finder:
            upstream_result = self.upstream_finder.find_upstream(alternative_image)
            if upstream_result.upstream_image:
                logger.info(
                    f"Upstream found: {alternative_image} → {upstream_result.upstream_image} "
                    f"(confidence: {upstream_result.confidence:.0%}, method: {upstream_result.method})"
                )
                image_to_match = upstream_result.upstream_image

        # Try each tier in sequence until a match is found
        for tier_matcher in [self.tier1, self.tier2, self.tier3, self.tier4]:
            if tier_matcher is None:
                continue

            result = tier_matcher.match(image_to_match)
            if result:
                # Add upstream information if available
                result.upstream_image = upstream_result.upstream_image if upstream_result else None
                result.upstream_confidence = upstream_result.confidence if upstream_result else None
                result.upstream_method = upstream_result.method if upstream_result else None
                return result

        # No match found
        logger.debug(f"No match found for {image_to_match}")
        return MatchResult(
            chainguard_image=None,
            confidence=0.0,
            method="none",
            upstream_image=upstream_result.upstream_image if upstream_result else None,
            upstream_confidence=upstream_result.confidence if upstream_result else None,
            upstream_method=upstream_result.method if upstream_result else None,
        )
