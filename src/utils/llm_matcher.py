"""
LLM-powered fuzzy image matching for Chainguard equivalents.

Implements Tier 4 matching using Claude API for complex image name transformations
that can't be handled by heuristics alone.
"""

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import anthropic

from constants import CLI_SUBPROCESS_TIMEOUT, DEFAULT_LLM_CONFIDENCE
from integrations.github_metadata import GitHubMetadataClient

logger = logging.getLogger(__name__)


@dataclass
class LLMMatchResult:
    """Result of an LLM matching attempt."""

    chainguard_image: Optional[str]
    """Matched Chainguard image reference"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    reasoning: str
    """LLM's reasoning for the match"""

    cached: bool = False
    """Whether result was from cache"""

    latency_ms: float = 0.0
    """API call latency in milliseconds"""


class LLMMatcher:
    """
    LLM-powered image matcher using Claude API.

    Uses Claude to perform fuzzy matching for complex image name patterns
    that can't be handled by rule-based heuristics.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5",
        cache_dir: Optional[Path] = None,
        github_token: Optional[str] = None,
        confidence_threshold: float = DEFAULT_LLM_CONFIDENCE,
    ):
        """
        Initialize LLM matcher.

        Args:
            api_key: Anthropic API key (falls back to ANTHROPIC_API_KEY env var)
            model: Claude model to use (default: claude-sonnet-4-5)
            cache_dir: Directory for SQLite cache (default: ~/.cache/gauge)
            github_token: GitHub token for fetching available images
            confidence_threshold: Minimum confidence to consider a match (default: {DEFAULT_LLM_CONFIDENCE})
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.confidence_threshold = confidence_threshold

        if not self.api_key:
            logger.warning(
                "No Anthropic API key found. LLM matching will be disabled. "
                "To enable, either:\n"
                "  1. Set ANTHROPIC_API_KEY environment variable\n"
                "  2. Pass api_key to constructor\n"
                "  3. Use --anthropic-api-key flag"
            )
            self.client = None
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)

        # Initialize cache
        self.cache_dir = cache_dir or Path.home() / ".cache" / "gauge"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_db = self.cache_dir / "llm_cache.db"
        self._init_cache_db()

        # Initialize GitHub metadata client for available images
        self.github_metadata = GitHubMetadataClient(github_token=github_token)

        # Telemetry
        self.telemetry_file = self.cache_dir / "llm_telemetry.jsonl"

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database."""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_cache (
                image_name TEXT PRIMARY KEY,
                model TEXT,
                chainguard_image TEXT,
                confidence REAL,
                reasoning TEXT,
                timestamp INTEGER
            )
        """
        )
        conn.commit()
        conn.close()

    def _get_cached_result(self, image_name: str) -> Optional[LLMMatchResult]:
        """
        Get cached result for image.

        Args:
            image_name: Image name to look up

        Returns:
            Cached result if available, None otherwise
        """
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT chainguard_image, confidence, reasoning
            FROM llm_cache
            WHERE image_name = ? AND model = ?
        """,
            (image_name, self.model),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            logger.debug(f"Cache hit for {image_name}")
            return LLMMatchResult(
                chainguard_image=row[0],
                confidence=row[1],
                reasoning=row[2],
                cached=True,
            )

        return None

    def _cache_result(
        self,
        image_name: str,
        chainguard_image: Optional[str],
        confidence: float,
        reasoning: str,
    ) -> None:
        """
        Cache LLM result.

        Args:
            image_name: Source image name
            chainguard_image: Matched Chainguard image (or None)
            confidence: Confidence score
            reasoning: LLM reasoning
        """
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO llm_cache
            (image_name, model, chainguard_image, confidence, reasoning, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (image_name, self.model, chainguard_image, confidence, reasoning, int(time.time())),
        )
        conn.commit()
        conn.close()

    def _log_telemetry(
        self,
        image_name: str,
        result: LLMMatchResult,
        success: bool,
    ) -> None:
        """
        Log telemetry data for LLM matching.

        Args:
            image_name: Source image name
            result: Match result
            success: Whether a match was found above threshold
        """
        telemetry = {
            "timestamp": int(time.time()),
            "image_name": image_name,
            "model": self.model,
            "chainguard_image": result.chainguard_image,
            "confidence": result.confidence,
            "success": success,
            "cached": result.cached,
            "latency_ms": result.latency_ms,
        }

        with open(self.telemetry_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(telemetry) + "\n")

    def _search_chainguard_images(self, search_term: str, org: str = "chainguard-private") -> list[str]:
        """
        Search for available Chainguard images using chainctl.

        Args:
            search_term: Term to fuzzy search for
            org: Chainguard organization (default: chainguard-private)

        Returns:
            List of matching image names
        """
        # Check if chainctl is available
        if not shutil.which("chainctl"):
            logger.debug("chainctl not available for image search")
            return []

        try:
            # Get all image repos from chainctl
            result = subprocess.run(
                ["chainctl", "img", "repos", "list", "--parent", org, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=CLI_SUBPROCESS_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(f"chainctl img repos list failed: {result.stderr}")
                return []

            # Parse JSON output
            repos_data = json.loads(result.stdout)
            items = repos_data.get("items", [])

            # Extract image names
            all_images = [item.get("name", "") for item in items if item.get("name")]

            # Fuzzy filter using search term
            # Split search term into parts for flexible matching
            search_parts = re.split(r"[-_\s]+", search_term.lower())

            matching_images = []
            for image in all_images:
                image_lower = image.lower()
                # Check if all search parts appear in the image name
                if all(part in image_lower for part in search_parts if len(part) > 2):
                    matching_images.append(image)

            # Sort by relevance (shorter names that contain all terms rank higher)
            matching_images.sort(key=lambda x: len(x))

            logger.debug(f"Found {len(matching_images)} Chainguard images matching '{search_term}': {matching_images[:10]}")
            return matching_images[:20]  # Limit to top 20 matches

        except subprocess.TimeoutExpired:
            logger.warning("chainctl image search timed out")
            return []
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse chainctl output: {e}")
            return []
        except Exception as e:
            logger.warning(f"chainctl image search failed: {e}")
            return []

    def _build_prompt(self, image_name: str) -> str:
        """
        Build matching prompt for Claude.

        Args:
            image_name: Image name to match

        Returns:
            Formatted prompt string
        """
        prompt = f"""You are an expert at matching container images to their Chainguard equivalents.

Your task is to find the best Chainguard image match for the following image:
**Image to match:** {image_name}

**CRITICAL: Do NOT hallucinate or invent image names. Only suggest images that you are highly confident actually exist in the Chainguard registry. If you are not confident that a specific Chainguard image exists, return null with low confidence rather than guessing.**

**Guidelines:**

1. **OS Images Rule (CRITICAL)**: If the image is a base OS image (debian, ubuntu, rhel, centos, alpine-base, almalinux, rocky, etc.), it should ALWAYS map to `cgr.dev/chainguard-private/chainguard-base:latest` with high confidence (0.9+).

2. **Only Common/Popular Images**: Chainguard primarily provides images for popular, widely-used software:
   - Languages: python, node, go, java, ruby, php
   - Databases: postgres, mysql, redis, mongodb
   - Web servers: nginx, apache (httpd)
   - Infrastructure: prometheus, grafana, jenkins, git
   - Kubernetes: kubectl, helm, kube-state-metrics
   - If the image is obscure, niche, or very specialized (like jmeter, selenium, custom tools), return null with confidence 0.0

3. **Naming Patterns:**
   - Strip registry prefixes (docker.io, gcr.io, ghcr.io, quay.io, etc.)
   - Strip organization/vendor prefixes (library, bitnami, etc.)
   - Extract base application name (postgres, nginx, python, etc.)

4. **FIPS Variants:**
   - If input has "-fips" or "_fips" suffix, prefer Chainguard FIPS variants
   - FIPS images are in the private registry: `cgr.dev/chainguard-private/IMAGE-fips:latest`

5. **Bitnami Images:**
   - Bitnami images often have Chainguard "iamguarded" equivalents
   - Example: bitnami/postgresql → cgr.dev/chainguard-private/postgresql-iamguarded:latest

6. **Complex Paths:**
   - For multi-component paths (e.g., kyverno/background-controller), try hyphenated variants
   - Example: ghcr.io/kyverno/background-controller → cgr.dev/chainguard-private/kyverno-background-controller:latest

7. **Registry Selection:**
   - Use `cgr.dev/chainguard/IMAGE:latest` for free/community images
   - Use `cgr.dev/chainguard-private/IMAGE:latest` for enterprise/commercial images
   - When uncertain, prefer chainguard-private (most enterprise workloads)

8. **Common Variations:**
   - mongo → mongodb
   - postgres → postgresql
   - node-chrome → node-chromium

**Output Format (JSON):**
{{
  "chainguard_image": "cgr.dev/chainguard-private/IMAGE:latest",
  "confidence": 0.85,
  "reasoning": "Brief explanation of why this match makes sense"
}}

**Confidence Scoring:**
- 0.9-1.0: Very high confidence (exact match, known pattern)
- 0.8-0.89: High confidence (strong heuristic match)
- 0.7-0.79: Medium confidence (reasonable guess based on patterns)
- 0.0-0.69: Low confidence (uncertain, should not be used)

If you cannot find a reasonable match (confidence < 0.7), return:
{{
  "chainguard_image": null,
  "confidence": 0.0,
  "reasoning": "Explanation of why no match was found"
}}

Respond with ONLY the JSON output, no additional text."""

        return prompt

    def _enhanced_match(self, image_name: str) -> LLMMatchResult:
        """
        Enhanced matching using web search and chainctl to find the best match.

        This method is called as a fallback when the simple LLM match fails.
        It uses Claude's tool use to:
        1. Search the web for the upstream project
        2. Search available Chainguard images via chainctl
        3. Reason about the best match

        Args:
            image_name: Source image to match

        Returns:
            LLMMatchResult with match and metadata
        """
        if not self.client:
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM matching disabled (no API key)",
            )

        start_time = time.time()

        # Extract base name for searching
        base_name = image_name
        if "/" in base_name:
            base_name = base_name.split("/")[-1]
        if ":" in base_name:
            base_name = base_name.split(":")[0]

        # Search for candidate Chainguard images
        # Try multiple search terms to increase chances of finding matches
        search_terms = [base_name]

        # Add individual words from the base name as search terms
        words = re.split(r"[-_]+", base_name)
        if len(words) > 1:
            # Add the most significant words (usually not generic ones like "manager", "controller")
            significant_words = [w for w in words if w.lower() not in ("manager", "controller", "server", "client")]
            if significant_words:
                search_terms.append(" ".join(significant_words[:2]))

        candidate_images = set()
        for term in search_terms:
            candidates = self._search_chainguard_images(term)
            candidate_images.update(candidates)

        candidate_list = sorted(candidate_images)[:30]  # Limit to 30 candidates

        logger.info(f"Enhanced matching for '{image_name}' with {len(candidate_list)} candidates")

        # Build enhanced prompt with candidate list
        candidates_str = "\n".join(f"  - {img}" for img in candidate_list) if candidate_list else "  (no candidates found via chainctl)"

        enhanced_prompt = f"""You are an expert at matching container images to their Chainguard equivalents.

**Image to match:** {image_name}

**CRITICAL CONTEXT**: The simple match suggested an image that does NOT exist in the Chainguard registry.
You MUST choose from the available images below, or return null if none match.

**Available Chainguard images (verified via chainctl):**
{candidates_str}

**Your task:**
1. Analyze the source image path and name to understand what software this is
2. Use your knowledge about this software's upstream project and common naming conventions
3. Match it to one of the available Chainguard images above

**Key insights:**
- mcr.microsoft.com/oss/kubernetes/* images are often Kubernetes cloud provider components
- The upstream project for Azure Kubernetes components is typically kubernetes-sigs/cloud-provider-azure
- Chainguard often uses the upstream project name (e.g., "cloud-provider-azure-*" rather than "azure-cloud-*")
- registry.k8s.io/provider-*/* images map to cloud-provider-* in Chainguard

**Output Format (JSON):**
{{
  "chainguard_image": "cgr.dev/chainguard-private/IMAGE:latest",
  "confidence": 0.85,
  "reasoning": "Brief explanation of why this match makes sense based on the upstream project"
}}

If no available image matches (confidence < 0.7), return:
{{
  "chainguard_image": null,
  "confidence": 0.0,
  "reasoning": "Explanation of why no match was possible"
}}

IMPORTANT: You MUST choose from the available images list above. Do NOT suggest images that aren't in the list.

Respond with ONLY the JSON output, no additional text."""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": enhanced_prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000

            # Extract text response
            response_text = message.content[0].text.strip() if message.content else None

            if not response_text:
                logger.warning("Enhanced match returned no text response")
                return LLMMatchResult(
                    chainguard_image=None,
                    confidence=0.0,
                    reasoning="No response from enhanced matching",
                    latency_ms=latency_ms,
                )

            # Remove markdown code blocks if present
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            response = json.loads(response_text)

            result = LLMMatchResult(
                chainguard_image=response.get("chainguard_image"),
                confidence=response.get("confidence", 0.0),
                reasoning=response.get("reasoning", ""),
                cached=False,
                latency_ms=latency_ms,
            )

            # Cache the result (with a marker that it was from enhanced matching)
            self._cache_result(
                image_name,
                result.chainguard_image,
                result.confidence,
                f"[enhanced] {result.reasoning}",
            )

            logger.info(
                f"Enhanced match for {image_name}: {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, latency: {latency_ms:.0f}ms)"
            )

            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error in enhanced matching: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"API error: {e}",
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse enhanced match response as JSON: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
            )
        except Exception as e:
            logger.error(f"Enhanced matching error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
            )

    def match(self, image_name: str) -> LLMMatchResult:
        """
        Find Chainguard image match using LLM.

        Args:
            image_name: Source image to match

        Returns:
            LLMMatchResult with match and metadata
        """
        # Check if LLM matching is available
        if not self.client:
            logger.debug("LLM matching disabled (no API key)")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM matching disabled (no API key)",
            )

        # Check cache first
        cached_result = self._get_cached_result(image_name)
        if cached_result:
            self._log_telemetry(
                image_name, cached_result, cached_result.confidence >= self.confidence_threshold
            )
            return cached_result

        # Call Claude API
        start_time = time.time()
        try:
            prompt = self._build_prompt(image_name)

            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000

            # Parse JSON response
            response_text = message.content[0].text.strip()

            # Remove markdown code blocks if present
            if response_text.startswith("```json"):
                response_text = response_text[7:]  # Remove ```json
            if response_text.startswith("```"):
                response_text = response_text[3:]  # Remove ```
            if response_text.endswith("```"):
                response_text = response_text[:-3]  # Remove closing ```
            response_text = response_text.strip()

            response = json.loads(response_text)

            result = LLMMatchResult(
                chainguard_image=response.get("chainguard_image"),
                confidence=response.get("confidence", 0.0),
                reasoning=response.get("reasoning", ""),
                cached=False,
                latency_ms=latency_ms,
            )

            logger.info(
                f"LLM match for {image_name}: {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, latency: {latency_ms:.0f}ms)"
            )

            # Verify the suggested image actually exists
            needs_enhanced = result.confidence < self.confidence_threshold
            simple_match_invalid = False

            if result.chainguard_image and result.confidence >= self.confidence_threshold:
                # Extract image name from full reference for verification
                suggested_name = result.chainguard_image
                if "/" in suggested_name:
                    suggested_name = suggested_name.split("/")[-1]
                if ":" in suggested_name:
                    suggested_name = suggested_name.split(":")[0]

                # Check if image exists via chainctl
                available_images = self._search_chainguard_images(suggested_name)
                if not any(suggested_name == img or suggested_name in img for img in available_images):
                    logger.warning(
                        f"Simple match suggested '{suggested_name}' but it doesn't appear to exist in Chainguard registry"
                    )
                    needs_enhanced = True
                    simple_match_invalid = True  # Mark as invalid so we prefer enhanced result

            # If simple match failed, has low confidence, or suggested non-existent image, try enhanced matching
            if needs_enhanced:
                logger.info(
                    f"Simple LLM match needs enhancement (confidence: {result.confidence:.0%}, "
                    f"threshold: {self.confidence_threshold:.0%}), trying enhanced matching..."
                )
                enhanced_result = self._enhanced_match(image_name)

                # Use enhanced result if it's better OR if simple match was invalid (non-existent image)
                if enhanced_result.confidence > result.confidence or (
                    simple_match_invalid and enhanced_result.confidence >= self.confidence_threshold
                ):
                    logger.info(
                        f"Using enhanced match: {enhanced_result.chainguard_image} "
                        f"(confidence: {enhanced_result.confidence:.0%})"
                    )
                    result = enhanced_result
                else:
                    # Cache the original result since enhanced didn't help
                    self._cache_result(
                        image_name, result.chainguard_image, result.confidence, result.reasoning
                    )
            else:
                # Cache the successful simple result
                self._cache_result(
                    image_name, result.chainguard_image, result.confidence, result.reasoning
                )

            # Log telemetry
            success = result.confidence >= self.confidence_threshold
            self._log_telemetry(image_name, result, success)

            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"API error: {e}",
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
            )

        except Exception as e:
            logger.error(f"LLM matching error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
            )
