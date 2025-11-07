"""
LLM-powered fuzzy image matching for Chainguard equivalents.

Implements Tier 4 matching using Claude API for complex image name transformations
that can't be handled by heuristics alone.
"""

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import anthropic

from constants import DEFAULT_LLM_CONFIDENCE
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

            # Cache the result
            self._cache_result(
                image_name, result.chainguard_image, result.confidence, result.reasoning
            )

            # Log telemetry
            success = result.confidence >= self.confidence_threshold
            self._log_telemetry(image_name, result, success)

            logger.info(
                f"LLM match for {image_name}: {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, latency: {latency_ms:.0f}ms)"
            )

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
