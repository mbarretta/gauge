"""
Scan result persistence for checkpoint/resume functionality.

Enables saving and loading scan results to support long-running scans
that can be interrupted and resumed.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.exceptions import CacheException
from core.models import (
    CHPSScore,
    ImageAnalysis,
    ImagePair,
    ScanResult,
    VulnerabilityCount,
)

logger = logging.getLogger(__name__)


class ScanResultPersistence:
    """
    Handles persistence of scan results to disk.

    Provides checkpoint/resume functionality for long-running scans,
    allowing recovery from interruptions without re-scanning.
    """

    def __init__(self, checkpoint_path: Optional[Path] = None):
        """
        Initialize persistence manager.

        Args:
            checkpoint_path: Path for checkpoint file
                           (default: .gauge_checkpoint.json)
        """
        self.checkpoint_path = checkpoint_path or Path(".gauge_checkpoint.json")

    def save_results(
        self,
        results: List[ScanResult],
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Save scan results to checkpoint file.

        Args:
            results: List of scan results to save
            metadata: Optional metadata (e.g., scan parameters)

        Raises:
            CacheException: If save fails
        """
        try:
            data = {
                "version": "2.0",
                "timestamp": datetime.now().isoformat(),
                "metadata": metadata or {},
                "results": [self._serialize_result(r) for r in results],
            }

            # Write atomically by writing to temp file then renaming
            temp_path = self.checkpoint_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(data, indent=2, default=str))
            temp_path.replace(self.checkpoint_path)

            logger.debug(
                f"Saved {len(results)} results to checkpoint: {self.checkpoint_path}"
            )

        except Exception as e:
            raise CacheException(f"Failed to save checkpoint: {e}")

    def load_results(self) -> tuple[List[ScanResult], dict]:
        """
        Load scan results from checkpoint file.

        Returns:
            Tuple of (results, metadata)

        Raises:
            CacheException: If load fails
        """
        if not self.checkpoint_path.exists():
            return [], {}

        try:
            data = json.loads(self.checkpoint_path.read_text())

            version = data.get("version", "1.0")
            if version != "2.0":
                logger.warning(
                    f"Checkpoint version mismatch: {version} (expected 2.0)"
                )

            results = [
                self._deserialize_result(r) for r in data.get("results", [])
            ]
            metadata = data.get("metadata", {})

            logger.info(
                f"Loaded {len(results)} results from checkpoint: {self.checkpoint_path}"
            )

            return results, metadata

        except json.JSONDecodeError as e:
            raise CacheException(f"Invalid checkpoint file: {e}")
        except Exception as e:
            raise CacheException(f"Failed to load checkpoint: {e}")

    def exists(self) -> bool:
        """
        Check if checkpoint file exists.

        Returns:
            True if checkpoint file exists
        """
        return self.checkpoint_path.exists()

    def clear(self) -> None:
        """Delete checkpoint file if it exists."""
        if self.checkpoint_path.exists():
            self.checkpoint_path.unlink()
            logger.debug(f"Cleared checkpoint: {self.checkpoint_path}")

    def get_metadata(self) -> Optional[dict]:
        """
        Get metadata from checkpoint without loading full results.

        Returns:
            Metadata dictionary or None if checkpoint doesn't exist
        """
        if not self.checkpoint_path.exists():
            return None

        try:
            data = json.loads(self.checkpoint_path.read_text())
            return data.get("metadata", {})
        except Exception:
            return None

    @staticmethod
    def _serialize_result(result: ScanResult) -> dict:
        """
        Serialize ScanResult to dictionary.

        Args:
            result: ScanResult to serialize

        Returns:
            Dictionary representation
        """
        return {
            "pair": {
                "chainguard_image": result.pair.chainguard_image,
                "alternative_image": result.pair.alternative_image,
            },
            "scan_successful": result.scan_successful,
            "error_message": result.error_message,
            "alternative_analysis": (
                ScanResultPersistence._serialize_analysis(result.alternative_analysis)
                if result.alternative_analysis
                else None
            ),
            "chainguard_analysis": (
                ScanResultPersistence._serialize_analysis(result.chainguard_analysis)
                if result.chainguard_analysis
                else None
            ),
        }

    @staticmethod
    def _serialize_analysis(analysis: ImageAnalysis) -> dict:
        """Serialize ImageAnalysis to dictionary."""
        return {
            "name": analysis.name,
            "size_mb": analysis.size_mb,
            "package_count": analysis.package_count,
            "vulnerabilities": analysis.vulnerabilities.to_dict(),
            "scan_timestamp": analysis.scan_timestamp.isoformat(),
            "digest": analysis.digest,
            "cache_hit": analysis.cache_hit,
            "chps_score": (
                {
                    "score": analysis.chps_score.score,
                    "grade": analysis.chps_score.grade,
                    "details": analysis.chps_score.details,
                }
                if analysis.chps_score
                else None
            ),
        }

    @staticmethod
    def _deserialize_result(data: dict) -> ScanResult:
        """
        Deserialize dictionary to ScanResult.

        Args:
            data: Dictionary representation

        Returns:
            ScanResult instance
        """
        pair = ImagePair(
            chainguard_image=data["pair"]["chainguard_image"],
            alternative_image=data["pair"]["alternative_image"],
        )

        return ScanResult(
            pair=pair,
            scan_successful=data["scan_successful"],
            error_message=data.get("error_message"),
            alternative_analysis=(
                ScanResultPersistence._deserialize_analysis(
                    data["alternative_analysis"]
                )
                if data.get("alternative_analysis")
                else None
            ),
            chainguard_analysis=(
                ScanResultPersistence._deserialize_analysis(
                    data["chainguard_analysis"]
                )
                if data.get("chainguard_analysis")
                else None
            ),
        )

    @staticmethod
    def _deserialize_analysis(data: dict) -> ImageAnalysis:
        """Deserialize dictionary to ImageAnalysis."""
        return ImageAnalysis(
            name=data["name"],
            size_mb=data["size_mb"],
            package_count=data["package_count"],
            vulnerabilities=VulnerabilityCount(**data["vulnerabilities"]),
            scan_timestamp=datetime.fromisoformat(data["scan_timestamp"]),
            digest=data.get("digest"),
            cache_hit=data.get("cache_hit", False),
            chps_score=(
                CHPSScore(
                    score=data["chps_score"]["score"],
                    grade=data["chps_score"]["grade"],
                    details=data["chps_score"].get("details", {}),
                )
                if data.get("chps_score")
                else None
            ),
        )


__all__ = ["ScanResultPersistence"]
