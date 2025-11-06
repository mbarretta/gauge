"""
Match command for automatically finding Chainguard image equivalents.

Implements the `gauge match` command for batch matching of alternative images
to their Chainguard equivalents.
"""

import csv
import logging
import sys
from pathlib import Path
from typing import Optional

from utils.image_matcher import ImageMatcher, MatchResult

logger = logging.getLogger(__name__)


def match_images(
    input_file: Path,
    output_file: Path,
    unmatched_file: Path,
    min_confidence: float = 0.7,
    interactive: bool = False,
    dfc_mappings_file: Optional[Path] = None,
    cache_dir: Optional[Path] = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """
    Match alternative images to Chainguard equivalents.

    Args:
        input_file: Input file with alternative images (one per line or CSV)
        output_file: Output CSV file with matched pairs
        unmatched_file: Output file for unmatched images
        min_confidence: Minimum confidence threshold (0.0 - 1.0)
        interactive: Enable interactive mode for low-confidence matches
        dfc_mappings_file: Optional local DFC mappings file
        cache_dir: Cache directory for DFC mappings

    Returns:
        Tuple of (matched_pairs, unmatched_images)
    """
    # Read input images
    logger.info(f"Reading images from {input_file}")
    alternative_images = read_input_file(input_file)
    logger.info(f"Found {len(alternative_images)} images to match")

    # Initialize matcher
    logger.info("Initializing image matcher...")
    matcher = ImageMatcher(
        cache_dir=cache_dir,
        dfc_mappings_file=dfc_mappings_file,
    )

    # Match images
    matched_pairs: list[tuple[str, str]] = []
    unmatched_images: list[str] = []
    low_confidence_matches: list[tuple[str, MatchResult]] = []

    logger.info("Matching images...")
    for i, alt_image in enumerate(alternative_images, 1):
        result = matcher.match(alt_image)

        if result.chainguard_image is None:
            logger.warning(f"[{i}/{len(alternative_images)}] No match: {alt_image}")
            unmatched_images.append(alt_image)
        elif result.confidence >= min_confidence:
            logger.info(
                f"[{i}/{len(alternative_images)}] ✓ Matched: {alt_image} → {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, method: {result.method})"
            )
            matched_pairs.append((alt_image, result.chainguard_image))
        else:
            logger.warning(
                f"[{i}/{len(alternative_images)}] Low confidence: {alt_image} → {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%})"
            )
            if interactive:
                low_confidence_matches.append((alt_image, result))
            else:
                unmatched_images.append(alt_image)

    # Handle interactive mode for low-confidence matches
    if interactive and low_confidence_matches:
        logger.info(f"\nReviewing {len(low_confidence_matches)} low-confidence matches...")
        for alt_image, result in low_confidence_matches:
            matched = handle_interactive_match(alt_image, result)
            if matched:
                matched_pairs.append(matched)
            else:
                unmatched_images.append(alt_image)

    # Write outputs
    logger.info(f"\nWriting matched pairs to {output_file}")
    write_matched_csv(output_file, matched_pairs)

    if unmatched_images:
        logger.warning(f"Writing {len(unmatched_images)} unmatched images to {unmatched_file}")
        write_unmatched_file(unmatched_file, unmatched_images)

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info(f"Matching complete:")
    logger.info(f"  Matched: {len(matched_pairs)}")
    logger.info(f"  Unmatched: {len(unmatched_images)}")
    logger.info(f"  Match rate: {len(matched_pairs) / len(alternative_images) * 100:.1f}%")
    logger.info("=" * 60)

    return matched_pairs, unmatched_images


def read_input_file(file_path: Path) -> list[str]:
    """
    Read alternative images from input file.

    Supports both text files (one image per line) and CSV files (first column).

    Args:
        file_path: Input file path

    Returns:
        List of alternative image references

    Raises:
        RuntimeError: If file cannot be read
    """
    images = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            # Try to detect if it's a CSV
            first_line = f.readline().strip()
            f.seek(0)

            if "," in first_line:
                # CSV file
                reader = csv.reader(f)
                # Skip header if present
                header = next(reader, None)
                if header and header[0].lower() in ["alternative_image", "image", "name"]:
                    pass  # Already skipped
                else:
                    # First line is data, add it
                    f.seek(0)
                    reader = csv.reader(f)

                for row in reader:
                    if row and row[0].strip():
                        images.append(row[0].strip())
            else:
                # Plain text file
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        images.append(line)

    except Exception as e:
        raise RuntimeError(f"Failed to read input file: {e}") from e

    if not images:
        raise RuntimeError("No images found in input file")

    return images


def write_matched_csv(file_path: Path, pairs: list[tuple[str, str]]) -> None:
    """Write matched image pairs to CSV file."""
    with open(file_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alternative_image", "chainguard_image"])
        for alt, cg in pairs:
            writer.writerow([alt, cg])


def write_unmatched_file(file_path: Path, images: list[str]) -> None:
    """Write unmatched images to text file."""
    with open(file_path, "w", encoding="utf-8") as f:
        for image in images:
            f.write(f"{image}\n")


def handle_interactive_match(alt_image: str, result: MatchResult) -> Optional[tuple[str, str]]:
    """
    Handle interactive matching for low-confidence results.

    Args:
        alt_image: Alternative image reference
        result: Match result with low confidence

    Returns:
        Matched pair if accepted, None if skipped
    """
    print(f"\nLow confidence match for: {alt_image}")
    print(f"  Suggested: {result.chainguard_image}")
    print(f"  Confidence: {result.confidence:.0%}")
    print(f"  Method: {result.method}")

    if result.alternatives:
        print("\n  Alternatives:")
        for i, alt in enumerate(result.alternatives[:5], 1):
            print(f"    {i}. {alt}")

    while True:
        choice = input("\nAccept (y), skip (n), or enter custom image: ").strip().lower()

        if choice == "y":
            return (alt_image, result.chainguard_image)
        elif choice == "n":
            return None
        elif choice.startswith("cgr.dev/"):
            # Custom Chainguard image provided
            return (alt_image, choice)
        elif choice.isdigit():
            # Selected alternative
            idx = int(choice) - 1
            if result.alternatives and 0 <= idx < len(result.alternatives):
                return (alt_image, result.alternatives[idx])
            else:
                print("Invalid selection. Try again.")
        else:
            print("Invalid input. Enter 'y', 'n', a number, or a custom image.")
