"""
Command-line interface for Gauge - Container Vulnerability Assessment Tool.

Provides a clean, intuitive CLI for vulnerability scanning with two output types:
- HTML: Vulnerability assessment summary reports
- XLSX: Vulnerability cost analysis with ROI calculations
"""

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import Optional

from constants import (
    DEFAULT_HOURS_PER_VULNERABILITY,
    DEFAULT_HOURLY_RATE,
    DEFAULT_MAX_WORKERS,
    DEFAULT_PLATFORM,
    DEFAULT_MATCH_CONFIDENCE,
    DEFAULT_UPSTREAM_CONFIDENCE,
    DEFAULT_LLM_CONFIDENCE,
    DEFAULT_LLM_MODEL,
)
from core.cache import ScanCache
from core.models import ImagePair
from core.scanner import VulnerabilityScanner
from integrations.kev_catalog import KEVCatalog
from outputs.html_generator import HTMLGenerator
from outputs.xlsx_generator import XLSXGenerator
from utils.docker_utils import DockerClient
from utils.logging_helpers import log_error_section, log_warning_section

logger = logging.getLogger(__name__)


# Output configuration for all report types
OUTPUT_CONFIGS = {
    "vuln_summary": {
        "description": "Vulnerability Assessment Summary (HTML)",
        "file_suffix": "assessment.html",
    },
    "cost_analysis": {
        "description": "Vulnerability Cost Analysis (XLSX)",
        "file_suffix": "cost_analysis.xlsx",
    },
    "pricing": {
        "description": "Pricing Quote",
        "formats": {
            "html": {
                "file_suffix": "pricing_quote.html",
                "description": "Pricing Quote (HTML)",
            },
            "txt": {
                "file_suffix": "pricing_quote.txt",
                "description": "Pricing Quote (TXT)",
            },
        },
    },
}


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        args: Optional list of arguments to parse (for testing).
              If None, uses sys.argv.
    """
    parser = argparse.ArgumentParser(
        description="Gauge - Container Vulnerability Assessment Tool\n\n"
                    "Scan and compare vulnerability posture between alternative images and Chainguard equivalents.\n"
                    "Supports automatic image matching from single-column CSV input.\n\n"
                    "Commands:\n"
                    "  gauge              Scan images and generate reports (default)\n"
                    "  gauge match        Match alternative images to Chainguard equivalents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output Types:
  cost_analysis  - Vulnerability cost analysis with ROI calculations (XLSX)
  vuln_summary   - Vulnerability assessment summary report (HTML)
  pricing        - Pricing quote for Chainguard subscriptions (HTML + TXT)
  both           - Generate both vuln_summary and cost_analysis

Input Format:
  Two-column CSV:   alternative_image,chainguard_image
  Single-column CSV: alternative_image (auto-matches Chainguard equivalents)

Examples:
  # Simplest usage (uses all defaults)
  gauge

  # Scan with single-column CSV (auto-matches Chainguard images)
  gauge --input alternative-images.csv

  # Scan with single-column CSV and upstream discovery
  gauge --input alternative-images.csv --find-upstream

  # Scan with single-column CSV, disable LLM matching
  gauge --input alternative-images.csv --disable-llm-matching

  # Generate vulnerability cost analysis (XLSX)
  gauge --output cost_analysis --output-dir ./reports \\
        --customer "Acme Corp" --hours-per-vuln 3 --hourly-rate 100

  # Generate vulnerability assessment summary (HTML)
  gauge --output vuln_summary --output-dir ./reports \\
        --customer "Acme Corp" --exec-summary summary.md

  # Generate all three output types
  gauge --output vuln_summary,cost_analysis,pricing --output-dir ./reports \\
        --customer "Acme Corp"

  # Enable all optional features
  gauge --output both --with-all --customer "Acme Corp"

  # Match alternative images to Chainguard equivalents
  gauge match --input images.txt

  # Match with LLM-powered Tier 4 fuzzy matching (enabled by default)
  gauge match --input images.txt --llm-model claude-sonnet-4-5

  # Match with upstream discovery for private/internal images
  gauge match --input images.txt --find-upstream

  # Generate DFC contribution files for discovered mappings
  gauge match --input images.txt --generate-dfc-pr

For more help on the match subcommand:
  gauge match --help
        """,
    )

    # Input/Output arguments
    io_group = parser.add_argument_group("input/output")
    io_group.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("images.csv"),
        help="Input CSV file with image pairs or single-column alternative images (default: images.csv)",
    )
    io_group.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help=(
            "Output types to generate (comma-separated): 'cost_analysis' (XLSX), "
            "'vuln_summary' (HTML), 'pricing' (price quote). "
            "Default: vuln_summary and cost_analysis. Example: --output cost_analysis,pricing"
        ),
    )
    io_group.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Output directory for generated reports (default: current directory)",
    )
    io_group.add_argument(
        "--pricing-policy",
        type=Path,
        default=Path("pricing-policy.yaml"),
        help="Pricing policy file for quote generation (default: pricing-policy.yaml)",
    )

    # Common options
    common = parser.add_argument_group("common options")
    common.add_argument(
        "-c",
        "--customer",
        "--customername",
        dest="customer_name",
        default="Customer",
        help="Customer name for report branding (default: Customer)",
    )
    common.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Number of parallel scanning threads (default: {DEFAULT_MAX_WORKERS})",
    )
    common.add_argument(
        "--platform",
        default=DEFAULT_PLATFORM,
        help=f"Platform for image pulls and scans (default: {DEFAULT_PLATFORM})",
    )

    # HTML-specific options (assessment summary)
    html_opts = parser.add_argument_group("assessment summary options (HTML)")
    html_opts.add_argument(
        "-e",
        "--exec-summary",
        type=Path,
        default=Path("exec-summary.md"),
        help="Markdown file for executive summary (default: exec-summary.md)",
    )
    html_opts.add_argument(
        "-a",
        "--appendix",
        type=Path,
        default=Path("appendix.md"),
        help="Markdown file for custom appendix (default: appendix.md)",
    )

    # XLSX-specific options (cost analysis)
    xlsx_opts = parser.add_argument_group("cost analysis options (XLSX)")
    xlsx_opts.add_argument(
        "--hours-per-vuln",
        "--vulnhours",
        type=float,
        default=DEFAULT_HOURS_PER_VULNERABILITY,
        help=f"Average hours to remediate one CVE (default: {DEFAULT_HOURS_PER_VULNERABILITY})",
    )
    xlsx_opts.add_argument(
        "--hourly-rate",
        "--hourlyrate",
        type=float,
        default=DEFAULT_HOURLY_RATE,
        help=f"Engineering hourly rate in USD (default: {DEFAULT_HOURLY_RATE})",
    )

    # Cache options
    cache_opts = parser.add_argument_group("cache options")
    cache_opts.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache"),
        help="Cache directory (default: .cache)",
    )
    cache_opts.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching",
    )
    cache_opts.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear cache before starting",
    )
    cache_opts.add_argument(
        "--no-fresh-check",
        action="store_true",
        help="Skip checking for fresh images (faster but may use stale images)",
    )
    cache_opts.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous checkpoint (if available)",
    )
    cache_opts.add_argument(
        "--checkpoint-file",
        type=Path,
        default=Path(".gauge_checkpoint.json"),
        help="Checkpoint file path (default: .gauge_checkpoint.json)",
    )

    # Matching options (for single-column CSV input)
    matching_opts = parser.add_argument_group("matching options (for single-column CSV)")
    matching_opts.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MATCH_CONFIDENCE,
        help=f"Minimum confidence threshold for automatic matching (0.0-1.0, default: {DEFAULT_MATCH_CONFIDENCE})",
    )
    matching_opts.add_argument(
        "--dfc-mappings-file",
        type=Path,
        help="Local DFC mappings file (for offline/air-gapped environments)",
    )
    matching_opts.add_argument(
        "--find-upstream",
        action="store_true",
        help="Enable upstream image discovery for private/internal images",
    )
    matching_opts.add_argument(
        "--upstream-confidence",
        type=float,
        default=DEFAULT_UPSTREAM_CONFIDENCE,
        help=f"Minimum confidence threshold for upstream discovery (0.0-1.0, default: {DEFAULT_UPSTREAM_CONFIDENCE})",
    )
    matching_opts.add_argument(
        "--upstream-mappings-file",
        type=Path,
        help="Manual upstream mappings file (default: config/upstream_mappings.yaml)",
    )
    matching_opts.add_argument(
        "--disable-llm-matching",
        action="store_true",
        help="Disable LLM-powered fuzzy matching (Tier 4). LLM matching is enabled by default.",
    )
    matching_opts.add_argument(
        "--llm-model",
        type=str,
        default=DEFAULT_LLM_MODEL,
        help=f"Claude model for LLM matching (default: {DEFAULT_LLM_MODEL}). "
             "Options: claude-sonnet-4-5 (balanced), claude-opus-4-1 (highest accuracy), claude-haiku-4-5 (fastest)",
    )
    matching_opts.add_argument(
        "--llm-confidence-threshold",
        type=float,
        default=DEFAULT_LLM_CONFIDENCE,
        help=f"Minimum confidence threshold for LLM matches (0.0-1.0, default: {DEFAULT_LLM_CONFIDENCE})",
    )
    matching_opts.add_argument(
        "--anthropic-api-key",
        type=str,
        help="Anthropic API key for LLM matching (can also use ANTHROPIC_API_KEY env var)",
    )
    matching_opts.add_argument(
        "--generate-dfc-pr",
        action="store_true",
        help="Generate DFC contribution files (dfc-suggestions.yaml and dfc-suggestions.patch) "
             "for successful heuristic (Tier 3) and LLM (Tier 4) matches with high confidence (>= 0.85)",
    )
    matching_opts.add_argument(
        "--disable-mapping-auto-population",
        action="store_true",
        help="Disable automatic population of config/image_mappings.yaml "
             "(by default, successful Tier 3/4 matches are saved for instant Tier 2 lookups in future runs)",
    )

    # Optional features
    parser.add_argument(
        "--with-chps",
        action="store_true",
        help="Include CHPS (Container Hardening and Provenance Scanner) scoring",
    )
    parser.add_argument(
        "--with-fips",
        action="store_true",
        help="Include FIPS cost analysis (auto-detects FIPS images by name)",
    )
    parser.add_argument(
        "--with-kevs",
        action="store_true",
        help="Include CISA Known Exploited Vulnerabilities (KEV) data in reports",
    )
    parser.add_argument(
        "--with-all",
        action="store_true",
        help="Enable all optional features (equivalent to --with-chps --with-fips --with-kevs)",
    )

    # Other options
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args(args)


def _detect_csv_format(csv_path: Path) -> bool:
    """
    Detect if CSV is single-column or two-column format.

    Args:
        csv_path: Path to CSV file

    Returns:
        True if single-column format, False if two-column format
    """
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and any(cell.strip() for cell in row):
                # Skip comment lines
                if row[0].strip().startswith('#'):
                    continue
                # Skip header
                if any(header in row[0].lower() for header in ["chainguard", "customer", "image", "alternative"]):
                    continue
                # First data row determines format
                return len(row) == 1

    # Empty file defaults to two-column
    return False


def _parse_two_column_csv(csv_path: Path) -> list[ImagePair]:
    """
    Parse two-column CSV format (alternative_image, chainguard_image).

    Args:
        csv_path: Path to CSV file

    Returns:
        List of validated ImagePair objects

    Raises:
        SystemExit: If validation fails
    """
    from core.exceptions import ValidationException
    from utils.validation import validate_image_reference

    pairs = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)

        for line_num, row in enumerate(reader, 1):
            # Skip empty lines
            if not row or not any(cell.strip() for cell in row):
                continue

            # Skip comment lines (lines starting with #)
            if row[0].strip().startswith('#'):
                continue

            # Skip header if it looks like a header
            if line_num == 1 and any(
                header in row[0].lower()
                for header in ["chainguard", "customer", "image", "alternative"]
            ):
                continue

            # Validate row has two columns
            if len(row) < 2:
                logger.warning(f"Line {line_num}: insufficient columns, skipping")
                continue

            alternative_image = row[0].strip()
            chainguard_image = row[1].strip()

            if not alternative_image or not chainguard_image:
                logger.warning(f"Line {line_num}: empty image reference, skipping")
                continue

            try:
                # Validate image references
                alternative_image = validate_image_reference(
                    alternative_image,
                    f"alternative_image (line {line_num})"
                )
                chainguard_image = validate_image_reference(
                    chainguard_image,
                    f"chainguard_image (line {line_num})"
                )

                # Check images aren't identical
                if alternative_image == chainguard_image:
                    logger.warning(
                        f"Line {line_num}: images are identical, skipping"
                    )
                    continue

                pairs.append(ImagePair(chainguard_image, alternative_image))

            except ValidationException as e:
                logger.error(f"Validation error: {e}")
                sys.exit(1)

    return pairs


def _parse_single_column_csv(csv_path: Path) -> list[str]:
    """
    Parse single-column CSV format (alternative_image only).

    Args:
        csv_path: Path to CSV file

    Returns:
        List of validated alternative image references

    Raises:
        SystemExit: If validation fails
    """
    from core.exceptions import ValidationException
    from utils.validation import validate_image_reference

    images = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)

        for line_num, row in enumerate(reader, 1):
            # Skip empty lines
            if not row or not any(cell.strip() for cell in row):
                continue

            # Skip comment lines (lines starting with #)
            if row[0].strip().startswith('#'):
                continue

            # Skip header if it looks like a header
            if line_num == 1 and any(
                header in row[0].lower()
                for header in ["chainguard", "customer", "image", "alternative"]
            ):
                continue

            alternative_image = row[0].strip()
            if alternative_image:
                try:
                    alternative_image = validate_image_reference(
                        alternative_image,
                        f"alternative_image (line {line_num})"
                    )
                    images.append(alternative_image)
                except ValidationException as e:
                    logger.error(f"Validation error: {e}")
                    sys.exit(1)

    return images


def _initialize_image_matcher(
    cache_dir: Optional[Path],
    dfc_mappings_file: Optional[Path],
    find_upstream: bool,
    upstream_confidence: float,
    upstream_mappings_file: Optional[Path],
    enable_llm_matching: bool,
    llm_model: str,
    llm_confidence_threshold: float,
    anthropic_api_key: Optional[str],
):
    """
    Initialize ImageMatcher with all dependencies (upstream finder, LLM matcher).

    Args:
        cache_dir: Cache directory for DFC mappings
        dfc_mappings_file: Optional local DFC mappings file
        find_upstream: Enable upstream image discovery
        upstream_confidence: Minimum confidence for upstream matches
        upstream_mappings_file: Optional manual upstream mappings file
        enable_llm_matching: Enable LLM-powered fuzzy matching
        llm_model: Claude model to use for LLM matching
        llm_confidence_threshold: Minimum confidence for LLM matches
        anthropic_api_key: Anthropic API key for LLM matching

    Returns:
        Tuple of (ImageMatcher, Optional[UpstreamImageFinder], Optional[LLMMatcher])
    """
    from utils.image_matcher import ImageMatcher
    from utils.upstream_finder import UpstreamImageFinder

    # Initialize upstream finder if enabled
    upstream_finder = None
    if find_upstream:
        logger.info("Upstream discovery enabled")
        upstream_finder = UpstreamImageFinder(
            manual_mappings_file=upstream_mappings_file,
            min_confidence=upstream_confidence,
        )

    # Initialize LLM matcher if enabled
    llm_matcher = None
    if enable_llm_matching:
        from utils.llm_matcher import LLMMatcher
        logger.info(f"LLM matching enabled (model: {llm_model}, threshold: {llm_confidence_threshold:.0%})")
        llm_matcher = LLMMatcher(
            api_key=anthropic_api_key,
            model=llm_model,
            cache_dir=cache_dir,
            confidence_threshold=llm_confidence_threshold,
        )

    # Initialize matcher with all options
    matcher = ImageMatcher(
        cache_dir=cache_dir,
        dfc_mappings_file=dfc_mappings_file,
        upstream_finder=upstream_finder,
        llm_matcher=llm_matcher,
    )

    return matcher


def _auto_match_images(
    images: list[str],
    matcher,
    min_confidence: float,
    generate_dfc_pr: bool,
    auto_populate_mappings: bool = False,
) -> tuple[list[ImagePair], list[str]]:
    """
    Auto-match alternative images to Chainguard equivalents.

    Args:
        images: List of alternative image references
        matcher: Initialized ImageMatcher instance
        min_confidence: Minimum confidence threshold for matching
        generate_dfc_pr: Generate DFC contribution files
        auto_populate_mappings: Auto-populate manual mappings for future runs

    Returns:
        Tuple of (matched_pairs, unmatched_images)
    """
    from utils.dfc_contributor import DFCContributor
    from utils.manual_mapping_populator import ManualMappingPopulator

    # Initialize DFC contributor if requested
    dfc_contributor = None
    if generate_dfc_pr:
        dfc_contributor = DFCContributor(output_dir=Path("output"))
        logger.info("DFC contribution generation enabled")

    # Initialize manual mapping populator (enabled by default)
    mapping_populator = None
    if auto_populate_mappings:
        mapping_populator = ManualMappingPopulator()
        logger.debug("Auto-population of manual mappings enabled (use --disable-mapping-auto-population to turn off)")

    pairs = []
    unmatched = []

    for alt_image in images:
        result = matcher.match(alt_image)
        if result.chainguard_image and result.confidence >= min_confidence:
            # Show upstream info if available
            upstream_info = ""
            if result.upstream_image:
                upstream_info = f" (via upstream: {result.upstream_image})"

            logger.info(
                f"✓ Matched: {alt_image} → {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, method: {result.method}){upstream_info}"
            )
            pairs.append(ImagePair(result.chainguard_image, alt_image, upstream_image=result.upstream_image))

            # Add to DFC contributor if heuristic or LLM match with high confidence
            if dfc_contributor and result.method in ["heuristic", "llm"]:
                dfc_contributor.add_match(alt_image, result)

            # Add to manual mapping populator if heuristic or LLM match with high confidence
            if mapping_populator and result.method in ["heuristic", "llm"]:
                mapping_populator.add_match(alt_image, result)
        else:
            logger.warning(f"✗ No match found for: {alt_image}")
            unmatched.append(alt_image)

    # Auto-populate manual mappings if requested
    if mapping_populator and mapping_populator.new_mappings:
        logger.info("\nAuto-populating manual mappings...")
        count = mapping_populator.populate_mappings()
        if count > 0:
            logger.info(
                f"Future runs will use these {count} mappings from Tier 2 (instant, 100% confidence) "
                f"instead of re-running Tier 3/4 matching"
            )

    # Generate DFC contribution files if requested
    if dfc_contributor and dfc_contributor.suggestions:
        logger.info(f"\nGenerating DFC contribution files...")
        dfc_files = dfc_contributor.generate_all()
        if dfc_files:
            logger.info("DFC contribution files generated:")
            for file_type, file_path in dfc_files.items():
                logger.info(f"  - {file_type}: {file_path}")

    if unmatched:
        unmatched_list = "\n".join(f"  - {img}" for img in unmatched)
        logger.warning(
            f"\n{len(unmatched)} images could not be auto-matched:\n"
            f"{unmatched_list}\n"
            f"\n"
            f"Consider:\n"
            f"  1. Using 'gauge match' command for more control\n"
            f"  2. Adding manual mappings to config/image_mappings.yaml\n"
            f"  3. Using two-column CSV with explicit Chainguard images"
        )

    return pairs, unmatched


def load_image_pairs(
    csv_path: Path,
    min_confidence: float = 0.7,
    dfc_mappings_file: Optional[Path] = None,
    cache_dir: Optional[Path] = None,
    find_upstream: bool = False,
    upstream_confidence: float = 0.7,
    upstream_mappings_file: Optional[Path] = None,
    enable_llm_matching: bool = True,
    llm_model: str = "claude-sonnet-4-5",
    llm_confidence_threshold: float = 0.7,
    anthropic_api_key: Optional[str] = None,
    generate_dfc_pr: bool = False,
    auto_populate_mappings: bool = True,
) -> list[ImagePair]:
    """
    Load image pairs from CSV file with validation.

    Supports both formats:
    - Two columns: alternative_image,chainguard_image
    - Single column: alternative_image (auto-matches Chainguard equivalent)

    Args:
        csv_path: Path to CSV file
        min_confidence: Minimum confidence threshold for matching
        dfc_mappings_file: Optional local DFC mappings file
        cache_dir: Cache directory for DFC mappings
        find_upstream: Enable upstream image discovery
        upstream_confidence: Minimum confidence for upstream matches
        upstream_mappings_file: Optional manual upstream mappings file
        enable_llm_matching: Enable LLM-powered fuzzy matching
        llm_model: Claude model to use for LLM matching
        llm_confidence_threshold: Minimum confidence for LLM matches
        anthropic_api_key: Anthropic API key for LLM matching
        generate_dfc_pr: Generate DFC contribution files
        auto_populate_mappings: Auto-populate manual mappings for future runs (default: True)

    Returns:
        List of validated ImagePair objects

    Raises:
        SystemExit: If file not found or validation fails
    """
    try:
        # Detect CSV format (single vs two-column)
        is_single_column = _detect_csv_format(csv_path)

        if is_single_column:
            # Single-column mode: parse and auto-match
            logger.info("Detected single-column CSV - will auto-match Chainguard images")
            images = _parse_single_column_csv(csv_path)

            if images:
                logger.info(f"Auto-matching {len(images)} images to Chainguard equivalents...")

                # Initialize matcher with all dependencies
                matcher = _initialize_image_matcher(
                    cache_dir=cache_dir,
                    dfc_mappings_file=dfc_mappings_file,
                    find_upstream=find_upstream,
                    upstream_confidence=upstream_confidence,
                    upstream_mappings_file=upstream_mappings_file,
                    enable_llm_matching=enable_llm_matching,
                    llm_model=llm_model,
                    llm_confidence_threshold=llm_confidence_threshold,
                    anthropic_api_key=anthropic_api_key,
                )

                # Auto-match images
                pairs, unmatched = _auto_match_images(
                    images=images,
                    matcher=matcher,
                    min_confidence=min_confidence,
                    generate_dfc_pr=generate_dfc_pr,
                    auto_populate_mappings=auto_populate_mappings,
                )
            else:
                pairs = []
        else:
            # Two-column mode: parse pairs directly
            pairs = _parse_two_column_csv(csv_path)

    except FileNotFoundError:
        if csv_path == Path("images.csv"):
            logger.error(f"The default 'images.csv' was not found in the current directory.")
            logger.error(f"Run again using '--input <your-csv-file>' to specify your input file.")
        else:
            logger.error(f"Input file not found: {csv_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading source file: {e}")
        sys.exit(1)

    if not pairs:
        logger.error("No valid image pairs found in source file")
        sys.exit(1)

    logger.info(f"Loaded {len(pairs)} image pairs")
    return pairs




def parse_output_types(output_arg: Optional[str]) -> set[str]:
    """
    Parse comma-delimited output types argument.

    Args:
        output_arg: Comma-delimited output types or None for default types

    Returns:
        Set of output types to generate

    Raises:
        ValueError: If invalid output type specified
    """
    valid_types = set(OUTPUT_CONFIGS.keys())

    # Default to vuln_summary and cost_analysis if not specified
    if output_arg is None:
        return {'vuln_summary', 'cost_analysis'}

    # Parse comma-delimited list
    requested_types = {t.strip() for t in output_arg.split(",")}

    # Validate types
    invalid_types = requested_types - valid_types
    if invalid_types:
        raise ValueError(
            f"Invalid output type(s): {', '.join(invalid_types)}. "
            f"Valid types: {', '.join(valid_types)}"
        )

    if not requested_types:
        raise ValueError("At least one output type must be specified")

    return requested_types


def sanitize_customer_name(name: str) -> str:
    """
    Sanitize customer name for use in filenames.

    Args:
        name: Customer name to sanitize

    Returns:
        Safe filename-compatible version of the name
    """
    import re
    # Remove & and . characters entirely
    safe_name = name.replace('&', '').replace('.', '')
    # Replace other special characters with underscores
    safe_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in safe_name)
    safe_name = safe_name.replace(' ', '_').lower()
    # Collapse multiple consecutive underscores
    safe_name = re.sub(r'_+', '_', safe_name)
    return safe_name


def initialize_components(args):
    """
    Initialize Docker client, cache, and KEV catalog.

    Args:
        args: Parsed command-line arguments

    Returns:
        Tuple of (docker_client, cache, kev_catalog)
    """
    # Initialize Docker client
    try:
        docker_client = DockerClient()
    except RuntimeError as e:
        logger.error(f"Docker/Podman not available: {e}")
        sys.exit(1)

    # Initialize cache
    cache = ScanCache(
        cache_dir=args.cache_dir,
        enabled=not args.no_cache,
    )

    if args.clear_cache:
        logger.info("Clearing cache...")
        cache.clear()

    # Validate Chainguard authentication
    if not docker_client.ensure_chainguard_auth():
        logger.error("Failed to authenticate to Chainguard registry")
        logger.error("")
        logger.error("Please run these commands:")
        logger.error("  chainctl auth login")
        logger.error("  chainctl auth configure-docker")
        logger.error("")
        logger.error("This sets up Docker authentication which works for both local and container execution.")
        sys.exit(1)

    # Load KEV catalog if requested
    kev_catalog = None
    if args.with_kevs:
        logger.info("KEV checking enabled, loading CISA KEV catalog...")
        kev_catalog = KEVCatalog()
        kev_catalog.load()

    return docker_client, cache, kev_catalog


def execute_scans(args, scanner, pairs):
    """
    Execute scans with checkpoint/resume support.

    Args:
        args: Parsed command-line arguments
        scanner: VulnerabilityScanner instance
        pairs: List of ImagePair objects to scan

    Returns:
        List of ScanResult objects
    """
    from core.persistence import ScanResultPersistence
    persistence = ScanResultPersistence(args.checkpoint_file)

    # Check for resume
    if args.resume and persistence.exists():
        logger.info(f"Resuming from checkpoint: {args.checkpoint_file}")
        results, metadata = persistence.load_results()
        logger.info(f"Loaded {len(results)} previous scan results")

        # Get already scanned images
        scanned_pairs = {
            (r.pair.alternative_image, r.pair.chainguard_image)
            for r in results if r.scan_successful
        }

        # Filter out already scanned pairs
        remaining_pairs = [
            p for p in pairs
            if (p.alternative_image, p.chainguard_image) not in scanned_pairs
        ]

        if remaining_pairs:
            logger.info(f"Scanning {len(remaining_pairs)} remaining pairs...")
            new_results = scanner.scan_image_pairs_parallel(remaining_pairs)
            results.extend(new_results)

            # Save updated checkpoint
            persistence.save_results(results)
        else:
            logger.info("All pairs already scanned, using checkpoint results")
    else:
        # Fresh scan
        logger.info("Starting vulnerability scans...")
        try:
            results = scanner.scan_image_pairs_parallel(pairs)

            # Save checkpoint after successful scan
            persistence.save_results(results, metadata={
                "pairs_count": len(pairs),
                "platform": args.platform,
            })
            logger.debug(f"Checkpoint saved: {args.checkpoint_file}")

        except KeyboardInterrupt:
            logger.warning("\nScan interrupted! Partial results saved to checkpoint.")
            logger.info(f"Run with --resume to continue from: {args.checkpoint_file}")
            sys.exit(1)

    return results


def generate_pricing_quote(args, results, safe_customer_name):
    """
    Generate pricing quote reports (HTML and TXT).

    Args:
        args: Parsed command-line arguments
        results: List of ScanResult objects
        safe_customer_name: Sanitized customer name for filenames

    Returns:
        Dictionary mapping output type to generated file path
        (keys: 'pricing_html', 'pricing_text')
    """
    from utils.image_classifier import ImageClassifier
    from utils.pricing_calculator import PricingCalculator
    from outputs.pricing_quote_generator import PricingQuoteGenerator
    from collections import Counter, defaultdict

    output_files = {}

    try:
        # Load pricing policy
        if not args.pricing_policy.exists():
            raise FileNotFoundError(
                f"Pricing policy file not found: {args.pricing_policy}. "
                f"Use --pricing-policy to specify a policy file, or create one based on example-pricing-policy.yaml"
            )

        calculator = PricingCalculator.from_policy_file(args.pricing_policy)
        logger.info(f"Loaded pricing policy: {calculator.policy.policy_name}")

        # Classify Chainguard images by tier
        logger.info("Classifying Chainguard images by tier...")
        github_token = None  # Will use GITHUB_TOKEN env var if available
        classifier = ImageClassifier(github_token=github_token, auto_update=True)

        # Extract Chainguard images from results
        chainguard_images = [r.pair.chainguard_image for r in results if r.scan_successful]

        # Classify images by tier and collect image names
        tier_images = defaultdict(list)
        tier_counts = Counter()

        for image in chainguard_images:
            try:
                tier = classifier.get_image_tier(image)
                tier_counts[tier] += 1
                tier_images[tier].append(image)
            except ValueError as e:
                logger.warning(f"Could not classify image {image}: {e}")

        if not tier_counts:
            logger.warning("No images could be classified for pricing. Skipping pricing quote generation.")
        else:
            # Calculate quote with image names
            quote_data = calculator.calculate_quote(dict(tier_counts), dict(tier_images))

            # Generate quote output (both text and HTML)
            generator = PricingQuoteGenerator(customer_name=args.customer_name)

            # Generate HTML quote
            html_path = args.output_dir / f"{safe_customer_name}_pricing_quote.html"
            generator.generate_html_quote(quote_data, html_path)
            output_files["pricing_html"] = html_path

            # Generate text quote
            text_path = args.output_dir / f"{safe_customer_name}_pricing_quote.txt"
            generator.generate_text_quote(quote_data, text_path)
            output_files["pricing_text"] = text_path

    except FileNotFoundError as e:
        logger.error(f"Pricing quote generation failed: {e}")
        logger.error("Skipping pricing quote generation.")
    except Exception as e:
        logger.error(f"Error generating pricing quote: {e}")
        logger.error("Skipping pricing quote generation.")

    return output_files


def generate_reports(args, results, kev_catalog, safe_customer_name, output_types):
    """
    Generate output reports based on requested types.

    Args:
        args: Parsed command-line arguments
        results: List of ScanResult objects
        kev_catalog: KEVCatalog instance or None
        safe_customer_name: Sanitized customer name for filenames
        output_types: Set of output types to generate

    Returns:
        Dictionary mapping output type to generated file path
    """
    from outputs.config import HTMLGeneratorConfig, XLSXGeneratorConfig

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    output_files = {}

    # Generate HTML assessment summary
    if "vuln_summary" in output_types:
        html_path = args.output_dir / f"{safe_customer_name}_assessment.html"
        generator = HTMLGenerator()
        exec_summary = args.exec_summary if args.exec_summary.exists() else None
        appendix = args.appendix if args.appendix.exists() else None
        html_config = HTMLGeneratorConfig(
            customer_name=args.customer_name,
            platform=args.platform,
            exec_summary_path=exec_summary,
            appendix_path=appendix,
            kev_catalog=kev_catalog,
        )
        generator.generate(
            results=results,
            output_path=html_path,
            config=html_config,
        )
        output_files["vuln_summary"] = html_path

    # Generate XLSX cost analysis
    if "cost_analysis" in output_types:
        xlsx_path = args.output_dir / f"{safe_customer_name}_cost_analysis.xlsx"
        generator = XLSXGenerator()
        xlsx_config = XLSXGeneratorConfig(
            customer_name=args.customer_name,
            platform=args.platform,
            hours_per_vuln=args.hours_per_vuln,
            hourly_rate=args.hourly_rate,
            auto_detect_fips=args.with_fips,
            kev_catalog=kev_catalog,
        )
        generator.generate(
            results=results,
            output_path=xlsx_path,
            config=xlsx_config,
        )
        output_files["cost_analysis"] = xlsx_path

    # Generate pricing quote
    if "pricing" in output_types:
        pricing_files = generate_pricing_quote(args, results, safe_customer_name)
        output_files.update(pricing_files)

    return output_files


class GitHubAuthValidator:
    """
    Validates GitHub authentication for pricing quote generation.

    Handles token validation, repository access testing, and SAML SSO refresh.
    """

    def __init__(self, pricing_policy_path: Path):
        """
        Initialize validator.

        Args:
            pricing_policy_path: Path to pricing policy YAML file
        """
        self.pricing_policy_path = pricing_policy_path

    def validate(self) -> None:
        """
        Validate GitHub authentication and repository access.

        Raises:
            SystemExit: If validation fails
        """
        # Check pricing policy file exists
        self._check_pricing_policy()

        # Test GitHub authentication
        logger.info("Validating GitHub authentication for pricing tier classification...")
        from integrations.github_metadata import GitHubMetadataClient
        test_client = GitHubMetadataClient()

        if not test_client.token:
            self._handle_no_token()
            sys.exit(1)

        # Test repository access
        self._test_repository_access(test_client.token)

    def _check_pricing_policy(self) -> None:
        """Check that pricing policy file exists."""
        if not self.pricing_policy_path.exists():
            log_error_section(
                "Pricing quote generation requires a pricing policy file.",
                [
                    f"Pricing policy file not found: {self.pricing_policy_path}",
                    "",
                    "To create a pricing policy:",
                    "  cp example-pricing-policy.yaml pricing-policy.yaml",
                    "  # Edit pricing-policy.yaml to match your pricing structure",
                    "",
                    "Or specify a custom policy file:",
                    "  gauge --pricing-policy /path/to/policy.yaml",
                ],
                logger=logger,
            )
            sys.exit(1)

    def _handle_no_token(self) -> None:
        """Handle case where no GitHub token is found."""
        log_error_section(
            "Pricing quote generation requires GitHub authentication.",
            [
                "",
                "Gauge needs access to chainguard-images/images-private repository",
                "to classify images by pricing tier (base, application, fips, ai).",
                "",
                "To authenticate, choose one of these options:",
                "",
                "Option 1: GitHub CLI (Recommended)",
                "  gh auth login",
                "",
                "Option 2: Personal Access Token",
                "  export GITHUB_TOKEN='your_token_here'",
                "  # Create token at: https://github.com/settings/tokens",
                "  # Required scopes: repo (for private repository access)",
                "",
            ],
            logger=logger,
        )

    def _test_repository_access(self, token: str) -> None:
        """
        Test GitHub repository access with authentication.

        Args:
            token: GitHub token to test

        Raises:
            SystemExit: If access test fails
        """
        logger.debug("Testing GitHub repository access...")
        try:
            import requests
            test_url = "https://api.github.com/repos/chainguard-images/images-private"
            response = requests.get(
                test_url,
                headers={"Authorization": f"token {token}"},
                timeout=5
            )
            response.raise_for_status()
            logger.info("✓ GitHub authentication configured")
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                self._handle_forbidden_error(e, test_url, token)
            elif e.response.status_code == 404:
                logger.warning("Could not verify repository access (404). Proceeding anyway...")
                logger.info("✓ GitHub authentication configured")
            else:
                logger.error(f"GitHub API error: {e}")
                sys.exit(1)
        except Exception as e:
            logger.warning(f"Could not verify repository access: {e}. Proceeding anyway...")
            logger.info("✓ GitHub authentication configured")

    def _handle_forbidden_error(self, error: Exception, test_url: str, token: str) -> None:
        """
        Handle 403 Forbidden errors (potentially SAML SSO issues).

        Args:
            error: Original HTTP error
            test_url: Repository URL being tested
            token: GitHub token being used

        Raises:
            SystemExit: If error cannot be resolved
        """
        # Check for SAML SSO issue
        is_saml_issue = False
        try:
            error_json = error.response.json()
            if "SAML" in error_json.get("message", ""):
                is_saml_issue = True
        except:
            pass

        if is_saml_issue:
            self._attempt_token_refresh(test_url)
        else:
            log_error_section(
                "GitHub token found, but access to chainguard-images/images-private is forbidden.",
                [
                    "",
                    "Your GitHub account may not have access to this private repository.",
                    "Contact your Chainguard administrator for repository access.",
                    "",
                ],
                logger=logger,
            )
            sys.exit(1)

    def _attempt_token_refresh(self, test_url: str) -> None:
        """
        Attempt to refresh GitHub token via gh CLI for SAML SSO.

        Args:
            test_url: Repository URL to test after refresh

        Raises:
            SystemExit: If refresh fails
        """
        log_warning_section(
            "GitHub token needs SAML SSO authorization.",
            [
                "",
                "Attempting to refresh token via gh CLI...",
            ],
            logger=logger,
        )

        try:
            import subprocess
            result = subprocess.run(
                ["gh", "auth", "refresh", "--hostname", "github.com", "-s", "repo"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                logger.info("✓ Token refreshed successfully")
                logger.info("Retrying repository access...")

                # Retry with new token
                from integrations.github_metadata import get_github_token_from_gh_cli
                import requests
                new_token = get_github_token_from_gh_cli()
                if new_token:
                    retry_response = requests.get(
                        test_url,
                        headers={"Authorization": f"token {new_token}"},
                        timeout=5
                    )
                    retry_response.raise_for_status()
                    logger.info("✓ GitHub authentication configured")
                    # Success - return and continue execution
                    return
                else:
                    raise Exception("Failed to get refreshed token")
            else:
                raise Exception(f"gh auth refresh failed: {result.stderr}")

        except FileNotFoundError:
            logger.error("")
            logger.error("gh CLI not found. Please install it:")
            logger.error("  brew install gh  # macOS")
            logger.error("  # or visit: https://cli.github.com/")
            logger.error("")
            logger.error("Then run: gh auth login")
            logger.error("=" * 60)
            sys.exit(1)
        except subprocess.TimeoutExpired:
            logger.error("")
            logger.error("Token refresh timed out.")
            logger.error("Please run manually: gh auth refresh --hostname github.com -s repo")
            logger.error("=" * 60)
            sys.exit(1)
        except Exception as refresh_error:
            logger.error("")
            logger.error(f"Failed to refresh token: {refresh_error}")
            logger.error("")
            logger.error("Manual steps:")
            logger.error("  1. Run: gh auth refresh --hostname github.com -s repo")
            logger.error("  2. Or go to: https://github.com/settings/tokens")
            logger.error("  3. Click on your token")
            logger.error("  4. Click 'Configure SSO'")
            logger.error("  5. Click 'Authorize' next to chainguard-dev organization")
            logger.error("=" * 60)
            sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    # Handle --with-all convenience flag
    if args.with_all:
        args.with_chps = True
        args.with_fips = True
        args.with_kevs = True

    logger.info("Gauge - Container Vulnerability Assessment v2.0")
    logger.info("=" * 60)

    # Parse output types
    try:
        output_types = parse_output_types(args.output)
    except ValueError as e:
        logger.error(f"Invalid output specification: {e}")
        sys.exit(1)

    # Build output description from OUTPUT_CONFIGS
    output_names = {}
    for output_type, config in OUTPUT_CONFIGS.items():
        output_names[output_type] = config["description"]
        # Add format-specific descriptions for multi-format outputs
        if "formats" in config:
            for format_key, format_config in config["formats"].items():
                output_names[f"{output_type}_{format_key}"] = format_config["description"]

    output_list = [output_names[t] for t in sorted(output_types)]
    logger.info(f"Output types: {', '.join(output_list)}")

    # Load image pairs (with matching options for single-column CSV)
    pairs = load_image_pairs(
        csv_path=args.input,
        min_confidence=args.min_confidence,
        dfc_mappings_file=args.dfc_mappings_file,
        cache_dir=args.cache_dir,
        find_upstream=args.find_upstream,
        upstream_confidence=args.upstream_confidence,
        upstream_mappings_file=args.upstream_mappings_file,
        enable_llm_matching=not args.disable_llm_matching,
        llm_model=args.llm_model,
        llm_confidence_threshold=args.llm_confidence_threshold,
        anthropic_api_key=args.anthropic_api_key,
        generate_dfc_pr=args.generate_dfc_pr,
        auto_populate_mappings=not args.disable_mapping_auto_population,
    )

    # Initialize components
    docker_client, cache, kev_catalog = initialize_components(args)

    # Validate GitHub authentication if pricing output requested
    if "pricing" in output_types:
        validator = GitHubAuthValidator(args.pricing_policy)
        validator.validate()

    # Initialize scanner
    scanner = VulnerabilityScanner(
        cache=cache,
        docker_client=docker_client,
        max_workers=args.max_workers,
        platform=args.platform,
        check_fresh_images=not args.no_fresh_check,
        with_chps=args.with_chps,
        kev_catalog=kev_catalog,
    )

    # Execute scans with checkpoint/resume support
    results = execute_scans(args, scanner, pairs)

    # Show cache summary
    logger.info(cache.summary())

    # Check if we have any successful results
    successful_count = sum(1 for r in results if r.scan_successful)
    if successful_count == 0:
        log_error_section(
            "No successful scan results to generate reports.",
            [
                "All image scans failed. Common causes:",
                "  - Chainguard images require authentication (run: chainctl auth configure-docker)",
                "  - Network connectivity issues",
                "  - Invalid image names in CSV",
                "Check the error messages above for details.",
            ],
            logger=logger,
        )
        sys.exit(1)

    # Sanitize customer name for filenames
    safe_customer_name = sanitize_customer_name(args.customer_name)

    # Generate reports
    output_files = generate_reports(args, results, kev_catalog, safe_customer_name, output_types)

    # Summary
    successful = sum(1 for r in results if r.scan_successful)
    failed = len(results) - successful

    logger.info("=" * 60)
    logger.info("Reports generated:")
    for output_type, file_path in output_files.items():
        logger.info(f"  - {output_names[output_type]}: {file_path}")
    logger.info(f"Scanned: {successful} successful, {failed} failed")
    logger.info("Done!")


def main_dispatch():
    """
    Main entry point with subcommand routing.

    Supports both the main scan command and the match subcommand:
    - gauge [args] - Run vulnerability scanning (default)
    - gauge match [args] - Match alternative images to Chainguard equivalents
    """
    # Check if first argument is "match" subcommand
    # Must check before argparse processes --help
    if len(sys.argv) > 1 and sys.argv[1] == "match":
        # Remove "match" from argv and dispatch to match command
        sys.argv.pop(1)
        main_match()
    elif len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        # Show main help with subcommand info
        main()
    else:
        # Default: run scan command
        main()


def main_match():
    """Match command entry point."""
    parser = argparse.ArgumentParser(
        prog="gauge match",
        description="Match alternative container images to Chainguard equivalents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Match images from text file (creates output/matched-log.csv and output/matched-intake.csv)
  gauge match --input images.txt

  # Disable LLM matching (use only Tiers 1-3: DFC, manual, heuristics)
  gauge match --input images.txt --disable-llm-matching

  # Use specific Claude model (Opus for highest accuracy)
  gauge match --input images.txt --llm-model claude-3-opus-20240229

  # Adjust LLM confidence threshold
  gauge match --input images.txt --llm-confidence-threshold 0.8

  # Generate DFC contribution files (outputs to output/ directory)
  gauge match --input images.txt --generate-dfc-pr

  # Enable upstream discovery for private/internal images
  gauge match --input images.txt --find-upstream

  # Match with interactive prompts for low-confidence matches
  gauge match --input images.txt --interactive

  # Use local DFC mappings file (offline mode)
  gauge match --input images.txt --dfc-mappings-file local-mappings.yaml

  # Adjust all confidence thresholds (match, LLM, upstream)
  gauge match --input images.txt --min-confidence 0.8 --llm-confidence-threshold 0.75 --upstream-confidence 0.7

  # Custom output location
  gauge match --input images.txt --output custom-dir/matched-log.csv

LLM Matching (Tier 4):
  LLM-powered fuzzy matching is enabled by default and uses Claude API for
  complex image name transformations. Set ANTHROPIC_API_KEY environment variable
  or use --anthropic-api-key flag. Get an API key at: https://console.anthropic.com/

  Models: claude-sonnet-4-5 (default, balanced)
          claude-opus-4-1 (highest accuracy, slower)
          claude-haiku-4-5 (fastest, cheapest)

  Cache: Responses cached in ~/.cache/gauge/llm_cache.db to reduce API costs
  Telemetry: Match metrics logged to ~/.cache/gauge/llm_telemetry.jsonl

Output Files:
  matched-log.csv    - Detailed matching log with all metadata (confidence, method, upstream)
  matched-intake.csv - 2-column CSV (alternative_image, chainguard_image) for gauge scan
  unmatched.txt      - List of images that couldn't be matched (only if there are any)
  dfc-suggestions.*  - DFC contribution files (only with --generate-dfc-pr)
""",
    )

    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        required=True,
        help="Input file with alternative images (text file or CSV with first column)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("output/matched-log.csv"),
        help="Output CSV file with detailed match log (default: output/matched-log.csv)",
    )

    parser.add_argument(
        "--unmatched",
        type=Path,
        default=Path("output/unmatched.txt"),
        help="Output file for unmatched images (default: output/unmatched.txt, only created if needed)",
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Enable interactive mode to review low-confidence matches",
    )

    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MATCH_CONFIDENCE,
        help=f"Minimum confidence threshold for automatic matching (0.0-1.0, default: {DEFAULT_MATCH_CONFIDENCE})",
    )

    parser.add_argument(
        "--dfc-mappings-file",
        type=Path,
        help="Local DFC mappings file (for offline/air-gapped environments)",
    )

    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="Cache directory for DFC mappings (default: ~/.cache/gauge)",
    )

    parser.add_argument(
        "--find-upstream",
        action="store_true",
        help="Enable upstream image discovery for private/internal images",
    )

    parser.add_argument(
        "--upstream-confidence",
        type=float,
        default=DEFAULT_UPSTREAM_CONFIDENCE,
        help=f"Minimum confidence threshold for upstream discovery (0.0-1.0, default: {DEFAULT_UPSTREAM_CONFIDENCE})",
    )

    parser.add_argument(
        "--upstream-mappings-file",
        type=Path,
        help="Manual upstream mappings file (default: config/upstream_mappings.yaml)",
    )

    # LLM matching options
    llm_group = parser.add_argument_group("llm matching options")
    llm_group.add_argument(
        "--disable-llm-matching",
        action="store_true",
        help="Disable LLM-powered fuzzy matching (Tier 4). LLM matching is enabled by default.",
    )
    llm_group.add_argument(
        "--llm-model",
        type=str,
        default=DEFAULT_LLM_MODEL,
        help=f"Claude model for LLM matching (default: {DEFAULT_LLM_MODEL}). "
             "Options: claude-sonnet-4-5 (balanced), claude-opus-4-1 (highest accuracy), claude-haiku-4-5 (fastest)",
    )
    llm_group.add_argument(
        "--llm-confidence-threshold",
        type=float,
        default=DEFAULT_LLM_CONFIDENCE,
        help=f"Minimum confidence threshold for LLM matches (0.0-1.0, default: {DEFAULT_LLM_CONFIDENCE})",
    )
    llm_group.add_argument(
        "--anthropic-api-key",
        type=str,
        help="Anthropic API key for LLM matching (can also use ANTHROPIC_API_KEY env var)",
    )
    llm_group.add_argument(
        "--generate-dfc-pr",
        action="store_true",
        help="Generate DFC contribution files (dfc-suggestions.yaml and dfc-suggestions.patch) "
             "for successful heuristic (Tier 3) and LLM (Tier 4) matches with high confidence (>= 0.85)",
    )
    llm_group.add_argument(
        "--disable-mapping-auto-population",
        action="store_true",
        help="Disable automatic population of config/image_mappings.yaml "
             "(by default, successful Tier 3/4 matches are saved for instant Tier 2 lookups in future runs)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Validate inputs
    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)

    if args.min_confidence < 0.0 or args.min_confidence > 1.0:
        logger.error("Confidence threshold must be between 0.0 and 1.0")
        sys.exit(1)

    if args.upstream_confidence < 0.0 or args.upstream_confidence > 1.0:
        logger.error("Upstream confidence threshold must be between 0.0 and 1.0")
        sys.exit(1)

    if args.dfc_mappings_file and not args.dfc_mappings_file.exists():
        logger.error(f"DFC mappings file not found: {args.dfc_mappings_file}")
        sys.exit(1)

    if args.upstream_mappings_file and not args.upstream_mappings_file.exists():
        logger.error(f"Upstream mappings file not found: {args.upstream_mappings_file}")
        sys.exit(1)

    # Import match command
    from commands.match import match_images

    # Validate LLM confidence threshold
    if hasattr(args, 'llm_confidence_threshold'):
        if args.llm_confidence_threshold < 0.0 or args.llm_confidence_threshold > 1.0:
            logger.error("LLM confidence threshold must be between 0.0 and 1.0")
            sys.exit(1)

    # Run matching
    try:
        matched_pairs, unmatched_images = match_images(
            input_file=args.input,
            output_file=args.output,
            unmatched_file=args.unmatched,
            min_confidence=args.min_confidence,
            interactive=args.interactive,
            dfc_mappings_file=args.dfc_mappings_file,
            cache_dir=args.cache_dir,
            find_upstream=args.find_upstream,
            upstream_confidence=args.upstream_confidence,
            upstream_mappings_file=args.upstream_mappings_file,
            enable_llm_matching=not args.disable_llm_matching,
            llm_model=args.llm_model,
            llm_confidence_threshold=args.llm_confidence_threshold,
            anthropic_api_key=args.anthropic_api_key,
            generate_dfc_pr=args.generate_dfc_pr,
        )

        # Only create unmatched file if there are unmatched images
        if not unmatched_images and args.unmatched.exists():
            args.unmatched.unlink()
            logger.info("All images matched successfully - no unmatched.txt file created")

    except Exception as e:
        logger.error(f"Match command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main_dispatch()
