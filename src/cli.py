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

from constants import (
    DEFAULT_HOURS_PER_VULNERABILITY,
    DEFAULT_HOURLY_RATE,
    DEFAULT_MAX_WORKERS,
    DEFAULT_PLATFORM,
)
from core.cache import ScanCache
from core.models import ImagePair
from core.scanner import VulnerabilityScanner
from integrations.kev_catalog import KEVCatalog
from outputs.html_generator import HTMLGenerator
from outputs.xlsx_generator import XLSXGenerator
from utils.docker_utils import DockerClient

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Gauge - Container Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output Types:
  cost_analysis  - Vulnerability cost analysis with ROI calculations (XLSX)
  vuln_summary   - Vulnerability assessment summary report (HTML)
  both           - Generate both HTML and XLSX reports

Examples:
  # Simplest usage (uses all defaults)
  gauge

  # Generate vulnerability cost analysis (XLSX)
  gauge --output cost_analysis --output-dir ./reports \\
        --customer "Acme Corp" --hours-per-vuln 3 --hourly-rate 100

  # Generate vulnerability assessment summary (HTML)
  gauge --output vuln_summary --output-dir ./reports \\
        --customer "Acme Corp" --exec-summary summary.md

  # Generate both outputs
  gauge --output both --output-dir ./reports \\
        --customer "Acme Corp" --exec-summary summary.md

  # Include FIPS cost analysis (cost_analysis only)
  gauge --output cost_analysis --with-fips
        """,
    )

    # Input/Output arguments
    io_group = parser.add_argument_group("input/output")
    io_group.add_argument(
        "-s",
        "--source",
        type=Path,
        default=Path("images.csv"),
        help="Source CSV file with image pairs (default: images.csv)",
    )
    io_group.add_argument(
        "-o",
        "--output",
        choices=["cost_analysis", "vuln_summary", "both"],
        default="both",
        help="Output type: 'cost_analysis' (XLSX), 'vuln_summary' (HTML), or 'both' (default: both)",
    )
    io_group.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Output directory for generated reports (default: current directory)",
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
    xlsx_opts.add_argument(
        "--with-fips",
        action="store_true",
        help="Include FIPS cost analysis (auto-detects FIPS images by name)",
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

    # CHPS integration
    parser.add_argument(
        "--with-chps",
        action="store_true",
        help="Include CHPS (Container Hardening and Provenance Scanner) scoring",
    )

    # KEV integration
    parser.add_argument(
        "--with-kevs",
        action="store_true",
        help="Include CISA Known Exploited Vulnerabilities (KEV) data in reports",
    )

    # Other options
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args()


def load_image_pairs(csv_path: Path) -> list[ImagePair]:
    """
    Load image pairs from CSV file with validation.

    Expected format: alternative_image,chainguard_image

    Args:
        csv_path: Path to CSV file

    Returns:
        List of validated ImagePair objects

    Raises:
        SystemExit: If file not found or validation fails
    """
    from core.exceptions import ValidationException
    from utils.validation import validate_image_reference

    pairs = []

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)

            for line_num, row in enumerate(reader, 1):
                # Skip empty lines
                if not row or not any(cell.strip() for cell in row):
                    continue

                # Skip header if it looks like a header
                if line_num == 1 and any(
                    header in row[0].lower()
                    for header in ["chainguard", "customer", "image", "alternative"]
                ):
                    continue

                # Parse pair
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

    except FileNotFoundError:
        if csv_path == Path("images.csv"):
            logger.error(f"The default 'images.csv' was not found in the current directory.")
            logger.error(f"Run again using '--source <your-csv-file>' to specify your input file.")
        else:
            logger.error(f"Source file not found: {csv_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading source file: {e}")
        sys.exit(1)

    if not pairs:
        logger.error("No valid image pairs found in source file")
        sys.exit(1)

    logger.info(f"Loaded {len(pairs)} image pairs")
    return pairs




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


def generate_reports(args, results, kev_catalog, safe_customer_name):
    """
    Generate output reports based on requested format.

    Args:
        args: Parsed command-line arguments
        results: List of ScanResult objects
        kev_catalog: KEVCatalog instance or None
        safe_customer_name: Sanitized customer name for filenames

    Returns:
        List of generated output file paths
    """
    from outputs.config import HTMLGeneratorConfig, XLSXGeneratorConfig

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    output_format = args.output
    output_files = []

    if output_format == "both":
        # Generate both outputs
        html_path = args.output_dir / f"{safe_customer_name}.html"
        xlsx_path = args.output_dir / f"{safe_customer_name}.xlsx"

        # Generate HTML assessment summary
        html_generator = HTMLGenerator()
        exec_summary = args.exec_summary if args.exec_summary.exists() else None
        appendix = args.appendix if args.appendix.exists() else None
        html_config = HTMLGeneratorConfig(
            customer_name=args.customer_name,
            platform=args.platform,
            exec_summary_path=exec_summary,
            appendix_path=appendix,
            kev_catalog=kev_catalog,
        )
        html_generator.generate(
            results=results,
            output_path=html_path,
            config=html_config,
        )

        # Generate XLSX cost analysis
        xlsx_generator = XLSXGenerator()
        xlsx_config = XLSXGeneratorConfig(
            customer_name=args.customer_name,
            platform=args.platform,
            hours_per_vuln=args.hours_per_vuln,
            hourly_rate=args.hourly_rate,
            auto_detect_fips=args.with_fips,
            kev_catalog=kev_catalog,
        )
        xlsx_generator.generate(
            results=results,
            output_path=xlsx_path,
            config=xlsx_config,
        )

        output_files = [html_path, xlsx_path]

    elif output_format == "cost_analysis":
        # Generate XLSX cost analysis
        xlsx_path = args.output_dir / f"{safe_customer_name}.xlsx"
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
        output_files = [xlsx_path]

    elif output_format == "vuln_summary":
        # Generate HTML assessment summary
        html_path = args.output_dir / f"{safe_customer_name}.html"
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
        output_files = [html_path]

    return output_files


def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    logger.info("Gauge - Container Vulnerability Assessment v2.0")
    logger.info("=" * 60)

    # Determine output type from args.output
    output_format = args.output
    if output_format == "both":
        output_type = "Both Assessment Summary (HTML) and Cost Analysis (XLSX)"
    elif output_format == "cost_analysis":
        output_type = "Vulnerability Cost Analysis (XLSX)"
    else:  # vuln_summary
        output_type = "Vulnerability Assessment Summary (HTML)"
    logger.info(f"Output type: {output_type}")

    # Load image pairs
    pairs = load_image_pairs(args.source)

    # Initialize components
    docker_client, cache, kev_catalog = initialize_components(args)

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
        logger.error("=" * 60)
        logger.error("No successful scan results to generate reports.")
        logger.error("All image scans failed. Common causes:")
        logger.error("  - Chainguard images require authentication (run: chainctl auth configure-docker)")
        logger.error("  - Network connectivity issues")
        logger.error("  - Invalid image names in CSV")
        logger.error("Check the error messages above for details.")
        logger.error("=" * 60)
        sys.exit(1)

    # Sanitize customer name for filenames
    safe_customer_name = sanitize_customer_name(args.customer_name)

    # Generate reports
    output_files = generate_reports(args, results, kev_catalog, safe_customer_name)

    # Summary
    successful = sum(1 for r in results if r.scan_successful)
    failed = len(results) - successful

    logger.info("=" * 60)
    if output_format == "both":
        logger.info(f"Reports generated:")
        for f in output_files:
            logger.info(f"  - {f}")
    else:
        logger.info(f"Report generated: {output_files[0]}")
    logger.info(f"Scanned: {successful} successful, {failed} failed")
    logger.info("Done!")


if __name__ == "__main__":
    main()
