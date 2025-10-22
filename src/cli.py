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
  HTML  - Vulnerability assessment summary report
  XLSX  - Vulnerability cost analysis with ROI calculations
  BOTH  - Generate both HTML and XLSX reports

Examples:
  # Generate vulnerability cost analysis (XLSX)
  gauge --source images.csv --output analysis.xlsx \\
        --customer "Acme Corp" --hours-per-vuln 3 --hourly-rate 100

  # Generate vulnerability assessment summary (HTML)
  gauge --source images.csv --output assessment.html \\
        --customer "Acme Corp" --exec-summary summary.md

  # Generate both outputs
  gauge --source images.csv --output report --both \\
        --customer "Acme Corp" --exec-summary summary.md

  # Include FIPS cost analysis (XLSX only)
  gauge --source images.csv --output cost-analysis.xlsx \\
        --fips-count 5
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
        type=Path,
        default=Path("gauge_output"),
        help="Output file path or base name for --both (default: gauge_output)",
    )

    # Output type
    format_group = parser.add_argument_group("output type")
    format_group.add_argument(
        "--format",
        choices=["html", "xlsx", "both"],
        help="Output type: 'html' for assessment summary, 'xlsx' for cost analysis, 'both' for both (auto-detected from extension)",
    )
    format_group.add_argument(
        "--both",
        action="store_true",
        default=True,
        help="Generate both HTML and XLSX outputs (default: True)",
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
        default=4,
        help="Number of parallel scanning threads (default: 4)",
    )
    common.add_argument(
        "--platform",
        help="Platform for scans (e.g., linux/amd64)",
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
        default=3.0,
        help="Average hours to remediate one CVE (default: 3.0)",
    )
    xlsx_opts.add_argument(
        "--hourly-rate",
        "--hourlyrate",
        type=float,
        default=100.0,
        help="Engineering hourly rate in USD (default: 100.0)",
    )
    xlsx_opts.add_argument(
        "--fips-count",
        "--fips",
        type=int,
        help="Number of FIPS images for cost calculation",
    )
    xlsx_opts.add_argument(
        "--auto-detect-fips",
        action="store_true",
        help="Auto-detect FIPS images from names (overrides --fips-count)",
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
    Load image pairs from CSV file.

    Expected format: alternative_image,chainguard_image
    """
    pairs = []

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)

            for line_num, row in enumerate(reader, 1):
                # Skip empty lines
                if not row or not any(row):
                    continue

                # Skip header if it looks like a header
                if line_num == 1 and any(
                    header in row[0].lower()
                    for header in ["chainguard", "customer", "image", "alternative"]
                ):
                    continue

                # Parse pair
                if len(row) >= 2:
                    alt_image = row[0].strip()
                    cgr_image = row[1].strip()

                    if cgr_image and alt_image:
                        pairs.append(ImagePair(cgr_image, alt_image))
                else:
                    logger.warning(f"Skipping malformed line {line_num}: {row}")

    except FileNotFoundError:
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


def detect_output_format(output_path: Path, specified_format: str = None, both_flag: bool = False) -> str:
    """Detect output format from file extension or specified format."""
    if both_flag or specified_format == "both":
        return "both"

    if specified_format:
        return specified_format.lower()

    suffix = output_path.suffix.lower()
    if suffix in [".xlsx", ".xls"]:
        return "xlsx"
    elif suffix in [".html", ".htm"]:
        return "html"
    else:
        logger.error(
            f"Could not detect output format from extension: {suffix}. "
            "Please specify --format explicitly or use --both."
        )
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    logger.info("Gauge - Container Vulnerability Assessment v2.0")
    logger.info("=" * 60)

    # Detect output type
    output_format = detect_output_format(args.output, args.format, args.both)
    if output_format == "both":
        output_type = "Both Assessment Summary (HTML) and Cost Analysis (XLSX)"
    elif output_format == "xlsx":
        output_type = "Vulnerability Cost Analysis"
    else:
        output_type = "Vulnerability Assessment Summary"
    logger.info(f"Output type: {output_type} ({output_format.upper()})")

    # Load image pairs
    pairs = load_image_pairs(args.source)

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

    # Initialize scanner
    scanner = VulnerabilityScanner(
        cache=cache,
        docker_client=docker_client,
        max_workers=args.max_workers,
        platform=args.platform,
        check_fresh_images=not args.no_fresh_check,
    )

    # Load KEV catalog (optional, for enhanced reporting)
    kev_catalog = KEVCatalog()
    kev_catalog.load()

    # Scan images
    logger.info("Starting vulnerability scans...")
    results = scanner.scan_image_pairs_parallel(pairs)

    # Show cache summary
    logger.info(cache.summary())

    # Generate report(s) based on format
    if output_format == "both":
        # Generate both outputs with appropriate extensions
        base_path = args.output.with_suffix("")
        html_path = base_path.with_suffix(".html")
        xlsx_path = base_path.with_suffix(".xlsx")

        # Generate HTML assessment summary
        html_generator = HTMLGenerator()
        # Only pass exec-summary and appendix if they exist
        exec_summary = args.exec_summary if args.exec_summary.exists() else None
        appendix = args.appendix if args.appendix.exists() else None
        html_generator.generate(
            results=results,
            output_path=html_path,
            customer_name=args.customer_name,
            exec_summary_path=exec_summary,
            appendix_path=appendix,
        )

        # Generate XLSX cost analysis
        xlsx_generator = XLSXGenerator()
        xlsx_generator.generate(
            results=results,
            output_path=xlsx_path,
            customer_name=args.customer_name,
            hours_per_vuln=args.hours_per_vuln,
            hourly_rate=args.hourly_rate,
            fips_count=args.fips_count,
            auto_detect_fips=args.auto_detect_fips,
        )

        output_files = [html_path, xlsx_path]

    elif output_format == "xlsx":
        generator = XLSXGenerator()
        generator.generate(
            results=results,
            output_path=args.output,
            customer_name=args.customer_name,
            hours_per_vuln=args.hours_per_vuln,
            hourly_rate=args.hourly_rate,
            fips_count=args.fips_count,
            auto_detect_fips=args.auto_detect_fips,
        )
        output_files = [args.output]

    elif output_format == "html":
        generator = HTMLGenerator()
        # Only pass exec-summary and appendix if they exist
        exec_summary = args.exec_summary if args.exec_summary.exists() else None
        appendix = args.appendix if args.appendix.exists() else None
        generator.generate(
            results=results,
            output_path=args.output,
            customer_name=args.customer_name,
            exec_summary_path=exec_summary,
            appendix_path=appendix,
        )
        output_files = [args.output]

    # Summary
    successful = sum(1 for r in results if r.scan_successful)
    failed = len(results) - successful

    logger.info("=" * 60)
    if output_format == "both":
        logger.info(f"Reports generated:")
        for f in output_files:
            logger.info(f"  - {f}")
    else:
        logger.info(f"Report generated: {args.output}")
    logger.info(f"Scanned: {successful} successful, {failed} failed")
    logger.info("Done!")


if __name__ == "__main__":
    main()
