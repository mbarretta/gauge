# Gauge

**Gauge your container security posture** - A unified tool for comprehensive container vulnerability assessments comparing the risks, the costs, and the "hardeness" (via [CHPs](https://github.com/chps-dev/chps)) of other container images as compared to [Chainguard Containers](https://www.chainguard.dev/containers).

<table width="100%" border="0" cellpadding="0" cellspacing="0">
<tr>
<td width="40%" valign="top">

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Input Format](#input-format)
- [Command-Line Options](#command-line-options)
- [Caching System](#caching-system)
- [Performance](#performance)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Development](#development)
- [Migration from Legacy Tools](#migration-from-legacy-tools)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

</td>
<td width="60%" valign="middle" align="center">

<img src="resources/gauge-logo-white.png" width="600" alt="Gauge Logo">

</td>
</tr>
</table>

## Features

### Core Capabilities
- **Dual Output Types**: Generate vulnerability assessment summaries (HTML) or cost analysis reports (XLSX)
- **CHPs Scoring**: Container Hardening and Provenance Scanner integration for evaluating non-CVE security factors like provenance, SBOM quality, signing, and container hardening practices
- **Intelligent Caching**: Digest-based caching dramatically improves performance on repeated scans
- **Checkpoint/Resume**: Automatically save progress and resume interrupted scans without losing work
- **Parallel Scanning**: Multi-threaded image scanning for optimal performance
- **Comprehensive Analysis**: Detailed vulnerability breakdowns by severity (Critical, High, Medium, Low, Negligible)

### Vulnerability Assessment Summary (HTML)
- Professional PDF-optimized assessment reports with Chainguard branding
- Executive summaries from markdown files
- Custom appendix support for organization-specific content
- CVE reduction metrics and visual comparisons
- Side-by-side image vulnerability analysis
- Focus: Security posture overview and vulnerability findings

### Vulnerability Cost Analysis (XLSX)
- Detailed ROI calculations for Chainguard adoption
- CVE backlog remediation cost estimates
- Projected future CVE costs based on historical data
- Optional FIPS implementation cost analysis
- Auto-detection of FIPS images
- Interactive formulas for scenario planning
- Focus: Financial planning and business case development

## Prerequisites

- **Python**: 3.10 or higher
- **Docker or Podman**: Container runtime for image operations
- **Grype**: Vulnerability scanner
  ```bash
  # macOS
  brew install anchore/grype/grype

  # Linux
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  ```
- **Syft**: SBOM generator
  ```bash
  # macOS
  brew install syft

  # Linux
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  ```

## Installation

### Option 1: Container (Recommended)

Run Gauge in a container built with Chainguard Images:

```bash
# Build the container
docker build -t gauge:latest .

# Authenticate to Chainguard registry (required for accessing Chainguard images)
chainctl auth login
chainctl auth configure-docker

# Run with your images CSV
docker run --rm \
  -v $(pwd):/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gauge:latest \
  --source /workspace/images.csv \
  --output both \
  --output-dir /workspace \
  --customer "Customer Name"
```

**Important requirements**:
- **Docker socket mount** (`-v /var/run/docker.sock:/var/run/docker.sock`): Required for pulling and scanning images, and CHPS scoring
- **Pre-authentication**: Run `chainctl auth login` and `chainctl auth configure-docker` on your host. This sets up Docker authentication via credential helper, which the container will use through the mounted Docker socket.

### Option 2: Local Installation

```bash
# Clone the repository
cd gauge

# Install dependencies
pip install -r requirements.txt

# Install as a package (recommended)
pip install -e .
```

## Quick Start

### Simplest Usage (with defaults)

With sensible defaults, you can run Gauge with minimal configuration:

```bash
gauge
```

This will:
- Read from `images.csv`
- Generate both `gauge_output.html` and `gauge_output.xlsx`
- Use `exec-summary.md` and `appendix.md` if they exist
- Use default ROI parameters (3 hours/CVE, $100/hour)

### Generate Vulnerability Cost Analysis (XLSX)

Generate a comprehensive cost analysis with ROI calculations:

```bash
gauge --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates `./reports/acme_corp.xlsx`.

### Generate Vulnerability Assessment Summary (HTML)

Generate an executive assessment summary report:

```bash
gauge --output vuln_summary \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates `./reports/acme_corp.html`.

### Generate Both Outputs

Generate both assessment summary (HTML) and cost analysis (XLSX):

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates both `./reports/acme_corp.html` and `./reports/acme_corp.xlsx`.

### With FIPS Cost Analysis

Add FIPS implementation cost calculations (XLSX only):

```bash
gauge --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-fips
```

This will auto-detect FIPS images from their names and create `cost-analysis.xlsx` with FIPS cost analysis included.

### With CHPS Hardening & Provenance Scoring

Include CHPS (Container Hardening and Provenance Scanner) scoring:

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-chps
```

This will include CHPS scores in both HTML and XLSX outputs. CHPS evaluates non-CVE security factors like provenance, SBOM quality, signing, and container hardening practices.

**Note:** CHPS runs in a container automatically. The first time you use `--with-chps`, the tool will pull the `ghcr.io/chps-dev/chps-scorer:latest` image. No local installation required!

### Custom Platform Specification

Override the default platform for specialized environments:

```bash
gauge --platform linux/arm64 \
      --output-dir ./reports \
      --customer "Acme Corp"
```

**Default behavior**: Gauge uses `linux/amd64` by default to ensure consistent results across all environments (including Apple Silicon Macs). This ensures that:
- Vulnerability scans are reproducible
- CHPS scores match direct CHPS execution
- Reports display the same platform across all scans

## Input Format

Create a CSV file with image pairs (one per line):

```csv
alternative_image,chainguard_image
python:3.12,cgr.dev/chainguard-private/python:latest
nginx:1.25,cgr.dev/chainguard-private/nginx:latest
postgres:16,cgr.dev/chainguard-private/postgres:latest
```

Optional header row is automatically skipped.

## Command-Line Options

### Input/Output Options

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --source` | `images.csv` | Source CSV file with image pairs |
| `-o, --output` | `both` | Output type: `cost_analysis` (XLSX), `vuln_summary` (HTML), or `both` |
| `--output-dir` | `.` (current directory) | Output directory for generated reports |

### Common Options

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --customer` | "Customer" | Customer name for report branding |
| `--max-workers` | 4 | Number of parallel scanning threads |
| `--platform` | `linux/amd64` | Platform for image pulls and scans (ensures consistency across all environments including ARM64 Macs) |
| `-v, --verbose` | - | Enable verbose logging |

### Assessment Summary Options (HTML)

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --exec-summary` | `exec-summary.md` | Markdown file for executive summary (optional if file doesn't exist) |
| `-a, --appendix` | `appendix.md` | Markdown file for custom appendix (optional if file doesn't exist) |

### Cost Analysis Options (XLSX)

| Option | Default | Description |
|--------|---------|-------------|
| `--hours-per-vuln` | 3.0 | Average hours to remediate one CVE |
| `--hourly-rate` | 100.0 | Engineering hourly rate in USD |
| `--with-fips` | - | Include FIPS cost analysis (auto-detects FIPS images) |

### CHPS Integration

| Option | Default | Description |
|--------|---------|-------------|
| `--with-chps` | - | Include CHPS (Container Hardening and Provenance Scanner) scoring |

### Cache Options

| Option | Default | Description |
|--------|---------|-------------|
| `--cache-dir` | `.cache` | Cache directory |
| `--no-cache` | - | Disable caching |
| `--clear-cache` | - | Clear cache before starting |
| `--no-fresh-check` | - | Skip checking for fresh images |
| `--resume` | - | Resume from previous checkpoint (if available) |
| `--checkpoint-file` | `.gauge_checkpoint.json` | Checkpoint file path for resume functionality |

## Caching System

Gauge includes two complementary performance systems:

### Intelligent Caching
- **Digest-based**: Uses image SHA256 digests as cache keys
- **Automatic freshness**: Only pulls when remote digest differs
- **Platform-aware**: Different cache per platform (linux/amd64, linux/arm64, etc.)
- **Portable**: Cache can be shared between machines

### Checkpoint/Resume
- **Automatic**: Progress saved after each image pair scan
- **Interruptible**: Safe to stop with Ctrl+C - no work lost
- **Resumable**: Continue from where you left off with `--resume`
- **Smart**: Only scans remaining pairs on resume

### Benefits
- **Significant speedup**: Cached scans return instantly
- **Reliable**: Digest-based validation ensures accuracy
- **Resilient**: Interrupted scans can be resumed
- **Efficient**: Perfect for scanning large fleets (50+ images)

### Cache Management

```bash
# View cache statistics (automatic in logs)
# Cache: 15 hits, 5 misses (75.0% hit rate)

# Clear cache before run
gauge --clear-cache

# Disable caching
gauge --no-cache

# Custom cache location
gauge --cache-dir /path/to/cache

# Resume from checkpoint
gauge --resume

# Custom checkpoint file
gauge --checkpoint-file /path/to/checkpoint.json
```

## Performance

### Optimization Features
- **Parallel scanning**: Multiple images scanned simultaneously
- **Intelligent caching**: Digest-based cache eliminates redundant scans
- **Efficient SBOM usage**: Syft SBOM reused for Grype scanning
- **Auto-tuned workers**: Defaults to optimal thread count

### Typical Performance
- First scan: ~30-60 seconds per image pair
- Cached scan: < 1 second per image pair
- With 4 workers: 3-5x faster than sequential

## Examples

### Basic Vulnerability Assessment Summary

Generate a simple assessment summary report:

```bash
gauge --source my-images.csv \
      --output vuln_summary \
      --output-dir ./reports \
      --customer "Acme Corporation"
```

This generates `./reports/acme_corporation.html`.

### Full Cost Analysis with FIPS

Generate a comprehensive cost analysis with ROI and FIPS calculations:

```bash
gauge --source production-images.csv \
      --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --hours-per-vuln 4 \
      --hourly-rate 125 \
      --with-fips \
      --max-workers 8
```

This generates `./reports/acme_corp.xlsx` with FIPS cost analysis.

### Generate Both Outputs

Generate both assessment summary and cost analysis in one scan:

```bash
gauge --source my-images.csv \
      --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --exec-summary summary.md \
      --hours-per-vuln 4 \
      --hourly-rate 125
```

This generates both `./reports/acme_corp.html` and `./reports/acme_corp.xlsx`.

### High-Performance Scan

Maximize scanning speed for large fleets:

```bash
gauge --source large-fleet.csv \
      --output vuln_summary \
      --output-dir ./reports \
      --customer "Large Fleet" \
      --max-workers 12 \
      --no-fresh-check  # Skip freshness checks for speed
```

This generates `./reports/large_fleet.html`.

### Resume Interrupted Scan

For long-running scans that may be interrupted, use checkpoint/resume functionality:

```bash
# Start a long scan (creates checkpoint automatically)
gauge --source large-fleet.csv \
      --output both \
      --output-dir ./reports \
      --customer "Fleet Analysis" \
      --resume

# If interrupted (Ctrl+C), you'll see:
# Scan interrupted! Partial results saved to checkpoint.
# Run with --resume to continue from: .gauge_checkpoint.json

# Resume from where you left off
gauge --source large-fleet.csv \
      --output both \
      --output-dir ./reports \
      --customer "Fleet Analysis" \
      --resume

# Output:
# Resuming from checkpoint: .gauge_checkpoint.json
# Loaded 15 previous scan results
# Scanning 10 remaining pairs...
```

**Benefits:**
- Automatically saves progress after each image pair
- Resume skips already-scanned images
- Safe to interrupt with Ctrl+C - no lost work
- Useful for scanning 50+ image pairs

## Troubleshooting

### Common Issues

**"Neither docker nor podman found"**
- Ensure Docker or Podman is installed and in PATH
- Test with `docker --version` or `podman --version`

**"syft is required but not found"**
- Install Syft following prerequisites above
- Test with `syft version`

**"grype is required but not found"**
- Install Grype following prerequisites above
- Test with `grype version`

**Slow scanning**
- Use `--cache-dir` to enable caching
- Increase `--max-workers` for more parallelism
- Use `--no-fresh-check` to skip image freshness validation

**Cache issues**
- Clear cache with `--clear-cache`
- Disable caching with `--no-cache`
- Check cache directory permissions

**Checkpoint/Resume issues**
- Delete stale checkpoint: `rm .gauge_checkpoint.json`
- Use different checkpoint file: `--checkpoint-file custom.json`
- Checkpoint is JSON - safe to inspect/edit manually
- Resume only works with same CSV file and image pairs

## Project Structure

```
gauge/
├── src/                              # Source code
│   ├── core/                         # Core functionality
│   │   ├── cache.py                 # Digest-based scan caching
│   │   ├── exceptions.py            # Exception hierarchy (GaugeException, ScanException, etc.)
│   │   ├── models.py                # Data models (ImageAnalysis, ScanResult, CHPSScore)
│   │   ├── persistence.py           # Checkpoint/resume functionality
│   │   ├── scanner.py               # Vulnerability scanner orchestration
│   │   └── scanner_interface.py    # Scanner plugin interface (VulnerabilityProvider)
│   ├── integrations/                # External tool integrations
│   │   ├── chainguard_api.py       # Chainguard API client for CVE growth rates
│   │   ├── grype_provider.py       # Grype scanner provider implementation
│   │   └── kev_catalog.py          # CISA KEV catalog integration
│   ├── outputs/                     # Report generators
│   │   ├── base.py                 # Base generator interface
│   │   ├── config.py               # Generator configuration dataclasses
│   │   ├── html_generator.py      # HTML assessment summary generator
│   │   ├── xlsx_formats.py         # XLSX formatting styles (factory pattern)
│   │   ├── xlsx_generator.py      # XLSX cost analysis generator
│   │   └── xlsx_writers.py         # XLSX section writers (modular components)
│   ├── utils/                       # Utility modules
│   │   ├── chps_utils.py           # CHPS (Container Hardening) integration
│   │   ├── cve_ratios.py           # CVE growth rate calculation with API fallback
│   │   ├── docker_utils.py         # Docker/Podman operations
│   │   ├── fips_calculator.py      # FIPS implementation cost calculations
│   │   ├── roi_calculator.py       # ROI and CVE cost projections
│   │   ├── validation.py           # Input validation utilities
│   │   └── vulnerability_utils.py  # Vulnerability aggregation logic
│   ├── constants.py                 # Centralized configuration constants
│   └── cli.py                       # Command-line interface
├── tests/                            # Unit tests (pytest)
│   ├── conftest.py                  # Shared test fixtures
│   ├── test_models.py              # Model tests
│   └── test_validation.py          # Validation tests
├── resources/                        # Static resources
│   ├── gauge-logo-black.png        # Gauge logo (dark backgrounds)
│   ├── gauge-logo-white.png        # Gauge logo (light backgrounds)
│   └── linky-white.png             # Chainguard logo for HTML reports
├── pytest.ini                        # Pytest configuration
├── example-images.csv               # Sample image pairs for testing
├── sample-exec-summary.md           # Example executive summary template
├── sample-appendix.md               # Example appendix template
├── requirements.txt                 # Python dependencies
├── setup.py                         # Package installation config
├── MIGRATION.md                     # Migration guide from legacy tools
└── README.md                        # This file
```

### Key Components

**Core Modules:**
- `scanner.py`: Orchestrates Syft (SBOM) → Grype (CVE scanning) → CHPS (hardening) pipeline
- `cache.py`: Digest-based caching for performance optimization
- `models.py`: Immutable data structures for type safety
- `exceptions.py`: Standardized exception hierarchy for consistent error handling
- `persistence.py`: Checkpoint/resume functionality for long-running scans
- `scanner_interface.py`: Plugin interface for extensible scanner integration

**Report Generators:**
- `html_generator.py`: Professional assessment summaries with Chainguard branding
- `xlsx_generator.py`: Interactive cost analysis with ROI calculations
- `xlsx_writers.py`: Modular section writers following single-responsibility principle
- `xlsx_formats.py`: Formatting factory pattern eliminates style duplication
- `config.py`: Strongly-typed generator configuration dataclasses

**Integrations:**
- `grype_provider.py`: Grype scanner provider implementing plugin interface
- `chainguard_api.py`: Chainguard API client for dynamic CVE growth rates
- `kev_catalog.py`: CISA Known Exploited Vulnerabilities catalog integration
- `chps_utils.py`: Containerized CHPS execution with score recalculation

**Utilities:**
- `validation.py`: Comprehensive input validation (images, paths, numbers, names)
- `vulnerability_utils.py`: Centralized vulnerability aggregation logic
- `cve_ratios.py`: CVE growth rate calculation with API fallback
- `docker_utils.py`: Unified Docker/Podman interface with platform awareness
- `roi_calculator.py`: ROI and CVE cost projections
- `fips_calculator.py`: FIPS implementation cost calculations

**Tests:**
- `conftest.py`: Shared pytest fixtures for test data and temporary resources
- `test_models.py`: Comprehensive model tests (immutability, serialization)
- `test_validation.py`: Input validation tests (edge cases, error handling)

**Resources:**
- `linky-white.png`: Chainguard logo embedded in HTML header
- `gauge-logo-*.png`: Gauge branding for documentation
- `pytest.ini`: Pytest configuration with markers and coverage options

### Design Principles

- **SOLID Principles**: Clean interfaces, single responsibilities
- **Immutable Data**: Frozen dataclasses prevent accidental mutation
- **Type Safety**: Comprehensive type hints throughout
- **Modern Python**: Uses `src/` layout (Python best practice)
- **Dependency Injection**: Testable, mockable components

## Development

### Running Without Install

```bash
# Using PYTHONPATH
PYTHONPATH=src python -m cli --help

# Or use the development script
python -m src.cli --help
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_models.py

# Run with verbose output
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Run only unit tests (fast)
pytest tests/ -m unit

# Type checking (if mypy installed)
mypy src/

# Code formatting (if black installed)
black src/
```

## Migration from Legacy Tools

If you're migrating from `cg_assessment` or `minibva`, see **[MIGRATION.md](MIGRATION.md)** for detailed instructions.

**Quick migration:**
- `python -m gauge` → `gauge`
- `python3 minibva.py` → `gauge`
- All features preserved, much simpler commands!

## Contributing

Gauge consolidates and improves upon two previous tools:
- `cg_assessment`: HTML/PDF report generator
- `minibva`: XLSX ROI calculator

The unified tool maintains 100% feature parity with both while adding:
- Cleaner architecture with `src/` layout
- Better error handling
- Improved performance
- Enhanced logging
- Type safety throughout

## License

Copyright © 2025 Chainguard. All Rights Reserved.

---

**Built with [Claude Code](https://claude.com/claude-code)**
