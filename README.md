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
- **Multiple Output Types**: Generate vulnerability summaries (HTML), cost analysis (XLSX), or pricing quotes (HTML + TXT)
- **CHPs Scoring**: Container Hardening and Provenance Scanner integration for evaluating non-CVE security factors like provenance, SBOM quality, signing, and container hardening practices
- **KEV Detection**: Optional integration with CISA's Known Exploited Vulnerabilities catalog to identify actively exploited CVEs in your images
- **Intelligent Caching**: Digest-based caching with exact flag matching dramatically improves performance on repeated scans
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

### Pricing Quote (HTML + TXT)
- Automated pricing quotes based on Chainguard image tiers (base, application, fips, ai)
- Automatic image tier classification via GitHub metadata
- Volume-based pricing with bulk discounts
- Configurable pricing policies per customer/partner
- Professional HTML quotes with customer branding and plain text versions for email
- Includes policy details, line items, and totals
- Focus: Sales enablement and subscription estimates

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

### With Known Exploited Vulnerabilities (KEV) Detection

Check CVEs against CISA's Known Exploited Vulnerabilities catalog:

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-kevs
```

This will fetch CISA's KEV catalog and identify which CVEs in your images are actively being exploited in the wild. KEVs are highlighted with red badges in HTML reports and red cells in XLSX reports, making them easy to spot for prioritization.

**Note:** The KEV catalog is fetched from CISA on each run when `--with-kevs` is enabled. This ensures you always have the most up-to-date list of exploited vulnerabilities.

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
| `-o, --output` | All three types | Output types to generate (comma-separated): `cost_analysis` (XLSX), `vuln_summary` (HTML), `pricing` (HTML + TXT). Default generates all three. Examples: `--output pricing`, `--output cost_analysis,pricing` |
| `--output-dir` | `.` (current directory) | Output directory for generated reports |
| `--pricing-policy` | `pricing-policy.yaml` | Pricing policy file for quote generation (see [Pricing Configuration](#pricing-configuration)) |

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

#### Template Variables for Executive Summary and Appendix

Both the executive summary and appendix markdown files support template variable substitution. Use `{{variable_name}}` syntax to insert dynamic values:

**Basic Metrics:**
- `{{customer_name}}` - Customer name from `--customer` flag
- `{{images_scanned}}` - Total number of images analyzed
- `{{total_customer_vulns}}` - Total CVEs in customer/alternative images
- `{{total_chainguard_vulns}}` - Total CVEs in Chainguard images
- `{{total_reduction}}` - Total CVE reduction (customer - chainguard)
- `{{reduction_percentage}}` - CVE reduction as percentage (with % sign)
- `{{images_with_reduction}}` - Number of images where Chainguard has fewer CVEs
- `{{average_reduction_per_image}}` - Average CVE reduction per image

**KEV Metrics** (available when using `--with-kevs` flag):
- `{{total_customer_kevs}}` - Total Known Exploited Vulnerabilities in customer images
- `{{total_chainguard_kevs}}` - Total KEVs in Chainguard images
- `{{kev_reduction}}` - KEV reduction (customer - chainguard)
- `{{images_with_customer_kevs}}` - Number of customer images containing KEVs
- `{{images_with_chainguard_kevs}}` - Number of Chainguard images containing KEVs

**Example usage in markdown:**
```markdown
### Security Assessment for {{customer_name}}

Analysis of {{images_scanned}} images found a {{reduction_percentage}} reduction in vulnerabilities.
Current images contain {{total_customer_vulns}} CVEs, while Chainguard equivalents reduce this to {{total_chainguard_vulns}}.

**Critical finding**: {{images_with_customer_kevs}} images contain {{total_customer_kevs}} actively exploited vulnerabilities (KEVs).
```

See `sample-exec-summary.md` and `sample-appendix.md` for complete examples.

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

### KEV Integration

| Option | Default | Description |
|--------|---------|-------------|
| `--with-kevs` | - | Check CVEs against CISA's Known Exploited Vulnerabilities catalog and highlight them in reports |

### Pricing Configuration

The pricing quote feature automatically generates subscription cost estimates based on the Chainguard images in your assessment. It classifies images by tier (base, application, fips, ai) and applies volume-based pricing with bulk discounts.

#### Prerequisites

1. **Pricing Policy File**: Create or customize `pricing-policy.yaml` from the example:
   ```bash
   cp example-pricing-policy.yaml pricing-policy.yaml
   # Edit pricing-policy.yaml to match your pricing structure
   ```

2. **GitHub Authentication** (for automatic image tier classification):

   Gauge needs access to the private `chainguard-images/images-private` repository to classify images by tier. Choose one of these authentication methods:

   **Option 1: GitHub CLI (Recommended)**
   ```bash
   # Install gh CLI if not already installed
   brew install gh  # macOS
   # or: https://cli.github.com/

   # Authenticate
   gh auth login
   ```
   Gauge will automatically use the `gh` CLI token.

   **Option 2: Environment Variable**
   ```bash
   export GITHUB_TOKEN="your_personal_access_token"
   ```
   Create a Personal Access Token at: https://github.com/settings/tokens

   Required scopes: `repo` (for private repository access)

#### Image Tier Classification

Gauge automatically classifies Chainguard images into pricing tiers:

- **base** - Minimal OS and language runtimes (python, node, golang-base, etc.)
- **application** - Full applications, databases, web servers (nginx, postgres, redis, etc.)
- **fips** - FIPS 140-2/140-3 validated images (python-fips, nginx-fips, etc.)
- **ai** - Machine learning and AI framework images (pytorch, tensorflow, etc.)

The classification:
1. Checks local tier mappings in `config/image_tiers.yaml` (cached from previous runs)
2. Fetches unknown images from GitHub metadata
3. Auto-saves new classifications for team sharing
4. Prompts to commit updated `image_tiers.yaml` to version control

#### Pricing Policy Format

The pricing policy YAML file defines tier-based pricing with volume discounts:

```yaml
# Base images pricing
base:
  - min: 1
    max: 10
    list_price: 29000  # $290.00 list price per image (prices in cents)
    discount_percent: 0  # No discount
  - min: 11
    max: 25
    list_price: 29000  # $290.00 list price
    discount_percent: 10  # 10% discount = $261.00 final price
  - min: 26
    max: null  # null = unlimited
    list_price: 29000  # $290.00 list price
    discount_percent: 20  # 20% discount = $232.00 final price

# Application images pricing
application:
  - min: 1
    max: 10
    list_price: 35000  # $350.00 list price per image
    discount_percent: 0
  # ... additional ranges

# Metadata
policy_name: "Standard Enterprise Pricing"
effective_date: "2025-01-01"
currency: "USD"
pricing_unit: "per image per year"
notes: |
  - All prices are annual subscription fees
  - Volume discounts apply within each tier independently
  - Contact sales@chainguard.dev for custom pricing
```

**Pricing Calculation:**
- `list_price`: The list price per image (before any discounts)
- `discount_percent`: Discount percentage as a float (e.g., `10` for 10%, `20.5` for 20.5%)
- **Discounted price is automatically calculated**: `list_price * (1 - discount_percent/100)`
- Example: `list_price: 29000` with `discount_percent: 10` yields final price of $261.00

See `example-pricing-policy.yaml` for a complete example with all four tiers.

#### Usage Examples

```bash
# Generate only pricing quote
gauge --source images.csv --customer "Acme Corp" --output pricing

# Generate pricing + cost analysis
gauge --output pricing,cost_analysis

# Use custom pricing policy
gauge --pricing-policy custom-pricing.yaml --output pricing

# Generate all outputs (default)
gauge --source images.csv --customer "Acme Corp"
```

#### Output

The pricing quote generator creates a professional HTML report (`{customer}_pricing_quote.html`) containing:
- Customer name and quote date
- Policy name and effective date
- Line items by tier with quantities, prices, and specific image names
- Volume discounts automatically applied
- Subtotal and grand total
- Policy notes and contact information

Images are listed under their respective tiers, making it easy to see which specific images are included in each pricing tier.

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
- **Exact flag matching**: Cache validated against CHPS/KEV/FIPS flags (e.g., running without `--with-chps` invalidates cache entries that have CHPS data)
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
├── src/                    # Source code (core, integrations, outputs, utils)
├── tests/                  # Unit and integration tests (188 tests)
├── config/                 # Configuration files
├── resources/              # Static assets (logos, images)
├── example-images.csv      # Sample input file
├── sample-exec-summary.md  # Example template
├── sample-appendix.md      # Example template
├── example-pricing-policy.yaml  # Pricing policy example
├── requirements.txt        # Python dependencies
├── setup.py                # Package configuration
├── Dockerfile              # Container build
├── README.md               # User documentation (this file)
├── CONTRIBUTING.md         # Developer documentation
└── MIGRATION.md            # Legacy tool migration guide
```

For detailed architecture, module organization, and development guidelines, see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

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

Contributions are welcome! For detailed information on:
- Development setup and environment
- Project architecture and design principles
- Code organization and module responsibilities
- Testing guidelines and procedures
- Code style and documentation standards
- Common development tasks
- Pull request process

Please see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

### Quick Start for Contributors

```bash
# Clone and setup
git clone <repository-url>
cd gauge
pip install -r requirements.txt
pip install -e .

# Run tests
pytest

# See CONTRIBUTING.md for detailed guidelines
```

## License

Copyright © 2025 Chainguard. All Rights Reserved.

---

**Built with [Claude Code](https://claude.com/claude-code)**
