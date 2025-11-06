"""
Centralized configuration constants for Gauge.

This module provides a single source of truth for configuration values
that are used across multiple modules, making them easier to update
and maintain.
"""

# ============================================================================
# Platform and Architecture
# ============================================================================

DEFAULT_PLATFORM = "linux/amd64"
"""Default container platform architecture."""

# ============================================================================
# Financial / ROI Calculation Defaults
# ============================================================================

DEFAULT_HOURS_PER_VULNERABILITY = 3.0
"""Default estimated hours to remediate one CVE."""

DEFAULT_HOURLY_RATE = 100.0
"""Default engineering hourly rate in USD."""

CHAINGUARD_IMAGE_COST = 29000
"""Annual cost per Chainguard image subscription in USD."""

# ============================================================================
# Concurrency and Performance
# ============================================================================

DEFAULT_MAX_WORKERS = 8
"""Default number of concurrent workers for parallel scanning."""

# ============================================================================
# Timeouts (in seconds)
# ============================================================================

SYFT_TIMEOUT = 300
"""Timeout for Syft SBOM generation (5 minutes)."""

GRYPE_TIMEOUT = 300
"""Timeout for Grype vulnerability scanning (5 minutes)."""

CHPS_TIMEOUT = 120
"""Timeout for CHPS scoring (2 minutes)."""

VERSION_CHECK_TIMEOUT = 5
"""Timeout for tool version checks (5 seconds)."""

API_REQUEST_TIMEOUT = 30
"""Timeout for general API requests (30 seconds)."""

KEV_CATALOG_TIMEOUT = 30
"""Timeout for KEV catalog download (30 seconds)."""

# ============================================================================
# CVE Monthly Occurrence Ratios
# ============================================================================

CVE_MONTHLY_RATIOS = {
    "CRITICAL": 0.06226879415733905,
    "HIGH": 0.048255074492743404,
    "MEDIUM": 0.09295663633080238,
    "LOW": 0.039432287834430285,
    "NEGLIGIBLE": 0.30331818635773494,
}
"""
Historical monthly CVE occurrence ratios by severity.

These represent the average monthly new CVE rate as a ratio of current CVEs,
derived from historical analysis of container image vulnerability trends.

USAGE NOTE: These static constants serve as FALLBACK values when dynamic
CVE growth rates cannot be fetched from the Chainguard API. The application
prefers to use real-time data via ChainguardAPI.calculate_cve_growth_rate()
when available (requires chainctl authentication). When the API is unavailable,
unreachable, or returns no data, these historical ratios are used instead.

See utils/cve_ratios.py:get_cve_monthly_ratios() for the fallback logic.
"""

# ============================================================================
# FIPS Phase Configurations
# ============================================================================

# These are imported from fips_calculator to avoid circular dependencies
# but documented here for reference. See utils.fips_calculator for details.

# ============================================================================
# External Service URLs
# ============================================================================

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
"""URL for CISA Known Exploited Vulnerabilities catalog."""

CHAINGUARD_API_URL = "https://console-api.enforce.dev"
"""Base URL for Chainguard API services."""

CHPS_SCORER_IMAGE = "ghcr.io/chps-dev/chps-scorer:latest"
"""Docker image for CHPS (Container Hardening and Provenance Scanner)."""

# ============================================================================
# Resource Paths
# ============================================================================

CHAINGUARD_LOGO_PATH = "resources/linky-white.png"
"""Path to Chainguard logo for HTML reports."""

# ============================================================================
# CHPS Grade Mappings
# ============================================================================

GRADE_TO_CSS_CLASS = {
    'A+': 'vuln-negligible',
    'A': 'vuln-negligible',
    'B': 'vuln-low',
    'C': 'vuln-medium',
    'D': 'vuln-high',
    'E': 'vuln-critical',
    'F': 'vuln-critical',
}
"""Mapping of CHPS letter grades to CSS color classes (without vuln-badge)."""
