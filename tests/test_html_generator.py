"""
Tests for HTML generator, including new metrics calculations.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from outputs.html_generator import HTMLGenerator
from core.models import (
    ImageAnalysis,
    ImagePair,
    ScanResult,
    VulnerabilityCount,
)


class TestMetricsCalculations:
    """Test the new metrics calculations in HTML generator."""

    @pytest.fixture
    def html_generator(self, tmp_path):
        """Create an HTMLGenerator instance for testing."""
        return HTMLGenerator()

    def test_images_with_reduction_all_reduced(self, html_generator):
        """Test images_with_reduction when all images have fewer CVEs with Chainguard."""
        results = [
            ScanResult(
                pair=ImagePair(
                    alternative_image="python:3.12",
                    chainguard_image="cgr.dev/chainguard/python:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="python:3.12",
                    size_mb=950.0,
                    package_count=427,
                    vulnerabilities=VulnerabilityCount(
                        total=100, critical=5, high=20, medium=30, low=40, negligible=5
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:abc123",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/python:latest",
                    size_mb=45.0,
                    package_count=35,
                    vulnerabilities=VulnerabilityCount(
                        total=10, critical=0, high=2, medium=3, low=5, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:def456",
                ),
                scan_successful=True,
            ),
            ScanResult(
                pair=ImagePair(
                    alternative_image="nginx:1.25",
                    chainguard_image="cgr.dev/chainguard/nginx:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="nginx:1.25",
                    size_mb=150.0,
                    package_count=200,
                    vulnerabilities=VulnerabilityCount(
                        total=50, critical=2, high=10, medium=15, low=20, negligible=3
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:ghi789",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/nginx:latest",
                    size_mb=25.0,
                    package_count=30,
                    vulnerabilities=VulnerabilityCount(
                        total=5, critical=0, high=1, medium=2, low=2, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:jkl012",
                ),
                scan_successful=True,
            ),
        ]

        metrics = html_generator._calculate_metrics(results)

        assert metrics['images_scanned'] == 2
        assert metrics['images_with_reduction'] == 2
        assert metrics['total_customer_vulns'] == 150
        assert metrics['total_chainguard_vulns'] == 15
        assert metrics['total_reduction'] == 135
        assert metrics['average_reduction_per_image'] == 67.5

    def test_images_with_reduction_partial(self, html_generator):
        """Test images_with_reduction when only some images have reduction."""
        results = [
            ScanResult(
                pair=ImagePair(
                    alternative_image="python:3.12",
                    chainguard_image="cgr.dev/chainguard/python:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="python:3.12",
                    size_mb=950.0,
                    package_count=427,
                    vulnerabilities=VulnerabilityCount(
                        total=100, critical=5, high=20, medium=30, low=40, negligible=5
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:abc123",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/python:latest",
                    size_mb=45.0,
                    package_count=35,
                    vulnerabilities=VulnerabilityCount(
                        total=10, critical=0, high=2, medium=3, low=5, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:def456",
                ),
                scan_successful=True,
            ),
            # Second image has same number of vulnerabilities
            ScanResult(
                pair=ImagePair(
                    alternative_image="nginx:1.25",
                    chainguard_image="cgr.dev/chainguard/nginx:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="nginx:1.25",
                    size_mb=150.0,
                    package_count=200,
                    vulnerabilities=VulnerabilityCount(
                        total=50, critical=2, high=10, medium=15, low=20, negligible=3
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:ghi789",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/nginx:latest",
                    size_mb=25.0,
                    package_count=30,
                    vulnerabilities=VulnerabilityCount(
                        total=50, critical=2, high=10, medium=15, low=20, negligible=3
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:jkl012",
                ),
                scan_successful=True,
            ),
        ]

        metrics = html_generator._calculate_metrics(results)

        assert metrics['images_scanned'] == 2
        assert metrics['images_with_reduction'] == 1  # Only first image has reduction
        assert metrics['total_customer_vulns'] == 150
        assert metrics['total_chainguard_vulns'] == 60
        assert metrics['total_reduction'] == 90
        assert metrics['average_reduction_per_image'] == 45.0

    def test_images_with_reduction_none(self, html_generator):
        """Test images_with_reduction when no images have reduction."""
        results = [
            ScanResult(
                pair=ImagePair(
                    alternative_image="python:3.12",
                    chainguard_image="cgr.dev/chainguard/python:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="python:3.12",
                    size_mb=950.0,
                    package_count=427,
                    vulnerabilities=VulnerabilityCount(
                        total=10, critical=0, high=2, medium=3, low=5, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:abc123",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/python:latest",
                    size_mb=45.0,
                    package_count=35,
                    vulnerabilities=VulnerabilityCount(
                        total=10, critical=0, high=2, medium=3, low=5, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:def456",
                ),
                scan_successful=True,
            ),
        ]

        metrics = html_generator._calculate_metrics(results)

        assert metrics['images_scanned'] == 1
        assert metrics['images_with_reduction'] == 0
        assert metrics['total_reduction'] == 0
        assert metrics['average_reduction_per_image'] == 0.0

    def test_average_reduction_per_image_zero_images(self, html_generator):
        """Test average_reduction_per_image with zero images (edge case)."""
        results = []

        metrics = html_generator._calculate_metrics(results)

        assert metrics['images_scanned'] == 0
        assert metrics['images_with_reduction'] == 0
        assert metrics['average_reduction_per_image'] == 0.0

    def test_metrics_with_negative_reduction(self, html_generator):
        """Test metrics when Chainguard has more CVEs (negative reduction)."""
        results = [
            ScanResult(
                pair=ImagePair(
                    alternative_image="python:3.12",
                    chainguard_image="cgr.dev/chainguard/python:latest"
                ),
                alternative_analysis=ImageAnalysis(
                    name="python:3.12",
                    size_mb=950.0,
                    package_count=427,
                    vulnerabilities=VulnerabilityCount(
                        total=10, critical=0, high=2, medium=3, low=5, negligible=0
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:abc123",
                ),
                chainguard_analysis=ImageAnalysis(
                    name="cgr.dev/chainguard/python:latest",
                    size_mb=45.0,
                    package_count=35,
                    vulnerabilities=VulnerabilityCount(
                        total=50, critical=5, high=10, medium=15, low=18, negligible=2
                    ),
                    scan_timestamp=datetime.now(timezone.utc),
                    digest="sha256:def456",
                ),
                scan_successful=True,
            ),
        ]

        metrics = html_generator._calculate_metrics(results)

        assert metrics['images_scanned'] == 1
        assert metrics['images_with_reduction'] == 0  # Chainguard has MORE CVEs
        assert metrics['total_reduction'] == -40  # Negative reduction
        assert metrics['average_reduction_per_image'] == -40.0


class TestFallbackNoteGeneration:
    """Test the _generate_fallback_note helper method."""

    @pytest.fixture
    def html_generator(self, tmp_path):
        """Create an HTMLGenerator instance for testing."""
        return HTMLGenerator()

    def test_generate_fallback_note_with_fallback(self, html_generator):
        """Test fallback note generation when fallback is used."""
        note = html_generator._generate_fallback_note(has_fallback=True, margin_top="20px")

        assert note != ""
        assert "margin-top: 20px" in note
        assert ":latest" in note
        assert "30 days" in note
        assert "*" in note

    def test_generate_fallback_note_without_fallback(self, html_generator):
        """Test fallback note generation when no fallback is used."""
        note = html_generator._generate_fallback_note(has_fallback=False)

        assert note == ""

    def test_generate_fallback_note_custom_margin(self, html_generator):
        """Test fallback note with custom margin."""
        note = html_generator._generate_fallback_note(has_fallback=True, margin_top="10px")

        assert "margin-top: 10px" in note
