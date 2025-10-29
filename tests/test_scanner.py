"""
Tests for vulnerability scanner, focusing on error handling paths.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import subprocess
from datetime import datetime, timezone

from core.scanner import VulnerabilityScanner
from core.cache import ScanCache
from core.models import ImageAnalysis, VulnerabilityCount
from utils.docker_utils import DockerClient


class TestScannerErrorHandling:
    """Test error handling in the vulnerability scanner."""

    @pytest.fixture
    def mock_cache(self, tmp_path):
        """Create a mock cache."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        return ScanCache(cache_dir=cache_dir, enabled=True)

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClient)
        client.ensure_fresh_image.return_value = ("test:latest", False, True)
        client.get_image_digest.return_value = "sha256:abc123"
        client.get_image_size_mb.return_value = 100.0
        return client

    @pytest.fixture
    def scanner(self, mock_cache, mock_docker_client):
        """Create a scanner instance with mocked dependencies."""
        with patch('subprocess.run') as mock_run:
            # Mock syft and grype version checks
            mock_run.return_value = Mock(returncode=0)
            scanner = VulnerabilityScanner(
                cache=mock_cache,
                docker_client=mock_docker_client,
                max_workers=2,
                check_fresh_images=True,
                with_chps=False,
            )
        return scanner

    def test_scan_image_syft_timeout(self, scanner, mock_docker_client):
        """Test handling of Syft timeout."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("syft", 300)

            with pytest.raises(RuntimeError, match="Syft scan timed out"):
                scanner.scan_image("python:3.12")

    def test_scan_image_syft_failure(self, scanner, mock_docker_client):
        """Test handling of Syft command failure."""
        with patch('subprocess.run') as mock_run:
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["syft", "python:3.12", "-o", "json"],
            )
            error.stderr = "Error: invalid image"
            error.stdout = ""
            mock_run.side_effect = error

            with pytest.raises(RuntimeError, match="Syft command failed"):
                scanner.scan_image("python:3.12")

    def test_scan_image_grype_timeout(self, scanner, mock_docker_client):
        """Test handling of Grype timeout."""
        with patch('subprocess.run') as mock_run:
            # First call succeeds (Syft)
            syft_result = Mock(returncode=0, stdout='{"artifacts": []}')
            # Second call times out (Grype)
            mock_run.side_effect = [
                syft_result,
                subprocess.TimeoutExpired("grype", 300)
            ]

            with pytest.raises(RuntimeError, match="Grype scan timed out"):
                scanner.scan_image("python:3.12")

    def test_scan_image_grype_failure(self, scanner, mock_docker_client):
        """Test handling of Grype command failure."""
        with patch('subprocess.run') as mock_run:
            # First call succeeds (Syft)
            syft_result = Mock(returncode=0, stdout='{"artifacts": []}')
            # Second call fails (Grype)
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["grype", "-o", "json"],
            )
            error.stderr = "Error: invalid SBOM"
            error.stdout = ""
            mock_run.side_effect = [syft_result, error]

            with pytest.raises(RuntimeError, match="Grype command failed"):
                scanner.scan_image("python:3.12")

    def test_scan_image_pull_failure(self, scanner, mock_docker_client):
        """Test handling of image pull failure."""
        # Mock pull failure
        mock_docker_client.ensure_fresh_image.return_value = ("test:latest", False, False)

        with pytest.raises(RuntimeError, match="Failed to pull image.*and all fallback strategies failed"):
            scanner.scan_image("nonexistent:image")

    def test_scan_image_with_fallback_success(self, scanner, mock_docker_client):
        """Test successful scan with fallback image."""
        # Mock fallback being used
        mock_docker_client.ensure_fresh_image.return_value = (
            "mirror.gcr.io/library/python:3.12",
            True,  # used_fallback
            True   # pull_successful
        )

        with patch('subprocess.run') as mock_run:
            # Mock successful Syft and Grype
            syft_result = Mock(
                returncode=0,
                stdout='{"artifacts": [{"name": "pkg1"}]}'
            )
            grype_result = Mock(
                returncode=0,
                stdout='{"matches": [{"vulnerability": {"severity": "High"}}]}'
            )
            mock_run.side_effect = [syft_result, grype_result]

            result = scanner.scan_image("python:3.12")

            assert result.used_latest_fallback is True
            assert result.original_image == "python:3.12"
            assert result.name == "mirror.gcr.io/library/python:3.12"


class TestSyftErrorMessages:
    """Test that Syft errors include helpful debug information."""

    @pytest.fixture
    def mock_cache(self, tmp_path):
        """Create a mock cache."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        return ScanCache(cache_dir=cache_dir, enabled=True)

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClient)
        client.ensure_fresh_image.return_value = ("test:latest", False, True)
        client.get_image_digest.return_value = "sha256:abc123"
        client.get_image_size_mb.return_value = 100.0
        return client

    @pytest.fixture
    def scanner(self, mock_cache, mock_docker_client):
        """Create a scanner instance."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0)
            scanner = VulnerabilityScanner(
                cache=mock_cache,
                docker_client=mock_docker_client,
                max_workers=2,
                check_fresh_images=True,
                with_chps=False,
            )
        return scanner

    def test_syft_error_includes_stderr(self, scanner):
        """Test that Syft errors include stderr for debugging."""
        with patch('subprocess.run') as mock_run:
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["syft", "python:3.12", "-o", "json"],
            )
            error.stderr = "Error: permission denied"
            error.stdout = "partial output"
            mock_run.side_effect = error

            with pytest.raises(RuntimeError) as exc_info:
                scanner.scan_image("python:3.12")

            error_msg = str(exc_info.value)
            assert "Stderr: Error: permission denied" in error_msg
            assert "Stdout: partial output" in error_msg

    def test_grype_error_includes_stderr(self, scanner):
        """Test that Grype errors include stderr for debugging."""
        with patch('subprocess.run') as mock_run:
            # Syft succeeds
            syft_result = Mock(returncode=0, stdout='{"artifacts": []}')
            # Grype fails with detailed error
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["grype", "-o", "json"],
            )
            error.stderr = "Error: database update failed"
            error.stdout = "debug info"
            mock_run.side_effect = [syft_result, error]

            with pytest.raises(RuntimeError) as exc_info:
                scanner.scan_image("python:3.12")

            error_msg = str(exc_info.value)
            assert "Stderr: Error: database update failed" in error_msg
            assert "Stdout: debug info" in error_msg
