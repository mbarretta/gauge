"""
Tests for Docker utilities including fallback strategies.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import subprocess

from utils.docker_utils import DockerClient


class TestDockerClientFallback:
    """Test fallback scenarios for Docker image pulling."""

    @pytest.fixture
    def docker_client(self):
        """Create a DockerClient instance for testing."""
        with patch.object(DockerClient, '_detect_runtime', return_value='docker'):
            return DockerClient()

    def test_pull_image_with_fallback_success_on_first_try(self, docker_client):
        """Test successful pull on first attempt without fallback."""
        with patch('subprocess.run') as mock_run:
            # Simulate successful pull
            mock_run.return_value = Mock(returncode=0, stderr="", stdout="")

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "python:3.12", "linux/amd64"
            )

            assert image == "python:3.12"
            assert used_fallback is False
            assert pull_successful is True
            assert mock_run.call_count == 1

    def test_pull_image_with_fallback_mirror_gcr_for_dockerhub(self, docker_client):
        """Test fallback to mirror.gcr.io for Docker Hub images."""
        with patch('subprocess.run') as mock_run:
            # First call (original) fails with not found
            # Second call (mirror.gcr.io) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="manifest unknown: not found", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # mirror.gcr.io success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "python:3.12", "linux/amd64"
            )

            assert image == "mirror.gcr.io/library/python:3.12"
            assert used_fallback is True
            assert pull_successful is True
            assert mock_run.call_count == 2

    def test_pull_image_with_fallback_latest_tag(self, docker_client):
        """Test fallback to :latest tag when image not found."""
        with patch('subprocess.run') as mock_run:
            # First call (original) fails with not found
            # Second call (mirror.gcr.io) - skipped for non-dockerhub
            # Third call (:latest) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="not found", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # :latest success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "cgr.dev/chainguard/python:3.12", "linux/amd64"
            )

            assert image == "cgr.dev/chainguard/python:latest"
            assert used_fallback is True
            assert pull_successful is True

    def test_pull_image_with_fallback_all_fail(self, docker_client):
        """Test when all fallback strategies fail."""
        with patch('subprocess.run') as mock_run:
            # All attempts fail
            mock_run.return_value = Mock(returncode=1, stderr="not found", stdout="")

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "python:3.12", "linux/amd64"
            )

            assert image == "python:3.12"  # Returns original image
            assert used_fallback is False
            assert pull_successful is False

    def test_pull_image_with_fallback_rate_limit(self, docker_client):
        """Test fallback triggers on rate limit error."""
        with patch('subprocess.run') as mock_run:
            # First call fails with rate limit
            # Second call (mirror.gcr.io) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="toomanyrequests: rate limit exceeded", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # mirror.gcr.io success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "ubuntu:20.04", "linux/amd64"
            )

            assert image == "mirror.gcr.io/library/ubuntu:20.04"
            assert used_fallback is True
            assert pull_successful is True

    def test_pull_image_with_fallback_timeout(self, docker_client):
        """Test timeout handling in pull_image_with_fallback."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("docker", 300)

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "python:3.12", "linux/amd64"
            )

            assert image == "python:3.12"
            assert used_fallback is False
            assert pull_successful is False

    def test_has_registry_prefix(self, docker_client):
        """Test registry prefix detection."""
        assert docker_client._has_registry_prefix("gcr.io/my/image:tag") is True
        assert docker_client._has_registry_prefix("registry.example.com:5000/image") is True
        assert docker_client._has_registry_prefix("cgr.dev/chainguard/python") is True
        assert docker_client._has_registry_prefix("python:3.12") is False
        assert docker_client._has_registry_prefix("ubuntu") is False
        assert docker_client._has_registry_prefix("myuser/myimage") is False

    def test_try_mirror_gcr_fallback_official_image(self, docker_client):
        """Test mirror.gcr.io construction for official images."""
        mirror = docker_client._try_mirror_gcr_fallback("python:3.12")
        assert mirror == "mirror.gcr.io/library/python:3.12"

        mirror = docker_client._try_mirror_gcr_fallback("ubuntu")
        assert mirror == "mirror.gcr.io/library/ubuntu"

    def test_try_mirror_gcr_fallback_user_image(self, docker_client):
        """Test mirror.gcr.io construction for user/org images."""
        mirror = docker_client._try_mirror_gcr_fallback("myuser/myimage:v1")
        assert mirror == "mirror.gcr.io/myuser/myimage:v1"

    def test_try_mirror_gcr_fallback_skip_registry_images(self, docker_client):
        """Test mirror.gcr.io fallback skips images with registry prefix."""
        mirror = docker_client._try_mirror_gcr_fallback("gcr.io/my/image:tag")
        assert mirror is None

        mirror = docker_client._try_mirror_gcr_fallback("cgr.dev/chainguard/python")
        assert mirror is None

    def test_try_mirror_gcr_fallback_skip_digest(self, docker_client):
        """Test mirror.gcr.io fallback skips digest-based images."""
        mirror = docker_client._try_mirror_gcr_fallback("python@sha256:abc123")
        assert mirror is None


class TestEnsureFreshImage:
    """Test ensure_fresh_image with fallback integration."""

    @pytest.fixture
    def docker_client(self):
        """Create a DockerClient instance for testing."""
        with patch.object(DockerClient, '_detect_runtime', return_value='docker'):
            return DockerClient()

    def test_ensure_fresh_image_up_to_date(self, docker_client):
        """Test when local image is already up-to-date."""
        with patch.object(docker_client, 'get_remote_digest', return_value="sha256:abc123"), \
             patch.object(docker_client, 'get_image_digest', return_value="sha256:abc123"):

            image, used_fallback, pull_successful = docker_client.ensure_fresh_image(
                "python:3.12", "linux/amd64"
            )

            assert image == "python:3.12"
            assert used_fallback is False
            assert pull_successful is True

    def test_ensure_fresh_image_needs_update(self, docker_client):
        """Test when local image needs updating."""
        with patch.object(docker_client, 'get_remote_digest', return_value="sha256:new123"), \
             patch.object(docker_client, 'get_image_digest', return_value="sha256:old123"), \
             patch.object(docker_client, 'pull_image_with_fallback', return_value=("python:3.12", False, True)):

            image, used_fallback, pull_successful = docker_client.ensure_fresh_image(
                "python:3.12", "linux/amd64"
            )

            assert image == "python:3.12"
            assert pull_successful is True

    def test_ensure_fresh_image_with_fallback(self, docker_client):
        """Test ensure_fresh_image when fallback is used."""
        with patch.object(docker_client, 'get_remote_digest', return_value=None), \
             patch.object(docker_client, 'pull_image_with_fallback',
                         return_value=("mirror.gcr.io/library/python:3.12", True, True)):

            image, used_fallback, pull_successful = docker_client.ensure_fresh_image(
                "python:3.12", "linux/amd64"
            )

            assert image == "mirror.gcr.io/library/python:3.12"
            assert used_fallback is True
            assert pull_successful is True
