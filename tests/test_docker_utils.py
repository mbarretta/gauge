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

    def test_pull_image_with_fallback_dns_error_with_upstream(self, docker_client):
        """Test upstream fallback when private registry has DNS lookup failure."""
        with patch('subprocess.run') as mock_run:
            # First call (private registry) fails with DNS error
            # Second call (upstream) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="dial tcp: lookup docker.artifactory.mars.pcf-maximus.com on 192.168.5.3:53: no such host", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # upstream success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "docker.artifactory.mars.pcf-maximus.com/bitnami/mongodb:7.0.2-debian-11-r7",
                "linux/amd64",
                upstream_image="bitnami/mongodb:7.0.2-debian-11-r7"
            )

            assert image == "bitnami/mongodb:7.0.2-debian-11-r7"
            assert used_fallback is True
            assert pull_successful is True
            assert mock_run.call_count == 2

    def test_pull_image_with_fallback_connection_refused_with_upstream(self, docker_client):
        """Test upstream fallback when private registry connection is refused."""
        with patch('subprocess.run') as mock_run:
            # First call (private registry) fails with connection refused
            # Second call (upstream) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="Error: connection refused to private.registry.com", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # upstream success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "private.registry.com/nginx:latest",
                "linux/amd64",
                upstream_image="nginx:latest"
            )

            assert image == "nginx:latest"
            assert used_fallback is True
            assert pull_successful is True
            assert mock_run.call_count == 2

    def test_pull_image_with_fallback_no_auth_with_upstream(self, docker_client):
        """Test upstream fallback when private registry requires authentication."""
        with patch('subprocess.run') as mock_run:
            # First call (private ECR) fails with no auth
            # Second call (upstream) succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stderr="Error: no basic auth credentials", stdout=""),
                Mock(returncode=0, stderr="", stdout=""),  # upstream success
            ]

            image, used_fallback, pull_successful = docker_client.pull_image_with_fallback(
                "602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/coredns:v1.8.7-eksbuild.1",
                "linux/amd64",
                upstream_image="eks/coredns:v1.8.7-eksbuild.1"
            )

            assert image == "eks/coredns:v1.8.7-eksbuild.1"
            assert used_fallback is True
            assert pull_successful is True
            assert mock_run.call_count == 2


class TestImageSize:
    """Test image size detection."""

    @pytest.fixture
    def docker_client(self):
        """Create a DockerClient instance for testing."""
        with patch.object(DockerClient, '_detect_runtime', return_value='docker'):
            return DockerClient()

    def test_get_image_size_mb_gigabytes(self, docker_client):
        """Test parsing image size in gigabytes."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="1.25GB\n", stderr="")
            
            size = docker_client.get_image_size_mb("python:3.12")
            
            assert size == 1280  # 1.25 * 1024 = 1280 MB

    def test_get_image_size_mb_megabytes(self, docker_client):
        """Test parsing image size in megabytes."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="234MB\n", stderr="")
            
            size = docker_client.get_image_size_mb("alpine:latest")
            
            assert size == 234

    def test_get_image_size_mb_kilobytes(self, docker_client):
        """Test parsing image size in kilobytes."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="1536KB\n", stderr="")
            
            size = docker_client.get_image_size_mb("busybox:latest")
            
            assert size == 2  # 1536/1024 = 1.5, rounded to 2

    def test_get_image_size_mb_bytes(self, docker_client):
        """Test parsing image size in bytes."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="1048576B\n", stderr="")
            
            size = docker_client.get_image_size_mb("scratch:latest")
            
            assert size == 1  # 1048576 / (1024*1024) = 1 MB

    def test_get_image_size_mb_docker_io_library(self, docker_client):
        """Test image size with docker.io/library prefix tries short name."""
        with patch('subprocess.run') as mock_run:
            # First call with full name fails, second with short name succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stdout="", stderr=""),
                Mock(returncode=0, stdout="234MB\n", stderr=""),
            ]
            
            size = docker_client.get_image_size_mb("docker.io/library/python:3.12")
            
            assert size == 234
            assert mock_run.call_count == 2

    def test_get_image_size_mb_docker_io_user(self, docker_client):
        """Test image size with docker.io user image tries short name."""
        with patch('subprocess.run') as mock_run:
            # First call with full name fails, second with short name succeeds
            mock_run.side_effect = [
                Mock(returncode=1, stdout="", stderr=""),
                Mock(returncode=0, stdout="156MB\n", stderr=""),
            ]
            
            size = docker_client.get_image_size_mb("docker.io/myuser/myimage:v1")
            
            assert size == 156
            assert mock_run.call_count == 2

    def test_get_image_size_mb_chainguard_image(self, docker_client):
        """Test image size for Chainguard images (cgr.dev)."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="15MB\n", stderr="")
            
            size = docker_client.get_image_size_mb("cgr.dev/chainguard/python:latest")
            
            assert size == 15

    def test_get_image_size_mb_not_found(self, docker_client):
        """Test image size when image is not found."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            
            size = docker_client.get_image_size_mb("nonexistent:image")
            
            assert size == 0.0

    def test_get_image_size_mb_timeout(self, docker_client):
        """Test image size with timeout."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)
            
            size = docker_client.get_image_size_mb("python:3.12")
            
            assert size == 0.0


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
