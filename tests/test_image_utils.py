"""Tests for shared image utilities."""

import pytest

from utils.image_utils import (
    ImageReference,
    extract_base_name,
    extract_name_with_org,
    extract_registry,
    extract_tag,
    has_explicit_registry,
    normalize_image_name,
    parse_image_reference,
    strip_tag_and_digest,
)


class TestParseImageReference:
    """Tests for parse_image_reference function."""

    def test_simple_image(self):
        """Test parsing simple image name."""
        ref = parse_image_reference("python")
        assert ref.registry is None
        assert ref.organization is None
        assert ref.name == "python"
        assert ref.tag is None
        assert ref.digest is None

    def test_image_with_tag(self):
        """Test parsing image with tag."""
        ref = parse_image_reference("python:3.12")
        assert ref.registry is None
        assert ref.organization is None
        assert ref.name == "python"
        assert ref.tag == "3.12"
        assert ref.digest is None

    def test_docker_hub_library(self):
        """Test parsing Docker Hub library image."""
        ref = parse_image_reference("docker.io/library/python:3.12")
        assert ref.registry == "docker.io"
        assert ref.organization == "library"
        assert ref.name == "python"
        assert ref.tag == "3.12"

    def test_gcr_image(self):
        """Test parsing GCR image."""
        ref = parse_image_reference("gcr.io/my-project/my-app:v1.0")
        assert ref.registry == "gcr.io"
        assert ref.organization == "my-project"
        assert ref.name == "my-app"
        assert ref.tag == "v1.0"

    def test_chainguard_image(self):
        """Test parsing Chainguard image."""
        ref = parse_image_reference("cgr.dev/chainguard/python:latest")
        assert ref.registry == "cgr.dev"
        assert ref.organization == "chainguard"
        assert ref.name == "python"
        assert ref.tag == "latest"

    def test_image_with_digest(self):
        """Test parsing image with digest."""
        ref = parse_image_reference("python@sha256:abc123def456")
        assert ref.name == "python"
        assert ref.tag is None
        assert ref.digest == "sha256:abc123def456"

    def test_image_with_tag_and_digest(self):
        """Test parsing image with both tag and digest."""
        ref = parse_image_reference("python:3.12@sha256:abc123")
        assert ref.name == "python"
        assert ref.tag == "3.12"
        assert ref.digest == "sha256:abc123"

    def test_registry_with_port(self):
        """Test parsing registry with port."""
        ref = parse_image_reference("localhost:5000/myimage:latest")
        assert ref.registry == "localhost:5000"
        assert ref.name == "myimage"
        assert ref.tag == "latest"

    def test_nested_org_path(self):
        """Test parsing image with nested organization path."""
        ref = parse_image_reference("gcr.io/my-project/subdir/app:v1")
        assert ref.registry == "gcr.io"
        assert ref.organization == "my-project/subdir"
        assert ref.name == "app"
        assert ref.tag == "v1"

    def test_org_without_registry(self):
        """Test parsing org/image without explicit registry."""
        ref = parse_image_reference("bitnami/redis:latest")
        assert ref.registry is None
        assert ref.organization == "bitnami"
        assert ref.name == "redis"
        assert ref.tag == "latest"

    def test_quay_io(self):
        """Test parsing quay.io image."""
        ref = parse_image_reference("quay.io/argoproj/argocd:v2.8.0")
        assert ref.registry == "quay.io"
        assert ref.organization == "argoproj"
        assert ref.name == "argocd"
        assert ref.tag == "v2.8.0"

    def test_name_is_lowercase(self):
        """Test that image name is lowercased."""
        ref = parse_image_reference("docker.io/library/PYTHON:3.12")
        assert ref.name == "python"


class TestImageReferenceProperties:
    """Tests for ImageReference properties."""

    def test_full_name_simple(self):
        """Test full_name with simple image."""
        ref = ImageReference(None, None, "python", "3.12", None)
        assert ref.full_name == "python:3.12"

    def test_full_name_with_registry(self):
        """Test full_name with registry."""
        ref = ImageReference("gcr.io", "project", "app", "v1", None)
        assert ref.full_name == "gcr.io/project/app:v1"

    def test_full_name_with_digest(self):
        """Test full_name with digest."""
        ref = ImageReference(None, None, "python", None, "sha256:abc")
        assert ref.full_name == "python@sha256:abc"

    def test_name_with_org(self):
        """Test name_with_org property."""
        ref = ImageReference("gcr.io", "myorg", "app", "v1", None)
        assert ref.name_with_org == "myorg/app"

    def test_name_with_org_no_org(self):
        """Test name_with_org when no org."""
        ref = ImageReference(None, None, "python", "3.12", None)
        assert ref.name_with_org == "python"


class TestExtractBaseName:
    """Tests for extract_base_name function."""

    def test_simple_image(self):
        """Test extracting from simple image."""
        assert extract_base_name("python") == "python"

    def test_with_tag(self):
        """Test extracting from image with tag."""
        assert extract_base_name("python:3.12") == "python"

    def test_with_registry(self):
        """Test extracting from image with registry."""
        assert extract_base_name("docker.io/library/python:3.12") == "python"

    def test_with_digest(self):
        """Test extracting from image with digest."""
        assert extract_base_name("python@sha256:abc123") == "python"

    def test_complex_reference(self):
        """Test extracting from complex reference."""
        assert extract_base_name("gcr.io/my-project/subpath/myapp:v1.2.3") == "myapp"

    def test_chainguard_image(self):
        """Test extracting from Chainguard image."""
        assert extract_base_name("cgr.dev/chainguard-private/redis:latest") == "redis"


class TestExtractTag:
    """Tests for extract_tag function."""

    def test_with_tag(self):
        """Test extracting existing tag."""
        assert extract_tag("python:3.12") == "3.12"

    def test_without_tag(self):
        """Test default when no tag."""
        assert extract_tag("python") == "latest"

    def test_custom_default(self):
        """Test custom default tag."""
        assert extract_tag("python", default="stable") == "stable"

    def test_with_digest_no_tag(self):
        """Test default when only digest."""
        assert extract_tag("python@sha256:abc") == "latest"


class TestExtractRegistry:
    """Tests for extract_registry function."""

    def test_with_registry(self):
        """Test extracting existing registry."""
        assert extract_registry("gcr.io/project/app") == "gcr.io"

    def test_without_registry(self):
        """Test default when no registry."""
        assert extract_registry("python:3.12") == "docker.io"

    def test_custom_default(self):
        """Test custom default registry."""
        assert extract_registry("python", default="quay.io") == "quay.io"


class TestExtractNameWithOrg:
    """Tests for extract_name_with_org function."""

    def test_with_org(self):
        """Test extracting org/name."""
        assert extract_name_with_org("docker.io/bitnami/redis:latest") == "bitnami/redis"

    def test_without_org(self):
        """Test when no org."""
        assert extract_name_with_org("python:3.12") == "python"

    def test_nested_org(self):
        """Test with nested org path."""
        assert extract_name_with_org("gcr.io/a/b/c/app:v1") == "a/b/c/app"


class TestStripTagAndDigest:
    """Tests for strip_tag_and_digest function."""

    def test_strip_tag(self):
        """Test stripping tag."""
        assert strip_tag_and_digest("python:3.12") == "python"

    def test_strip_digest(self):
        """Test stripping digest."""
        assert strip_tag_and_digest("python@sha256:abc") == "python"

    def test_strip_both(self):
        """Test stripping both tag and digest."""
        assert strip_tag_and_digest("python:3.12@sha256:abc") == "python"

    def test_with_registry(self):
        """Test stripping from image with registry."""
        assert strip_tag_and_digest("gcr.io/project/app:v1") == "gcr.io/project/app"

    def test_registry_with_port(self):
        """Test preserving registry port."""
        assert strip_tag_and_digest("localhost:5000/app:latest") == "localhost:5000/app"


class TestNormalizeImageName:
    """Tests for normalize_image_name function."""

    def test_basic(self):
        """Test basic normalization."""
        assert normalize_image_name("docker.io/library/PYTHON:3.12") == "python"

    def test_already_normalized(self):
        """Test already normalized name."""
        assert normalize_image_name("redis") == "redis"


class TestHasExplicitRegistry:
    """Tests for has_explicit_registry function."""

    def test_with_registry(self):
        """Test image with explicit registry."""
        assert has_explicit_registry("gcr.io/project/app") is True

    def test_without_registry(self):
        """Test image without registry."""
        assert has_explicit_registry("python:3.12") is False

    def test_org_without_registry(self):
        """Test org/image without registry."""
        assert has_explicit_registry("bitnami/redis") is False

    def test_localhost(self):
        """Test localhost as registry."""
        assert has_explicit_registry("localhost/app") is True

    def test_registry_with_port(self):
        """Test registry with port."""
        assert has_explicit_registry("registry.local:5000/app") is True
