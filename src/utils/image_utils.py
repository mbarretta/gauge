"""
Shared utilities for parsing and manipulating container image references.

This module consolidates image name extraction logic that was previously
duplicated across multiple files.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ImageReference:
    """Parsed container image reference."""

    registry: Optional[str]
    organization: Optional[str]
    name: str
    tag: Optional[str]
    digest: Optional[str]

    @property
    def full_name(self) -> str:
        """Return the full image reference."""
        parts = []
        if self.registry:
            parts.append(self.registry)
        if self.organization:
            parts.append(self.organization)
        parts.append(self.name)

        result = "/".join(parts)

        if self.digest:
            result = f"{result}@{self.digest}"
        elif self.tag:
            result = f"{result}:{self.tag}"

        return result

    @property
    def name_with_org(self) -> str:
        """Return org/name if org exists, otherwise just name."""
        if self.organization:
            return f"{self.organization}/{self.name}"
        return self.name


def parse_image_reference(image: str) -> ImageReference:
    """
    Parse a container image reference into its components.

    Args:
        image: Full image reference (e.g., "docker.io/library/python:3.12")

    Returns:
        ImageReference with parsed components

    Examples:
        >>> parse_image_reference("python:3.12")
        ImageReference(registry=None, organization=None, name='python', tag='3.12', digest=None)

        >>> parse_image_reference("docker.io/library/python:3.12")
        ImageReference(registry='docker.io', organization='library', name='python', tag='3.12', digest=None)

        >>> parse_image_reference("cgr.dev/chainguard/python@sha256:abc123")
        ImageReference(registry='cgr.dev', organization='chainguard', name='python', tag=None, digest='sha256:abc123')
    """
    registry = None
    organization = None
    tag = None
    digest = None

    # Extract digest first (after @)
    if "@" in image:
        image, digest = image.rsplit("@", 1)

    # Extract tag (after last :, but only if it's not part of registry port)
    if ":" in image:
        # Check if : appears after / (indicates tag, not port)
        if "/" in image:
            last_slash = image.rfind("/")
            last_colon = image.rfind(":")
            if last_colon > last_slash:
                image, tag = image.rsplit(":", 1)
        else:
            # No slash, so : must be a tag
            image, tag = image.rsplit(":", 1)

    # Split on /
    parts = image.split("/")

    if len(parts) == 1:
        # Just image name (e.g., "python")
        name = parts[0]
    elif len(parts) == 2:
        # Could be org/image or registry/image
        first_part = parts[0]
        if _is_registry(first_part):
            registry = first_part
            name = parts[1]
        else:
            organization = first_part
            name = parts[1]
    else:
        # 3+ parts: registry/org/name or registry/nested/path/name
        first_part = parts[0]
        if _is_registry(first_part):
            registry = first_part
            # Everything between registry and name is organization/path
            organization = "/".join(parts[1:-1])
            name = parts[-1]
        else:
            # No registry, just nested org path
            organization = "/".join(parts[:-1])
            name = parts[-1]

    return ImageReference(
        registry=registry,
        organization=organization,
        name=name.lower(),
        tag=tag,
        digest=digest,
    )


def _is_registry(part: str) -> bool:
    """Check if a string looks like a registry hostname."""
    # Contains . or : (port), or is localhost
    return "." in part or ":" in part or part == "localhost"


def extract_base_name(image: str) -> str:
    """
    Extract base image name from full reference.

    Removes registry, organization, tag, and digest to get just the image name.

    Args:
        image: Full image reference

    Returns:
        Base image name (lowercase)

    Examples:
        >>> extract_base_name("docker.io/library/python:3.12")
        'python'
        >>> extract_base_name("cgr.dev/chainguard/redis:latest")
        'redis'
        >>> extract_base_name("myregistry.com/org/app@sha256:abc")
        'app'
    """
    ref = parse_image_reference(image)
    return ref.name


def extract_tag(image: str, default: str = "latest") -> str:
    """
    Extract tag from image reference.

    Args:
        image: Full image reference
        default: Default tag if none specified

    Returns:
        Tag string

    Examples:
        >>> extract_tag("python:3.12")
        '3.12'
        >>> extract_tag("python")
        'latest'
        >>> extract_tag("python@sha256:abc")
        'latest'
    """
    ref = parse_image_reference(image)
    return ref.tag or default


def extract_registry(image: str, default: str = "docker.io") -> str:
    """
    Extract registry hostname from image reference.

    Args:
        image: Full image reference
        default: Default registry if none specified

    Returns:
        Registry hostname

    Examples:
        >>> extract_registry("gcr.io/project/image:tag")
        'gcr.io'
        >>> extract_registry("python:3.12")
        'docker.io'
    """
    ref = parse_image_reference(image)
    return ref.registry or default


def extract_name_with_org(image: str) -> str:
    """
    Extract org/name from image reference (without registry, tag, digest).

    Args:
        image: Full image reference

    Returns:
        Organization and name (e.g., "library/python" or just "python")

    Examples:
        >>> extract_name_with_org("docker.io/library/python:3.12")
        'library/python'
        >>> extract_name_with_org("gcr.io/my-project/my-app:v1")
        'my-project/my-app'
    """
    ref = parse_image_reference(image)
    return ref.name_with_org


def strip_tag_and_digest(image: str) -> str:
    """
    Remove tag and digest from image reference.

    Args:
        image: Full image reference

    Returns:
        Image reference without tag or digest

    Examples:
        >>> strip_tag_and_digest("python:3.12")
        'python'
        >>> strip_tag_and_digest("gcr.io/project/image@sha256:abc")
        'gcr.io/project/image'
    """
    # Remove digest
    if "@" in image:
        image = image.rsplit("@", 1)[0]

    # Remove tag (but careful with registry ports)
    if ":" in image:
        if "/" in image:
            last_slash = image.rfind("/")
            last_colon = image.rfind(":")
            if last_colon > last_slash:
                image = image.rsplit(":", 1)[0]
        else:
            image = image.rsplit(":", 1)[0]

    return image


def normalize_image_name(image: str) -> str:
    """
    Normalize image name for comparison.

    Extracts base name and normalizes to lowercase.

    Args:
        image: Full image reference

    Returns:
        Normalized image name
    """
    return extract_base_name(image).lower()


def has_explicit_registry(image: str) -> bool:
    """
    Check if image has an explicit registry prefix.

    Args:
        image: Image reference

    Returns:
        True if image has explicit registry

    Examples:
        >>> has_explicit_registry("gcr.io/project/image")
        True
        >>> has_explicit_registry("python:3.12")
        False
        >>> has_explicit_registry("library/python")
        False
    """
    if "/" not in image:
        return False

    first_part = image.split("/")[0]
    return _is_registry(first_part)
