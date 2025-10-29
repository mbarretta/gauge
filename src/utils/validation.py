"""
Input validation utilities for Gauge application.

Provides validation functions for image references, file paths,
and other user inputs to ensure data integrity and security.
"""

import re
from pathlib import Path
from typing import Optional

from core.exceptions import ValidationException


def validate_image_reference(image: str, field_name: str = "image") -> str:
    """
    Validate and normalize container image reference.

    Args:
        image: Image reference to validate
        field_name: Field name for error messages

    Returns:
        Normalized image reference

    Raises:
        ValidationException: If image reference is invalid

    Examples:
        >>> validate_image_reference("python:3.12")
        'python:3.12'
        >>> validate_image_reference("cgr.dev/chainguard/python:latest")
        'cgr.dev/chainguard/python:latest'
        >>> validate_image_reference("invalid image!")
        ValidationException: ...
    """
    if not image or not image.strip():
        raise ValidationException("Image reference cannot be empty", field_name)

    image = image.strip()

    # Check for obviously invalid characters
    if any(char in image for char in ['"', "'", ";", "&", "|", "$", "`", "\n", "\r"]):
        raise ValidationException(
            f"Image reference contains invalid characters: {image}",
            field_name
        )

    # Basic format validation (registry/repo:tag or repo:tag)
    # Allows: lowercase alphanumeric, dots, slashes, colons, hyphens, underscores
    pattern = r'^[a-z0-9]+([\._\-][a-z0-9]+)*(\/[a-z0-9]+([\._\-][a-z0-9]+)*)*(:[a-zA-Z0-9\._\-]+)?$'
    if not re.match(pattern, image, re.IGNORECASE):
        raise ValidationException(
            f"Invalid image reference format: {image}",
            field_name
        )

    return image


def validate_file_path(path: Path, must_exist: bool = True) -> Path:
    """
    Validate file path.

    Args:
        path: Path to validate
        must_exist: Whether file must already exist

    Returns:
        Validated Path object

    Raises:
        ValidationException: If path is invalid
    """
    if not path:
        raise ValidationException("File path cannot be empty", "path")

    if must_exist and not path.exists():
        raise ValidationException(f"File not found: {path}", "path")

    return path


def validate_positive_number(
    value: float,
    field_name: str,
    min_value: float = 0.0,
    max_value: Optional[float] = None,
) -> float:
    """
    Validate numeric value is within acceptable range.

    Args:
        value: Value to validate
        field_name: Field name for error messages
        min_value: Minimum acceptable value
        max_value: Maximum acceptable value (optional)

    Returns:
        Validated value

    Raises:
        ValidationException: If value is out of range
    """
    if value < min_value:
        raise ValidationException(
            f"Value must be >= {min_value}, got {value}",
            field_name
        )

    if max_value is not None and value > max_value:
        raise ValidationException(
            f"Value must be <= {max_value}, got {value}",
            field_name
        )

    return value


def validate_customer_name(name: str) -> str:
    """
    Validate and normalize customer name.

    Args:
        name: Customer name to validate

    Returns:
        Normalized customer name

    Raises:
        ValidationException: If name is invalid
    """
    if not name or not name.strip():
        raise ValidationException("Customer name cannot be empty", "customer_name")

    name = name.strip()

    # Prevent path traversal and injection attempts
    # Customer names are used in filenames, so restrict special characters
    if any(char in name for char in ["/", "\\", "<", ">", '"', "'", ";", "|", "&"]):
        raise ValidationException(
            "Customer name contains invalid characters",
            "customer_name"
        )

    if len(name) > 100:
        raise ValidationException(
            "Customer name too long (max 100 characters)",
            "customer_name"
        )

    return name


__all__ = [
    "validate_image_reference",
    "validate_file_path",
    "validate_positive_number",
    "validate_customer_name",
]
