"""Setup script for Gauge - Container Vulnerability Assessment Tool."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="gauge",
    version="2.0.0",
    description="Gauge your container security posture - Unified vulnerability assessment tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Chainguard",
    python_requires=">=3.10",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "docker>=7.0.0",
        "xlsxwriter>=3.2.0",
        "requests>=2.32.0",
        "markdown>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "gauge=cli:main_dispatch",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
