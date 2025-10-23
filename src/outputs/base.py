"""
Base output generator interface.

Defines the contract that all output generators must implement.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from core.models import ScanResult
from outputs.config import GeneratorConfig


class OutputGenerator(ABC):
    """
    Abstract base class for report generators.

    All output generators (HTML, XLSX, etc.) must implement this interface.
    """

    @abstractmethod
    def generate(
        self,
        results: list[ScanResult],
        output_path: Path,
        config: GeneratorConfig,
    ) -> None:
        """
        Generate report from scan results.

        Args:
            results: List of scan results to include in report
            output_path: Where to write the output file
            config: Generator-specific configuration
        """
        pass

    @abstractmethod
    def supports_format(self) -> str:
        """
        Return the format this generator supports.

        Returns:
            Format identifier (e.g., "html", "xlsx")
        """
        pass
