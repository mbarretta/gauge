"""
Common constants and classes shared across the Gauge application.
"""

import logging
import sys
from pathlib import Path

from utils.logging_helpers import log_error_section, log_warning_section

logger = logging.getLogger(__name__)

# Output configuration for all report types
OUTPUT_CONFIGS = {
    "vuln_summary": {
        "description": "Vulnerability Assessment Summary (HTML)",
        "file_suffix": "assessment.html",
    },
    "cost_analysis": {
        "description": "Vulnerability Cost Analysis (XLSX)",
        "file_suffix": "cost_analysis.xlsx",
    },
    "pricing": {
        "description": "Pricing Quote",
        "formats": {
            "html": {
                "file_suffix": "pricing_quote.html",
                "description": "Pricing Quote (HTML)",
            },
            "txt": {
                "file_suffix": "pricing_quote.txt",
                "description": "Pricing Quote (TXT)",
            },
        },
    },
}


class GitHubAuthValidator:
    """
    Validates GitHub authentication for pricing quote generation.
    """

    def __init__(self, pricing_policy_path: Path):
        self.pricing_policy_path = pricing_policy_path

    def validate(self) -> None:
        """Validate GitHub authentication and repository access."""
        self._check_pricing_policy()
        logger.info("Validating GitHub authentication for pricing tier classification...")
        from integrations.github_metadata import GitHubMetadataClient
        test_client = GitHubMetadataClient()
        if not test_client.token:
            self._handle_no_token()
        self._test_repository_access(test_client.token)

    def _check_pricing_policy(self) -> None:
        """Check that pricing policy file exists."""
        if not self.pricing_policy_path.exists():
            log_error_section(
                "Pricing policy file not found.",
                [f"File not found: {self.pricing_policy_path}", "Use --pricing-policy or create one based on example-pricing-policy.yaml."],
                logger=logger
            )
            sys.exit(1)

    def _handle_no_token(self) -> None:
        """Handle case where no GitHub token is found."""
        log_error_section(
            "GitHub authentication required for pricing.",
            ["Set GITHUB_TOKEN environment variable or use 'gh auth login'."],
            logger=logger
        )
        sys.exit(1)

    def _test_repository_access(self, token: str) -> None:
        """Test GitHub repository access."""
        logger.debug("Testing GitHub repository access...")
        try:
            import requests
            test_url = "https://api.github.com/repos/chainguard-images/images-private"
            response = requests.get(test_url, headers={"Authorization": f"token {token}"}, timeout=5)
            response.raise_for_status()
            logger.info("✓ GitHub authentication configured")
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                self._handle_forbidden_error(e, test_url, token)
            elif e.response.status_code == 404:
                logger.warning("Could not verify repository access (404). Proceeding anyway...")
            else:
                logger.error(f"GitHub API error: {e}")
                sys.exit(1)
        except Exception as e:
            logger.warning(f"Could not verify repository access: {e}. Proceeding anyway...")

    def _handle_forbidden_error(self, error: Exception, test_url: str, token: str) -> None:
        """Handle 403 Forbidden errors."""
        is_saml_issue = "SAML" in error.response.text
        if is_saml_issue:
            self._attempt_token_refresh(test_url)
        else:
            log_error_section(
                "Access to chainguard-images/images-private is forbidden.",
                ["Ensure your GitHub account has access to this repository."],
                logger=logger
            )
            sys.exit(1)

    def _attempt_token_refresh(self, test_url: str) -> None:
        """Attempt to refresh GitHub token via gh CLI."""
        log_warning_section("GitHub token needs SAML SSO authorization.", ["Attempting refresh via gh CLI..."], logger=logger)
        try:
            import subprocess
            subprocess.run(["gh", "auth", "refresh", "-s", "repo"], check=True, capture_output=True)
            logger.info("✓ Token refreshed successfully. Retrying access...")
            from integrations.github_metadata import get_github_token_from_gh_cli
            import requests
            new_token = get_github_token_from_gh_cli()
            if new_token:
                requests.get(test_url, headers={"Authorization": f"token {new_token}"}, timeout=5).raise_for_status()
                logger.info("✓ GitHub authentication configured")
            else:
                raise Exception("Failed to get refreshed token.")
        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            log_error_section("Failed to refresh GitHub token.", [f"Error: {e}", "Try running 'gh auth refresh -s repo' manually."], logger=logger)
            sys.exit(1)
