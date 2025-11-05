"""Tests for CLI argument parsing and output type handling."""

import pytest
from pathlib import Path

from cli import parse_args, parse_output_types


class TestOutputTypeParsing:
    """Tests for parse_output_types function."""

    def test_default_none_returns_all_types(self):
        """Test that None (default) returns all three output types."""
        result = parse_output_types(None)
        assert result == {'cost_analysis', 'vuln_summary', 'pricing'}

    def test_single_type(self):
        """Test parsing a single output type."""
        result = parse_output_types('pricing')
        assert result == {'pricing'}

    def test_comma_delimited_two_types(self):
        """Test parsing comma-delimited list of two types."""
        result = parse_output_types('cost_analysis,pricing')
        assert result == {'cost_analysis', 'pricing'}

    def test_comma_delimited_all_three(self):
        """Test parsing comma-delimited list of all three types."""
        result = parse_output_types('cost_analysis,vuln_summary,pricing')
        assert result == {'cost_analysis', 'vuln_summary', 'pricing'}

    def test_with_spaces_strips_whitespace(self):
        """Test that spaces around commas are handled correctly."""
        result = parse_output_types('cost_analysis, pricing')
        assert result == {'cost_analysis', 'pricing'}

    def test_invalid_type_raises_value_error(self):
        """Test that invalid output type raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_output_types('invalid_type')
        assert 'Invalid output type(s): invalid_type' in str(exc_info.value)
        assert 'Valid types:' in str(exc_info.value)

    def test_mixed_valid_and_invalid_raises_value_error(self):
        """Test that mix of valid and invalid types raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            parse_output_types('pricing,invalid,cost_analysis')
        assert 'Invalid output type(s): invalid' in str(exc_info.value)

    def test_duplicate_types_deduped(self):
        """Test that duplicate types are deduplicated."""
        result = parse_output_types('pricing,pricing,cost_analysis')
        assert result == {'pricing', 'cost_analysis'}


class TestCLIArguments:
    """Tests for parse_args function."""

    def test_output_default_is_none(self):
        """Test that --output defaults to None (all types)."""
        args = parse_args(['--source', 'test.csv'])
        assert args.output is None

    def test_output_single_type(self):
        """Test --output with single type."""
        args = parse_args(['--source', 'test.csv', '--output', 'pricing'])
        assert args.output == 'pricing'

    def test_output_comma_delimited(self):
        """Test --output with comma-delimited types."""
        args = parse_args(['--source', 'test.csv', '--output', 'cost_analysis,pricing'])
        assert args.output == 'cost_analysis,pricing'

    def test_pricing_policy_default(self):
        """Test that --pricing-policy has correct default."""
        args = parse_args(['--source', 'test.csv'])
        assert args.pricing_policy == Path('pricing-policy.yaml')

    def test_pricing_policy_custom(self):
        """Test --pricing-policy with custom path."""
        args = parse_args(['--source', 'test.csv', '--pricing-policy', 'custom-policy.yaml'])
        assert args.pricing_policy == Path('custom-policy.yaml')

    def test_short_option_o_works(self):
        """Test that -o short option works for --output."""
        args = parse_args(['--source', 'test.csv', '-o', 'pricing'])
        assert args.output == 'pricing'


class TestCLIIntegration:
    """Integration tests for CLI argument parsing with output type parsing."""

    def test_default_workflow(self):
        """Test default workflow: no --output flag generates all types."""
        args = parse_args(['--source', 'test.csv'])
        output_types = parse_output_types(args.output)
        assert output_types == {'cost_analysis', 'vuln_summary', 'pricing'}

    def test_single_pricing_workflow(self):
        """Test workflow for generating only pricing quote."""
        args = parse_args(['--source', 'test.csv', '--output', 'pricing'])
        output_types = parse_output_types(args.output)
        assert output_types == {'pricing'}

    def test_dual_output_workflow(self):
        """Test workflow for generating two output types."""
        args = parse_args(['--source', 'test.csv', '--output', 'cost_analysis,pricing'])
        output_types = parse_output_types(args.output)
        assert output_types == {'cost_analysis', 'pricing'}

    def test_invalid_output_raises_on_parsing(self):
        """Test that invalid output type is caught during parsing phase."""
        args = parse_args(['--source', 'test.csv', '--output', 'invalid'])
        with pytest.raises(ValueError) as exc_info:
            parse_output_types(args.output)
        assert 'Invalid output type(s): invalid' in str(exc_info.value)
