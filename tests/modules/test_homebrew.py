# tests/modules/test_homebrew.py
"""Tests for Homebrew cleanup module."""

from unittest.mock import MagicMock, patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult
from macos_maid.modules.homebrew import HomebrewModule


@pytest.fixture
def homebrew_module():
    """Create a HomebrewModule instance for testing."""
    return HomebrewModule()


def test_homebrew_metadata(homebrew_module):
    """Test that HomebrewModule has correct metadata."""
    assert homebrew_module.name == "homebrew"
    assert homebrew_module.category == "dev"
    assert homebrew_module.requires_sudo is False


def test_scan_with_homebrew_installed(homebrew_module):
    """Test scan() when Homebrew is installed with outdated packages and cache."""
    with (
        patch.object(homebrew_module, "_is_brew_installed", return_value=True),
        patch.object(homebrew_module, "_get_outdated_count", return_value=5),
        patch.object(homebrew_module, "_get_cache_size", return_value=1024 * 1024 * 500),  # 500 MB
    ):
        result = homebrew_module.scan()

        assert isinstance(result, ScanResult)
        assert result.requires_sudo is False
        assert result.bytes_reclaimable == 1024 * 1024 * 500
        assert len(result.items) == 2
        assert "5 outdated packages" in result.items[0]
        assert "500.0 MB cache" in result.items[1]


def test_scan_homebrew_not_installed(homebrew_module):
    """Test scan() returns empty result when Homebrew is not installed."""
    with patch.object(homebrew_module, "_is_brew_installed", return_value=False):
        result = homebrew_module.scan()

        assert isinstance(result, ScanResult)
        assert result.items == []
        assert result.bytes_reclaimable == 0
        assert result.requires_sudo is False


def test_clean_homebrew_installed(homebrew_module):
    """Test clean() updates, upgrades, and cleans up Homebrew."""
    mock_run_brew = MagicMock()
    mock_run_brew.side_effect = [
        "Updated 1 tap",  # brew update
        "Upgraded 5 packages",  # brew upgrade
        "Pruned 500 MB",  # brew cleanup
    ]

    with (
        patch.object(homebrew_module, "_is_brew_installed", return_value=True),
        patch.object(homebrew_module, "_run_brew", mock_run_brew),
    ):
        result = homebrew_module.clean()

        assert isinstance(result, CleanResult)
        assert len(result.items_cleaned) == 3
        assert "brew update" in result.items_cleaned[0]
        assert "brew upgrade" in result.items_cleaned[1]
        assert "brew cleanup" in result.items_cleaned[2]
        assert result.bytes_reclaimed == 0
        assert result.errors == []

        # Verify brew commands were called
        assert mock_run_brew.call_count == 3


def test_audit_returns_empty(homebrew_module):
    """Test audit() returns empty result (no security checks)."""
    result = homebrew_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []
