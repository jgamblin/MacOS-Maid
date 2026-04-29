# tests/modules/test_homebrew.py
"""Tests for Homebrew cleanup module."""

from unittest.mock import patch

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


def test_clean_homebrew_installed():
    """Test clean() updates, upgrades, and cleans up Homebrew."""
    # Explicitly enable update/upgrade (defaults are False for safety)
    module = HomebrewModule(update=True, upgrade=True, cleanup=True)
    # Mock _get_cache_size directly to avoid subprocess complexity
    with (
        patch.object(module, "_is_brew_installed", return_value=True),
        patch.object(module, "_get_cache_size", return_value=52428800),  # 50MB
        patch.object(module, "_run_brew", return_value="") as mock_run_brew,
    ):
        result = module.clean()

        assert isinstance(result, CleanResult)
        assert len(result.items_cleaned) == 3
        assert "brew update" in result.items_cleaned[0]
        assert "brew upgrade" in result.items_cleaned[1]
        assert "brew cleanup" in result.items_cleaned[2]
        # bytes_reclaimed is calculated from cache size diff (both are same, so 0)
        assert result.bytes_reclaimed == 0
        assert result.errors == []

        # Verify brew commands were called: update, upgrade, cleanup
        assert mock_run_brew.call_count == 3
        mock_run_brew.assert_any_call("update")
        mock_run_brew.assert_any_call("upgrade")
        mock_run_brew.assert_any_call("cleanup", "--prune=all")


def test_clean_default_only_cleanup(homebrew_module):
    """Test clean() with defaults only runs cleanup (update/upgrade are off)."""
    with (
        patch.object(homebrew_module, "_is_brew_installed", return_value=True),
        patch.object(homebrew_module, "_get_cache_size", return_value=52428800),
        patch.object(homebrew_module, "_run_brew", return_value="") as mock_run_brew,
    ):
        result = homebrew_module.clean()

        assert isinstance(result, CleanResult)
        assert len(result.items_cleaned) == 1
        assert "brew cleanup" in result.items_cleaned[0]
        assert mock_run_brew.call_count == 1
        mock_run_brew.assert_any_call("cleanup", "--prune=all")


def test_audit_returns_empty(homebrew_module):
    """Test audit() returns empty result (no security checks)."""
    result = homebrew_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []
