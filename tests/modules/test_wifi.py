# tests/modules/test_wifi.py
"""Tests for WiFi cleanup module."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from macos_maid.modules.wifi import WiFiModule


def test_wifi_module_metadata():
    """Test module metadata is correctly set."""
    module = WiFiModule()
    assert module.name == "wifi"
    assert module.category == "security"
    assert module.requires_sudo is True


def test_should_keep_current_network():
    """Test that current network is ALWAYS kept, even if old."""
    module = WiFiModule(keep_days=30, keep_ssids=[], interface="en0")

    # Current network is always kept, even if 100 days old
    old_date = datetime.now() - timedelta(days=100)
    assert (
        module._should_keep_network(
            ssid="CurrentNetwork",
            last_joined=old_date,
            keep_days=30,
            keep_ssids=[],
            current_ssid="CurrentNetwork",
        )
        is True
    )


def test_should_keep_allowlisted():
    """Test that allowlisted networks are kept."""
    module = WiFiModule(keep_days=30, keep_ssids=["HomeWiFi"], interface="en0")

    # Allowlisted network is kept even if old
    old_date = datetime.now() - timedelta(days=100)
    assert (
        module._should_keep_network(
            ssid="HomeWiFi",
            last_joined=old_date,
            keep_days=30,
            keep_ssids=["HomeWiFi"],
            current_ssid="CurrentNetwork",
        )
        is True
    )


def test_should_keep_recent():
    """Test that recently joined networks are kept."""
    module = WiFiModule(keep_days=30, keep_ssids=[], interface="en0")

    # Network joined 10 days ago should be kept (within 30 days)
    recent_date = datetime.now() - timedelta(days=10)
    assert (
        module._should_keep_network(
            ssid="RecentNetwork",
            last_joined=recent_date,
            keep_days=30,
            keep_ssids=[],
            current_ssid="CurrentNetwork",
        )
        is True
    )


def test_should_remove_old():
    """Test that old networks not in allowlist are removed."""
    module = WiFiModule(keep_days=30, keep_ssids=[], interface="en0")

    # Network joined 100 days ago should be removed
    old_date = datetime.now() - timedelta(days=100)
    assert (
        module._should_keep_network(
            ssid="OldNetwork",
            last_joined=old_date,
            keep_days=30,
            keep_ssids=[],
            current_ssid="CurrentNetwork",
        )
        is False
    )


@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_scan_empty_when_no_stale(mock_get_networks, mock_get_current):
    """Test scan returns empty when no stale networks exist."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "HomeWiFi"]

    module = WiFiModule(keep_days=90, keep_ssids=["HomeWiFi"], interface="en0")
    result = module.scan()

    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_scan_finds_stale_networks(mock_get_networks, mock_get_current):
    """Test scan finds networks that should be removed."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "HomeWiFi", "CoffeeShop", "AirportWiFi"]

    module = WiFiModule(keep_days=90, keep_ssids=["HomeWiFi"], interface="en0")
    result = module.scan()

    # Should find CoffeeShop and AirportWiFi as removable
    assert len(result.items) == 2
    assert any("CoffeeShop" in item for item in result.items)
    assert any("AirportWiFi" in item for item in result.items)
    assert result.bytes_reclaimable == 0  # WiFi networks don't take disk space
    assert result.requires_sudo is True


@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_scan_never_removes_current(mock_get_networks, mock_get_current):
    """Test scan never marks current network for removal."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "OldNetwork"]

    # Even with keep_days=0 and empty allowlist, current network is kept
    module = WiFiModule(keep_days=0, keep_ssids=[], interface="en0")
    result = module.scan()

    # Only OldNetwork should be marked for removal
    assert len(result.items) == 1
    assert "OldNetwork" in result.items[0]
    assert "CurrentWiFi" not in result.items[0]


@patch("macos_maid.modules.wifi.WiFiModule._remove_network")
@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_clean_success(mock_get_networks, mock_get_current, mock_remove):
    """Test clean removes stale networks successfully."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "HomeWiFi", "CoffeeShop"]
    mock_remove.return_value = None  # Success

    module = WiFiModule(keep_days=90, keep_ssids=["HomeWiFi"], interface="en0")
    result = module.clean()

    assert len(result.items_cleaned) == 1
    assert "CoffeeShop" in result.items_cleaned[0]
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0
    mock_remove.assert_called_once_with("CoffeeShop", "en0")


@patch("macos_maid.modules.wifi.WiFiModule._remove_network")
@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_clean_error(mock_get_networks, mock_get_current, mock_remove):
    """Test clean handles errors gracefully."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "CoffeeShop"]
    mock_remove.side_effect = Exception("Permission denied")

    module = WiFiModule(keep_days=90, keep_ssids=[], interface="en0")
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 1
    assert "CoffeeShop" in result.errors[0]
    assert "Permission denied" in result.errors[0]


@patch("macos_maid.modules.wifi.WiFiModule._remove_network")
@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_clean_empty_when_no_stale(mock_get_networks, mock_get_current, mock_remove):
    """Test clean returns empty when no stale networks exist."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi"]

    module = WiFiModule(keep_days=90, keep_ssids=[], interface="en0")
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0
    mock_remove.assert_not_called()


def test_wifi_audit_empty():
    """Test audit returns empty result (no security checks)."""
    module = WiFiModule()
    result = module.audit()

    assert result.status == "pass"
    assert len(result.findings) == 0


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_current_ssid_success(mock_run):
    """Test getting current SSID successfully."""
    mock_run.return_value.stdout = "Current Wi-Fi Network: HomeWiFi\n"
    mock_run.return_value.returncode = 0

    module = WiFiModule(interface="en0")
    ssid = module._get_current_ssid("en0")

    assert ssid == "HomeWiFi"
    mock_run.assert_called_once()


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_current_ssid_not_connected(mock_run):
    """Test getting current SSID when not connected."""
    mock_run.return_value.stdout = "You are not associated with an AirPort network.\n"
    mock_run.return_value.returncode = 0

    module = WiFiModule(interface="en0")
    ssid = module._get_current_ssid("en0")

    assert ssid is None


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_current_ssid_error(mock_run):
    """Test getting current SSID handles errors."""
    mock_run.side_effect = Exception("Command failed")

    module = WiFiModule(interface="en0")
    ssid = module._get_current_ssid("en0")

    assert ssid is None


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_known_networks_success(mock_run):
    """Test getting known networks successfully."""
    mock_run.return_value.stdout = """Preferred networks on en0:
	HomeWiFi
	CoffeeShop
	AirportWiFi
"""
    mock_run.return_value.returncode = 0

    module = WiFiModule(interface="en0")
    networks = module._get_known_networks("en0")

    assert networks == ["HomeWiFi", "CoffeeShop", "AirportWiFi"]


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_known_networks_empty(mock_run):
    """Test getting known networks when none exist."""
    mock_run.return_value.stdout = "Preferred networks on en0:\n"
    mock_run.return_value.returncode = 0

    module = WiFiModule(interface="en0")
    networks = module._get_known_networks("en0")

    assert networks == []


@patch("macos_maid.modules.wifi.subprocess.run")
def test_get_known_networks_error(mock_run):
    """Test getting known networks handles errors."""
    mock_run.side_effect = Exception("Command failed")

    module = WiFiModule(interface="en0")
    networks = module._get_known_networks("en0")

    assert networks == []
