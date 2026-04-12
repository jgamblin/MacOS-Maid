# tests/modules/test_wifi.py
"""Tests for WiFi cleanup module."""

import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch

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


def test_should_keep_when_no_timestamp():
    """SAFETY: Networks with unknown join time must be KEPT, not deleted.

    networksetup doesn't expose timestamps, so last_joined is always None.
    Defaulting to delete would nuke all saved WiFi networks.
    """
    module = WiFiModule(keep_days=30, keep_ssids=[], interface="en0")

    assert (
        module._should_keep_network(
            ssid="UnknownNetwork",
            last_joined=None,
            keep_days=30,
            keep_ssids=[],
            current_ssid="CurrentNetwork",
        )
        is True
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
def test_wifi_scan_keeps_all_without_timestamps(mock_get_networks, mock_get_current):
    """SAFETY: Without timestamps, scan should remove nothing.

    networksetup doesn't expose join timestamps, so all networks have
    last_joined=None. The safe default is to keep them all.
    """
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "HomeWiFi", "CoffeeShop", "AirportWiFi"]

    module = WiFiModule(keep_days=90, keep_ssids=["HomeWiFi"], interface="en0")
    result = module.scan()

    # No networks removed — timestamps unavailable, so all are kept
    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_scan_never_removes_current(mock_get_networks, mock_get_current):
    """Test scan never marks current network for removal."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "OldNetwork"]

    # Even with keep_days=0 and empty allowlist, nothing is removed
    # because networksetup can't provide timestamps
    module = WiFiModule(keep_days=0, keep_ssids=[], interface="en0")
    result = module.scan()

    assert len(result.items) == 0


@patch("macos_maid.modules.wifi.WiFiModule._remove_network")
@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_clean_keeps_all_without_timestamps(mock_get_networks, mock_get_current, mock_remove):
    """SAFETY: Clean removes nothing when timestamps are unavailable."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "HomeWiFi", "CoffeeShop"]
    mock_remove.return_value = None

    module = WiFiModule(keep_days=90, keep_ssids=["HomeWiFi"], interface="en0")
    result = module.clean()

    # Nothing removed — no timestamps available
    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0
    mock_remove.assert_not_called()


@patch("macos_maid.modules.wifi.WiFiModule._remove_network")
@patch("macos_maid.modules.wifi.WiFiModule._get_current_ssid")
@patch("macos_maid.modules.wifi.WiFiModule._get_known_networks")
def test_wifi_clean_error(mock_get_networks, mock_get_current, mock_remove):
    """Test clean handles errors gracefully when a removal fails."""
    mock_get_current.return_value = "CurrentWiFi"
    mock_get_networks.return_value = ["CurrentWiFi", "CoffeeShop"]

    # Patch _should_keep_network to simulate a scenario where removal is attempted
    with patch.object(WiFiModule, "_should_keep_network", side_effect=[True, False]):
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
    mock_run.side_effect = subprocess.SubprocessError("Command failed")

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
    mock_run.side_effect = subprocess.SubprocessError("Command failed")

    module = WiFiModule(interface="en0")
    networks = module._get_known_networks("en0")

    assert networks == []
