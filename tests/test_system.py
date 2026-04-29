# tests/test_system.py
from unittest.mock import patch

from macos_maid.system import Platform, detect_platform


def test_platform_dataclass():
    p = Platform(
        arch="arm64",
        macos_version=(15, 4, 0),
        macos_name="Sequoia",
        filesystem="apfs",
        homebrew_prefix="/opt/homebrew",
        wifi_interface="en0",
        is_apple_silicon=True,
    )
    assert p.is_apple_silicon is True
    assert p.homebrew_prefix == "/opt/homebrew"


def test_platform_is_apple_silicon_derived():
    p = Platform(
        arch="x86_64",
        macos_version=(13, 0, 0),
        macos_name="Ventura",
        filesystem="apfs",
        homebrew_prefix="/usr/local",
        wifi_interface="en0",
        is_apple_silicon=False,
    )
    assert p.is_apple_silicon is False


def test_platform_homebrew_prefix_intel():
    p = Platform(
        arch="x86_64",
        macos_version=(12, 0, 0),
        macos_name="Monterey",
        filesystem="apfs",
        homebrew_prefix="/usr/local",
        wifi_interface="en0",
        is_apple_silicon=False,
    )
    assert p.homebrew_prefix == "/usr/local"


@patch("macos_maid.system._get_arch", return_value="arm64")
@patch("macos_maid.system._get_macos_version", return_value=(15, 4, 0))
@patch("macos_maid.system._get_filesystem", return_value="apfs")
@patch("macos_maid.system._get_wifi_interface", return_value="en0")
def test_detect_platform_apple_silicon(mock_wifi, mock_fs, mock_ver, mock_arch):
    p = detect_platform()
    assert p.arch == "arm64"
    assert p.is_apple_silicon is True
    assert p.homebrew_prefix == "/opt/homebrew"
    assert p.macos_name == "Sequoia"


@patch("macos_maid.system._get_arch", return_value="x86_64")
@patch("macos_maid.system._get_macos_version", return_value=(12, 6, 0))
@patch("macos_maid.system._get_filesystem", return_value="apfs")
@patch("macos_maid.system._get_wifi_interface", return_value="en1")
def test_detect_platform_intel(mock_wifi, mock_fs, mock_ver, mock_arch):
    p = detect_platform()
    assert p.arch == "x86_64"
    assert p.is_apple_silicon is False
    assert p.homebrew_prefix == "/usr/local"
    assert p.wifi_interface == "en1"


def test_macos_name_mapping():
    from macos_maid.system import _macos_name

    assert _macos_name((12, 0, 0)) == "Monterey"
    assert _macos_name((13, 0, 0)) == "Ventura"
    assert _macos_name((14, 0, 0)) == "Sonoma"
    assert _macos_name((15, 0, 0)) == "Sequoia"
    assert _macos_name((26, 0, 0)) == "Tahoe"
    assert _macos_name((99, 0, 0)) == "Unknown"
