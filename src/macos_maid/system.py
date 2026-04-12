# src/macos_maid/system.py
"""Platform detection for MacOS Maid.

Detects architecture, macOS version, filesystem type, Homebrew prefix,
and WiFi interface at startup. Passed to all modules.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass

_MACOS_NAMES: dict[int, str] = {
    12: "Monterey",
    13: "Ventura",
    14: "Sonoma",
    15: "Sequoia",
}


def _macos_name(version: tuple[int, ...]) -> str:
    return _MACOS_NAMES.get(version[0], "Unknown")


@dataclass
class Platform:
    """Detected platform information."""

    arch: str
    macos_version: tuple[int, ...]
    macos_name: str
    filesystem: str
    homebrew_prefix: str
    wifi_interface: str
    is_apple_silicon: bool


def _get_arch() -> str:
    """Return CPU architecture: 'arm64' or 'x86_64'."""
    return platform.machine()


def _get_macos_version() -> tuple[int, ...]:
    """Return macOS version as a tuple, e.g. (15, 4, 0)."""
    ver_str = platform.mac_ver()[0]
    parts = ver_str.split(".")
    return tuple(int(p) for p in parts)


def _get_filesystem() -> str:
    """Detect root filesystem type."""
    try:
        result = subprocess.run(
            ["diskutil", "info", "/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "Type (Bundle):" in line:
                if "apfs" in line.lower():
                    return "apfs"
                if "hfs" in line.lower():
                    return "hfs+"
        return "apfs"  # default for modern macOS
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "apfs"


def _get_wifi_interface() -> str:
    """Detect the primary WiFi interface name."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if "Wi-Fi" in line or "AirPort" in line:
                for j in range(i + 1, min(i + 3, len(lines))):
                    if lines[j].startswith("Device:"):
                        return lines[j].split(":", 1)[1].strip()
        return "en0"  # fallback
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "en0"


def detect_platform() -> Platform:
    """Detect and return the current platform information."""
    arch = _get_arch()
    version = _get_macos_version()
    is_apple_silicon = arch == "arm64"

    return Platform(
        arch=arch,
        macos_version=version,
        macos_name=_macos_name(version),
        filesystem=_get_filesystem(),
        homebrew_prefix="/opt/homebrew" if is_apple_silicon else "/usr/local",
        wifi_interface=_get_wifi_interface(),
        is_apple_silicon=is_apple_silicon,
    )
