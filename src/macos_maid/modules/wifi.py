"""WiFi cleanup module for MacOS Maid."""

from __future__ import annotations

import subprocess
from datetime import datetime

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult


class WiFiModule(Module):
    """Module to clean up stale WiFi networks.

    SAFETY: Always keeps the currently connected network, regardless of config.
    This is hardcoded and not configurable.
    """

    name = "wifi"
    category = "security"
    requires_sudo = True

    def __init__(
        self,
        keep_days: int = 90,
        keep_ssids: list[str] | None = None,
        interface: str = "en0",
    ):
        """Initialize WiFi module.

        Args:
            keep_days: Keep networks joined within this many days
            keep_ssids: List of network SSIDs to always keep
            interface: Network interface to manage (default: en0)
        """
        self.keep_days = keep_days
        self.keep_ssids = keep_ssids or []
        self.interface = interface

    def _should_keep_network(
        self,
        ssid: str,
        last_joined: datetime | None,
        keep_days: int,
        keep_ssids: list[str],
        current_ssid: str | None,
    ) -> bool:
        """Determine if a network should be kept.

        Args:
            ssid: Network SSID
            last_joined: Last joined timestamp (may be None if unavailable)
            keep_days: Keep networks joined within this many days
            keep_ssids: List of SSIDs to always keep
            current_ssid: Currently connected SSID (always kept)

        Returns:
            True if network should be kept, False if it should be removed
        """
        # SAFETY: Always keep current network
        if ssid == current_ssid:
            return True

        # Keep allowlisted networks
        if ssid in keep_ssids:
            return True

        # Keep recently joined networks (if timestamp available)
        if last_joined is not None:
            days_ago = (datetime.now() - last_joined).days
            if days_ago <= keep_days:
                return True
            return False

        # SAFETY: When timestamp is unavailable (e.g., networksetup doesn't
        # expose join dates), default to KEEP. Never delete a network just
        # because we can't determine when it was last used.
        return True

    def _get_current_ssid(self, interface: str) -> str | None:
        """Get the currently connected SSID.

        Args:
            interface: Network interface to check

        Returns:
            Current SSID or None if not connected
        """
        try:
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", interface],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            output = result.stdout.strip()

            # Parse "Current Wi-Fi Network: NetworkName"
            if "Current Wi-Fi Network:" in output:
                return output.split("Current Wi-Fi Network:")[1].strip()

            # Not connected
            return None

        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return None

    def _get_known_networks(self, interface: str) -> list[str]:
        """Get list of known (preferred) WiFi networks.

        Args:
            interface: Network interface to check

        Returns:
            List of known network SSIDs
        """
        try:
            result = subprocess.run(
                ["networksetup", "-listpreferredwirelessnetworks", interface],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            output = result.stdout.strip()
            networks = []

            # Parse output - skip header line, networks are indented with tabs
            for line in output.split("\n")[1:]:  # Skip "Preferred networks on en0:"
                line = line.strip()
                if line:
                    networks.append(line)

            return networks

        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return []

    def _remove_network(self, ssid: str, interface: str) -> None:
        """Remove a WiFi network.

        Args:
            ssid: Network SSID to remove
            interface: Network interface

        Raises:
            Exception: If removal fails
        """
        subprocess.run(
            ["sudo", "networksetup", "-removepreferredwirelessnetwork", interface, ssid],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

    def scan(self) -> ScanResult:
        """Preview WiFi networks that would be removed."""
        current_ssid = self._get_current_ssid(self.interface)
        known_networks = self._get_known_networks(self.interface)

        removable = []
        for ssid in known_networks:
            # Since networksetup doesn't expose join timestamps, we can't use
            # timestamp-based retention yet. For now, only check current and allowlist.
            if not self._should_keep_network(
                ssid=ssid,
                last_joined=None,  # Timestamp not available from networksetup
                keep_days=self.keep_days,
                keep_ssids=self.keep_ssids,
                current_ssid=current_ssid,
            ):
                removable.append(f"Remove network: {ssid}")

        return ScanResult(
            items=removable,
            bytes_reclaimable=0,  # WiFi networks don't take disk space
            requires_sudo=True,
        )

    def clean(self) -> CleanResult:
        """Remove stale WiFi networks."""
        current_ssid = self._get_current_ssid(self.interface)
        known_networks = self._get_known_networks(self.interface)

        cleaned = []
        errors = []

        for ssid in known_networks:
            if not self._should_keep_network(
                ssid=ssid,
                last_joined=None,  # Timestamp not available from networksetup
                keep_days=self.keep_days,
                keep_ssids=self.keep_ssids,
                current_ssid=current_ssid,
            ):
                try:
                    self._remove_network(ssid, self.interface)
                    cleaned.append(f"Removed network: {ssid}")
                except Exception as e:
                    errors.append(f"Failed to remove {ssid}: {e}")

        return CleanResult(
            items_cleaned=cleaned,
            bytes_reclaimed=0,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """WiFi module has no security checks."""
        return AuditResult.empty()
