"""Network security module for MacOS Maid."""

from __future__ import annotations

import subprocess

from macos_maid.modules.base import AuditResult, CleanResult, Finding, Module, ScanResult


class NetworkModule(Module):
    """Module for network security checks and DNS cache management."""

    name = "network"
    category = "security"
    requires_sudo = True  # DNS flush requires sudo

    def _flush_dns(self) -> None:
        """Flush DNS cache using macOS system commands."""
        # Flush dscacheutil cache
        subprocess.run(
            ["sudo", "dscacheutil", "-flushcache"],
            capture_output=True,
            text=True,
            check=True,
        )
        # Restart mDNSResponder
        subprocess.run(
            ["sudo", "killall", "-HUP", "mDNSResponder"],
            capture_output=True,
            text=True,
            check=True,
        )

    def _get_open_ports(self) -> list[tuple[str, str]]:
        """Get list of open TCP listening ports and their processes.

        Returns:
            List of (port, process_name) tuples
        """
        try:
            result = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP"],
                capture_output=True,
                text=True,
                check=True,
            )

            ports = []
            for line in result.stdout.splitlines():
                # Skip header line
                if line.startswith("COMMAND"):
                    continue

                # Parse lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                parts = line.split()
                if len(parts) >= 9:
                    process_name = parts[0]
                    # NAME field contains IP:PORT
                    name_field = parts[8]
                    if ":" in name_field:
                        port = name_field.split(":")[-1]
                        ports.append((port, process_name))

            return ports
        except (subprocess.CalledProcessError, IndexError):
            return []

    def _check_firewall_enabled(self) -> bool:
        """Check if macOS firewall is enabled.

        Returns:
            True if firewall is enabled, False otherwise
        """
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True,
                text=True,
                check=True,
            )
            # "Firewall is enabled. (State = 1)" or "...disabled. (State = 0)"
            return "enabled" in result.stdout.lower()
        except subprocess.CalledProcessError:
            return False

    def _get_vpn_profiles(self) -> list[str]:
        """Get list of configured VPN profiles.

        Returns:
            List of VPN profile names
        """
        try:
            result = subprocess.run(
                ["scutil", "--nc", "list"],
                capture_output=True,
                text=True,
                check=True,
            )

            profiles = []
            for line in result.stdout.splitlines():
                # Lines look like: * (Connected)  "VPN Name"  [UUID] [Type]
                # or:              "VPN Name"  [UUID] [Type]
                if '"' in line:
                    # Extract name between quotes
                    start = line.index('"') + 1
                    end = line.index('"', start)
                    profile_name = line[start:end]
                    profiles.append(profile_name)

            return profiles
        except (subprocess.CalledProcessError, ValueError, IndexError):
            return []

    def scan(self) -> ScanResult:
        """Preview what this module would do (DNS flush)."""
        return ScanResult(
            items=["Flush DNS cache"],
            bytes_reclaimable=0,
            requires_sudo=True,
        )

    def clean(self) -> CleanResult:
        """Flush DNS cache."""
        try:
            self._flush_dns()
            return CleanResult(
                items_cleaned=["Flushed DNS cache"],
                bytes_reclaimed=0,
                errors=[],
            )
        except Exception as e:
            return CleanResult(
                items_cleaned=[],
                bytes_reclaimed=0,
                errors=[f"Failed to flush DNS cache: {e}"],
            )

    def audit(self) -> AuditResult:
        """Run network security checks."""
        findings = []

        # Check firewall status
        firewall_enabled = self._check_firewall_enabled()
        if firewall_enabled:
            findings.append(
                Finding(
                    severity="pass",
                    title="Firewall Status",
                    detail="macOS Application Firewall is enabled",
                    remediation=None,
                )
            )
        else:
            findings.append(
                Finding(
                    severity="fail",
                    title="Firewall Status",
                    detail="macOS Application Firewall is disabled",
                    remediation=(
                        "Enable firewall in System Preferences > Security & Privacy > Firewall"
                    ),
                )
            )

        # Check open ports
        open_ports = self._get_open_ports()
        if open_ports:
            port_list = ", ".join(f"{port} ({proc})" for port, proc in open_ports[:5])
            if len(open_ports) > 5:
                port_list += f" and {len(open_ports) - 5} more"

            findings.append(
                Finding(
                    severity="info",
                    title="Open Listening Ports",
                    detail=f"Found {len(open_ports)} open TCP ports: {port_list}",
                    remediation="Review open ports and close any unnecessary services",
                )
            )
        else:
            findings.append(
                Finding(
                    severity="pass",
                    title="Open Listening Ports",
                    detail="No unexpected open TCP ports detected",
                    remediation=None,
                )
            )

        # Check VPN profiles
        vpn_profiles = self._get_vpn_profiles()
        if vpn_profiles:
            profile_list = ", ".join(vpn_profiles)
            findings.append(
                Finding(
                    severity="info",
                    title="VPN Profiles",
                    detail=f"Found {len(vpn_profiles)} VPN profile(s): {profile_list}",
                    remediation=None,
                )
            )
        else:
            findings.append(
                Finding(
                    severity="info",
                    title="VPN Profiles",
                    detail="No VPN profiles configured",
                    remediation=None,
                )
            )

        # Determine overall status (worst severity)
        severity_order = {"pass": 0, "info": 1, "warn": 2, "fail": 3}
        worst_severity = max(
            (f.severity for f in findings),
            key=lambda s: severity_order.get(s, 0),
            default="pass",
        )

        return AuditResult(status=worst_severity, findings=findings)
