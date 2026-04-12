"""System integrity audit module for MacOS Maid.

Read-only audit-only module that checks security settings:
- System Integrity Protection (SIP)
- FileVault disk encryption
- Gatekeeper
- XProtect
- Firewall
"""

from __future__ import annotations

import subprocess

from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
)


class SystemIntegrityModule(Module):
    """Audit system security settings (read-only, never modifies anything)."""

    name = "system_integrity"
    category = "security"
    requires_sudo = False

    def scan(self) -> ScanResult:
        """Preview what this module would do (audit-only, returns empty)."""
        return ScanResult.empty()

    def clean(self) -> CleanResult:
        """Execute cleanup operations (audit-only, returns empty)."""
        return CleanResult.empty()

    def audit(self) -> AuditResult:
        """Run security checks for system integrity settings."""
        findings = [
            self._check_sip(),
            self._check_filevault(),
            self._check_gatekeeper(),
            self._check_xprotect(),
            self._check_firewall(),
        ]

        # Determine worst status: fail > warn > pass
        status = "pass"
        for finding in findings:
            if finding.severity == "fail":
                status = "fail"
                break
            elif finding.severity == "warn":
                status = "warn"

        return AuditResult(status=status, findings=findings)

    def _check_sip(self) -> Finding:
        """Check System Integrity Protection status."""
        try:
            result = subprocess.run(
                ["csrutil", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.lower()

            if "enabled" in output:
                return Finding(
                    severity="pass",
                    title="System Integrity Protection",
                    detail="SIP is enabled",
                    remediation=None,
                )
            else:
                return Finding(
                    severity="fail",
                    title="System Integrity Protection",
                    detail="SIP is disabled",
                    remediation="Enable SIP by booting into Recovery Mode and running 'csrutil enable'",
                )
        except Exception as e:
            return Finding(
                severity="warn",
                title="System Integrity Protection",
                detail=f"Could not check SIP status: {e}",
                remediation="Verify SIP manually with 'csrutil status'",
            )

    def _check_filevault(self) -> Finding:
        """Check FileVault disk encryption status."""
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.lower()

            if "on" in output:
                return Finding(
                    severity="pass",
                    title="FileVault Encryption",
                    detail="FileVault is on",
                    remediation=None,
                )
            else:
                return Finding(
                    severity="fail",
                    title="FileVault Encryption",
                    detail="FileVault is off",
                    remediation="Enable FileVault in System Preferences > Security & Privacy > FileVault",
                )
        except Exception as e:
            return Finding(
                severity="warn",
                title="FileVault Encryption",
                detail=f"Could not check FileVault status: {e}",
                remediation="Verify FileVault manually with 'fdesetup status'",
            )

    def _check_gatekeeper(self) -> Finding:
        """Check Gatekeeper status."""
        try:
            result = subprocess.run(
                ["spctl", "--status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.lower()

            if "enabled" in output or "assessments enabled" in output:
                return Finding(
                    severity="pass",
                    title="Gatekeeper",
                    detail="Gatekeeper is enabled",
                    remediation=None,
                )
            elif "disabled" in output or "assessments disabled" in output:
                return Finding(
                    severity="fail",
                    title="Gatekeeper",
                    detail="Gatekeeper is disabled",
                    remediation="Enable Gatekeeper with 'sudo spctl --master-enable'",
                )
            else:
                return Finding(
                    severity="warn",
                    title="Gatekeeper",
                    detail="Gatekeeper status is unclear",
                    remediation="Verify Gatekeeper manually with 'spctl --status'",
                )
        except Exception as e:
            return Finding(
                severity="warn",
                title="Gatekeeper",
                detail=f"Could not check Gatekeeper status: {e}",
                remediation="Verify Gatekeeper manually with 'spctl --status'",
            )

    def _check_xprotect(self) -> Finding:
        """Check XProtect status."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPInstallHistoryDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout.lower()

            if "xprotect" in output:
                return Finding(
                    severity="pass",
                    title="XProtect",
                    detail="XProtect is installed",
                    remediation=None,
                )
            else:
                return Finding(
                    severity="warn",
                    title="XProtect",
                    detail="XProtect installation not found in system history",
                    remediation="XProtect should be automatically installed by macOS",
                )
        except Exception as e:
            return Finding(
                severity="warn",
                title="XProtect",
                detail=f"Could not check XProtect status: {e}",
                remediation="Verify XProtect manually with 'system_profiler SPInstallHistoryDataType | grep -i xprotect'",
            )

    def _check_firewall(self) -> Finding:
        """Check firewall status."""
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.lower()

            if "enabled" in output:
                return Finding(
                    severity="pass",
                    title="Firewall",
                    detail="Firewall is enabled",
                    remediation=None,
                )
            else:
                return Finding(
                    severity="fail",
                    title="Firewall",
                    detail="Firewall is disabled",
                    remediation="Enable firewall in System Preferences > Security & Privacy > Firewall",
                )
        except Exception as e:
            return Finding(
                severity="warn",
                title="Firewall",
                detail=f"Could not check firewall status: {e}",
                remediation="Verify firewall manually with '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate'",
            )
