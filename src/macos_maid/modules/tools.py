"""External security tools integration module for MacOS Maid.

Optional integration with security tools like Lynis, osquery, and KnockKnock.
Never installs tools - only runs them if installed and suggests installation if not.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
)


class ToolsModule(Module):
    """Audit system using external security tools (read-only, never modifies anything)."""

    name = "tools"
    category = "security"
    requires_sudo = False

    def __init__(
        self,
        lynis_enabled: bool = True,
        osquery_enabled: bool = True,
        knockknock_enabled: bool = False,
    ):
        """Initialize tools module.

        Args:
            lynis_enabled: Run Lynis security audit if installed
            osquery_enabled: Run osquery checks if installed
            knockknock_enabled: Run KnockKnock scan if installed
        """
        self.lynis_enabled = lynis_enabled
        self.osquery_enabled = osquery_enabled
        self.knockknock_enabled = knockknock_enabled

    def scan(self) -> ScanResult:
        """Preview what this module would do (audit-only, returns empty)."""
        return ScanResult.empty()

    def clean(self) -> CleanResult:
        """Execute cleanup operations (audit-only, returns empty)."""
        return CleanResult.empty()

    def audit(self) -> AuditResult:
        """Run security checks using external tools."""
        findings: list[Finding] = []

        # Check Lynis
        if self.lynis_enabled:
            if shutil.which("lynis"):
                try:
                    findings.extend(self._run_lynis())
                except Exception as e:
                    findings.append(
                        Finding(
                            severity="warn",
                            title="Lynis Execution Failed",
                            detail=f"Failed to run Lynis: {e}",
                            remediation="Verify Lynis installation with 'lynis --version'",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        severity="info",
                        title="Lynis Not Installed",
                        detail="Install Lynis for comprehensive system security auditing. Install with: brew install lynis",
                        remediation=None,
                    )
                )

        # Check osquery
        if self.osquery_enabled:
            if shutil.which("osqueryi"):
                try:
                    findings.extend(self._run_osquery_check())
                except Exception as e:
                    findings.append(
                        Finding(
                            severity="warn",
                            title="Osquery Execution Failed",
                            detail=f"Failed to run osquery: {e}",
                            remediation="Verify osquery installation with 'osqueryi --version'",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        severity="info",
                        title="Osquery Not Installed",
                        detail="Install osquery for system querying and monitoring. Install with: brew install osquery",
                        remediation=None,
                    )
                )

        # Check KnockKnock
        if self.knockknock_enabled:
            if shutil.which("knockknock"):
                try:
                    findings.extend(self._run_knockknock_check())
                except Exception as e:
                    findings.append(
                        Finding(
                            severity="warn",
                            title="KnockKnock Execution Failed",
                            detail=f"Failed to run KnockKnock: {e}",
                            remediation="Verify KnockKnock installation",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        severity="info",
                        title="KnockKnock Not Installed",
                        detail="Install KnockKnock to scan for persistent malware. Download from: https://objective-see.org/products/knockknock.html",
                        remediation=None,
                    )
                )

        # Determine worst status: fail > warn > info > pass
        status = "pass"
        for finding in findings:
            if finding.severity == "fail":
                status = "fail"
                break
            elif finding.severity == "warn" and status != "fail":
                status = "warn"
            elif finding.severity == "info" and status not in ["fail", "warn"]:
                status = "info"

        return AuditResult(status=status, findings=findings)

    def _run_lynis(self) -> list[Finding]:
        """Run Lynis security audit.

        Returns:
            List of findings from Lynis audit
        """
        findings: list[Finding] = []

        try:
            # Run Lynis with quick mode and no colors
            result = subprocess.run(
                ["lynis", "audit", "system", "--quick", "--no-colors"],
                capture_output=True,
                text=True,
                timeout=120,  # Lynis can take a while
            )

            output = result.stdout

            # Parse hardening index
            hardening_match = re.search(r"Hardening index\s*:\s*(\d+)", output)
            if hardening_match:
                hardening_index = int(hardening_match.group(1))
                if hardening_index >= 80:
                    severity = "pass"
                    remediation = None
                elif hardening_index >= 60:
                    severity = "warn"
                    remediation = "Review Lynis suggestions to improve system hardening"
                else:
                    severity = "fail"
                    remediation = "System hardening is weak. Review and implement Lynis suggestions"

                findings.append(
                    Finding(
                        severity=severity,
                        title="Lynis Hardening Index",
                        detail=f"Hardening index: {hardening_index}",
                        remediation=remediation,
                    )
                )

            # Parse warnings
            warning_lines = [
                line for line in output.split("\n") if "Warning:" in line or "[WARNING]" in line
            ]
            for warning in warning_lines[:5]:  # Limit to first 5 warnings
                # Clean up the warning text
                warning_text = re.sub(r"\[WARNING\]|\[.*?\]|Warning:", "", warning).strip()
                if warning_text:
                    findings.append(
                        Finding(
                            severity="warn",
                            title="Lynis Warning",
                            detail=warning_text,
                            remediation="Review Lynis report for detailed recommendations",
                        )
                    )

            # Parse suggestions
            suggestion_lines = [
                line
                for line in output.split("\n")
                if "Suggestion:" in line or "[SUGGESTION]" in line
            ]
            for suggestion in suggestion_lines[:3]:  # Limit to first 3 suggestions
                # Clean up the suggestion text
                suggestion_text = re.sub(
                    r"\[SUGGESTION\]|\[.*?\]|Suggestion:", "", suggestion
                ).strip()
                if suggestion_text:
                    findings.append(
                        Finding(
                            severity="info",
                            title="Lynis Suggestion",
                            detail=suggestion_text,
                            remediation=None,
                        )
                    )

        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    severity="warn",
                    title="Lynis Timeout",
                    detail="Lynis audit took too long and was terminated",
                    remediation="Try running 'lynis audit system --quick' manually",
                )
            )
        except Exception as e:
            raise  # Re-raise to be caught by audit()

        return findings

    def _run_osquery_check(self) -> list[Finding]:
        """Run targeted osquery checks.

        Returns:
            List of findings from osquery checks
        """
        findings: list[Finding] = []

        # Check for unsigned processes
        unsigned_query = """
        SELECT name, path, pid
        FROM processes
        WHERE on_disk = 1
          AND (
            path NOT LIKE '/System/%'
            AND path NOT LIKE '/usr/%'
            AND path NOT LIKE '/Applications/%'
          )
          AND NOT EXISTS (
            SELECT 1 FROM signature
            WHERE signature.path = processes.path
              AND signature.signed = 1
          )
        LIMIT 10;
        """

        try:
            result = subprocess.run(
                ["osqueryi", "--json", unsigned_query],
                capture_output=True,
                text=True,
                timeout=30,
            )

            import json

            unsigned_processes = json.loads(result.stdout)
            if unsigned_processes:
                process_names = [p.get("name", "unknown") for p in unsigned_processes[:5]]
                findings.append(
                    Finding(
                        severity="warn",
                        title="Unsigned Processes Detected",
                        detail=f"Found {len(unsigned_processes)} unsigned processes: {', '.join(process_names)}",
                        remediation="Investigate and remove suspicious unsigned processes",
                    )
                )
        except Exception:
            # Silently skip if query fails
            pass

        # Check for unexpected listeners
        listeners_query = """
        SELECT DISTINCT process.name, listening.port, listening.address
        FROM listening_ports AS listening
        JOIN processes AS process USING (pid)
        WHERE listening.address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '::')
        LIMIT 10;
        """

        try:
            result = subprocess.run(
                ["osqueryi", "--json", listeners_query],
                capture_output=True,
                text=True,
                timeout=30,
            )

            import json

            listeners = json.loads(result.stdout)
            if listeners:
                listener_info = [
                    f"{l.get('name', 'unknown')}:{l.get('port', '?')}" for l in listeners[:5]
                ]
                findings.append(
                    Finding(
                        severity="info",
                        title="Network Listeners Detected",
                        detail=f"Processes listening on network: {', '.join(listener_info)}",
                        remediation="Verify these listeners are expected and legitimate",
                    )
                )
        except Exception:
            # Silently skip if query fails
            pass

        return findings

    def _run_knockknock_check(self) -> list[Finding]:
        """Run KnockKnock persistent item scan.

        Returns:
            List of findings from KnockKnock scan
        """
        findings: list[Finding] = []

        try:
            # KnockKnock CLI (if available) or just report that it should be run manually
            # Since KnockKnock is primarily a GUI app, we'll suggest manual usage
            findings.append(
                Finding(
                    severity="info",
                    title="KnockKnock Available",
                    detail="KnockKnock is installed. Run it manually to scan for persistent malware.",
                    remediation=None,
                )
            )
        except Exception:
            raise  # Re-raise to be caught by audit()

        return findings
