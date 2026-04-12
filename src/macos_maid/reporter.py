# src/macos_maid/reporter.py
"""Report card generator for MacOS Maid.

Formats cleanup and audit results for terminal, JSON, or markdown output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult
from macos_maid.system import Platform


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string."""
    if num_bytes == 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes = int(num_bytes / 1024.0)
    return f"{num_bytes:.1f} PB"


class Reporter:
    """Formats results into terminal, JSON, or markdown output."""

    def __init__(self, platform: Platform, output_format: str = "terminal") -> None:
        self._platform = platform
        self._format = output_format

    def _header(self) -> str:
        p = self._platform
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        ver = ".".join(str(v) for v in p.macos_version)
        return (
            f"MacOS Maid Report — {date}\n"
            f"macOS {p.macos_name} {ver} | {p.arch} | {p.filesystem.upper()}"
        )

    def format_clean(self, results: dict[str, CleanResult]) -> str:
        if self._format == "json":
            return json.dumps(
                {
                    name: {
                        "items": r.items_cleaned,
                        "bytes_reclaimed": r.bytes_reclaimed,
                        "errors": r.errors,
                    }
                    for name, r in results.items()
                },
                indent=2,
            )

        lines: list[str] = []
        if self._format == "markdown":
            lines.append(f"# {self._header()}\n")
            lines.append("## Cleanup\n")
        else:
            lines.append(self._header())
            lines.append("=" * 44)
            lines.append("\nCleanup")
            lines.append("-" * 7)

        total_bytes = 0
        for name, result in results.items():
            total_bytes += result.bytes_reclaimed
            detail = ", ".join(result.items_cleaned) if result.items_cleaned else "nothing to clean"
            byte_str = format_bytes(result.bytes_reclaimed)
            if self._format == "markdown":
                lines.append(f"- **{name}**: {detail} ({byte_str})")
            else:
                lines.append(f"  {name}: {detail} ({byte_str})")

            for error in result.errors:
                if self._format == "markdown":
                    lines.append(f"  - Error: {error}")
                else:
                    lines.append(f"    Error: {error}")

        lines.append(f"\nTotal reclaimed: {format_bytes(total_bytes)}")
        return "\n".join(lines)

    def format_audit(self, results: dict[str, AuditResult]) -> str:
        if self._format == "json":
            return json.dumps(
                {
                    name: {
                        "status": r.status,
                        "findings": [
                            {
                                "severity": f.severity,
                                "title": f.title,
                                "detail": f.detail,
                                "remediation": f.remediation,
                            }
                            for f in r.findings
                        ],
                    }
                    for name, r in results.items()
                },
                indent=2,
            )

        lines: list[str] = []
        if self._format == "markdown":
            lines.append(f"# {self._header()}\n")
            lines.append("## Security Audit\n")
        else:
            lines.append(self._header())
            lines.append("=" * 44)
            lines.append("\nSecurity Audit")
            lines.append("-" * 14)

        for name, result in results.items():
            for finding in result.findings:
                severity_label = finding.severity.upper()
                if self._format == "markdown":
                    lines.append(f"- **{severity_label}**: {finding.title} — {finding.detail}")
                    if finding.remediation:
                        lines.append(f"  - Fix: {finding.remediation}")
                else:
                    lines.append(f"  {severity_label}: {finding.title} — {finding.detail}")
                    if finding.remediation:
                        lines.append(f"    Fix: {finding.remediation}")

        return "\n".join(lines)

    def format_dry_run(self, results: dict[str, ScanResult]) -> str:
        if self._format == "json":
            return json.dumps(
                {
                    name: {
                        "items": r.items,
                        "bytes_reclaimable": r.bytes_reclaimable,
                        "requires_sudo": r.requires_sudo,
                    }
                    for name, r in results.items()
                },
                indent=2,
            )

        lines: list[str] = []
        if self._format == "markdown":
            lines.append(f"# {self._header()}\n")
            lines.append("## Preview (Dry Run)\n")
        else:
            lines.append(self._header())
            lines.append("=" * 44)
            lines.append("\nPreview (DRY RUN — no changes will be made)")
            lines.append("-" * 44)

        total_bytes = 0
        for name, result in results.items():
            total_bytes += result.bytes_reclaimable
            for item in result.items:
                if self._format == "markdown":
                    lines.append(f"- **{name}**: {item}")
                else:
                    lines.append(f"  {name}: {item}")

        lines.append(f"\nEstimated reclaimable: {format_bytes(total_bytes)}")
        return "\n".join(lines)
