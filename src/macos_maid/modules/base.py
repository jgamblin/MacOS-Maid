"""Base module class and shared data types for MacOS Maid."""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Finding severity levels, ordered by increasing urgency."""

    PASS = 0
    INFO = 1
    WARN = 2
    FAIL = 3

    @classmethod
    def from_str(cls, s: str) -> Severity:
        return cls[s.upper()]

    def __str__(self) -> str:
        return self.name.lower()


def worst_severity(findings: list[Finding]) -> str:
    """Return the worst severity string from a list of findings."""
    if not findings:
        return "pass"
    worst = max(f.severity for f in findings)
    return str(worst)


@dataclass
class ScanResult:
    """What would this module do? Used for dry-run previews."""

    items: list[str]
    bytes_reclaimable: int
    requires_sudo: bool

    @classmethod
    def empty(cls) -> ScanResult:
        return cls(items=[], bytes_reclaimable=0, requires_sudo=False)


@dataclass
class CleanResult:
    """What did this module actually do?"""

    items_cleaned: list[str]
    bytes_reclaimed: int
    errors: list[str] = field(default_factory=list)

    @classmethod
    def empty(cls) -> CleanResult:
        return cls(items_cleaned=[], bytes_reclaimed=0, errors=[])


@dataclass
class Finding:
    """A single security finding."""

    severity: Severity | str
    title: str
    detail: str
    remediation: str | None = None

    def __post_init__(self) -> None:
        """Coerce severity to Severity enum; raise on invalid values."""
        if isinstance(self.severity, Severity):
            return
        if isinstance(self.severity, str):
            try:
                self.severity = Severity.from_str(self.severity)
            except KeyError:
                allowed = ", ".join(s.name.lower() for s in Severity)
                raise ValueError(
                    f"Invalid severity '{self.severity}'. Must be one of: {allowed}"
                ) from None
            return
        raise ValueError(f"severity must be Severity or str, got {type(self.severity).__name__}")


@dataclass
class AuditResult:
    """Security findings (read-only, never modifies anything)."""

    status: str  # "pass", "info", "warn", "fail" — worst finding severity
    findings: list[Finding] = field(default_factory=list)

    @classmethod
    def empty(cls) -> AuditResult:
        return cls(status="pass", findings=[])


class Module(ABC):
    """Base class for all MacOS Maid modules.

    Subclasses must set name, category, and requires_sudo as class attributes.
    Implement scan() and clean() for cleanup modules, audit() for security modules.
    Default implementations return empty results for modules that don't need them.
    """

    name: str
    category: str  # "dev", "security", or "both"
    requires_sudo: bool

    def scan(self) -> ScanResult:
        """Preview what this module would do (dry-run)."""
        return ScanResult.empty()

    def clean(self) -> CleanResult:
        """Execute cleanup operations."""
        return CleanResult.empty()

    def audit(self) -> AuditResult:
        """Run security checks (read-only, never modifies anything)."""
        return AuditResult.empty()
