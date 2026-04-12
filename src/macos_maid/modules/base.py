"""Base module class and shared data types for MacOS Maid."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


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

    severity: str  # "pass", "info", "warn", "fail"
    title: str
    detail: str
    remediation: str | None = None


@dataclass
class AuditResult:
    """Security findings (read-only, never modifies anything)."""

    status: str  # "pass", "warn", "fail" — worst finding severity
    findings: list[Finding] = field(default_factory=list)

    @classmethod
    def empty(cls) -> AuditResult:
        return cls(status="pass", findings=[])


class Module(ABC):
    """Base class for all MacOS Maid modules.

    Subclasses must set name, category, and requires_sudo as class attributes
    and implement scan(), clean(), and audit().
    """

    name: str
    category: str  # "dev", "security", or "both"
    requires_sudo: bool

    @abstractmethod
    def scan(self) -> ScanResult:
        """Preview what this module would do (dry-run)."""
        ...

    @abstractmethod
    def clean(self) -> CleanResult:
        """Execute cleanup operations."""
        ...

    @abstractmethod
    def audit(self) -> AuditResult:
        """Run security checks (read-only, never modifies anything)."""
        ...
