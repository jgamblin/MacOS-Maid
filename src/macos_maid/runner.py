# src/macos_maid/runner.py
"""Module executor for MacOS Maid.

Handles dry-run mode, sudo gating, category/module filtering,
and audit log recording.
"""

from __future__ import annotations

from typing import Any

from macos_maid.audit_log import AuditLog
from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult


class ModuleRunner:
    """Runs modules with filtering, sudo gating, and logging."""

    def __init__(
        self,
        modules: list[Module],
        dry_run: bool,
        allow_sudo: bool,
        audit_log: AuditLog,
        categories: list[str] | None = None,
        module_names: list[str] | None = None,
    ) -> None:
        self._modules = modules
        self._dry_run = dry_run
        self._allow_sudo = allow_sudo
        self._audit_log = audit_log
        self._categories = categories
        self._module_names = module_names

    def _filter_modules(self, require_sudo_check: bool = True) -> list[Module]:
        """Filter modules by category, name, and sudo requirements."""
        filtered = self._modules

        if self._module_names is not None:
            filtered = [m for m in filtered if m.name in self._module_names]
        elif self._categories is not None:
            filtered = [
                m for m in filtered if m.category in self._categories or m.category == "both"
            ]

        if require_sudo_check and not self._allow_sudo:
            filtered = [m for m in filtered if not m.requires_sudo]

        return filtered

    def run_clean(self) -> dict[str, ScanResult | CleanResult]:
        """Run cleanup on all matching modules.

        Returns ScanResult per module in dry-run mode, CleanResult otherwise.
        """
        modules = self._filter_modules()
        results: dict[str, Any] = {}

        for module in modules:
            self._audit_log.record_module(module.name)

            if self._dry_run:
                results[module.name] = module.scan()
            else:
                clean_result = module.clean()
                results[module.name] = clean_result

                for i, item in enumerate(clean_result.items_cleaned):
                    self._audit_log.add_action(
                        module=module.name,
                        action="clean",
                        detail=item,
                        bytes_reclaimed=clean_result.bytes_reclaimed if i == 0 else 0,
                    )

                for error in clean_result.errors:
                    self._audit_log.add_error(module=module.name, error=error)

        return results

    def run_audit(self) -> dict[str, AuditResult]:
        """Run security audits on all matching modules.

        Audit methods are read-only, so sudo gating is not applied.
        """
        modules = self._filter_modules(require_sudo_check=False)
        results: dict[str, AuditResult] = {}

        for module in modules:
            self._audit_log.record_module(module.name)
            results[module.name] = module.audit()

        return results

    def get_sudo_modules(self) -> list[Module]:
        """Return modules that would need sudo but are currently excluded."""
        if self._allow_sudo:
            return []
        all_modules = self._modules
        if self._module_names is not None:
            all_modules = [m for m in all_modules if m.name in self._module_names]
        elif self._categories is not None:
            all_modules = [
                m for m in all_modules if m.category in self._categories or m.category == "both"
            ]
        return [m for m in all_modules if m.requires_sudo]
