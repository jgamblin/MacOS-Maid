# tests/test_runner.py
from macos_maid.audit_log import AuditLog
from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
)
from macos_maid.runner import ModuleRunner


class FakeCleanModule(Module):
    name = "fake_clean"
    category = "dev"
    requires_sudo = False

    def scan(self) -> ScanResult:
        return ScanResult(
            items=["would clean 100 MB"], bytes_reclaimable=104857600, requires_sudo=False
        )

    def clean(self) -> CleanResult:
        return CleanResult(items_cleaned=["cleaned 100 MB"], bytes_reclaimed=104857600, errors=[])

    def audit(self) -> AuditResult:
        return AuditResult.empty()


class FakeSudoModule(Module):
    name = "fake_sudo"
    category = "security"
    requires_sudo = True

    def scan(self) -> ScanResult:
        return ScanResult(items=["would flush DNS"], bytes_reclaimable=0, requires_sudo=True)

    def clean(self) -> CleanResult:
        return CleanResult(items_cleaned=["flushed DNS"], bytes_reclaimed=0, errors=[])

    def audit(self) -> AuditResult:
        return AuditResult(
            status="fail",
            findings=[
                Finding(severity="fail", title="Firewall off", detail="Firewall is disabled")
            ],
        )


class FakeAuditOnlyModule(Module):
    name = "fake_audit"
    category = "security"
    requires_sudo = False

    def scan(self) -> ScanResult:
        return ScanResult.empty()

    def clean(self) -> CleanResult:
        return CleanResult.empty()

    def audit(self) -> AuditResult:
        return AuditResult(
            status="pass",
            findings=[Finding(severity="pass", title="SIP enabled", detail="OK")],
        )


def test_runner_dry_run():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeCleanModule()], dry_run=True, allow_sudo=False, audit_log=log
    )
    results = runner.run_clean()
    # Dry run returns scan results, not clean results
    assert len(results) == 1
    assert results["fake_clean"].items == ["would clean 100 MB"]


def test_runner_clean():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeCleanModule()], dry_run=False, allow_sudo=False, audit_log=log
    )
    results = runner.run_clean()
    assert results["fake_clean"].items_cleaned == ["cleaned 100 MB"]
    assert log.total_bytes_reclaimed == 104857600


def test_runner_skips_sudo_modules_without_flag():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeCleanModule(), FakeSudoModule()],
        dry_run=False,
        allow_sudo=False,
        audit_log=log,
    )
    results = runner.run_clean()
    assert "fake_clean" in results
    assert "fake_sudo" not in results


def test_runner_includes_sudo_modules_with_flag():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeSudoModule()],
        dry_run=False,
        allow_sudo=True,
        audit_log=log,
    )
    results = runner.run_clean()
    assert "fake_sudo" in results


def test_runner_audit():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeAuditOnlyModule(), FakeSudoModule()],
        dry_run=False,
        allow_sudo=False,
        audit_log=log,
    )
    results = runner.run_audit()
    # audit-only module included
    assert "fake_audit" in results
    # sudo module included in audits (audit() is read-only, no sudo needed)
    assert "fake_sudo" in results


def test_runner_filter_by_category():
    log = AuditLog()
    modules = [FakeCleanModule(), FakeSudoModule()]
    runner = ModuleRunner(
        modules=modules,
        dry_run=False,
        allow_sudo=True,
        audit_log=log,
        categories=["dev"],
    )
    results = runner.run_clean()
    assert "fake_clean" in results
    assert "fake_sudo" not in results


def test_runner_filter_by_module_names():
    log = AuditLog()
    runner = ModuleRunner(
        modules=[FakeCleanModule(), FakeAuditOnlyModule()],
        dry_run=False,
        allow_sudo=False,
        audit_log=log,
        module_names=["fake_audit"],
    )
    results = runner.run_clean()
    assert "fake_audit" in results
    assert "fake_clean" not in results
