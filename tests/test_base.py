# tests/test_base.py
from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
)


def test_scan_result_defaults():
    result = ScanResult(items=[], bytes_reclaimable=0, requires_sudo=False)
    assert result.items == []
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_result_defaults():
    result = CleanResult(items_cleaned=[], bytes_reclaimed=0, errors=[])
    assert result.errors == []


def test_finding_with_remediation():
    f = Finding(
        severity="warn",
        title="Firewall disabled",
        detail="macOS firewall is not enabled",
        remediation="Enable via System Settings > Network > Firewall",
    )
    assert f.severity == "warn"
    assert f.remediation is not None


def test_finding_without_remediation():
    f = Finding(severity="pass", title="SIP enabled", detail="SIP is active", remediation=None)
    assert f.remediation is None


def test_audit_result_status():
    result = AuditResult(status="pass", findings=[])
    assert result.status == "pass"


def test_scan_result_empty():
    """ScanResult.empty() returns a no-op result."""
    result = ScanResult.empty()
    assert result.items == []
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_result_empty():
    """CleanResult.empty() returns a no-op result."""
    result = CleanResult.empty()
    assert result.items_cleaned == []
    assert result.bytes_reclaimed == 0
    assert result.errors == []


def test_audit_result_empty():
    """AuditResult.empty() returns a passing no-op result."""
    result = AuditResult.empty()
    assert result.status == "pass"
    assert result.findings == []


class ConcreteModule(Module):
    name = "test"
    category = "dev"
    requires_sudo = False

    def scan(self) -> ScanResult:
        return ScanResult(items=["would do thing"], bytes_reclaimable=100, requires_sudo=False)

    def clean(self) -> CleanResult:
        return CleanResult(items_cleaned=["did thing"], bytes_reclaimed=100, errors=[])

    def audit(self) -> AuditResult:
        return AuditResult.empty()


def test_module_subclass():
    mod = ConcreteModule()
    assert mod.name == "test"
    assert mod.category == "dev"
    scan = mod.scan()
    assert len(scan.items) == 1
