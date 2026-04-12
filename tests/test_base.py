# tests/test_base.py
from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Finding,
    Module,
    ScanResult,
    Severity,
    worst_severity,
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


def test_severity_from_str_pass():
    """Test Severity.from_str for pass."""
    assert Severity.from_str("pass") == Severity.PASS


def test_severity_from_str_info():
    """Test Severity.from_str for info."""
    assert Severity.from_str("info") == Severity.INFO


def test_severity_from_str_warn():
    """Test Severity.from_str for warn."""
    assert Severity.from_str("warn") == Severity.WARN


def test_severity_from_str_fail():
    """Test Severity.from_str for fail."""
    assert Severity.from_str("fail") == Severity.FAIL


def test_severity_str_conversion():
    """Test str(Severity) returns lowercase name."""
    assert str(Severity.PASS) == "pass"
    assert str(Severity.INFO) == "info"
    assert str(Severity.WARN) == "warn"
    assert str(Severity.FAIL) == "fail"


def test_worst_severity_empty_list():
    """Test worst_severity returns 'pass' for empty list."""
    result = worst_severity([])
    assert result == "pass"


def test_worst_severity_single_finding():
    """Test worst_severity with a single finding."""
    findings = [Finding(severity="warn", title="Test", detail="Detail")]
    result = worst_severity(findings)
    assert result == "warn"


def test_worst_severity_mixed_findings():
    """Test worst_severity returns the worst severity from mixed findings."""
    findings = [
        Finding(severity="pass", title="Good", detail="All good"),
        Finding(severity="info", title="Info", detail="FYI"),
        Finding(severity="warn", title="Warning", detail="Be careful"),
        Finding(severity="info", title="Info2", detail="Another FYI"),
    ]
    result = worst_severity(findings)
    assert result == "warn"


def test_worst_severity_with_fail():
    """Test worst_severity returns 'fail' when any finding is fail."""
    findings = [
        Finding(severity="pass", title="Good", detail="All good"),
        Finding(severity="warn", title="Warning", detail="Be careful"),
        Finding(severity="fail", title="Critical", detail="Very bad"),
        Finding(severity="info", title="Info", detail="FYI"),
    ]
    result = worst_severity(findings)
    assert result == "fail"
