# tests/modules/test_app_audit.py
"""Tests for app audit module."""

from unittest.mock import patch

from macos_maid.modules.app_audit import AppAuditModule
from macos_maid.modules.base import Severity


def test_app_audit_module_metadata():
    """Test module metadata is correctly set."""
    module = AppAuditModule()
    assert module.name == "app_audit"
    assert module.category == "security"
    assert module.requires_sudo is False


def test_scan_returns_empty():
    """Test scan returns empty result (audit-only module)."""
    module = AppAuditModule()
    result = module.scan()

    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_returns_empty():
    """Test clean returns empty result (audit-only module)."""
    module = AppAuditModule()
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0


def test_classify_signed_app():
    """Test classification of signed applications."""
    module = AppAuditModule()

    # Signed app should be "ok"
    result = module._classify_app(signed=True, from_app_store=False, has_elevated_perms=False)
    assert result == "ok"

    # App Store app should be "ok"
    result = module._classify_app(signed=False, from_app_store=True, has_elevated_perms=False)
    assert result == "ok"

    # Both signed and from App Store should be "ok"
    result = module._classify_app(signed=True, from_app_store=True, has_elevated_perms=False)
    assert result == "ok"


def test_classify_unsigned_sandboxed():
    """Test classification of unsigned sandboxed applications."""
    module = AppAuditModule()

    # Unsigned, not from App Store, no elevated perms = "info"
    result = module._classify_app(signed=False, from_app_store=False, has_elevated_perms=False)
    assert result == "info"


def test_classify_unsigned_privileged():
    """Test classification of unsigned applications with elevated permissions."""
    module = AppAuditModule()

    # Unsigned with elevated permissions = "warn"
    result = module._classify_app(signed=False, from_app_store=False, has_elevated_perms=True)
    assert result == "warn"


@patch("macos_maid.modules.app_audit.AppAuditModule._get_applications")
def test_audit_no_apps(mock_get_apps):
    """Test audit when no applications are found."""
    mock_get_apps.return_value = []

    module = AppAuditModule()
    result = module.audit()

    assert result.status == "pass"
    assert len(result.findings) == 0


@patch("macos_maid.modules.app_audit.AppAuditModule._get_applications")
def test_audit_all_signed_apps(mock_get_apps):
    """Test audit when all applications are signed."""
    mock_get_apps.return_value = [
        {
            "path": "/Applications/Safari.app",
            "signed": True,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
        {
            "path": "/Applications/TextEdit.app",
            "signed": True,
            "from_app_store": True,
            "has_elevated_perms": False,
        },
    ]

    module = AppAuditModule()
    result = module.audit()

    assert result.status == "pass"
    # Should have one summary finding
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.PASS
    assert "2 applications" in result.findings[0].detail.lower()


@patch("macos_maid.modules.app_audit.AppAuditModule._get_applications")
def test_audit_unsigned_sandboxed_apps(mock_get_apps):
    """Test audit with unsigned sandboxed applications."""
    mock_get_apps.return_value = [
        {
            "path": "/Applications/SafeApp.app",
            "signed": True,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
        {
            "path": "/Applications/UnsignedSandboxed.app",
            "signed": False,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
    ]

    module = AppAuditModule()
    result = module.audit()

    # Should be "info" status (no warnings or failures)
    assert result.status == "info"

    # Should have findings for unsigned apps
    unsigned_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(unsigned_findings) >= 1

    # Check that the unsigned app is mentioned
    assert any("UnsignedSandboxed.app" in f.detail for f in result.findings)


@patch("macos_maid.modules.app_audit.AppAuditModule._get_applications")
def test_audit_unsigned_privileged_apps(mock_get_apps):
    """Test audit with unsigned applications that have elevated permissions."""
    mock_get_apps.return_value = [
        {
            "path": "/Applications/SafeApp.app",
            "signed": True,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
        {
            "path": "/Applications/DangerousApp.app",
            "signed": False,
            "from_app_store": False,
            "has_elevated_perms": True,
        },
    ]

    module = AppAuditModule()
    result = module.audit()

    # Should be "warn" status (has warnings)
    assert result.status == "warn"

    # Should have findings for unsigned privileged apps
    warn_findings = [f for f in result.findings if f.severity == Severity.WARN]
    assert len(warn_findings) >= 1

    # Check that the dangerous app is mentioned
    assert any("DangerousApp.app" in f.detail for f in result.findings)

    # Check that remediation is provided
    for finding in warn_findings:
        assert finding.remediation is not None


@patch("macos_maid.modules.app_audit.AppAuditModule._get_applications")
def test_audit_mixed_apps(mock_get_apps):
    """Test audit with mix of signed, unsigned sandboxed, and unsigned privileged apps."""
    mock_get_apps.return_value = [
        {
            "path": "/Applications/SignedApp.app",
            "signed": True,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
        {
            "path": "/Applications/UnsignedSandboxed.app",
            "signed": False,
            "from_app_store": False,
            "has_elevated_perms": False,
        },
        {
            "path": "/Applications/UnsignedPrivileged.app",
            "signed": False,
            "from_app_store": False,
            "has_elevated_perms": True,
        },
    ]

    module = AppAuditModule()
    result = module.audit()

    # Worst severity is "warn" (has privileged unsigned app)
    assert result.status == "warn"

    # Should have multiple findings
    assert len(result.findings) >= 2

    # Should have at least one warning
    warn_findings = [f for f in result.findings if f.severity == Severity.WARN]
    assert len(warn_findings) >= 1

    # Should have at least one info
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 1
