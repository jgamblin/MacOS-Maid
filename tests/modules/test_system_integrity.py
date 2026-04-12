# tests/modules/test_system_integrity.py
"""Tests for system integrity audit module."""

from unittest.mock import patch

import pytest

from macos_maid.modules.system_integrity import SystemIntegrityModule


def test_system_integrity_module_metadata():
    """Test module metadata is correctly set."""
    module = SystemIntegrityModule()
    assert module.name == "system_integrity"
    assert module.category == "security"
    assert module.requires_sudo is False


def test_scan_returns_empty():
    """Test scan returns empty result (audit-only module)."""
    module = SystemIntegrityModule()
    result = module.scan()

    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_returns_empty():
    """Test clean returns empty result (audit-only module)."""
    module = SystemIntegrityModule()
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0


@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_sip")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_filevault")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_gatekeeper")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_xprotect")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_firewall")
def test_audit_all_pass(mock_firewall, mock_xprotect, mock_gatekeeper, mock_filevault, mock_sip):
    """Test audit when all checks pass."""
    from macos_maid.modules.base import Finding

    mock_sip.return_value = Finding(
        severity="pass",
        title="System Integrity Protection",
        detail="SIP is enabled",
        remediation=None,
    )
    mock_filevault.return_value = Finding(
        severity="pass",
        title="FileVault Encryption",
        detail="FileVault is on",
        remediation=None,
    )
    mock_gatekeeper.return_value = Finding(
        severity="pass",
        title="Gatekeeper",
        detail="Gatekeeper is enabled",
        remediation=None,
    )
    mock_xprotect.return_value = Finding(
        severity="pass",
        title="XProtect",
        detail="XProtect is installed",
        remediation=None,
    )
    mock_firewall.return_value = Finding(
        severity="pass",
        title="Firewall",
        detail="Firewall is enabled",
        remediation=None,
    )

    module = SystemIntegrityModule()
    result = module.audit()

    assert result.status == "pass"
    assert len(result.findings) == 5
    assert all(f.severity == "pass" for f in result.findings)


@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_sip")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_filevault")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_gatekeeper")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_xprotect")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_firewall")
def test_audit_mixed_results(
    mock_firewall, mock_xprotect, mock_gatekeeper, mock_filevault, mock_sip
):
    """Test audit with mixed pass/warn/fail results."""
    from macos_maid.modules.base import Finding

    mock_sip.return_value = Finding(
        severity="fail",
        title="System Integrity Protection",
        detail="SIP is disabled",
        remediation="Enable SIP by booting into Recovery Mode and running 'csrutil enable'",
    )
    mock_filevault.return_value = Finding(
        severity="pass",
        title="FileVault Encryption",
        detail="FileVault is on",
        remediation=None,
    )
    mock_gatekeeper.return_value = Finding(
        severity="warn",
        title="Gatekeeper",
        detail="Gatekeeper is partially enabled",
        remediation="Enable Gatekeeper with 'sudo spctl --master-enable'",
    )
    mock_xprotect.return_value = Finding(
        severity="pass",
        title="XProtect",
        detail="XProtect is installed",
        remediation=None,
    )
    mock_firewall.return_value = Finding(
        severity="fail",
        title="Firewall",
        detail="Firewall is disabled",
        remediation="Enable firewall in System Preferences > Security & Privacy > Firewall",
    )

    module = SystemIntegrityModule()
    result = module.audit()

    # Worst severity is "fail" (2 fail, 1 warn, 2 pass)
    assert result.status == "fail"
    assert len(result.findings) == 5

    # Check that fail findings are present
    fail_findings = [f for f in result.findings if f.severity == "fail"]
    assert len(fail_findings) == 2

    # Check that remediation is provided for failed checks
    for finding in fail_findings:
        assert finding.remediation is not None


@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_sip")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_filevault")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_gatekeeper")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_xprotect")
@patch("macos_maid.modules.system_integrity.SystemIntegrityModule._check_firewall")
def test_audit_warn_status(mock_firewall, mock_xprotect, mock_gatekeeper, mock_filevault, mock_sip):
    """Test audit status is 'warn' when there are warnings but no failures."""
    from macos_maid.modules.base import Finding

    mock_sip.return_value = Finding(
        severity="pass", title="SIP", detail="SIP is enabled", remediation=None
    )
    mock_filevault.return_value = Finding(
        severity="pass", title="FileVault", detail="FileVault is on", remediation=None
    )
    mock_gatekeeper.return_value = Finding(
        severity="warn",
        title="Gatekeeper",
        detail="Gatekeeper is partially enabled",
        remediation="Enable Gatekeeper with 'sudo spctl --master-enable'",
    )
    mock_xprotect.return_value = Finding(
        severity="pass", title="XProtect", detail="XProtect is installed", remediation=None
    )
    mock_firewall.return_value = Finding(
        severity="pass", title="Firewall", detail="Firewall is enabled", remediation=None
    )

    module = SystemIntegrityModule()
    result = module.audit()

    # Worst severity is "warn" (1 warn, 4 pass)
    assert result.status == "warn"
    assert len(result.findings) == 5
