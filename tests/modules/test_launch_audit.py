# tests/modules/test_launch_audit.py
from pathlib import Path
from unittest.mock import patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult, Severity
from macos_maid.modules.launch_audit import LaunchAuditModule


@pytest.fixture
def launch_audit_module():
    """Create a LaunchAuditModule instance for testing."""
    return LaunchAuditModule()


def test_launch_audit_module_metadata(launch_audit_module):
    """Test module metadata is set correctly."""
    assert launch_audit_module.name == "launch_audit"
    assert launch_audit_module.category == "security"
    assert launch_audit_module.requires_sudo is False


def test_is_apple_daemon():
    """Test _is_apple_daemon correctly identifies Apple daemons."""
    module = LaunchAuditModule()

    # Apple daemons
    assert module._is_apple_daemon("com.apple.loginwindow") is True
    assert module._is_apple_daemon("com.apple.xpc.launchd") is True
    assert module._is_apple_daemon("com.apple.securityd") is True

    # Non-Apple daemons
    assert module._is_apple_daemon("com.google.keystone") is False
    assert module._is_apple_daemon("org.virtualbox.startup") is False
    assert module._is_apple_daemon("homebrew.mxcl.nginx") is False


def test_launch_audit_scan_returns_empty(launch_audit_module):
    """Test scan returns empty result (audit-only module)."""
    result = launch_audit_module.scan()

    assert isinstance(result, ScanResult)
    assert result.items == []
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_launch_audit_clean_returns_empty(launch_audit_module):
    """Test clean returns empty result (audit-only module)."""
    result = launch_audit_module.clean()

    assert isinstance(result, CleanResult)
    assert result.items_cleaned == []
    assert result.bytes_reclaimed == 0
    assert result.errors == []


def test_launch_audit_with_no_non_apple_items(launch_audit_module):
    """Test audit reports pass when only Apple items are found."""
    mock_items = [
        {
            "label": "com.apple.loginwindow",
            "path": "/Library/LaunchAgents/com.apple.loginwindow.plist",
        },
        {
            "label": "com.apple.xpc.launchd",
            "path": "/Library/LaunchDaemons/com.apple.xpc.launchd.plist",
        },
    ]

    with patch.object(launch_audit_module, "_list_launch_items", return_value=mock_items):
        result = launch_audit_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status == "pass"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.PASS
        assert "no non-apple" in result.findings[0].detail.lower()


def test_launch_audit_with_non_apple_items(launch_audit_module):
    """Test audit reports info findings for non-Apple items."""
    mock_items = [
        {
            "label": "com.apple.loginwindow",
            "path": "/Library/LaunchAgents/com.apple.loginwindow.plist",
        },
        {"label": "com.google.keystone", "path": "/Library/LaunchAgents/com.google.keystone.plist"},
        {
            "label": "org.virtualbox.startup",
            "path": "/Library/LaunchDaemons/org.virtualbox.startup.plist",
        },
    ]

    with patch.object(launch_audit_module, "_list_launch_items", return_value=mock_items):
        result = launch_audit_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status == "info"
        # Should have findings for the 2 non-Apple items
        non_apple_findings = [f for f in result.findings if f.severity == Severity.INFO]
        assert len(non_apple_findings) == 2

        # Check that non-Apple items are in findings
        labels = [f.detail for f in non_apple_findings]
        assert any("com.google.keystone" in label for label in labels)
        assert any("org.virtualbox.startup" in label for label in labels)


def test_launch_audit_with_all_non_apple_items(launch_audit_module):
    """Test audit with only non-Apple items."""
    mock_items = [
        {"label": "com.docker.helper", "path": "/Library/LaunchDaemons/com.docker.helper.plist"},
        {
            "label": "homebrew.mxcl.nginx",
            "path": Path.home() / "Library/LaunchAgents/homebrew.mxcl.nginx.plist",
        },
    ]

    with patch.object(launch_audit_module, "_list_launch_items", return_value=mock_items):
        result = launch_audit_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status == "info"
        # Should have findings for both items
        non_apple_findings = [f for f in result.findings if f.severity == Severity.INFO]
        assert len(non_apple_findings) == 2


def test_launch_audit_with_no_items(launch_audit_module):
    """Test audit reports pass when no launch items are found."""
    with patch.object(launch_audit_module, "_list_launch_items", return_value=[]):
        result = launch_audit_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status == "pass"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.PASS
