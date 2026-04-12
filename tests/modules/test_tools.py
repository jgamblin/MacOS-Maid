"""Tests for external security tools integration module."""

from unittest.mock import patch

from macos_maid.modules.tools import ToolsModule


def test_tools_module_metadata():
    """Test module metadata is correctly set."""
    module = ToolsModule()
    assert module.name == "tools"
    assert module.category == "security"
    assert module.requires_sudo is False


def test_scan_returns_empty():
    """Test scan returns empty result (audit-only module)."""
    module = ToolsModule()
    result = module.scan()

    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_returns_empty():
    """Test clean returns empty result (audit-only module)."""
    module = ToolsModule()
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 0


@patch("shutil.which")
@patch("macos_maid.modules.tools.ToolsModule._run_lynis")
def test_audit_with_lynis_installed(mock_run_lynis, mock_which):
    """Test audit when lynis is installed and enabled."""
    from macos_maid.modules.base import Finding

    # Mock lynis being installed
    mock_which.side_effect = lambda cmd: "/usr/local/bin/lynis" if cmd == "lynis" else None

    # Mock lynis findings
    mock_run_lynis.return_value = [
        Finding(
            severity="warn",
            title="Lynis Hardening Index",
            detail="Hardening index: 65",
            remediation="Review Lynis suggestions to improve system hardening",
        ),
        Finding(
            severity="warn",
            title="Lynis Warning",
            detail="No password set for single user mode",
            remediation="Set a password for single user mode",
        ),
    ]

    module = ToolsModule(lynis_enabled=True, osquery_enabled=False, knockknock_enabled=False)
    result = module.audit()

    # Should have findings from lynis
    assert len(result.findings) >= 2
    assert result.status == "warn"

    # Verify lynis was called
    mock_run_lynis.assert_called_once()


@patch("shutil.which")
def test_audit_with_lynis_not_installed(mock_which):
    """Test audit when lynis is not installed."""
    # Mock lynis not being installed
    mock_which.return_value = None

    module = ToolsModule(lynis_enabled=True, osquery_enabled=False, knockknock_enabled=False)
    result = module.audit()

    # Should have info finding suggesting installation
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "lynis" in result.findings[0].title.lower()
    assert "brew install lynis" in result.findings[0].detail.lower()


@patch("shutil.which")
@patch("macos_maid.modules.tools.ToolsModule._run_osquery_check")
def test_audit_with_osquery_installed(mock_run_osquery, mock_which):
    """Test audit when osquery is installed and enabled."""
    from macos_maid.modules.base import Finding

    # Mock osquery being installed
    mock_which.side_effect = lambda cmd: "/usr/local/bin/osqueryi" if cmd == "osqueryi" else None

    # Mock osquery findings
    mock_run_osquery.return_value = [
        Finding(
            severity="warn",
            title="Unsigned Process Detected",
            detail="Process 'suspicious_app' is running without code signature",
            remediation="Investigate and remove suspicious unsigned processes",
        ),
    ]

    module = ToolsModule(lynis_enabled=False, osquery_enabled=True, knockknock_enabled=False)
    result = module.audit()

    # Should have findings from osquery
    assert len(result.findings) >= 1
    assert result.status == "warn"

    # Verify osquery was called
    mock_run_osquery.assert_called_once()


@patch("shutil.which")
def test_audit_with_osquery_not_installed(mock_which):
    """Test audit when osquery is not installed."""
    # Mock osquery not being installed
    mock_which.return_value = None

    module = ToolsModule(lynis_enabled=False, osquery_enabled=True, knockknock_enabled=False)
    result = module.audit()

    # Should have info finding suggesting installation
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "osquery" in result.findings[0].title.lower()
    assert "brew install osquery" in result.findings[0].detail.lower()


@patch("shutil.which")
@patch("macos_maid.modules.tools.ToolsModule._run_knockknock_check")
def test_audit_with_knockknock_installed(mock_run_knockknock, mock_which):
    """Test audit when knockknock is installed and enabled."""
    from macos_maid.modules.base import Finding

    # Mock knockknock being installed
    mock_which.side_effect = lambda cmd: (
        "/usr/local/bin/KnockKnock.app/Contents/MacOS/KnockKnock" if cmd == "knockknock" else None
    )

    # Mock knockknock findings
    mock_run_knockknock.return_value = [
        Finding(
            severity="info",
            title="KnockKnock Scan Complete",
            detail="Scanned persistent items",
            remediation=None,
        ),
    ]

    module = ToolsModule(lynis_enabled=False, osquery_enabled=False, knockknock_enabled=True)
    result = module.audit()

    # Should have findings from knockknock
    assert len(result.findings) >= 1

    # Verify knockknock was called
    mock_run_knockknock.assert_called_once()


@patch("shutil.which")
def test_audit_with_knockknock_not_installed(mock_which):
    """Test audit when knockknock is not installed."""
    # Mock knockknock not being installed
    mock_which.return_value = None

    module = ToolsModule(lynis_enabled=False, osquery_enabled=False, knockknock_enabled=True)
    result = module.audit()

    # Should have info finding suggesting installation
    assert len(result.findings) == 1
    assert result.findings[0].severity == "info"
    assert "knockknock" in result.findings[0].title.lower()


@patch("shutil.which")
def test_audit_all_tools_disabled(mock_which):
    """Test audit when all tools are disabled."""
    module = ToolsModule(lynis_enabled=False, osquery_enabled=False, knockknock_enabled=False)
    result = module.audit()

    # Should return empty result
    assert result.status == "pass"
    assert len(result.findings) == 0


@patch("shutil.which")
@patch("macos_maid.modules.tools.ToolsModule._run_lynis")
@patch("macos_maid.modules.tools.ToolsModule._run_osquery_check")
def test_audit_multiple_tools(mock_run_osquery, mock_run_lynis, mock_which):
    """Test audit with multiple tools enabled and installed."""
    from macos_maid.modules.base import Finding

    # Mock both tools being installed
    def which_side_effect(cmd):
        if cmd == "lynis":
            return "/usr/local/bin/lynis"
        elif cmd == "osqueryi":
            return "/usr/local/bin/osqueryi"
        return None

    mock_which.side_effect = which_side_effect

    # Mock findings from both tools
    mock_run_lynis.return_value = [
        Finding(severity="pass", title="Lynis Check", detail="OK", remediation=None),
    ]
    mock_run_osquery.return_value = [
        Finding(severity="warn", title="Osquery Check", detail="Issue found", remediation="Fix it"),
    ]

    module = ToolsModule(lynis_enabled=True, osquery_enabled=True, knockknock_enabled=False)
    result = module.audit()

    # Should have findings from both tools
    assert len(result.findings) == 2
    assert result.status == "warn"  # Worst severity wins

    # Verify both tools were called
    mock_run_lynis.assert_called_once()
    mock_run_osquery.assert_called_once()


@patch("shutil.which")
@patch("macos_maid.modules.tools.ToolsModule._run_lynis")
def test_audit_handles_lynis_exception(mock_run_lynis, mock_which):
    """Test audit handles exceptions from lynis gracefully."""
    # Mock lynis being installed
    mock_which.return_value = "/usr/local/bin/lynis"

    # Mock lynis raising exception
    mock_run_lynis.side_effect = Exception("Lynis execution failed")

    module = ToolsModule(lynis_enabled=True, osquery_enabled=False, knockknock_enabled=False)
    result = module.audit()

    # Should have a warning finding about the error
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warn"
    assert "lynis" in result.findings[0].title.lower()
    assert "failed" in result.findings[0].detail.lower()
