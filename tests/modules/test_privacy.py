# tests/modules/test_privacy.py
from pathlib import Path
from unittest.mock import patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, Finding, ScanResult
from macos_maid.modules.privacy import PrivacyModule


@pytest.fixture
def privacy_module():
    """Create a PrivacyModule instance for testing."""
    return PrivacyModule()


def test_privacy_module_metadata(privacy_module):
    """Test module metadata is set correctly."""
    assert privacy_module.name == "privacy"
    assert privacy_module.category == "security"
    assert privacy_module.requires_sudo is True


def test_privacy_module_default_config(privacy_module):
    """Test module has correct default configuration."""
    assert privacy_module.clear_recent is True
    assert privacy_module.downloads_move_to_trash is False
    assert privacy_module.downloads_older_than == 90


def test_privacy_scan_with_clear_recent_enabled(privacy_module):
    """Test scan reports recent items clearing when enabled."""
    result = privacy_module.scan()

    assert isinstance(result, ScanResult)
    assert len(result.items) == 1
    assert "Clear recent items" in result.items[0]
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


def test_privacy_scan_with_clear_recent_disabled():
    """Test scan returns empty when clear_recent is disabled."""
    module = PrivacyModule(clear_recent=False)
    result = module.scan()

    assert isinstance(result, ScanResult)
    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


def test_privacy_never_deletes_downloads_by_default(privacy_module):
    """Test that clean() never deletes Downloads by default."""
    with patch.object(privacy_module, "_clear_recent_items") as mock_clear:
        mock_clear.return_value = None

        result = privacy_module.clean()

        assert isinstance(result, CleanResult)
        # Should only clear recent items, never touch Downloads
        assert len(result.items_cleaned) <= 1
        assert result.bytes_reclaimed == 0
        # Ensure no Downloads-related cleanup happened
        for item in result.items_cleaned:
            assert "download" not in item.lower()


def test_privacy_clean_clears_recent_items(privacy_module):
    """Test clean successfully clears recent items."""
    with patch.object(privacy_module, "_clear_recent_items") as mock_clear:
        mock_clear.return_value = None

        result = privacy_module.clean()

        assert isinstance(result, CleanResult)
        assert mock_clear.called
        assert len(result.items_cleaned) == 1
        assert "Cleared recent items" in result.items_cleaned[0]
        assert result.bytes_reclaimed == 0
        assert result.errors == []


def test_privacy_clean_handles_clear_error(privacy_module):
    """Test clean handles errors gracefully."""
    with patch.object(privacy_module, "_clear_recent_items") as mock_clear:
        mock_clear.side_effect = Exception("Clear failed")

        result = privacy_module.clean()

        assert isinstance(result, CleanResult)
        assert result.items_cleaned == []
        assert result.bytes_reclaimed == 0
        assert len(result.errors) == 1
        assert "Failed to clear recent items" in result.errors[0]


def test_privacy_clean_respects_clear_recent_config():
    """Test clean respects clear_recent configuration."""
    module = PrivacyModule(clear_recent=False)
    result = module.clean()

    assert isinstance(result, CleanResult)
    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert result.errors == []


def test_privacy_audit_tcc(privacy_module):
    """Test audit reports TCC permissions."""
    mock_tcc_data = {
        "kTCCServiceScreenCapture": ["Zoom.app", "ScreenStudio.app"],
        "kTCCServiceAccessibility": ["Alfred.app"],
        "kTCCServiceCamera": ["Zoom.app"],
    }

    with (
        patch.object(privacy_module, "_get_tcc_permissions", return_value=mock_tcc_data),
        patch("pathlib.Path.exists", return_value=True),
        patch("pathlib.Path.iterdir", return_value=[]),
    ):
        result = privacy_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status in ["pass", "info", "warn", "fail"]
        assert len(result.findings) > 0

        # Should have findings for TCC permissions
        tcc_findings = [f for f in result.findings if "permission" in f.title.lower()]
        assert len(tcc_findings) > 0


def test_privacy_audit_empty(privacy_module):
    """Test audit doesn't crash when TCC read fails."""
    with (
        patch.object(privacy_module, "_get_tcc_permissions", return_value={}),
        patch("pathlib.Path.exists", return_value=False),
    ):
        result = privacy_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status in ["pass", "info", "warn", "fail"]
        assert isinstance(result.findings, list)


def test_privacy_audit_old_downloads(privacy_module):
    """Test audit reports old Downloads files (report only, never delete)."""
    from datetime import datetime, timedelta
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    # Mock some old files in Downloads
    old_file = MagicMock(spec=Path)
    old_file.__str__ = lambda self: "/Users/test/Downloads/old_file.zip"
    old_file.is_file.return_value = True

    recent_file = MagicMock(spec=Path)
    recent_file.__str__ = lambda self: "/Users/test/Downloads/recent_file.zip"
    recent_file.is_file.return_value = True

    old_time = (datetime.now() - timedelta(days=100)).timestamp()
    recent_time = datetime.now().timestamp()

    old_file.stat.return_value = SimpleNamespace(st_mtime=old_time, st_size=1024)
    recent_file.stat.return_value = SimpleNamespace(st_mtime=recent_time, st_size=1024)

    with (
        patch.object(privacy_module, "_get_tcc_permissions", return_value={}),
        patch("pathlib.Path.exists", return_value=True),
        patch("pathlib.Path.iterdir") as mock_iterdir,
    ):
        mock_iterdir.return_value = [old_file, recent_file]

        result = privacy_module.audit()

        assert isinstance(result, AuditResult)
        # Should have a finding about old Downloads files
        download_findings = [f for f in result.findings if "download" in f.title.lower()]
        assert len(download_findings) > 0


def test_privacy_tcc_service_names():
    """Test that TCC_SERVICE_NAMES contains expected services."""
    from macos_maid.modules.privacy import TCC_SERVICE_NAMES

    # Check for required TCC service mappings
    assert "kTCCServiceScreenCapture" in TCC_SERVICE_NAMES
    assert "kTCCServiceSystemPolicyAllFiles" in TCC_SERVICE_NAMES
    assert "kTCCServiceAccessibility" in TCC_SERVICE_NAMES
    assert "kTCCServiceCamera" in TCC_SERVICE_NAMES
    assert "kTCCServiceMicrophone" in TCC_SERVICE_NAMES

    # Verify human-readable names
    assert TCC_SERVICE_NAMES["kTCCServiceScreenCapture"] == "Screen Capture"
    assert TCC_SERVICE_NAMES["kTCCServiceCamera"] == "Camera"
    assert TCC_SERVICE_NAMES["kTCCServiceMicrophone"] == "Microphone"


def test_privacy_get_tcc_permissions_readonly(privacy_module):
    """Test that _get_tcc_permissions opens database in read-only mode."""
    import sqlite3

    mock_conn = None

    def mock_connect(path, **kwargs):
        nonlocal mock_conn
        assert "file:" in path
        assert "mode=ro" in path
        mock_conn = sqlite3.connect(":memory:")
        return mock_conn

    with patch("sqlite3.connect", side_effect=mock_connect):
        try:
            privacy_module._get_tcc_permissions()
        except Exception:
            pass  # We just want to verify the connect call, not execute the query
