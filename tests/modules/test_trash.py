# tests/modules/test_trash.py
"""Tests for trash cleanup module."""

from unittest.mock import patch

from macos_maid.modules.trash import TrashModule


def test_trash_module_metadata():
    """Test module metadata is correctly set."""
    module = TrashModule()
    assert module.name == "trash"
    assert module.category == "dev"
    assert module.requires_sudo is False


@patch("macos_maid.modules.trash.TrashModule._get_trash_size")
def test_scan_with_items(mock_get_size):
    """Test scan returns size info when trash has items."""
    mock_get_size.return_value = 1024 * 1024 * 100  # 100 MB

    module = TrashModule()
    result = module.scan()

    assert len(result.items) == 1
    assert "100.0 MB" in result.items[0]
    assert result.bytes_reclaimable == 1024 * 1024 * 100
    assert result.requires_sudo is False


@patch("macos_maid.modules.trash.TrashModule._get_trash_size")
def test_scan_empty_trash(mock_get_size):
    """Test scan returns empty result when trash is empty."""
    mock_get_size.return_value = 0

    module = TrashModule()
    result = module.scan()

    assert len(result.items) == 1
    assert "empty" in result.items[0].lower()
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


@patch("macos_maid.modules.trash.TrashModule._empty_trash")
@patch("macos_maid.modules.trash.TrashModule._get_trash_size")
def test_clean_success(mock_get_size, mock_empty):
    """Test clean empties trash successfully."""
    mock_get_size.return_value = 1024 * 1024 * 50  # 50 MB
    mock_empty.return_value = None  # No error

    module = TrashModule()
    result = module.clean()

    assert len(result.items_cleaned) == 1
    assert "50.0 MB" in result.items_cleaned[0]
    assert result.bytes_reclaimed == 1024 * 1024 * 50
    assert len(result.errors) == 0
    mock_empty.assert_called_once()


@patch("macos_maid.modules.trash.TrashModule._empty_trash")
@patch("macos_maid.modules.trash.TrashModule._get_trash_size")
def test_clean_error(mock_get_size, mock_empty):
    """Test clean handles errors gracefully."""
    mock_get_size.return_value = 1024 * 1024 * 50  # 50 MB
    mock_empty.side_effect = Exception("Permission denied")

    module = TrashModule()
    result = module.clean()

    assert len(result.items_cleaned) == 0
    assert result.bytes_reclaimed == 0
    assert len(result.errors) == 1
    assert "Permission denied" in result.errors[0]


def test_audit_empty():
    """Test audit returns empty result (no security checks)."""
    module = TrashModule()
    result = module.audit()

    assert result.status == "pass"
    assert len(result.findings) == 0
