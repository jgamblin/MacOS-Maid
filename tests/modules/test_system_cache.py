# tests/modules/test_system_cache.py
"""Tests for system cache cleanup module."""

from unittest.mock import MagicMock, patch

from macos_maid.modules.system_cache import SystemCacheModule


def test_system_cache_module_metadata():
    """Test module metadata is correctly set."""
    module = SystemCacheModule()
    assert module.name == "system_cache"
    assert module.category == "both"
    assert module.requires_sudo is True


def test_safe_dirs_never_include_var_folders():
    """Test that NONE of the cache/log dirs contain /private/var/folders."""
    module = SystemCacheModule()

    # Check SAFE_CACHE_DIRS
    for cache_dir in module.SAFE_CACHE_DIRS:
        assert "/private/var/folders" not in str(cache_dir), (
            f"DANGEROUS: {cache_dir} contains /private/var/folders"
        )
        assert "var/folders" not in str(cache_dir), f"DANGEROUS: {cache_dir} contains var/folders"

    # Check SAFE_LOG_DIRS
    for log_dir in module.SAFE_LOG_DIRS:
        assert "/private/var/folders" not in str(log_dir), (
            f"DANGEROUS: {log_dir} contains /private/var/folders"
        )
        assert "var/folders" not in str(log_dir), f"DANGEROUS: {log_dir} contains var/folders"


@patch("macos_maid.modules.system_cache.SystemCacheModule._dir_size")
def test_scan_with_existing_dirs(mock_dir_size):
    """Test scan reports sizes of cache and log dirs that exist."""

    # Mock dir_size to return different sizes based on exact path
    def size_side_effect(path):
        path_str = str(path)
        if path_str.endswith("Library/Caches"):
            return 1024 * 1024 * 500  # 500 MB
        elif path_str == "/Library/Logs/DiagnosticReports":
            return 1024 * 1024 * 10  # 10 MB
        elif (
            "Library/Logs/DiagnosticReports" in path_str
            and "Library/Logs/DiagnosticReports" in path_str
        ):
            return 1024 * 1024 * 10  # 10 MB for user diagnostic reports too
        return 0

    mock_dir_size.side_effect = size_side_effect

    module = SystemCacheModule()

    # Mock exists() to return True for all paths
    with patch("pathlib.Path.exists", return_value=True):
        result = module.scan()

    # Should have items for cache and log dirs
    assert len(result.items) == 3  # Cache + 2 log dirs
    # 500 MB + 10 MB + 10 MB = 520 MB
    assert result.bytes_reclaimable == 1024 * 1024 * 520
    assert result.requires_sudo is True

    # Check that sizes are formatted in items
    items_str = " ".join(result.items)
    assert "500.0 MB" in items_str or "Caches" in items_str


@patch("macos_maid.modules.system_cache.SystemCacheModule._dir_size")
def test_scan_with_nonexistent_dirs(mock_dir_size):
    """Test scan skips nonexistent directories."""
    mock_dir_size.return_value = 0

    module = SystemCacheModule()

    # Mock exists() to return False for all paths
    with patch("pathlib.Path.exists", return_value=False):
        result = module.scan()

    # Should have no items if dirs don't exist
    assert len(result.items) == 0
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


@patch("subprocess.run")
@patch("macos_maid.modules.system_cache.SystemCacheModule._dir_size")
def test_clean_success(mock_dir_size, mock_run):
    """Test clean removes cache contents and log files."""
    # Return different sizes: before and after for each directory
    size_values = [
        1024 * 1024 * 100,  # Cache dir before
        0,  # Cache dir after
        1024 * 1024 * 10,  # First log dir before
        0,  # First log dir after
        1024 * 1024 * 5,  # Second log dir before
        0,  # Second log dir after
    ]
    mock_dir_size.side_effect = size_values

    # Mock successful subprocess calls
    mock_run.return_value = MagicMock(returncode=0)

    module = SystemCacheModule()

    with patch("pathlib.Path.exists", return_value=True):
        with patch("pathlib.Path.iterdir") as mock_iterdir:
            # Mock cache/log directory contents
            mock_file = MagicMock()
            mock_file.name = "some-file"
            mock_file.is_file.return_value = True
            mock_file.is_dir.return_value = False
            mock_iterdir.return_value = [mock_file]

            result = module.clean()

    assert len(result.items_cleaned) > 0
    assert result.bytes_reclaimed > 0
    assert len(result.errors) == 0


@patch("macos_maid.modules.system_cache.SystemCacheModule._dir_size")
def test_clean_error_handling(mock_dir_size):
    """Test clean handles errors gracefully."""
    mock_dir_size.return_value = 1024 * 1024 * 100

    module = SystemCacheModule()

    with patch("pathlib.Path.exists", return_value=True):
        with patch("pathlib.Path.iterdir") as mock_iterdir:
            # Mock a file that raises an error when trying to delete
            mock_file = MagicMock()
            mock_file.name = "some-file"
            mock_file.is_file.return_value = True
            mock_file.unlink.side_effect = PermissionError("Permission denied")
            mock_iterdir.return_value = [mock_file]

            result = module.clean()

    # Should have errors but not crash
    assert len(result.errors) > 0
    assert "Permission denied" in str(result.errors) or "error" in str(result.errors).lower()


def test_audit_empty():
    """Test audit returns empty result (no security checks)."""
    module = SystemCacheModule()
    result = module.audit()

    assert result.status == "pass"
    assert len(result.findings) == 0
