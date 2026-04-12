# tests/modules/test_dev_caches.py
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult
from macos_maid.modules.dev_caches import DevCachesModule


@pytest.fixture
def dev_caches_module():
    """Create a DevCachesModule instance for testing."""
    return DevCachesModule()


def test_dev_caches_module_metadata(dev_caches_module):
    """Test module metadata is set correctly."""
    assert dev_caches_module.name == "dev_caches"
    assert dev_caches_module.category == "dev"
    assert dev_caches_module.requires_sudo is False


def test_cache_paths_are_safe(dev_caches_module):
    """Test that all cache paths are safe and under home directory."""
    home = Path.home()

    for cache_name, cache_path in dev_caches_module.CACHE_PATHS.items():
        # All paths must be under home directory
        assert cache_path.is_relative_to(home), f"{cache_name} path {cache_path} is not under home"

        # None should contain dangerous project directories
        path_str = str(cache_path)
        assert "node_modules" not in path_str, f"{cache_name} contains node_modules"
        assert ".venv" not in path_str, f"{cache_name} contains .venv"
        assert "/target/" not in path_str and not path_str.endswith("/target"), (
            f"{cache_name} contains target/"
        )
        assert "/build/" not in path_str and not path_str.endswith("/build"), (
            f"{cache_name} contains build/"
        )


def test_cache_paths_never_contain_registry_src(dev_caches_module):
    """Test that cargo cache points to registry/cache not registry/src."""
    cargo_path = dev_caches_module.CACHE_PATHS.get("cargo")
    assert cargo_path is not None

    path_str = str(cargo_path)
    assert "registry/cache" in path_str, "cargo should point to registry/cache"
    assert "registry/src" not in path_str, "cargo must NOT point to registry/src"


def test_scan_with_existing_caches(dev_caches_module):
    """Test scan reports existing caches with their sizes."""
    mock_cache_sizes = {
        "pip": (True, 1024 * 1024 * 500),  # 500 MB
        "npm": (True, 1024 * 1024 * 1024 * 2),  # 2 GB
        "cargo": (True, 1024 * 1024 * 300),  # 300 MB
        "gradle": (False, 0),  # doesn't exist
        "cocoapods": (True, 1024 * 1024 * 100),  # 100 MB
        "xcode_derived": (False, 0),  # doesn't exist
    }

    def mock_dir_size(path):
        for cache_name, cache_path in dev_caches_module.CACHE_PATHS.items():
            if path == cache_path:
                exists, size = mock_cache_sizes[cache_name]
                return size if exists else 0
        return 0

    with patch.object(dev_caches_module, "_dir_size", side_effect=mock_dir_size):
        result = dev_caches_module.scan()

    assert isinstance(result, ScanResult)
    assert len(result.items) == 4  # Only the 4 that exist
    assert result.bytes_reclaimable == 1024 * 1024 * (500 + 2048 + 300 + 100)
    assert result.requires_sudo is False

    # Check that items contain the cache names and sizes
    items_str = " ".join(result.items)
    assert "pip" in items_str
    assert "npm" in items_str
    assert "cargo" in items_str
    assert "cocoapods" in items_str
    assert "gradle" not in items_str
    assert "xcode_derived" not in items_str


def test_scan_with_no_caches(dev_caches_module):
    """Test scan returns empty result when no caches exist."""
    with patch.object(dev_caches_module, "_dir_size", return_value=0):
        result = dev_caches_module.scan()

    assert isinstance(result, ScanResult)
    assert result.items == []
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_clean_removes_and_recreates_caches(dev_caches_module):
    """Test clean removes and recreates existing cache directories."""
    mock_cache_exists = {
        "pip": True,
        "npm": True,
        "cargo": False,
        "gradle": False,
        "cocoapods": True,
        "xcode_derived": False,
    }

    mock_cache_sizes = {
        "pip": 1024 * 1024 * 500,  # 500 MB
        "npm": 1024 * 1024 * 1024 * 2,  # 2 GB
        "cocoapods": 1024 * 1024 * 100,  # 100 MB
    }

    def mock_dir_size(path):
        for cache_name, cache_path in dev_caches_module.CACHE_PATHS.items():
            if path == cache_path and mock_cache_exists[cache_name]:
                return mock_cache_sizes.get(cache_name, 0)
        return 0

    mock_paths_to_check = []

    with (
        patch.object(dev_caches_module, "_dir_size", side_effect=mock_dir_size),
        patch("macos_maid.modules.dev_caches.Path.exists") as mock_exists,
        patch("macos_maid.modules.dev_caches.shutil.rmtree") as mock_rmtree,
        patch("macos_maid.modules.dev_caches.Path.mkdir") as mock_mkdir,
    ):
        # Mock exists to return True for pip, npm, cocoapods
        mock_exists.side_effect = lambda: (
            mock_cache_exists[
                next(
                    k
                    for k, v in dev_caches_module.CACHE_PATHS.items()
                    if v == mock_paths_to_check[-1]
                )
            ]
            if mock_paths_to_check
            else False
        )

        # Simpler approach: just mock the behavior
        def exists_impl(path_obj):
            for cache_name, cache_path in dev_caches_module.CACHE_PATHS.items():
                if str(path_obj) == str(cache_path):
                    return mock_cache_exists[cache_name]
            return False

        # Need to patch Path.exists as a method
        with patch("macos_maid.modules.dev_caches.Path.exists", exists_impl):
            result = dev_caches_module.clean()

    assert isinstance(result, CleanResult)
    assert len(result.items_cleaned) == 3  # pip, npm, cocoapods
    assert result.bytes_reclaimed == 1024 * 1024 * (500 + 2048 + 100)
    assert result.errors == []

    # Verify rmtree was called 3 times (for existing caches)
    assert mock_rmtree.call_count == 3

    # Verify mkdir was called 3 times (to recreate)
    assert mock_mkdir.call_count == 3


def test_clean_handles_errors_gracefully(dev_caches_module):
    """Test clean handles errors and continues with other caches."""

    def mock_dir_size(path):
        # All caches exist with some size
        return 1024 * 1024 * 100

    def mock_exists(path_obj):
        return True

    def mock_rmtree(path):
        # Simulate error on npm cache
        if "npm" in str(path):
            raise OSError("Permission denied")

    with (
        patch.object(dev_caches_module, "_dir_size", side_effect=mock_dir_size),
        patch("macos_maid.modules.dev_caches.Path.exists", mock_exists),
        patch("macos_maid.modules.dev_caches.shutil.rmtree", side_effect=mock_rmtree),
        patch("macos_maid.modules.dev_caches.Path.mkdir"),
    ):
        result = dev_caches_module.clean()

    assert isinstance(result, CleanResult)
    # Should clean all except npm (5 errors out of 6)
    assert len(result.items_cleaned) < 6
    assert len(result.errors) >= 1
    assert any("npm" in error for error in result.errors)


def test_audit_returns_empty(dev_caches_module):
    """Test audit returns empty result (no security checks)."""
    result = dev_caches_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []


def test_dir_size_with_existing_directory(dev_caches_module):
    """Test _dir_size returns correct size for existing directory."""
    test_path = Path("/fake/path")

    with patch("macos_maid.modules.dev_caches.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="1024\t/fake/path\n")

        size = dev_caches_module._dir_size(test_path)

        assert size == 1024 * 1024  # du -sk returns KB, we convert to bytes
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "du"
        assert "-sk" in args
        assert str(test_path) in args


def test_dir_size_with_nonexistent_directory(dev_caches_module):
    """Test _dir_size returns 0 for nonexistent directory."""
    test_path = Path("/fake/nonexistent")

    with patch("macos_maid.modules.dev_caches.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        size = dev_caches_module._dir_size(test_path)

        assert size == 0


def test_dir_size_with_invalid_output(dev_caches_module):
    """Test _dir_size returns 0 for invalid du output."""
    test_path = Path("/fake/path")

    with patch("macos_maid.modules.dev_caches.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="invalid output")

        size = dev_caches_module._dir_size(test_path)

        assert size == 0
