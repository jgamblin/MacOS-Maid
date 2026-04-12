# tests/modules/test_docker.py
from unittest.mock import MagicMock, patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult
from macos_maid.modules.docker import DockerModule


@pytest.fixture
def docker_module():
    """Create a DockerModule instance for testing."""
    return DockerModule()


def test_docker_module_metadata(docker_module):
    """Test module metadata is set correctly."""
    assert docker_module.name == "docker"
    assert docker_module.category == "dev"
    assert docker_module.requires_sudo is False


def test_scan_docker_not_running(docker_module):
    """Test scan returns empty result when Docker is not running."""
    with patch.object(docker_module, "_is_docker_running", return_value=False):
        result = docker_module.scan()

        assert isinstance(result, ScanResult)
        assert result.items == []
        assert result.bytes_reclaimable == 0
        assert result.requires_sudo is False


def test_scan_docker_running(docker_module):
    """Test scan reports dangling images and unused volumes."""
    with (
        patch.object(docker_module, "_is_docker_running", return_value=True),
        patch.object(docker_module, "_get_dangling_images", return_value=["img1", "img2", "img3"]),
        patch.object(docker_module, "_get_unused_volumes", return_value=["vol1", "vol2"]),
    ):
        result = docker_module.scan()

        assert isinstance(result, ScanResult)
        assert len(result.items) == 2
        assert "3 dangling images" in result.items[0]
        assert "2 unused volumes" in result.items[1]
        assert result.bytes_reclaimable == 0  # Size estimation not implemented
        assert result.requires_sudo is False


def test_clean_docker_running(docker_module):
    """Test clean prunes images and volumes."""
    mock_image_output = (
        "Deleted Images:\nsha256:abc123\nsha256:def456\n\nTotal reclaimed space: 1.5GB"
    )
    mock_volume_output = "Deleted Volumes:\nvol1\nvol2\n\nTotal reclaimed space: 500MB"

    with (
        patch.object(docker_module, "_is_docker_running", return_value=True),
        patch.object(
            docker_module, "_run_docker", side_effect=[mock_image_output, mock_volume_output]
        ),
    ):
        result = docker_module.clean()

        assert isinstance(result, CleanResult)
        assert len(result.items_cleaned) == 2
        assert "Pruned dangling images" in result.items_cleaned[0]
        assert "Pruned unused volumes" in result.items_cleaned[1]
        assert result.bytes_reclaimed == 0  # Size calculation not implemented
        assert result.errors == []


def test_audit_returns_empty(docker_module):
    """Test audit returns empty result (no security checks)."""
    result = docker_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []
