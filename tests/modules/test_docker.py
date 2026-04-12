# tests/modules/test_docker.py
from unittest.mock import patch

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
        # Verify space calculation: 1.5GB + 500MB = 1.5 * 1024^3 + 500 * 1024^2
        expected_bytes = int(1.5 * 1024**3) + int(500 * 1024**2)
        assert result.bytes_reclaimed == expected_bytes
        assert result.errors == []


def test_audit_returns_empty(docker_module):
    """Test audit returns empty result (no security checks)."""
    result = docker_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []


def test_parse_reclaimed_space_gb():
    """Test parsing GB from docker prune output."""
    output = "Total reclaimed space: 1.5GB"
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 1610612736  # 1.5 * 1024^3


def test_parse_reclaimed_space_mb():
    """Test parsing MB from docker prune output."""
    output = "Total reclaimed space: 500MB"
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 524288000  # 500 * 1024^2


def test_parse_reclaimed_space_kb():
    """Test parsing KB from docker prune output."""
    output = "Total reclaimed space: 1024KB"
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 1048576  # 1024 * 1024


def test_parse_reclaimed_space_bytes():
    """Test parsing bytes from docker prune output."""
    output = "Total reclaimed space: 100B"
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 100


def test_parse_reclaimed_space_empty():
    """Test parsing empty string returns 0."""
    result = DockerModule._parse_reclaimed_space("")
    assert result == 0


def test_parse_reclaimed_space_no_match():
    """Test parsing random text returns 0."""
    output = "Some random docker output without space info"
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 0


def test_parse_reclaimed_space_with_surrounding_text():
    """Test parsing with other text before/after the reclaimed line."""
    output = """Deleted Images:
untagged: sha256:abc123
untagged: sha256:def456

Total reclaimed space: 2.5GB

Some other output here"""
    result = DockerModule._parse_reclaimed_space(output)
    assert result == 2684354560  # 2.5 * 1024^3


def test_scan_docker_stopped_containers():
    """Test scan reports stopped containers when enabled."""
    docker_module = DockerModule(remove_stopped_containers=True)
    with (
        patch.object(docker_module, "_is_docker_running", return_value=True),
        patch.object(docker_module, "_get_dangling_images", return_value=[]),
        patch.object(docker_module, "_get_unused_volumes", return_value=[]),
        patch.object(docker_module, "_get_stopped_containers", return_value=["c1", "c2"]),
    ):
        result = docker_module.scan()

        assert isinstance(result, ScanResult)
        assert len(result.items) == 1
        assert "2 stopped containers" in result.items[0]


def test_clean_all_flags_disabled():
    """Test clean does nothing when all flags are False."""
    docker_module = DockerModule(
        remove_dangling_images=False,
        remove_unused_volumes=False,
        remove_stopped_containers=False,
    )
    with patch.object(docker_module, "_is_docker_running", return_value=True):
        result = docker_module.clean()

        assert isinstance(result, CleanResult)
        assert result.items_cleaned == []
        assert result.bytes_reclaimed == 0
        assert result.errors == []
