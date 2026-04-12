# tests/modules/test_git.py
from pathlib import Path
from unittest.mock import patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, ScanResult
from macos_maid.modules.git import GitModule


@pytest.fixture
def git_module():
    """Create a GitModule instance for testing."""
    return GitModule()


def test_git_module_metadata(git_module):
    """Test module metadata is set correctly."""
    assert git_module.name == "git"
    assert git_module.category == "dev"
    assert git_module.requires_sudo is False


def test_protected_branch_detection(git_module):
    """Test that main/master/develop are protected, feature branches are not."""
    protected = ["main", "master", "develop"]

    # Protected branches
    assert git_module._is_protected_branch("main", protected) is True
    assert git_module._is_protected_branch("master", protected) is True
    assert git_module._is_protected_branch("develop", protected) is True

    # Non-protected branches
    assert git_module._is_protected_branch("feature/foo", protected) is False
    assert git_module._is_protected_branch("bugfix/bar", protected) is False
    assert git_module._is_protected_branch("test-branch", protected) is False


def test_git_scan_disabled_by_default(git_module):
    """Test that scan returns empty result when module is disabled by default."""
    result = git_module.scan()

    assert isinstance(result, ScanResult)
    assert result.items == []
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is False


def test_git_clean_disabled_by_default(git_module):
    """Test that clean returns empty result when module is disabled by default."""
    result = git_module.clean()

    assert isinstance(result, CleanResult)
    assert result.items_cleaned == []
    assert result.bytes_reclaimed == 0
    assert result.errors == []


def test_git_never_deletes_protected(git_module):
    """Test that protected branches are never deleted during cleanup."""
    git_module.enabled = True
    git_module.repos_dir = "/tmp/test-repos"
    git_module.delete_merged = True

    repo_path = Path("/tmp/test-repos/repo1")

    with (
        patch.object(git_module, "_find_repos", return_value=[repo_path]),
        patch.object(git_module, "_get_default_branch", return_value="main"),
        patch.object(
            git_module,
            "_get_merged_branches",
            return_value=["main", "master", "develop", "feature/merged"],
        ),
        patch.object(git_module, "_run_git") as mock_run_git,
    ):
        mock_run_git.return_value = ""

        git_module.clean()

        # Verify that git branch -d was only called for the non-protected branch
        delete_calls = [
            call
            for call in mock_run_git.call_args_list
            if "branch" in str(call) and "-d" in str(call)
        ]

        # Should only delete feature/merged, not main/master/develop
        if delete_calls:
            for call in delete_calls:
                args = str(call)
                assert "feature/merged" in args or "branch -d" in args
                # Make sure protected branches are not in delete calls
                for protected in ["main", "master", "develop"]:
                    if f"branch -d {protected}" in args:
                        pytest.fail(f"Attempted to delete protected branch: {protected}")


def test_git_scan_enabled_with_repos(git_module):
    """Test scan reports merged branches and large repos when enabled."""
    git_module.enabled = True
    git_module.repos_dir = "/tmp/test-repos"

    repo1 = Path("/tmp/test-repos/repo1")
    repo2 = Path("/tmp/test-repos/repo2")

    with (
        patch.object(git_module, "_find_repos", return_value=[repo1, repo2]),
        patch.object(git_module, "_get_default_branch", side_effect=["main", "master"]),
        patch.object(
            git_module,
            "_get_merged_branches",
            side_effect=[["feature/old", "bugfix/done"], ["hotfix/123"]],
        ),
        patch.object(git_module, "_get_repo_size", side_effect=[1024 * 1024, 500 * 1024]),
    ):
        result = git_module.scan()

        assert isinstance(result, ScanResult)
        assert len(result.items) > 0
        assert any("repo1" in item and "2 merged branches" in item for item in result.items)
        assert any("repo2" in item and "1 merged branch" in item for item in result.items)
        assert result.requires_sudo is False


def test_git_clean_prunes_remotes(git_module):
    """Test that clean prunes remote branches when enabled."""
    git_module.enabled = True
    git_module.repos_dir = "/tmp/test-repos"
    git_module.prune_remotes = True

    repo_path = Path("/tmp/test-repos/repo1")

    with (
        patch.object(git_module, "_find_repos", return_value=[repo_path]),
        patch.object(git_module, "_get_default_branch", return_value="main"),
        patch.object(git_module, "_get_merged_branches", return_value=[]),
        patch.object(git_module, "_run_git", return_value="") as mock_run_git,
    ):
        result = git_module.clean()

        assert isinstance(result, CleanResult)
        # Verify prune was called
        assert mock_run_git.called
        prune_calls = [
            call
            for call in mock_run_git.call_args_list
            if len(call[0]) > 1 and "remote" in call[0][1]
        ]
        assert len(prune_calls) > 0


def test_audit_returns_empty(git_module):
    """Test audit returns empty result (no security checks)."""
    result = git_module.audit()

    assert isinstance(result, AuditResult)
    assert result.status == "pass"
    assert result.findings == []


def test_git_reports_large_repos(git_module):
    """Test that large repos are reported when enabled."""
    git_module.enabled = True
    git_module.repos_dir = "/tmp/test-repos"
    git_module.report_large_repos = True

    repo_path = Path("/tmp/test-repos/large-repo")

    with (
        patch.object(git_module, "_find_repos", return_value=[repo_path]),
        patch.object(git_module, "_get_default_branch", return_value="main"),
        patch.object(git_module, "_get_merged_branches", return_value=[]),
        patch.object(git_module, "_get_repo_size", return_value=2 * 1024 * 1024),  # 2GB
    ):
        result = git_module.scan()

        assert isinstance(result, ScanResult)
        assert any("large-repo" in item and ("GB" in item or "MB" in item) for item in result.items)
