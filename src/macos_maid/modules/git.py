"""Git repository cleanup module for MacOS Maid."""

from __future__ import annotations

import subprocess
from pathlib import Path

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult
from macos_maid.reporter import format_bytes
from macos_maid.utils import dir_size

DEFAULT_PROTECTED = ["main", "master", "develop"]


class GitModule(Module):
    """Clean up git repositories: prune remotes, delete merged branches, report large repos.

    SAFETY: Disabled by default. repos_dir must be explicitly set.
    Never deletes protected branches. Only deletes branches merged into default branch.
    """

    name = "git"
    category = "dev"
    requires_sudo = False

    def __init__(
        self,
        enabled: bool = False,
        repos_dir: str | None = None,
        prune_remotes: bool = True,
        delete_merged: bool = False,
        protected_branches: list[str] | None = None,
        report_large_repos: bool = True,
    ) -> None:
        """Initialize Git module.

        Args:
            enabled: Enable git repository cleanup (default: False)
            repos_dir: Directory containing git repositories (default: None)
            prune_remotes: Prune stale remote branches (default: True)
            delete_merged: Delete branches merged into default branch (default: False)
            protected_branches: Branch names to never delete
                (default: ["main", "master", "develop"])
            report_large_repos: Report repositories over 1GB (default: True)
        """
        self.enabled = enabled
        self.repos_dir = repos_dir
        self.prune_remotes = prune_remotes
        self.delete_merged = delete_merged
        self.protected_branches = (
            protected_branches if protected_branches is not None else DEFAULT_PROTECTED.copy()
        )
        self.report_large_repos = report_large_repos

    def _is_protected_branch(self, branch: str, protected: list[str]) -> bool:
        """Check if a branch is protected."""
        return branch in protected

    def _get_default_branch(self, repo_path: Path) -> str | None:
        """Get the default branch name for a repo using git symbolic-ref."""
        try:
            result = subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Output is like "refs/remotes/origin/main"
                return result.stdout.strip().split("/")[-1]
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None

    def _get_merged_branches(self, repo_path: Path, default_branch: str) -> list[str]:
        """Get list of branches merged into the default branch."""
        try:
            result = subprocess.run(
                ["git", "branch", "--merged", default_branch],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Parse branch names, skipping the current branch (marked with *)
                branches = []
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line or line.startswith("*"):
                        continue
                    branches.append(line)
                return branches
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return []

    def _get_repo_size(self, repo_path: Path) -> int:
        """Get repository size in bytes using dir_size utility."""
        return dir_size(repo_path)

    def _run_git(self, repo_path: Path, args: list[str]) -> str:
        """Run a git command in a repository."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return ""

    def _find_repos(self) -> list[Path]:
        """Find all git repositories in repos_dir."""
        if not self.repos_dir:
            return []

        repos_path = Path(self.repos_dir)
        if not repos_path.exists() or not repos_path.is_dir():
            return []

        repos = []
        try:
            for item in repos_path.iterdir():
                if item.is_dir() and (item / ".git").exists():
                    repos.append(item)
        except (OSError, PermissionError):
            pass

        return repos

    def scan(self) -> ScanResult:
        """Preview what this module would do (dry-run)."""
        if not self.enabled or not self.repos_dir:
            return ScanResult.empty()

        items = []
        repos = self._find_repos()

        for repo in repos:
            default_branch = self._get_default_branch(repo)
            if not default_branch:
                continue

            # Report merged branches
            merged = self._get_merged_branches(repo, default_branch)
            # Filter out protected branches
            deletable = [
                b for b in merged if not self._is_protected_branch(b, self.protected_branches)
            ]

            if deletable:
                count = len(deletable)
                branch_word = "branch" if count == 1 else "branches"
                items.append(f"{repo.name}: {count} merged {branch_word}")

            # Report large repos if enabled
            if self.report_large_repos:
                size_bytes = self._get_repo_size(repo)
                if size_bytes > 1024 * 1024 * 1024:  # > 1GB
                    items.append(f"{repo.name}: large repo ({format_bytes(size_bytes)})")

        return ScanResult(items=items, bytes_reclaimable=0, requires_sudo=False)

    def clean(self) -> CleanResult:
        """Execute cleanup operations."""
        if not self.enabled or not self.repos_dir:
            return CleanResult.empty()

        items_cleaned = []
        errors = []
        repos = self._find_repos()

        for repo in repos:
            # Prune remote branches
            if self.prune_remotes:
                try:
                    self._run_git(repo, ["remote", "prune", "origin"])
                    items_cleaned.append(f"{repo.name}: pruned remote branches")
                except Exception as e:
                    errors.append(f"{repo.name}: failed to prune remotes - {str(e)}")

            # Delete merged branches if enabled
            if self.delete_merged:
                default_branch = self._get_default_branch(repo)
                if not default_branch:
                    continue

                merged = self._get_merged_branches(repo, default_branch)
                # Filter out protected branches
                deletable = [
                    b for b in merged if not self._is_protected_branch(b, self.protected_branches)
                ]

                for branch in deletable:
                    try:
                        self._run_git(repo, ["branch", "-d", branch])
                    except Exception as e:
                        errors.append(f"{repo.name}: failed to delete {branch} - {str(e)}")

                if deletable:
                    count = len(deletable)
                    branch_word = "branch" if count == 1 else "branches"
                    items_cleaned.append(f"{repo.name}: deleted {count} merged {branch_word}")

        return CleanResult(items_cleaned=items_cleaned, bytes_reclaimed=0, errors=errors)

    def audit(self) -> AuditResult:
        """Run security checks (read-only, never modifies anything)."""
        return AuditResult.empty()
