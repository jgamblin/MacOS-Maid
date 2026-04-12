"""Docker cleanup module for MacOS Maid."""

from __future__ import annotations

import shutil
import subprocess

from macos_maid.modules.base import AuditResult, CleanResult, Module, ScanResult


class DockerModule(Module):
    """Clean up Docker dangling images and unused volumes.

    This module:
    - Checks if Docker is installed and running
    - Identifies dangling (untagged) images
    - Identifies unused (dangling) volumes
    - NEVER touches stopped containers by default
    - Returns empty results if Docker is not running
    """

    name = "docker"
    category = "dev"
    requires_sudo = False

    def _is_docker_running(self) -> bool:
        """Check if Docker is installed and running."""
        # First check if docker command exists
        if not shutil.which("docker"):
            return False

        # Then check if Docker daemon is running
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_docker(self, args: list[str]) -> str:
        """Run a docker command and return output."""
        result = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return result.stdout

    def _get_dangling_images(self) -> list[str]:
        """Get list of dangling (untagged) image IDs."""
        try:
            output = self._run_docker(["images", "-q", "--filter", "dangling=true"])
            images = [line.strip() for line in output.splitlines() if line.strip()]
            return images
        except subprocess.CalledProcessError:
            return []

    def _get_unused_volumes(self) -> list[str]:
        """Get list of unused (dangling) volume names."""
        try:
            output = self._run_docker(["volume", "ls", "-q", "--filter", "dangling=true"])
            volumes = [line.strip() for line in output.splitlines() if line.strip()]
            return volumes
        except subprocess.CalledProcessError:
            return []

    def scan(self) -> ScanResult:
        """Preview what Docker cleanup would do."""
        if not self._is_docker_running():
            return ScanResult.empty()

        dangling_images = self._get_dangling_images()
        unused_volumes = self._get_unused_volumes()

        items = []
        if dangling_images:
            items.append(f"{len(dangling_images)} dangling images")
        if unused_volumes:
            items.append(f"{len(unused_volumes)} unused volumes")

        # Size estimation not implemented - would require additional docker commands
        return ScanResult(items=items, bytes_reclaimable=0, requires_sudo=False)

    def clean(self) -> CleanResult:
        """Clean up Docker dangling images and unused volumes."""
        if not self._is_docker_running():
            return CleanResult.empty()

        items_cleaned = []
        errors = []

        # Prune dangling images
        try:
            self._run_docker(["image", "prune", "-f"])
            items_cleaned.append("Pruned dangling images")
        except subprocess.CalledProcessError as e:
            errors.append(f"Failed to prune images: {e}")

        # Prune unused volumes
        try:
            self._run_docker(["volume", "prune", "-f"])
            items_cleaned.append("Pruned unused volumes")
        except subprocess.CalledProcessError as e:
            errors.append(f"Failed to prune volumes: {e}")

        # Size calculation not implemented - would require parsing prune output
        return CleanResult(items_cleaned=items_cleaned, bytes_reclaimed=0, errors=errors)

    def audit(self) -> AuditResult:
        """Run security checks (not applicable for Docker cleanup)."""
        return AuditResult.empty()
