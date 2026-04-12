"""Module registry for MacOS Maid."""

from __future__ import annotations

from typing import TYPE_CHECKING

from macos_maid.modules.app_audit import AppAuditModule
from macos_maid.modules.base import Module
from macos_maid.modules.dev_caches import DevCachesModule
from macos_maid.modules.docker import DockerModule
from macos_maid.modules.git import GitModule
from macos_maid.modules.homebrew import HomebrewModule
from macos_maid.modules.launch_audit import LaunchAuditModule
from macos_maid.modules.network import NetworkModule
from macos_maid.modules.privacy import PrivacyModule
from macos_maid.modules.system_cache import SystemCacheModule
from macos_maid.modules.system_integrity import SystemIntegrityModule
from macos_maid.modules.tools import ToolsModule
from macos_maid.modules.trash import TrashModule
from macos_maid.modules.wifi import WiFiModule

if TYPE_CHECKING:
    from macos_maid.config import MaidConfig


def get_all_modules(config: MaidConfig | None = None) -> list[Module]:
    """Return instances of all available modules.

    Args:
        config: Optional MaidConfig to configure modules. If None, uses default settings.

    Returns:
        List of configured module instances
    """
    # Get module configurations from config or use defaults
    if config is not None:
        wifi_cfg = config.get_module_config("wifi")
        privacy_cfg = config.get_module_config("privacy")
        tools_cfg = config.get_module_config("tools")
        git_cfg = config.get_module_config("git")
        homebrew_cfg = config.get_module_config("homebrew")
        docker_cfg = config.get_module_config("docker")
    else:
        wifi_cfg = {}
        privacy_cfg = {}
        tools_cfg = {}
        git_cfg = {}
        homebrew_cfg = {}
        docker_cfg = {}

    # WiFi module
    wifi = WiFiModule(
        keep_days=wifi_cfg.get("keep_days", 90),
        keep_ssids=wifi_cfg.get("keep_ssids", []),
    )

    # Privacy module
    privacy = PrivacyModule(
        clear_recent=privacy_cfg.get("clear_recent_items", True),
        downloads_move_to_trash=privacy_cfg.get("downloads_move_to_trash", False),
        downloads_older_than=privacy_cfg.get("downloads_older_than", 90),
    )

    # Tools module
    tools = ToolsModule(
        lynis_enabled=tools_cfg.get("lynis", True),
        osquery_enabled=tools_cfg.get("osquery", True),
        knockknock_enabled=tools_cfg.get("knockknock", False),
    )

    # Git module
    git = GitModule(
        enabled=git_cfg.get("enabled", False),
        repos_dir=git_cfg.get("repos_dir"),
        prune_remotes=git_cfg.get("prune_remotes", True),
        delete_merged=git_cfg.get("delete_merged_branches", False),
        protected_branches=git_cfg.get("protected_branches", ["main", "master", "develop"]),
        report_large_repos=git_cfg.get("report_large_repos", True),
    )

    # Homebrew module
    homebrew = HomebrewModule(
        update=homebrew_cfg.get("update", False),
        upgrade=homebrew_cfg.get("upgrade", False),
        cleanup=homebrew_cfg.get("cleanup", True),
    )

    # Docker module
    docker = DockerModule(
        remove_dangling_images=docker_cfg.get("remove_dangling_images", True),
        remove_unused_volumes=docker_cfg.get("remove_unused_volumes", True),
        remove_stopped_containers=docker_cfg.get("remove_stopped_containers", False),
    )

    return [
        # Dev modules
        TrashModule(),
        homebrew,
        docker,
        DevCachesModule(),
        git,
        # Security modules
        SystemIntegrityModule(),
        NetworkModule(),
        wifi,
        privacy,
        AppAuditModule(),
        LaunchAuditModule(),
        tools,
        # Both
        SystemCacheModule(),
    ]
