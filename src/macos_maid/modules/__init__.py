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
        List of configured module instances (only those with enabled=True)
    """
    # Import inside function to avoid circular import at module-load time.
    from macos_maid.config import DEFAULT_CONFIG, MaidConfig

    cfg = config if config is not None else MaidConfig(DEFAULT_CONFIG)

    modules: list[Module] = []

    if cfg.trash.enabled:
        modules.append(TrashModule())

    if cfg.homebrew.enabled:
        modules.append(
            HomebrewModule(
                update=cfg.homebrew.update,
                upgrade=cfg.homebrew.upgrade,
                cleanup=cfg.homebrew.cleanup,
            )
        )

    if cfg.docker.enabled:
        modules.append(
            DockerModule(
                remove_dangling_images=cfg.docker.remove_dangling_images,
                remove_unused_volumes=cfg.docker.remove_unused_volumes,
                remove_stopped_containers=cfg.docker.remove_stopped_containers,
            )
        )

    if cfg.dev_caches.enabled:
        modules.append(DevCachesModule())

    if cfg.git.enabled:
        modules.append(
            GitModule(
                enabled=cfg.git.enabled,
                repos_dir=cfg.git.repos_dir,
                prune_remotes=cfg.git.prune_remotes,
                delete_merged=cfg.git.delete_merged_branches,
                protected_branches=cfg.git.protected_branches,
                report_large_repos=cfg.git.report_large_repos,
            )
        )

    if cfg.system_integrity.enabled:
        modules.append(SystemIntegrityModule())

    if cfg.network.enabled:
        modules.append(NetworkModule())

    if cfg.wifi.enabled:
        modules.append(
            WiFiModule(
                keep_days=cfg.wifi.keep_days,
                keep_ssids=cfg.wifi.keep_ssids,
            )
        )

    if cfg.privacy.enabled:
        modules.append(
            PrivacyModule(
                clear_recent=cfg.privacy.clear_recent_items,
                downloads_move_to_trash=cfg.privacy.downloads_move_to_trash,
                downloads_older_than=cfg.privacy.downloads_older_than,
            )
        )

    if cfg.app_audit.enabled:
        modules.append(AppAuditModule())

    if cfg.launch_audit.enabled:
        modules.append(LaunchAuditModule())

    if cfg.tools.enabled:
        modules.append(
            ToolsModule(
                lynis_enabled=cfg.tools.lynis,
                osquery_enabled=cfg.tools.osquery,
                knockknock_enabled=cfg.tools.knockknock,
            )
        )

    if cfg.system_cache.enabled:
        modules.append(SystemCacheModule())

    return modules
