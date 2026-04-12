"""Module registry for MacOS Maid."""

from __future__ import annotations

from macos_maid.modules.base import Module


def get_all_modules() -> list[Module]:
    """Return instances of all available modules.

    Modules are imported here to avoid circular imports and to serve
    as the single registry of available modules.
    """
    modules: list[Module] = []

    # Dev modules — imported as they are implemented
    from macos_maid.modules.dev_caches import DevCachesModule
    from macos_maid.modules.docker import DockerModule
    from macos_maid.modules.git import GitModule
    from macos_maid.modules.homebrew import HomebrewModule
    from macos_maid.modules.trash import TrashModule

    # Security modules
    from macos_maid.modules.app_audit import AppAuditModule
    from macos_maid.modules.launch_audit import LaunchAuditModule
    from macos_maid.modules.network import NetworkModule
    from macos_maid.modules.privacy import PrivacyModule
    from macos_maid.modules.system_integrity import SystemIntegrityModule
    from macos_maid.modules.tools import ToolsModule
    from macos_maid.modules.wifi import WiFiModule

    modules.append(HomebrewModule())
    modules.append(DockerModule())
    modules.append(GitModule())
    modules.append(TrashModule())
    modules.append(DevCachesModule())
    modules.append(AppAuditModule())
    modules.append(LaunchAuditModule())
    modules.append(NetworkModule())
    modules.append(PrivacyModule())
    modules.append(SystemIntegrityModule())
    modules.append(ToolsModule())
    modules.append(WiFiModule())

    return modules
