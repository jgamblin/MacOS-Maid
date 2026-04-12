"""Module registry for MacOS Maid."""

from __future__ import annotations

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


def get_all_modules() -> list[Module]:
    """Return instances of all available modules."""
    return [
        # Dev modules
        TrashModule(),
        HomebrewModule(),
        DockerModule(),
        DevCachesModule(),
        GitModule(),
        # Security modules
        SystemIntegrityModule(),
        NetworkModule(),
        WiFiModule(),
        PrivacyModule(),
        AppAuditModule(),
        LaunchAuditModule(),
        ToolsModule(),
        # Both
        SystemCacheModule(),
    ]
