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

    modules.append(HomebrewModule())
    modules.append(DockerModule())
    modules.append(GitModule())
    modules.append(TrashModule())
    modules.append(DevCachesModule())

    return modules
