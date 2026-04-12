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
    # from macos_maid.modules.trash import TrashModule
    # modules.append(TrashModule())

    return modules
