"""Shared utility functions for MacOS Maid modules."""

from __future__ import annotations

import subprocess
from pathlib import Path


def dir_size(path: Path) -> int:
    """Get directory size in bytes using du -sk.

    Args:
        path: Directory path to measure

    Returns:
        Size in bytes, or 0 if directory doesn't exist or error occurs
    """
    try:
        result = subprocess.run(
            ["du", "-sk", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return 0

        # Parse output: "1024\t/path/to/dir\n"
        output = result.stdout.strip()
        if not output:
            return 0

        size_kb = int(output.split("\t")[0])
        return size_kb * 1024  # Convert KB to bytes

    except (ValueError, IndexError, OSError):
        return 0
