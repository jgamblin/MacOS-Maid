"""Configuration loading and defaults for MacOS Maid."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "categories": ["dev", "security"],
    "report": {
        "show_disk_before_after": True,
        "output": "terminal",
    },
    "homebrew": {
        "update": False,
        "upgrade": False,
        "cleanup": True,
        "audit_casks": True,
        "check_untapped": True,
    },
    "docker": {
        "remove_dangling_images": True,
        "remove_unused_volumes": True,
        "remove_stopped_containers": False,
    },
    "dev_caches": {
        "clean": ["pip", "npm", "cargo", "gradle", "cocoapods", "xcode_derived"],
    },
    "git": {
        "enabled": False,
        "repos_dir": None,
        "prune_remotes": True,
        "delete_merged_branches": False,
        "protected_branches": ["main", "master", "develop"],
        "report_large_repos": True,
    },
    "trash": {
        "empty": True,
    },
    "wifi": {
        "keep_days": 90,
        "keep_ssids": [],
    },
    "network": {
        "flush_dns": True,
        "check_open_ports": True,
        "audit_vpn_profiles": True,
        "check_firewall": True,
    },
    "privacy": {
        "clear_recent_items": True,
        "report_old_downloads": True,
        "downloads_move_to_trash": False,
        "downloads_older_than": 90,
        "audit_tcc_permissions": True,
    },
    "system_integrity": {
        "check_sip": True,
        "check_filevault": True,
        "check_gatekeeper": True,
        "check_xprotect": True,
    },
    "app_audit": {
        "check_unsigned": True,
    },
    "launch_audit": {
        "audit_launch_daemons": True,
        "audit_launch_agents": True,
        "flag_non_apple": True,
    },
    "system_cache": {
        "clean_system_logs": True,
        "clean_user_caches": True,
    },
    "tools": {
        "lynis": True,
        "osquery": True,
        "knockknock": False,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge override into base. Override values win. Dicts merge recursively."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class MaidConfig:
    """Parsed configuration for MacOS Maid."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @property
    def categories(self) -> list[str]:
        result = self._data.get("categories", ["dev", "security"])
        if not isinstance(result, list):
            return ["dev", "security"]
        return result

    @property
    def report(self) -> dict[str, Any]:
        result = self._data.get("report", DEFAULT_CONFIG["report"])
        if not isinstance(result, dict):
            return dict(DEFAULT_CONFIG["report"])
        return result

    def get_module_config(self, module_name: str) -> dict[str, Any]:
        """Get config for a specific module, with defaults applied."""
        result = self._data.get(module_name, DEFAULT_CONFIG.get(module_name, {}))
        if not isinstance(result, dict):
            return dict(DEFAULT_CONFIG.get(module_name, {}))
        return result


def load_config(path: Path | None) -> MaidConfig:
    """Load config from YAML file, falling back to defaults.

    If path is None or doesn't exist, returns defaults.
    User config is deep-merged with defaults so partial configs work.
    """
    if path is not None and path.exists():
        with open(path) as f:
            user_data = yaml.safe_load(f) or {}
        merged = _deep_merge(DEFAULT_CONFIG, user_data)
        return MaidConfig(merged)

    return MaidConfig(copy.deepcopy(DEFAULT_CONFIG))


def generate_default_config_yaml() -> str:
    """Generate a commented YAML string with all defaults for `maid init`."""
    result: str = yaml.dump(DEFAULT_CONFIG, default_flow_style=False, sort_keys=False)
    return result
