"""Configuration loading and defaults for MacOS Maid."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
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
        "enabled": True,
        "update": False,
        "upgrade": False,
        "cleanup": True,
        "audit_casks": True,
        "check_untapped": True,
    },
    "docker": {
        "enabled": True,
        "remove_dangling_images": True,
        "remove_unused_volumes": True,
        "remove_stopped_containers": False,
    },
    "dev_caches": {
        "enabled": True,
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
        "enabled": True,
        "empty": True,
    },
    "wifi": {
        "enabled": True,
        "keep_days": 90,
        "keep_ssids": [],
    },
    "network": {
        "enabled": True,
        "flush_dns": True,
        "check_open_ports": True,
        "audit_vpn_profiles": True,
        "check_firewall": True,
    },
    "privacy": {
        "enabled": True,
        "clear_recent_items": True,
        "report_old_downloads": True,
        "downloads_move_to_trash": False,
        "downloads_older_than": 90,
        "audit_tcc_permissions": True,
    },
    "system_integrity": {
        "enabled": True,
        "check_sip": True,
        "check_filevault": True,
        "check_gatekeeper": True,
        "check_xprotect": True,
    },
    "app_audit": {
        "enabled": True,
        "check_unsigned": True,
    },
    "launch_audit": {
        "enabled": True,
        "audit_launch_daemons": True,
        "audit_launch_agents": True,
        "flag_non_apple": True,
    },
    "system_cache": {
        "enabled": True,
        "clean_system_logs": True,
        "clean_user_caches": True,
    },
    "tools": {
        "enabled": True,
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


@dataclass
class HomebrewConfig:
    enabled: bool = True
    update: bool = False
    upgrade: bool = False
    cleanup: bool = True
    audit_casks: bool = True
    check_untapped: bool = True


@dataclass
class DockerConfig:
    enabled: bool = True
    remove_dangling_images: bool = True
    remove_unused_volumes: bool = True
    remove_stopped_containers: bool = False


@dataclass
class DevCachesConfig:
    enabled: bool = True
    clean: list[str] = field(
        default_factory=lambda: ["pip", "npm", "cargo", "gradle", "cocoapods", "xcode_derived"]
    )


@dataclass
class GitConfig:
    enabled: bool = False
    repos_dir: str | None = None
    prune_remotes: bool = True
    delete_merged_branches: bool = False
    protected_branches: list[str] = field(default_factory=lambda: ["main", "master", "develop"])
    report_large_repos: bool = True


@dataclass
class TrashConfig:
    enabled: bool = True
    empty: bool = True


@dataclass
class WiFiConfig:
    enabled: bool = True
    keep_days: int = 90
    keep_ssids: list[str] = field(default_factory=list)


@dataclass
class NetworkConfig:
    enabled: bool = True
    flush_dns: bool = True
    check_open_ports: bool = True
    audit_vpn_profiles: bool = True
    check_firewall: bool = True


@dataclass
class PrivacyConfig:
    enabled: bool = True
    clear_recent_items: bool = True
    report_old_downloads: bool = True
    downloads_move_to_trash: bool = False
    downloads_older_than: int = 90
    audit_tcc_permissions: bool = True


@dataclass
class SystemIntegrityConfig:
    enabled: bool = True
    check_sip: bool = True
    check_filevault: bool = True
    check_gatekeeper: bool = True
    check_xprotect: bool = True


@dataclass
class AppAuditConfig:
    enabled: bool = True
    check_unsigned: bool = True


@dataclass
class LaunchAuditConfig:
    enabled: bool = True
    audit_launch_daemons: bool = True
    audit_launch_agents: bool = True
    flag_non_apple: bool = True


@dataclass
class SystemCacheConfig:
    enabled: bool = True
    clean_system_logs: bool = True
    clean_user_caches: bool = True


@dataclass
class ToolsConfig:
    enabled: bool = True
    lynis: bool = True
    osquery: bool = True
    knockknock: bool = False


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

    def _build(self, section: str, cls: type) -> object:
        """Build a dataclass from config data, ignoring unknown keys."""
        data = self.get_module_config(section)
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    @property
    def homebrew(self) -> HomebrewConfig:
        return self._build("homebrew", HomebrewConfig)  # type: ignore[return-value]

    @property
    def docker(self) -> DockerConfig:
        return self._build("docker", DockerConfig)  # type: ignore[return-value]

    @property
    def dev_caches(self) -> DevCachesConfig:
        return self._build("dev_caches", DevCachesConfig)  # type: ignore[return-value]

    @property
    def git(self) -> GitConfig:
        return self._build("git", GitConfig)  # type: ignore[return-value]

    @property
    def trash(self) -> TrashConfig:
        return self._build("trash", TrashConfig)  # type: ignore[return-value]

    @property
    def wifi(self) -> WiFiConfig:
        return self._build("wifi", WiFiConfig)  # type: ignore[return-value]

    @property
    def network(self) -> NetworkConfig:
        return self._build("network", NetworkConfig)  # type: ignore[return-value]

    @property
    def privacy(self) -> PrivacyConfig:
        return self._build("privacy", PrivacyConfig)  # type: ignore[return-value]

    @property
    def system_integrity(self) -> SystemIntegrityConfig:
        return self._build("system_integrity", SystemIntegrityConfig)  # type: ignore[return-value]

    @property
    def app_audit(self) -> AppAuditConfig:
        return self._build("app_audit", AppAuditConfig)  # type: ignore[return-value]

    @property
    def launch_audit(self) -> LaunchAuditConfig:
        return self._build("launch_audit", LaunchAuditConfig)  # type: ignore[return-value]

    @property
    def system_cache(self) -> SystemCacheConfig:
        return self._build("system_cache", SystemCacheConfig)  # type: ignore[return-value]

    @property
    def tools(self) -> ToolsConfig:
        return self._build("tools", ToolsConfig)  # type: ignore[return-value]


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
