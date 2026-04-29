"""Tests for typed per-module config accessors."""

from dataclasses import fields

from macos_maid.config import (
    DEFAULT_CONFIG,
    AppAuditConfig,
    DevCachesConfig,
    DockerConfig,
    GitConfig,
    HomebrewConfig,
    LaunchAuditConfig,
    MaidConfig,
    NetworkConfig,
    PrivacyConfig,
    SystemCacheConfig,
    SystemIntegrityConfig,
    ToolsConfig,
    TrashConfig,
    WiFiConfig,
)


def test_homebrew_typed_config_defaults():
    cfg = MaidConfig(DEFAULT_CONFIG)
    hb = cfg.homebrew
    assert hb.enabled is True
    assert hb.update is False
    assert hb.upgrade is False
    assert hb.cleanup is True


def test_wifi_typed_config_keep_days_default():
    cfg = MaidConfig(DEFAULT_CONFIG)
    assert cfg.wifi.keep_days == 90
    assert cfg.wifi.keep_ssids == []


def test_privacy_typed_config_from_user_override():
    data = {**DEFAULT_CONFIG, "privacy": {**DEFAULT_CONFIG["privacy"], "downloads_older_than": 30}}
    cfg = MaidConfig(data)
    assert cfg.privacy.downloads_older_than == 30
    # Other fields preserved
    assert cfg.privacy.clear_recent_items is True


def test_git_typed_config_defaults():
    cfg = MaidConfig(DEFAULT_CONFIG)
    assert cfg.git.enabled is False
    assert cfg.git.protected_branches == ["main", "master", "develop"]


def test_tools_typed_config_defaults():
    cfg = MaidConfig(DEFAULT_CONFIG)
    assert cfg.tools.lynis is True
    assert cfg.tools.knockknock is False


def test_dataclass_defaults_match_default_config():
    """Guard against drift between DEFAULT_CONFIG dict and dataclass defaults."""
    configs: list[tuple[str, type]] = [
        ("homebrew", HomebrewConfig),
        ("docker", DockerConfig),
        ("dev_caches", DevCachesConfig),
        ("git", GitConfig),
        ("trash", TrashConfig),
        ("wifi", WiFiConfig),
        ("network", NetworkConfig),
        ("privacy", PrivacyConfig),
        ("system_integrity", SystemIntegrityConfig),
        ("app_audit", AppAuditConfig),
        ("launch_audit", LaunchAuditConfig),
        ("system_cache", SystemCacheConfig),
        ("tools", ToolsConfig),
    ]
    for section, cls in configs:
        dict_defaults = DEFAULT_CONFIG[section]
        instance = cls()
        for f in fields(cls):
            dc_value = getattr(instance, f.name)
            dict_value = dict_defaults.get(f.name)
            assert dc_value == dict_value, (
                f"Drift in {section}.{f.name}: "
                f"dataclass={dc_value!r} vs DEFAULT_CONFIG={dict_value!r}"
            )
