"""Tests for typed per-module config accessors."""

from macos_maid.config import DEFAULT_CONFIG, MaidConfig


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
