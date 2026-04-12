# tests/test_config.py
import tempfile
from pathlib import Path

import yaml

from macos_maid.config import DEFAULT_CONFIG, load_config


def test_default_config_has_all_modules():
    assert "homebrew" in DEFAULT_CONFIG
    assert "docker" in DEFAULT_CONFIG
    assert "dev_caches" in DEFAULT_CONFIG
    assert "git" in DEFAULT_CONFIG
    assert "trash" in DEFAULT_CONFIG
    assert "wifi" in DEFAULT_CONFIG
    assert "network" in DEFAULT_CONFIG
    assert "privacy" in DEFAULT_CONFIG
    assert "system_integrity" in DEFAULT_CONFIG
    assert "app_audit" in DEFAULT_CONFIG
    assert "launch_audit" in DEFAULT_CONFIG
    assert "system_cache" in DEFAULT_CONFIG
    assert "tools" in DEFAULT_CONFIG


def test_default_config_safe_defaults():
    """Verify safety-critical defaults."""
    assert DEFAULT_CONFIG["git"]["enabled"] is False
    assert DEFAULT_CONFIG["git"]["repos_dir"] is None
    assert DEFAULT_CONFIG["git"]["delete_merged_branches"] is False
    assert DEFAULT_CONFIG["docker"]["remove_stopped_containers"] is False
    assert DEFAULT_CONFIG["privacy"]["downloads_move_to_trash"] is False
    assert DEFAULT_CONFIG["tools"]["knockknock"] is False


def test_load_config_from_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump({"homebrew": {"update": False}}, f)
        f.flush()
        config = load_config(Path(f.name))
    # Overridden value
    assert config.get_module_config("homebrew")["update"] is False
    # Default value preserved
    assert config.get_module_config("homebrew")["cleanup"] is True


def test_load_config_default_when_missing():
    config = load_config(Path("/nonexistent/path.yml"))
    assert config.get_module_config("homebrew")["update"] is False


def test_config_categories():
    config = load_config(None)
    assert "dev" in config.categories
    assert "security" in config.categories


def test_config_report_settings():
    config = load_config(None)
    assert config.report["output"] == "terminal"
    assert config.report["show_disk_before_after"] is True


def test_config_merge_deep():
    """User config merges deeply, not replaces."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump({"dev_caches": {"clean": ["pip", "npm"]}}, f)
        f.flush()
        config = load_config(Path(f.name))
    # User narrowed the clean list
    assert config.get_module_config("dev_caches")["clean"] == ["pip", "npm"]


def test_generate_default_config():
    from macos_maid.config import generate_default_config_yaml

    content = generate_default_config_yaml()
    assert "categories:" in content
    assert "homebrew:" in content
    assert "wifi:" in content
